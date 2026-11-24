"""URL feature extraction for phishing / quishing detection.

All features are computed locally from the URL string - no network calls are
made. This keeps inference fast and privacy preserving (the scanned URL never
leaves the device unless you explicitly call a remote service).
"""

from __future__ import annotations

import ipaddress
import math
import re
from collections import Counter
from functools import lru_cache
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import parse_qsl, unquote, urlsplit

import numpy as np

from .brands import (
    BRANDS,
    COMMON_TLDS,
    CRYPTO_KEYWORDS,
    DANGEROUS_SCHEMES,
    FREE_HOSTING_SUFFIXES,
    GENERIC_LABELS,
    LOGIN_KEYWORDS,
    OFFICIAL_BRAND_DOMAINS,
    PAYMENT_KEYWORDS,
    REDIRECT_PARAMETERS,
    SUSPICIOUS_KEYWORDS,
    SUSPICIOUS_TLDS,
    URL_SHORTENERS,
)
from .config import MAX_URL_LENGTH, MULTI_PART_SUFFIXES

try:  # tldextract ships a bundled PSL snapshot; never hit the network.
    import tldextract

    _EXTRACTOR = tldextract.TLDExtract(
        suffix_list_urls=(),
        cache_dir=None,
        include_psl_private_domains=False,
    )
except Exception:  # pragma: no cover - only if tldextract is unavailable
    _EXTRACTOR = None


# ---------------------------------------------------------------------------
# Parsing helpers
# ---------------------------------------------------------------------------

_SCHEME_RE = re.compile(r"^([a-zA-Z][a-zA-Z0-9+.-]*)://")
_OPAQUE_SCHEME_RE = re.compile(
    r"^(javascript|data|file|mailto|tel|sms|smsto|mms|geo|bitcoin|ethereum|"
    r"litecoin|dogecoin|monero|upi|intent|market|magnet|ftp|ftps|ws|wss|"
    r"chrome|about|blob):",
    re.IGNORECASE,
)
_HOST_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9\u0080-\uFFFF_-]{1,63}"
    r"(?:\.[A-Za-z0-9\u0080-\uFFFF_-]{1,63})+\.?$"
)
_IPV4_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
_URL_IN_TEXT_RE = re.compile(
    r"(?:https?://|www\.)[^\s<>\"'`]+", re.IGNORECASE
)
_HEX_TOKEN_RE = re.compile(r"[0-9a-f]{16,}", re.IGNORECASE)
_LONG_TOKEN_RE = re.compile(r"[A-Za-z0-9_\-]{24,}")
_DIGIT_RUN_RE = re.compile(r"\d+")
_ALPHA_RUN_RE = re.compile(r"[A-Za-z]+")
_NON_ALNUM_RE = re.compile(r"[^a-z0-9]+")

# Character substitutions commonly used for brand lookalikes.
_LEET_MAP = str.maketrans({
    "0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t",
    "8": "b", "9": "g", "@": "a", "$": "s", "!": "i", "|": "l",
})


def has_scheme(value: str) -> bool:
    value = value.strip()
    return bool(_SCHEME_RE.match(value) or _OPAQUE_SCHEME_RE.match(value))


def ensure_scheme(value: str, default: str = "http://") -> str:
    """Turn a bare host/path into an absolute URL, leaving schemes intact."""
    value = value.strip()
    if not value:
        return value
    if value.startswith("//"):
        return "http:" + value
    if has_scheme(value):
        return value
    return default + value


def get_scheme(value: str) -> str:
    value = value.strip()
    m = _SCHEME_RE.match(value) or _OPAQUE_SCHEME_RE.match(value)
    return m.group(1).lower() if m else ""


def extract_urls_from_text(text: str, limit: int = 10) -> List[str]:
    """Find URLs inside arbitrary QR payload text (e.g. a redirect wrapper)."""
    found = _URL_IN_TEXT_RE.findall(text or "")
    seen = set()
    out: List[str] = []
    for url in found:
        url = url.rstrip(").,;:!?'\"]}>")
        if url.lower() not in seen:
            seen.add(url.lower())
            out.append(url)
        if len(out) >= limit:
            break
    return out


def normalize_url(value: str) -> str:
    """Canonical-ish URL used only for model text features."""
    value = value.strip()
    if not value:
        return ""
    value = ensure_scheme(value)
    try:
        parts = urlsplit(value)
        host = (parts.hostname or "").lower().rstrip(".")
        if host:
            netloc = host
            if parts.port:
                netloc += ":" + str(parts.port)
            value = parts._replace(netloc=netloc, fragment="").geturl()
    except ValueError:
        pass
    value = unquote(value)
    return value[:MAX_URL_LENGTH].lower()


def is_ip_host(host: str) -> bool:
    if not host:
        return False
    try:
        ipaddress.ip_address(host.strip("[]"))
        return True
    except ValueError:
        return _IPV4_RE.match(host) is not None


@lru_cache(maxsize=400_000)
def split_host(host: str) -> Tuple[str, str, str]:
    """Return (subdomain, registered_domain, suffix) for a hostname."""
    host = (host or "").strip().lower().rstrip(".")
    if not host:
        return "", "", ""
    if is_ip_host(host):
        return "", host, ""
    if "." not in host:
        return "", host, ""
    if _EXTRACTOR is not None:
        try:
            ext = _EXTRACTOR(host)
            top = getattr(ext, "top_domain_under_public_suffix", None)
            if top is None:
                top = ext.registered_domain
            registered = top or host
            return ext.subdomain or "", registered, ext.suffix or ""
        except Exception:
            pass
    labels = host.split(".")
    suffix = labels[-1]
    if len(labels) >= 3 and ".".join(labels[-2:]) in MULTI_PART_SUFFIXES:
        suffix = ".".join(labels[-2:])
        registered = ".".join(labels[-3:])
        sub = ".".join(labels[:-3])
    else:
        registered = ".".join(labels[-2:])
        sub = ".".join(labels[:-2])
    return sub, registered, suffix


def _entropy(text: str) -> float:
    if not text:
        return 0.0
    counts = Counter(text)
    n = len(text)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _tokens(value: str) -> List[str]:
    return [t for t in _NON_ALNUM_RE.split(value.lower()) if t]


def _split_brand_tokens(host: str) -> List[str]:
    """Split a hostname into tokens, handling hyphen/camelCase obfuscation."""
    spaced = re.sub(r"([a-z])([A-Z])", r"\1-\2", host)
    return _tokens(spaced)


def _skeleton(value: str) -> str:
    return value.lower().translate(_LEET_MAP)


# Index brands by length for fast lookalike checks.
_BRAND_BY_LEN: Dict[int, List[str]] = {}
for _brand in BRANDS:
    if len(_brand) >= 4:
        _BRAND_BY_LEN.setdefault(len(_brand), []).append(_brand)
_BRAND_TOKENS = set(BRANDS)


def _close_brand(label: str) -> Optional[str]:
    """Cheap Levenshtein-1 / leet lookalike check for a domain label."""
    if len(label) < 4 or label.isdigit():
        return None
    skel = _skeleton(label)
    for brand in _BRAND_BY_LEN.get(len(label), []):
        if len(brand) < 4:
            continue
        if skel == _skeleton(brand):
            return brand
        diffs = sum(1 for a, b in zip(skel, _skeleton(brand)) if a != b)
        if diffs == 1:
            return brand
    for brand in _BRAND_BY_LEN.get(len(label) - 1, []):
        if _skeleton(brand) in skel[1:] or _skeleton(brand) in skel[:-1]:
            return brand
    for brand in _BRAND_BY_LEN.get(len(label) + 1, []):
        if skel in _skeleton(brand)[1:] or skel in _skeleton(brand)[:-1]:
            return brand
    return None


@lru_cache(maxsize=100_000)
def _analyse_host(host: str) -> Dict[str, float]:
    sub, registered, suffix = split_host(host)
    reg_label = registered.split(".")[0] if registered else ""
    labels = [lab for lab in host.split(".") if lab]
    brand_tokens = set(_split_brand_tokens(host))

    brand_exact = bool(brand_tokens & _BRAND_TOKENS)
    brand_substring = False
    if not brand_exact and 4 <= len(host) <= 80:
        for brand in BRANDS:
            if brand in host and brand not in GENERIC_LABELS:
                brand_exact = True
                break
    if brand_exact:
        brand_substring = True

    official = registered in OFFICIAL_BRAND_DOMAINS
    sub_tokens = set(_split_brand_tokens(sub)) if sub else set()
    brand_in_sub = bool(sub_tokens & _BRAND_TOKENS)

    # Lookalike domains (paypa1.com, g00gle.net, arnazon.com).
    fuzzy_brand = _close_brand(reg_label) if reg_label and not official else None
    # A brand inside the host but missing from the registered domain.
    token_hit = bool(brand_tokens & _BRAND_TOKENS) or brand_substring
    brand_not_official = token_hit and not official
    brand_in_sub_only = (brand_in_sub or token_hit) and not official

    return {
        "subdomain_count": float(len([x for x in sub.split(".") if x])),
        "host_label_count": float(len(labels)),
        "host_has_brand": 1.0 if token_hit else 0.0,
        "brand_in_subdomain_only": 1.0 if brand_in_sub_only else 0.0,
        "brand_not_official": 1.0 if brand_not_official else 0.0,
        "brand_official": 1.0 if official else 0.0,
        "brand_fuzzy_lookalike": 1.0 if fuzzy_brand else 0.0,
        "brand_substring": 1.0 if brand_substring else 0.0,
        "is_free_hosting": 1.0 if any(
            host == s or host.endswith("." + s) for s in FREE_HOSTING_SUFFIXES
        ) else 0.0,
        "is_shortener": 1.0 if registered in URL_SHORTENERS else 0.0,
        "tld_risky": 1.0 if suffix in SUSPICIOUS_TLDS else 0.0,
        "tld_common": 1.0 if suffix in COMMON_TLDS else 0.0,
        "tld_len": float(len(suffix)),
        "registered_domain_len": float(len(registered)),
    }


def extract_features(url: str) -> np.ndarray:
    """Return a fixed-order float32 feature vector for one URL."""
    values = _extract_feature_dict(url)
    return np.asarray([values[name] for name in FEATURE_NAMES], dtype=np.float32)


def _extract_feature_dict(url: str) -> Dict[str, float]:
    raw = (url or "").strip()[:MAX_URL_LENGTH]
    scheme = get_scheme(raw)
    full = ensure_scheme(raw)
    malformed = 0.0
    try:
        parts = urlsplit(full)
        host = (parts.hostname or "").lower().rstrip(".")
        path = parts.path or ""
        query = parts.query or ""
        fragment = parts.fragment or ""
        port = parts.port
        username = parts.username or ""
        password = parts.password or ""
    except ValueError:
        malformed = 1.0
        host, path, query, fragment, port = "", "", "", "", None
        username = password = ""

    if not host:
        # Maybe a bare "domain.tld/path" that urlsplit treated as a path.
        guess = raw.split("/", 1)[0].split("?", 1)[0]
        if _HOST_RE.match(guess) or _IPV4_RE.match(guess):
            host = guess.lower()
            path = raw[len(guess):]

    is_ip = is_ip_host(host)
    is_https = 1.0 if scheme == "https" or (not scheme and raw.lower().startswith("https")) else 0.0
    host_info = _analyse_host(host) if host else _EMPTY_HOST_FEATURES
    sub, registered, suffix = split_host(host)

    host_len = len(host)
    path_len = len(path)
    query_len = len(query)
    url_len = len(raw)
    total = max(url_len, 1)

    digits = sum(c.isdigit() for c in raw)
    letters = sum(c.isalpha() for c in raw)
    upper = sum(c.isupper() for c in raw)
    specials = sum(not c.isalnum() and not c.isspace() for c in raw)
    host_digits = sum(c.isdigit() for c in host)

    host_hyphens = host.count("-")
    host_dots = host.count(".")
    total_hyphens = raw.count("-")
    total_dots = raw.count(".")
    underscores = raw.count("_")

    path_segments = [s for s in path.split("/") if s]
    query_pairs = []
    try:
        query_pairs = parse_qsl(query, keep_blank_values=True)
    except Exception:
        pass

    lower_all = f"{host}{path}?{query}".lower()
    decoded = unquote(lower_all)
    tokens = set(_tokens(decoded))
    suspicious_hits = tokens & SUSPICIOUS_KEYWORDS
    payment_hits = tokens & PAYMENT_KEYWORDS
    crypto_hits = tokens & CRYPTO_KEYWORDS
    login_hits = tokens & LOGIN_KEYWORDS

    # Brand in path/query but not host (evil.example/paypal/login).
    path_brand = 1.0 if (tokens & _BRAND_TOKENS) and not host_info["host_has_brand"] else 0.0

    # Nested / redirect URLs.
    nested_count = 0
    nested_diff_domain = 0.0
    open_redirect_param = 0.0
    embedded = 0.0
    for key, value in query_pairs:
        val = (value or "").strip()
        if not val:
            continue
        decoded_val = unquote(val)
        if "http://" in decoded_val.lower() or "https://" in decoded_val.lower() or decoded_val.startswith("//"):
            embedded = 1.0
            inner = extract_urls_from_text(decoded_val, limit=1)
            if inner:
                nested_count += 1
                try:
                    inner_host = (urlsplit(ensure_scheme(inner[0])).hostname or "").lower()
                except ValueError:
                    inner_host = ""
                if inner_host:
                    _, inner_reg, _ = split_host(inner_host)
                    if inner_reg and inner_reg != registered:
                        nested_diff_domain = 1.0
        if key.lower() in REDIRECT_PARAMETERS:
            open_redirect_param = 1.0
            if re.search(r"(?:https?:)?//|www\.", decoded_val, re.IGNORECASE):
                embedded = 1.0

    # Double scheme / scheme hidden in path.
    double_scheme = 1.0 if lower_all.count("http://") + lower_all.count("https://") > 1 else 0.0
    scheme_in_path = 1.0 if re.search(r"https?:/", path + query, re.IGNORECASE) else 0.0

    encoded_count = raw.count("%")
    encoded_ratio = encoded_count / total
    has_hex = 1.0 if _HEX_TOKEN_RE.search(raw) else 0.0
    has_long_token = 1.0 if _LONG_TOKEN_RE.search(raw) else 0.0

    digit_runs = [len(m) for m in _DIGIT_RUN_RE.findall(raw)]
    alpha_runs = [len(m) for m in _ALPHA_RUN_RE.findall(raw)]

    dangerous_scheme = 1.0 if scheme in DANGEROUS_SCHEMES else 0.0
    has_nonstandard_port = 1.0 if port not in (None, 80, 443) else 0.0
    has_credentials = 1.0 if (username or password) else 0.0

    file_ext = 0.0
    if path:
        ext = path.rsplit(".", 1)[-1].lower() if "." in path.rsplit("/", 1)[-1] else ""
        if ext in {"exe", "apk", "msi", "zip", "rar", "scr", "bat", "cmd", "jar", "vbs", "js", "hta", "iso", "img"}:
            file_ext = 1.0

    return {
        "url_len": float(url_len),
        "host_len": float(host_len),
        "path_len": float(path_len),
        "query_len": float(query_len),
        "fragment_len": float(len(fragment)),
        "num_digits": float(digits),
        "num_letters": float(letters),
        "num_hyphens": float(total_hyphens),
        "num_underscores": float(underscores),
        "num_dots": float(total_dots),
        "host_hyphens": float(host_hyphens),
        "host_dots": float(host_dots),
        "num_slashes": float(raw.count("/")),
        "num_query_params": float(len(query_pairs)),
        "num_path_segments": float(len(path_segments)),
        "num_at": float(raw.count("@")),
        "num_percent": float(encoded_count),
        "num_equals": float(raw.count("=")),
        "num_ampersand": float(raw.count("&")),
        "num_question": float(raw.count("?")),
        "num_colon": float(raw.count(":")),
        "num_semicolon": float(raw.count(";")),
        "num_plus": float(raw.count("+")),
        "num_exclamation": float(raw.count("!")),
        "num_dollar": float(raw.count("$")),
        "digit_ratio": digits / total,
        "letter_ratio": letters / total,
        "special_ratio": specials / total,
        "upper_ratio": upper / max(letters, 1),
        "host_digit_ratio": host_digits / max(host_len, 1),
        "path_digit_ratio": sum(c.isdigit() for c in path) / max(path_len, 1),
        "url_entropy": _entropy(raw),
        "host_entropy": _entropy(host),
        "path_entropy": _entropy(path),
        "max_label_len": float(max((len(x) for x in host.split(".")), default=0)),
        "avg_label_len": float(np.mean([len(x) for x in host.split(".") if x])) if host else 0.0,
        "longest_digit_run": float(max(digit_runs, default=0)),
        "longest_alpha_run": float(max(alpha_runs, default=0)),
        "encoded_ratio": encoded_ratio,
        "is_https": is_https,
        "is_http": 1.0 if scheme == "http" or (not scheme and raw.lower().startswith("http:")) else 0.0,
        "has_www": 1.0 if host.startswith("www.") else 0.0,
        "is_ip": 1.0 if is_ip else 0.0,
        "is_punycode": 1.0 if "xn--" in host else 0.0,
        "has_non_ascii": 1.0 if any(ord(c) > 127 for c in host) else 0.0,
        "has_port": 1.0 if port is not None else 0.0,
        "has_nonstandard_port": has_nonstandard_port,
        "has_credentials": has_credentials,
        "has_hex_token": has_hex,
        "has_long_token": has_long_token,
        "has_dangerous_scheme": dangerous_scheme,
        "has_file_extension": file_ext,
        "double_scheme": double_scheme,
        "scheme_in_path": scheme_in_path,
        "open_redirect_param": open_redirect_param,
        "embedded_url": embedded,
        "nested_url_count": float(nested_count),
        "nested_diff_domain": nested_diff_domain,
        "suspicious_kw_count": float(len(suspicious_hits)),
        "payment_kw_count": float(len(payment_hits)),
        "crypto_kw_count": float(len(crypto_hits)),
        "login_kw_count": float(len(login_hits)),
        "path_has_brand": path_brand,
        "malformed": malformed,
        # Host/reputation-derived features (from cached host analysis).
        **host_info,
    }


_EMPTY_HOST_FEATURES: Dict[str, float] = {
    "subdomain_count": 0.0, "host_label_count": 0.0, "host_has_brand": 0.0,
    "brand_in_subdomain_only": 0.0, "brand_not_official": 0.0,
    "brand_official": 0.0, "brand_fuzzy_lookalike": 0.0,
    "brand_substring": 0.0, "is_free_hosting": 0.0, "is_shortener": 0.0,
    "tld_risky": 0.0, "tld_common": 0.0, "tld_len": 0.0,
    "registered_domain_len": 0.0,
}

FEATURE_NAMES: List[str] = [
    "url_len", "host_len", "path_len", "query_len", "fragment_len",
    "num_digits", "num_letters", "num_hyphens", "num_underscores", "num_dots",
    "host_hyphens", "host_dots", "num_slashes", "num_query_params",
    "num_path_segments", "num_at", "num_percent", "num_equals",
    "num_ampersand", "num_question", "num_colon", "num_semicolon",
    "num_plus", "num_exclamation", "num_dollar", "digit_ratio",
    "letter_ratio", "special_ratio", "upper_ratio", "host_digit_ratio",
    "path_digit_ratio", "url_entropy", "host_entropy", "path_entropy",
    "max_label_len", "avg_label_len", "longest_digit_run",
    "longest_alpha_run", "encoded_ratio", "is_https", "is_http", "has_www",
    "is_ip", "is_punycode", "has_non_ascii", "has_port",
    "has_nonstandard_port", "has_credentials", "has_hex_token",
    "has_long_token", "has_dangerous_scheme", "has_file_extension",
    "double_scheme", "scheme_in_path", "open_redirect_param", "embedded_url",
    "nested_url_count", "nested_diff_domain", "suspicious_kw_count",
    "payment_kw_count", "crypto_kw_count", "login_kw_count",
    "path_has_brand", "malformed", "subdomain_count", "host_label_count",
    "host_has_brand", "brand_in_subdomain_only", "brand_not_official",
    "brand_official", "brand_fuzzy_lookalike", "brand_substring",
    "is_free_hosting", "is_shortener", "tld_risky", "tld_common", "tld_len",
    "registered_domain_len",
]

FEATURE_INDEX = {name: i for i, name in enumerate(FEATURE_NAMES)}


def features_to_matrix(urls: List[str], n_jobs: int = 1) -> np.ndarray:
    """Vectorise many URLs, optionally in parallel."""
    urls = list(urls)
    if not urls:
        return np.zeros((0, len(FEATURE_NAMES)), dtype=np.float32)
    if n_jobs == 1 or len(urls) < 2000:
        return np.vstack([extract_features(u) for u in urls])
    from joblib import Parallel, delayed

    chunks = np.array_split(np.arange(len(urls)), min(n_jobs * 4, max(1, len(urls) // 500)))
    parts = Parallel(n_jobs=n_jobs, batch_size=2000)(
        delayed(_features_for_indices)(urls, idx) for idx in chunks if len(idx)
    )
    return np.vstack(parts)


def _features_for_indices(urls: List[str], indices: np.ndarray) -> np.ndarray:
    return np.vstack([extract_features(urls[i]) for i in indices])


def text_for_model(url: str) -> str:
    """Text representation passed to the char/word TF-IDF models."""
    norm = normalize_url(url)
    if not norm:
        return ""
    # Keep the host and path; the scheme is already a numeric feature.
    norm = re.sub(r"^[a-z]+://", "", norm)
    return norm[:MAX_URL_LENGTH]


def explain_features(url: str) -> Dict[str, float]:
    vals = _extract_feature_dict(url)
    labels = {
        "url_len": "URL length",
        "host_len": "Hostname length",
        "num_hyphens": "Hyphens in URL",
        "host_hyphens": "Hyphens in hostname",
        "num_digits": "Digits in URL",
        "subdomain_count": "Subdomains",
        "has_credentials": "Credentials before host (@)",
        "is_ip": "IP address instead of domain",
        "is_punycode": "Punycode/IDN hostname",
        "has_nonstandard_port": "Non-standard port",
        "open_redirect_param": "Redirect parameter",
        "embedded_url": "Embedded/nested URL",
        "nested_diff_domain": "Nested URL on another domain",
        "brand_in_subdomain_only": "Brand in subdomain only",
        "brand_not_official": "Brand outside official domain",
        "brand_fuzzy_lookalike": "Lookalike/typo domain",
        "is_free_hosting": "Free hosting platform",
        "is_shortener": "URL shortener",
        "tld_risky": "High-abuse TLD",
        "suspicious_kw_count": "Suspicious keywords",
        "payment_kw_count": "Payment keywords",
        "crypto_kw_count": "Crypto keywords",
        "login_kw_count": "Login keywords",
        "has_dangerous_scheme": "Dangerous URL scheme",
        "has_file_extension": "Executable/archive link",
        "double_scheme": "Multiple schemes",
    }
    out = {}
    for key, label in labels.items():
        value = vals.get(key, 0.0)
        if value:
            out[label] = round(float(value), 3)
    return out


def keyword_hits(url: str, keywords: set) -> List[str]:
    """Which suspicious keywords occur in a URL (separator-insensitive)."""
    skeleton = re.sub(r"[^a-z0-9]", "", unquote(url or "").lower())
    hits = []
    for word in keywords:
        needle = re.sub(r"[^a-z0-9]", "", word)
        if needle and needle in skeleton:
            hits.append(word)
    return sorted(hits)


def url_info(url: str) -> Dict[str, Any]:
    """Parsed components for display in the UI."""
    full = ensure_scheme(url)
    try:
        parts = urlsplit(full)
        host = (parts.hostname or "").lower().rstrip(".")
    except ValueError:
        parts, host = None, ""
    sub, registered, suffix = split_host(host)
    return {
        "url": url,
        "normalized": normalize_url(url),
        "scheme": (parts.scheme if parts else "").lower(),
        "host": host,
        "subdomain": sub,
        "registered_domain": registered,
        "tld": suffix,
        "path": parts.path if parts else "",
        "is_ip": is_ip_host(host),
        "is_https": (parts.scheme if parts else "").lower() == "https",
    }


def detect_brand(url: str) -> Optional[Dict[str, Any]]:
    """Identify a brand mentioned in the URL and whether its domain is official."""
    info = url_info(url)
    host = info["host"]
    if not host:
        return None
    registered = info["registered_domain"]
    tokens = set(_split_brand_tokens(host))
    path_tokens = set(_tokens(unquote(url)))
    reg_label = registered.split(".")[0] if registered else ""

    for brand, official in BRANDS.items():
        in_host = brand in tokens
        if in_host:
            return {
                "brand": brand,
                "official": registered in official,
                "where": "subdomain" if registered not in official else "domain",
            }
        if brand in path_tokens:
            return {
                "brand": brand,
                "official": registered in official,
                "where": "path",
            }
    close = _close_brand(reg_label) if reg_label else None
    if close:
        return {"brand": close, "official": False, "where": "lookalike"}
    return None
