"""High-level scanning: QR image -> decoded payload -> risk verdict."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Union
from urllib.parse import parse_qsl, unquote, urlsplit

from .brands import (
    CRYPTO_KEYWORDS,
    DANGEROUS_SCHEMES,
    LOGIN_KEYWORDS,
    PAYMENT_KEYWORDS,
    SUSPICIOUS_KEYWORDS,
)
from .config import (
    ALLOWLIST_PATH,
    DEFAULT_MALICIOUS_THRESHOLD,
    DEFAULT_SUSPICIOUS_THRESHOLD,
    MAX_NESTED_URLS,
)
from .features import (
    FEATURE_INDEX,
    detect_brand,
    ensure_scheme,
    explain_features,
    extract_features,
    extract_urls_from_text,
    keyword_hits,
    url_info,
)
from .model import ModelNotFoundError, QRShieldModel, load_model
from .qr_decode import decode_qr

_SEVERITY_WEIGHT = {
    "critical": 0.90,
    "high": 0.62,
    "medium": 0.42,
    "low": 0.15,
    "info": 0.02,
    "positive": 0.0,
}
_SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "positive": 5}
_BARE_URL_RE = re.compile(
    r"^(?:[A-Za-z0-9\u0080-\uFFFF_-]+\.)+[A-Za-z]{2,}(?::\d{1,5})?(?:[/?#]|$)"
)
_ANY_SCHEME_RE = re.compile(r"^([A-Za-z][A-Za-z0-9+.-]*):")

_ALLOWLIST_CACHE: Dict[str, Any] = {"mtime": None, "entries": set()}


def _load_allowlist() -> set:
    path = Path(ALLOWLIST_PATH)
    if not path.exists():
        return set()
    try:
        mtime = path.stat().st_mtime
    except OSError:
        return set()
    if _ALLOWLIST_CACHE["mtime"] == mtime:
        return _ALLOWLIST_CACHE["entries"]
    entries = set()
    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = line.strip().lower()
        if line and not line.startswith("#"):
            entries.add(line.rstrip("/"))
    _ALLOWLIST_CACHE.update(mtime=mtime, entries=entries)
    return entries


def _is_allowlisted(info: Dict, raw_url: str) -> bool:
    entries = _load_allowlist()
    if not entries:
        return False
    host = info.get("host", "")
    registered = info.get("registered_domain", "")
    normalized = info.get("normalized", "").rstrip("/")
    for entry in entries:
        if entry == host or entry == registered:
            return True
        if entry.startswith("http") and normalized.startswith(entry):
            return True
    return False


def _reason(code: str, severity: str, message: str, detail: Any = None) -> Dict:
    item = {"code": code, "severity": severity, "message": message}
    if detail is not None:
        item["detail"] = detail
    return item


def _rule_score(reasons: List[Dict]) -> float:
    weights = [
        _SEVERITY_WEIGHT.get(r["severity"], 0.0)
        for r in reasons if r["severity"] != "positive"
    ]
    if not weights:
        return 0.0
    base = max(weights)
    highs = sum(1 for r in reasons if r["severity"] == "high")
    mediums = sum(1 for r in reasons if r["severity"] == "medium")
    lows = sum(1 for r in reasons if r["severity"] == "low")
    bonus = 0.05 * max(0, highs - 1) + 0.03 * max(0, mediums - 1) + 0.01 * max(0, lows - 1)
    return min(0.97, base + bonus)


def _value(vec, name: str) -> float:
    return float(vec[FEATURE_INDEX[name]])


def _verdict(probability: float, thresholds: Dict[str, float]) -> str:
    if probability >= thresholds.get("malicious", DEFAULT_MALICIOUS_THRESHOLD):
        return "malicious"
    if probability >= thresholds.get("suspicious", DEFAULT_SUSPICIOUS_THRESHOLD):
        return "suspicious"
    return "safe"


def analyze_url(
    url: str,
    model: Optional[QRShieldModel] = None,
    depth: int = 0,
) -> Dict:
    """Score a single URL and explain the decision."""
    url = (url or "").strip()
    info = url_info(url)
    vec = extract_features(url)
    reasons: List[Dict] = []

    if _value(vec, "has_dangerous_scheme"):
        reasons.append(_reason(
            "dangerous_scheme", "critical",
            "The QR payload uses a dangerous URL scheme (javascript:/data:/file:). "
            "It can run code or open local files instead of a normal website.",
        ))

    if _value(vec, "has_credentials"):
        reasons.append(_reason(
            "credentials_in_url", "critical",
            f"The URL hides its real destination before an '@' sign. "
            f"The actual host is {info['host'] or 'unknown'}.",
            info["host"],
        ))

    brand = detect_brand(url)
    if brand and not brand["official"]:
        where = brand["where"]
        if where in ("lookalike", "subdomain"):
            reasons.append(_reason(
                "brand_impersonation", "critical",
                f"Impersonates {brand['brand'].title()} using a non-official domain "
                f"({info['registered_domain'] or info['host']}).",
                brand,
            ))
        else:
            reasons.append(_reason(
                "brand_misuse", "high",
                f"Mentions {brand['brand'].title()} but does not use its official domain "
                f"({info['registered_domain'] or info['host']}).",
                brand,
            ))
    elif brand and brand["official"]:
        reasons.append(_reason(
            "official_brand_domain", "positive",
            f"Uses the official {brand['brand'].title()} domain.",
            brand,
        ))

    if _value(vec, "brand_fuzzy_lookalike") and not (brand and brand["official"]):
        reasons.append(_reason(
            "lookalike_domain", "high",
            "The domain uses characters or spelling that imitate a well-known brand.",
        ))

    if _value(vec, "is_ip"):
        reasons.append(_reason(
            "ip_host", "high",
            "Links directly to an IP address instead of a named domain. "
            "Legitimate brands and banks almost never do this in QR codes.",
        ))

    if _value(vec, "is_punycode") or _value(vec, "has_non_ascii"):
        reasons.append(_reason(
            "punycode_host", "high",
            "The domain uses international/punycode characters which can visually "
            "mimic ordinary Latin letters.",
        ))

    if _value(vec, "nested_diff_domain"):
        reasons.append(_reason(
            "nested_redirect", "high",
            "Contains a second URL that points to a different domain. "
            "This is a common way to hide the real destination behind a trusted link.",
        ))
    elif _value(vec, "open_redirect_param") or _value(vec, "embedded_url"):
        reasons.append(_reason(
            "redirect_parameter", "medium",
            "The link contains a redirect parameter that may forward you to another site.",
        ))

    if _value(vec, "double_scheme") or _value(vec, "scheme_in_path"):
        reasons.append(_reason(
            "nested_scheme", "high",
            "The URL contains a second http(s):// sequence, often used to disguise "
            "the real destination.",
        ))

    if _value(vec, "has_file_extension"):
        reasons.append(_reason(
            "downloadable_file", "high",
            "The link points to an executable, script or archive file. "
            "QR codes should not be used to install software.",
        ))

    if _value(vec, "is_shortener"):
        reasons.append(_reason(
            "shortener", "medium",
            "Uses a URL shortener, so the final destination is hidden until you open it.",
        ))

    if _value(vec, "is_free_hosting"):
        reasons.append(_reason(
            "free_hosting", "medium",
            "Hosted on a free page-builder or tunnelling service. "
            "Attackers use these because the root domain looks familiar.",
        ))

    if _value(vec, "tld_risky"):
        reasons.append(_reason(
            "risky_tld", "low",
            f"Uses the .{info['tld']} extension, which has above-average abuse rates.",
        ))

    if _value(vec, "has_nonstandard_port"):
        reasons.append(_reason(
            "nonstandard_port", "medium",
            "Uses a non-standard network port, which is unusual for consumer websites.",
        ))

    suspicious_hits = keyword_hits(url, SUSPICIOUS_KEYWORDS)
    if suspicious_hits:
        severity = "medium" if len(suspicious_hits) >= 2 else "low"
        reasons.append(_reason(
            "suspicious_keywords", severity,
            "Uses urgency/credential words commonly found in phishing: "
            + ", ".join(suspicious_hits[:6]),
            suspicious_hits[:10],
        ))

    login_hits = keyword_hits(url, LOGIN_KEYWORDS)
    if login_hits and not info["is_https"]:
        reasons.append(_reason(
            "login_without_tls", "medium",
            "Looks like a login/verification page but does not use HTTPS.",
            login_hits[:6],
        ))

    payment_hits = keyword_hits(url, PAYMENT_KEYWORDS)
    if payment_hits and not (brand and brand["official"]):
        reasons.append(_reason(
            "payment_lure", "low",
            "Contains payment-related terms. Verify the payee before entering "
            "card, UPI or banking details.",
            payment_hits[:6],
        ))

    crypto_hits = keyword_hits(url, CRYPTO_KEYWORDS)
    if crypto_hits:
        reasons.append(_reason(
            "crypto_lure", "medium",
            "Contains cryptocurrency/wallet terms often used in giveaway and "
            "wallet-drainer scams.",
            crypto_hits[:6],
        ))

    if _value(vec, "url_len") > 120:
        reasons.append(_reason(
            "long_url", "low",
            f"The URL is unusually long ({int(_value(vec, 'url_len'))} characters), "
            "which can hide the real destination.",
        ))
    if _value(vec, "host_len") > 40 or _value(vec, "host_hyphens") >= 3:
        reasons.append(_reason(
            "host_complexity", "low",
            "The hostname is unusually long or hyphenated.",
        ))

    if not info["is_https"] and info["scheme"] in ("http", ""):
        reasons.append(_reason(
            "no_https", "low",
            "The destination does not use HTTPS, so traffic is not encrypted.",
        ))

    if _value(vec, "malformed"):
        reasons.append(_reason(
            "malformed_url", "low",
            "The URL is malformed or uses unusual encoding.",
        ))

    # Analyse a nested redirect target with the model as well.
    redirect = None
    if _value(vec, "nested_diff_domain") and depth < 1:
        redirect = _analyse_nested(url, model)
        if redirect:
            reasons.append(_reason(
                "redirect_target", "high",
                f"The embedded link redirects to a different domain: "
                f"{redirect.get('url_info', {}).get('registered_domain') or 'unknown'}.",
                redirect.get("url"),
            ))

    model_prob = None
    model_error = None
    if model is not None:
        try:
            model_prob = float(model.predict_proba(url)[0])
        except Exception as exc:  # keep rules working even if the model fails
            model_error = str(exc)

    rule_prob = _rule_score(reasons)
    high_risk = any(r["severity"] in ("critical", "high") for r in reasons)
    # Official brand pages often contain words like "login" and "account".
    # Do not let generic keyword rules alone turn paypal.com/signin into a
    # warning; keep strong structural signals (redirects, @, IDN) intact.
    if brand and brand["official"] and not high_risk:
        rule_prob = min(rule_prob, 0.25)
    probability = max(rule_prob, model_prob or 0.0)
    if redirect:
        probability = max(probability, redirect["probability"])

    thresholds = {
        "suspicious": float(getattr(model, "thresholds", {}).get(
            "suspicious", DEFAULT_SUSPICIOUS_THRESHOLD)),
        "malicious": float(getattr(model, "thresholds", {}).get(
            "malicious", DEFAULT_MALICIOUS_THRESHOLD)),
    }

    # A shortener or free host alone cannot be verified offline. Warn, but do
    # not call the link malicious unless another structural signal fired.
    if not high_risk and (_value(vec, "is_shortener") or _value(vec, "is_free_hosting")):
        other_risks = [
            r for r in reasons
            if r["severity"] not in ("positive", "info")
            and r["code"] not in ("shortener", "free_hosting", "no_https",
                                  "risky_tld", "long_url", "host_complexity")
        ]
        if not other_risks:
            probability = min(probability, thresholds["suspicious"] + 0.05)

    verdict = _verdict(probability, thresholds)
    allowlisted = _is_allowlisted(info, url) and not _value(vec, "has_dangerous_scheme")
    if allowlisted:
        verdict = "allowlisted"
        probability = 0.0
        reasons.insert(0, _reason(
            "allowlisted", "positive",
            "This domain is on your local allowlist.",
        ))

    reasons.sort(key=lambda r: _SEVERITY_RANK.get(r["severity"], 9))

    top_tokens = []
    if model is not None and model_prob is not None:
        try:
            top_tokens = model.top_tokens(url, k=6)
        except Exception:
            top_tokens = []

    return {
        "ok": True,
        "payload_type": "url",
        "payload": url,
        "url": url,
        "url_info": info,
        "score": round(probability * 100, 1),
        "probability": round(probability, 5),
        "verdict": verdict,
        "thresholds": thresholds,
        "reasons": reasons,
        "signals": explain_features(url),
        "brand": brand,
        "model": {
            "used": model_prob is not None,
            "probability": None if model_prob is None else round(model_prob, 5),
            "error": model_error,
        },
        "top_tokens": top_tokens,
        "redirect": redirect,
        "allowlisted": allowlisted,
    }


def _analyse_nested(url: str, model: Optional[QRShieldModel]) -> Optional[Dict]:
    try:
        pairs = parse_qsl(urlsplit(ensure_scheme(url)).query, keep_blank_values=True)
    except Exception:
        return None
    outer_reg = url_info(url)["registered_domain"]
    candidates: List[str] = []
    for _, value in pairs:
        inner = extract_urls_from_text(unquote(value or ""), limit=1)
        if inner:
            candidates.append(inner[0])
        if len(candidates) >= MAX_NESTED_URLS:
            break
    for candidate in candidates:
        inner_info = url_info(candidate)
        if inner_info["registered_domain"] and inner_info["registered_domain"] != outer_reg:
            return analyze_url(candidate, model=model, depth=2)
    return None


def analyze_payload(payload: str, model: Optional[QRShieldModel] = None) -> Dict:
    """Analyse any QR payload: URL, redirect wrapper, Wi-Fi join, payment URI..."""
    payload = (payload or "").replace("\x00", "").strip()
    if not payload:
        return _plain_result("", "The QR code is empty.")

    scheme_match = _ANY_SCHEME_RE.match(payload)
    scheme = scheme_match.group(1).lower() if scheme_match else ""

    if scheme in DANGEROUS_SCHEMES:
        result = _plain_result(payload, "This QR code attempts to use a dangerous local scheme.", 0.97)
        result["payload_type"] = "dangerous_uri"
        result["reasons"] = [_reason(
            "dangerous_scheme", "critical",
            f"The payload starts with '{scheme}:' which can execute code or open local files.",
        )]
        result["url_info"] = None
        return result

    if scheme in ("http", "https") or (not scheme and _BARE_URL_RE.match(payload)):
        return analyze_url(payload, model=model)

    if scheme and scheme not in ("", "http", "https"):
        return _analyze_special_uri(payload, scheme, model)

    nested = extract_urls_from_text(payload, limit=MAX_NESTED_URLS)
    if nested:
        primary = max((analyze_url(u, model=model) for u in nested),
                      key=lambda r: r["probability"])
        primary = dict(primary)
        primary["payload"] = payload
        primary["payload_type"] = "text_with_url"
        primary["reasons"] = list(primary["reasons"]) + [_reason(
            "link_in_text", "low",
            "The QR code contains a link embedded in other text. "
            "Read the destination carefully before opening it.",
        )]
        primary["reasons"].sort(key=lambda r: _SEVERITY_RANK.get(r["severity"], 9))
        return primary

    return _plain_result(payload, "The QR code contains text, not a website link.", 0.10)


def _analyze_special_uri(payload: str, scheme: str, model: Optional[QRShieldModel]) -> Dict:
    if scheme in ("bitcoin", "ethereum", "litecoin", "dogecoin", "monero", "upi"):
        result = _plain_result(payload, "This QR code requests a cryptocurrency/UPI payment.", 0.55)
        result["payload_type"] = "payment_uri"
        result["reasons"] = [_reason(
            "payment_request", "medium",
            "Payment QR codes cannot be verified automatically. Confirm the recipient "
            "and amount inside your own payment app before approving anything.",
        )]
        return result
    if scheme == "wifi":
        result = _plain_result(payload, "This QR code joins a Wi-Fi network.", 0.25)
        result["payload_type"] = "wifi_uri"
        result["reasons"] = [_reason(
            "wifi_join", "low",
            "Joining an unknown Wi-Fi network can expose your traffic. "
            "Only connect to networks you trust.",
        )]
        return result
    if scheme in ("tel", "sms", "smsto", "mms", "mailto"):
        result = _plain_result(payload, "This QR code starts a call, message or email.", 0.15)
        result["payload_type"] = "contact_uri"
        result["reasons"] = [_reason(
            "contact_uri", "low",
            "Verify the phone number or email address. Premium-rate numbers and "
            "lookalike addresses are sometimes used in scams.",
        )]
        return result
    if scheme == "intent":
        result = _plain_result(payload, "This QR code asks Android to open an app or action.", 0.50)
        result["payload_type"] = "intent_uri"
        result["reasons"] = [_reason(
            "intent_uri", "medium",
            "Android intents can launch apps, open settings or trigger actions. "
            "Only continue if you trust the source of this code.",
        )]
        return result
    if scheme in ("otpauth", "totp"):
        result = _plain_result(payload, "This is a two-factor authentication setup code.", 0.20)
        result["payload_type"] = "otp_uri"
        result["reasons"] = [_reason(
            "otp_setup", "low",
            "Adding an unknown account to your authenticator app could leak future codes. "
            "Only scan codes from a service you are actively setting up.",
        )]
        return result
    result = _plain_result(payload, f"This QR code uses the '{scheme}:' scheme.", 0.35)
    result["payload_type"] = "other_uri"
    result["reasons"] = [_reason(
        "unknown_scheme", "medium",
        f"The '{scheme}:' scheme is not a normal website link. Verify the app that will open it.",
    )]
    return result


def _plain_result(payload: str, message: str, score: float = 0.10) -> Dict:
    return {
        "ok": True,
        "payload_type": "text",
        "payload": payload,
        "url": None,
        "url_info": None,
        "score": round(score * 100, 1),
        "probability": round(score, 5),
        "verdict": _verdict(score, {"suspicious": DEFAULT_SUSPICIOUS_THRESHOLD,
                                     "malicious": DEFAULT_MALICIOUS_THRESHOLD}),
        "thresholds": {"suspicious": DEFAULT_SUSPICIOUS_THRESHOLD,
                       "malicious": DEFAULT_MALICIOUS_THRESHOLD},
        "reasons": [_reason("non_url", "info", message)],
        "signals": {},
        "brand": None,
        "model": {"used": False, "probability": None, "error": None},
        "top_tokens": [],
        "redirect": None,
        "allowlisted": False,
    }


def scan_payload(
    payload: str,
    model: Optional[QRShieldModel] = None,
    allowlist: bool = True,
) -> Dict:
    """Public entry point for analysing raw QR payload text."""
    result = analyze_payload(payload, model=model)
    if not allowlist and result.get("url_info"):
        result["allowlisted"] = False
    return result


def scan_url(url: str, model: Optional[QRShieldModel] = None) -> Dict:
    return analyze_url(url, model=model)


def scan_image(
    source: Union[str, Path, bytes],
    model: Optional[QRShieldModel] = None,
    use_allowlist: bool = True,
) -> Dict:
    """Decode and analyse every QR code in an image."""
    decoded = decode_qr(source)
    payloads = decoded.get("payloads", [])
    image_info = decoded.get("image", {})
    if not payloads:
        return {
            "ok": False,
            "error": decoded.get("error") or "No QR code could be decoded.",
            "image": image_info,
            "results": [],
            "overall": None,
        }

    if model is None:
        try:
            model = load_model()
        except ModelNotFoundError:
            model = None

    results = []
    for item in payloads:
        analysis = analyze_payload(item["data"], model=model)
        analysis["bbox"] = item.get("bbox")
        analysis["decode_method"] = item.get("method")
        analysis["decode_variant"] = item.get("variant")
        if not use_allowlist:
            analysis["allowlisted"] = False
        results.append(analysis)

    overall_score = max(r["score"] for r in results)
    warnings = list(image_info.get("warnings", []))
    if len(results) > 1:
        warnings.append(
            f"{len(results)} different QR codes were found in one image. "
            "Overlaying a sticker with a malicious code over a real one is a known attack."
        )
        overall_score = max(overall_score, 60.0)

    thresholds = results[0].get("thresholds", {})
    overall_verdict = _verdict(overall_score / 100.0, thresholds)
    if any(r["verdict"] == "allowlisted" for r in results) and overall_score == 0.0:
        overall_verdict = "allowlisted"

    return {
        "ok": True,
        "error": None,
        "image": image_info,
        "decoded_count": len(results),
        "results": results,
        "overall": {
            "score": round(overall_score, 1),
            "verdict": overall_verdict,
            "warnings": warnings,
        },
    }
