import math

import numpy as np

from qrshield.brands import SUSPICIOUS_KEYWORDS
from qrshield.features import (
    FEATURE_INDEX,
    FEATURE_NAMES,
    detect_brand,
    ensure_scheme,
    explain_features,
    extract_features,
    keyword_hits,
    normalize_url,
    split_host,
    text_for_model,
    url_info,
)


def test_feature_vector_shape_and_finite():
    urls = [
        "https://www.google.com/search?q=hello",
        "http://paypal.com.secure-login.xyz/verify?id=123",
        "http://192.168.1.10:8080/bank/login.php",
        "https://xn--pypal-4ve.com/",
        "javascript:alert(1)",
        "example.com/path",
    ]
    for url in urls:
        vec = extract_features(url)
        assert vec.shape == (len(FEATURE_NAMES),)
        assert vec.dtype == np.float32
        assert np.isfinite(vec).all()


def test_ensure_scheme_does_not_mistake_host_port_for_scheme():
    assert ensure_scheme("example.com:8080/login") == "http://example.com:8080/login"
    assert ensure_scheme("https://example.com") == "https://example.com"
    assert ensure_scheme("javascript:alert(1)") == "javascript:alert(1)"
    assert ensure_scheme("//example.com/x") == "http://example.com/x"


def test_split_host_handles_multi_part_suffixes_and_ips():
    assert split_host("www.example.co.uk") == ("www", "example.co.uk", "co.uk")
    assert split_host("a.b.example.com") == ("a.b", "example.com", "com")
    assert split_host("192.168.1.1") == ("", "192.168.1.1", "")


def test_brand_detection_official_and_impersonation():
    official = detect_brand("https://www.amazon.co.uk/dp/B08N5WRWNW")
    assert official["brand"] == "amazon" and official["official"] is True

    fake = detect_brand("http://paypal.com.secure-login.xyz/verify")
    assert fake["brand"] == "paypal" and fake["official"] is False

    lookalike = detect_brand("https://paypa1.com/login")
    assert lookalike["brand"] == "paypal" and lookalike["official"] is False
    assert lookalike["where"] == "lookalike"


def test_credentials_and_nested_redirect_features():
    cred = extract_features("https://example.com@evil.com/path")
    assert cred[FEATURE_INDEX["has_credentials"]] == 1.0
    assert url_info("https://example.com@evil.com/path")["host"] == "evil.com"

    nested = extract_features(
        "https://trusted.example/redirect?url=https%3A%2F%2Fevil.example%2Flogin"
    )
    assert nested[FEATURE_INDEX["embedded_url"]] == 1.0
    assert nested[FEATURE_INDEX["nested_diff_domain"]] == 1.0
    assert nested[FEATURE_INDEX["open_redirect_param"]] == 1.0


def test_risky_and_dangerous_signals():
    js = extract_features("javascript:alert(document.cookie)")
    assert js[FEATURE_INDEX["has_dangerous_scheme"]] == 1.0

    ip = extract_features("http://10.0.0.5/login")
    assert ip[FEATURE_INDEX["is_ip"]] == 1.0
    assert ip[FEATURE_INDEX["has_nonstandard_port"]] == 0.0

    port = extract_features("http://10.0.0.5:8080/login")
    assert port[FEATURE_INDEX["has_nonstandard_port"]] == 1.0


def test_keyword_hits_are_separator_insensitive():
    hits = keyword_hits("https://evil.example/log-in/verify-account", SUSPICIOUS_KEYWORDS)
    assert "login" in hits or "log-in" in hits
    assert "verify" in hits
    assert "account" in hits


def test_text_for_model_removes_scheme_and_normalises():
    assert text_for_model("HTTPS://WWW.Example.COM/Login").startswith("www.example.com")
    assert "https://" not in text_for_model("https://example.com")
    assert normalize_url("https://user:pass@example.com/x") == "https://example.com/x"


def test_explain_features_reports_triggered_signals():
    explained = explain_features("http://192.168.1.10:8080/bank/login.php")
    assert explained["IP address instead of domain"] == 1.0
    assert explained["Non-standard port"] == 1.0
    assert all(math.isfinite(v) for v in explained.values())
