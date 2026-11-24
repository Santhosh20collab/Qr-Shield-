
from qrshield.features import url_info
from qrshield.scanner import (
    _is_allowlisted,
    analyze_payload,
    scan_image,
    scan_url,
)


def test_scan_safe_url_has_positive_official_signal():
    result = scan_url("https://www.google.com/")
    assert result["ok"] is True
    assert result["verdict"] in ("safe", "suspicious")
    codes = [r["code"] for r in result["reasons"]]
    assert "official_brand_domain" in codes
    assert result["score"] < 50


def test_scan_brand_impersonation_is_malicious():
    result = scan_url("http://paypal.com.secure-login.xyz/verify?id=123")
    assert result["verdict"] == "malicious"
    codes = [r["code"] for r in result["reasons"]]
    assert "brand_impersonation" in codes
    assert result["url_info"]["registered_domain"] == "secure-login.xyz"


def test_scan_credentials_is_malicious():
    result = scan_url("https://example.com@evil.com/path")
    assert result["verdict"] == "malicious"
    assert any(r["code"] == "credentials_in_url" for r in result["reasons"])


def test_scan_dangerous_scheme_payload():
    result = analyze_payload("javascript:alert(document.cookie)")
    assert result["verdict"] == "malicious"
    assert result["payload_type"] == "dangerous_uri"
    assert result["score"] >= 90


def test_scan_payment_and_wifi_payloads():
    upi = analyze_payload("upi://pay?pa=attacker@upi&am=5000")
    assert upi["payload_type"] == "payment_uri"
    assert upi["verdict"] == "suspicious"

    wifi = analyze_payload("WIFI:S:CoffeeShop;T:WPA;P:password;;")
    assert wifi["payload_type"] == "wifi_uri"
    assert wifi["score"] < 40


def test_text_payload_with_embedded_url_is_analysed():
    result = analyze_payload("Verify your parcel here: https://paypa1.com/login")
    assert result["payload_type"] == "text_with_url"
    assert result["url_info"]["registered_domain"] == "paypa1.com"
    assert result["verdict"] == "malicious"


def test_allowlist_matching(monkeypatch):
    info = url_info("https://sub.example.com/path")
    monkeypatch.setattr("qrshield.scanner._load_allowlist", lambda: {"example.com"})
    assert _is_allowlisted(info, "https://sub.example.com/path") is True
    monkeypatch.setattr("qrshield.scanner._load_allowlist", lambda: {"other.com"})
    assert _is_allowlisted(info, "https://sub.example.com/path") is False


def test_scan_image_invalid_bytes_returns_error():
    result = scan_image(b"this is not an image")
    assert result["ok"] is False
    assert "Could not open image" in result["error"]


def test_url_info_shape():
    info = url_info("https://www.example.co.uk/a?b=1")
    assert info["registered_domain"] == "example.co.uk"
    assert info["host"] == "www.example.co.uk"
    assert info["is_https"] is True
