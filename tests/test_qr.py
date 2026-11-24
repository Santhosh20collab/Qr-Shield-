import cv2
import numpy as np
import pytest
import qrcode

from qrshield.config import MODEL_PATH
from qrshield.model import load_model
from qrshield.qr_decode import decode_qr
from qrshield.scanner import scan_image


def _qr_bgr(text: str, size: int = 360) -> np.ndarray:
    img = qrcode.make(text, box_size=10, border=4).convert("RGB")
    img = img.resize((size, size))
    return cv2.cvtColor(np.array(img), cv2.COLOR_RGB2BGR)


def test_decode_simple_qr(tmp_path):
    path = tmp_path / "qr.png"
    qrcode.make("https://www.example.com/login").save(path)
    result = decode_qr(path)
    assert result["count"] == 1
    assert result["payloads"][0]["data"] == "https://www.example.com/login"
    assert result["payloads"][0]["bbox"] is not None
    assert result["image"]["width"] > 0


def test_decode_rotated_and_blurred():
    img = _qr_bgr("https://www.example.com/verify?id=42")
    img = cv2.rotate(img, cv2.ROTATE_90_CLOCKWISE)
    img = cv2.GaussianBlur(img, (5, 5), 1.4)
    result = decode_qr(img)
    assert result["count"] == 1
    assert "example.com" in result["payloads"][0]["data"]


def test_decode_multiple_qr_codes():
    canvas = np.full((420, 820, 3), 255, dtype=np.uint8)
    canvas[30:390, 30:390] = _qr_bgr("https://one.example/a")
    canvas[30:390, 430:790] = _qr_bgr("https://two.example/b")
    result = decode_qr(canvas)
    payloads = {p["data"] for p in result["payloads"]}
    assert len(payloads) >= 2
    assert "https://one.example/a" in payloads
    assert "https://two.example/b" in payloads


def test_scan_image_reports_multiple_codes():
    canvas = np.full((420, 820, 3), 255, dtype=np.uint8)
    canvas[30:390, 30:390] = _qr_bgr("https://www.google.com/")
    canvas[30:390, 430:790] = _qr_bgr("http://paypal.com.secure-login.xyz/verify")
    result = scan_image(canvas)
    assert result["ok"] is True
    assert result["decoded_count"] >= 2
    assert result["overall"]["score"] >= 60
    assert any("different QR codes" in w for w in result["overall"]["warnings"])


def test_scan_non_url_payload():
    img = _qr_bgr("WIFI:S:CoffeeShop;T:WPA;P:secret;;")
    result = scan_image(img)
    assert result["ok"] is True
    assert result["results"][0]["payload_type"] == "wifi_uri"


def test_decode_wifi_qr_from_photo_style_image():
    """Glossy/overexposed photos are decoded by the ZXing pass."""
    img = _qr_bgr("WIFI:S:LSSD-Home;T:WPA;P:Lssd@123;H:false;;", size=1077)
    img = cv2.convertScaleAbs(img, alpha=0.98, beta=28)
    result = decode_qr(img)
    assert result["count"] == 1
    assert result["payloads"][0]["data"].startswith("WIFI:")


def test_zxing_helper_reports_bbox_and_method():
    pytest.importorskip("zxingcpp")
    from qrshield.qr_decode import _decode_with_zxing

    img = cv2.cvtColor(_qr_bgr("https://www.example.com/zxing"), cv2.COLOR_BGR2GRAY)
    results, seen = [], set()
    _decode_with_zxing(img, "original", 1.0, results, seen)
    assert results, "ZXing should decode a clean synthetic QR"
    assert results[0]["method"] == "zxing"
    assert results[0]["bbox"] is not None
    assert len(results[0]["bbox"]) == 4


def test_blank_image_returns_helpful_error():
    result = scan_image(np.full((300, 300, 3), 255, dtype=np.uint8))
    assert result["ok"] is False
    assert "No QR code" in result["error"]


@pytest.mark.skipif(not MODEL_PATH.exists(), reason="model not trained")
def test_model_scores_official_and_impersonated_domains():
    model = load_model()
    assert model.predict_one("https://www.google.com/") < 0.5
    assert model.predict_one("https://www.amazon.co.uk/dp/B08N5WRWNW") < 0.5
    assert model.predict_one("http://paypal.com.secure-login.xyz/verify") > 0.5
