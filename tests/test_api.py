import io

import pytest
import qrcode
from fastapi.testclient import TestClient

from app.main import app


@pytest.fixture()
def client(tmp_path, monkeypatch):
    from qrshield import config

    monkeypatch.setattr(config, "HISTORY_DB_PATH", tmp_path / "api.db")
    with TestClient(app) as test_client:
        yield test_client


def _qr_png(text: str) -> bytes:
    image = qrcode.make(text, box_size=8, border=4)
    buffer = io.BytesIO()
    image.save(buffer, format="PNG")
    return buffer.getvalue()


def test_health_and_info(client):
    health = client.get("/api/health")
    assert health.status_code == 200
    assert health.json()["ok"] is True
    assert "uptime_seconds" in health.json()

    info = client.get("/api/info")
    assert info.status_code == 200
    body = info.json()
    assert body["app_version"]
    assert body["limits"]["max_batch_files"] == 20


def test_index_and_static_assets(client):
    assert client.get("/").status_code == 200
    assert client.get("/static/styles.css").status_code == 200
    assert client.get("/static/app.js").status_code == 200


def test_scan_url_records_history(client):
    response = client.post(
        "/api/scan-url",
        json={"url": "http://paypal.com.secure-login.xyz/verify?id=123"},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["verdict"] == "malicious"
    assert body["score"] >= 90

    history = client.get("/api/history").json()
    assert history["total"] == 1
    assert history["items"][0]["verdict"] == "malicious"

    scan_id = history["items"][0]["id"]
    detail = client.get(f"/api/history/{scan_id}").json()
    assert detail["detail"]["result"]["payload"].endswith("id=123")

    stats = client.get("/api/stats").json()
    assert stats["total"] == 1
    assert stats["by_verdict"]["malicious"] == 1


def test_scan_url_validation(client):
    assert client.post("/api/scan-url", json={"url": "   "}).status_code == 400
    assert client.post("/api/scan-url", json={"url": "https://example.com"}).status_code == 200


def test_scan_url_batch(client):
    response = client.post(
        "/api/scan-url/batch",
        json={"urls": ["https://www.google.com/", "https://paypa1.com/login"]},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["count"] == 2
    assert body["overall"]["verdict"] == "malicious"
    assert client.get("/api/history").json()["total"] == 2


def test_scan_single_image(client):
    response = client.post(
        "/api/scan",
        files={"file": ("qr.png", _qr_png("https://www.google.com/"), "image/png")},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["ok"] is True
    assert body["decoded_count"] == 1
    assert body["results"][0]["verdict"] in ("safe", "suspicious")


def test_scan_rejects_bad_image(client):
    response = client.post(
        "/api/scan",
        files={"file": ("bad.png", b"not really an image", "image/png")},
    )
    assert response.status_code == 400
    assert "Could not open" in response.json()["detail"]

    wrong_type = client.post(
        "/api/scan",
        files={"file": ("notes.txt", b"hello", "text/plain")},
    )
    assert wrong_type.status_code == 415


def test_scan_batch_mixed_files(client):
    files = [
        ("files", ("safe.png", _qr_png("https://www.google.com/"), "image/png")),
        ("files", ("bad.png", _qr_png("http://paypal.com.secure-login.xyz/verify"), "image/png")),
        ("files", ("broken.png", b"nope", "image/png")),
    ]
    response = client.post("/api/scan-batch", files=files)
    assert response.status_code == 200
    body = response.json()
    assert body["count"] == 3
    assert body["decoded_count"] == 2
    assert body["overall"]["verdict"] == "malicious"
    assert any(not item["ok"] for item in body["results"])
    assert body["overall"]["warnings"]


def test_batch_rejects_too_many_files(client):
    files = [
        ("files", (f"{i}.png", _qr_png("https://example.com/"), "image/png"))
        for i in range(21)
    ]
    assert client.post("/api/scan-batch", files=files).status_code == 413


def test_delete_and_clear_history(client):
    client.post("/api/scan-url", json={"url": "https://example.com/"})
    scan_id = client.get("/api/history").json()["items"][0]["id"]
    assert client.delete(f"/api/history/{scan_id}").status_code == 200
    assert client.delete(f"/api/history/{scan_id}").status_code == 404

    client.post("/api/scan-url", json={"url": "https://example.org/"})
    cleared = client.delete("/api/history").json()
    assert cleared["deleted"] >= 1
    assert client.get("/api/stats").json()["total"] == 0
