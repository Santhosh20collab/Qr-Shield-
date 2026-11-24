import json

import pytest

from qrshield import history


def _result(payload, verdict, score, host=None, reasons=None):
    return {
        "payload": payload,
        "verdict": verdict,
        "score": score,
        "probability": score / 100,
        "payload_type": "url",
        "url": payload if payload.startswith("http") else None,
        "url_info": {"host": host} if host else None,
        "reasons": reasons or [],
        "model": {"used": True, "probability": score / 100},
        "decode_method": None,
    }


@pytest.fixture()
def db(tmp_path):
    path = tmp_path / "history.db"
    history.init_db(path)
    return path


def test_record_list_and_get(db):
    first = history.record_scan(
        _result(
            "http://paypal.com.secure-login.xyz/verify",
            "malicious",
            100,
            "paypal.com.secure-login.xyz",
            [{"code": "brand_impersonation", "severity": "critical", "message": "Fake PayPal"}],
        ),
        source="url",
        path=db,
    )
    second = history.record_scan(
        _result("https://www.google.com/", "safe", 0, "www.google.com"),
        source="image",
        filename="qr.png",
        path=db,
    )
    assert second > first

    page = history.list_scans(path=db)
    assert page["total"] == 2
    assert page["items"][0]["id"] == second  # newest first
    assert page["items"][0]["filename"] == "qr.png"
    assert page["items"][1]["reasons"][0]["code"] == "brand_impersonation"

    item = history.get_scan(first, path=db)
    assert item["verdict"] == "malicious"
    assert item["detail"]["result"]["payload"].startswith("http://paypal")
    assert history.get_scan(999, path=db) is None


def test_filters_and_pagination(db):
    for index in range(5):
        verdict = "malicious" if index % 2 else "safe"
        history.record_scan(
            _result(f"https://example{index}.com/path", verdict, 90 if verdict == "malicious" else 5,
                    f"example{index}.com"),
            path=db,
        )
    assert history.list_scans(verdict="malicious", path=db)["total"] == 2
    assert history.list_scans(query="example3", path=db)["total"] == 1
    page = history.list_scans(limit=2, offset=0, path=db)
    assert len(page["items"]) == 2
    assert page["total"] == 5
    page2 = history.list_scans(limit=2, offset=2, path=db)
    assert {p["id"] for p in page["items"]}.isdisjoint({p["id"] for p in page2["items"]})


def test_stats_aggregates(db):
    history.record_scan(
        _result("http://evil.example/login", "malicious", 100, "evil.example",
                [{"code": "brand_impersonation", "severity": "critical", "message": "x"},
                 {"code": "login_without_tls", "severity": "medium", "message": "y"}]),
        path=db,
    )
    history.record_scan(
        _result("https://www.google.com/", "safe", 0, "www.google.com",
                [{"code": "official_brand_domain", "severity": "positive", "message": "ok"}]),
        path=db,
    )
    data = history.stats(path=db)
    assert data["total"] == 2
    assert data["today"] == 2
    assert data["by_verdict"] == {"malicious": 1, "safe": 1}
    assert data["malicious_rate"] == 0.5
    assert len(data["last_7_days"]) == 7
    codes = {entry["code"] for entry in data["top_reasons"]}
    assert codes == {"brand_impersonation", "login_without_tls"}
    assert data["top_hosts"][0]["host"] in {"evil.example", "www.google.com"}


def test_delete_and_clear(db):
    scan_id = history.record_scan(_result("https://example.com", "safe", 1), path=db)
    assert history.delete_scan(scan_id, path=db) is True
    assert history.delete_scan(scan_id, path=db) is False

    for _ in range(3):
        history.record_scan(_result("https://example.com", "safe", 1), path=db)
    assert history.clear_history(path=db) == 3
    assert history.stats(path=db)["total"] == 0


def test_history_survives_bad_json(db, tmp_path):
    import sqlite3

    scan_id = history.record_scan(_result("https://example.com", "safe", 1), path=db)
    with sqlite3.connect(db) as conn:
        conn.execute("UPDATE scans SET reasons = ?, result_json = ? WHERE id = ?",
                     ("not json", "{broken", scan_id))
    item = history.get_scan(scan_id, path=db)
    assert item["reasons"] == []
    assert item["detail"] == {}


def test_default_path_comes_from_config(monkeypatch, tmp_path):
    from qrshield import config

    target = tmp_path / "configured.db"
    monkeypatch.setattr(config, "HISTORY_DB_PATH", target)
    history.record_scan(_result("https://example.com", "safe", 1))
    assert target.exists()
    assert json.loads(json.dumps(history.stats()))["total"] == 1
