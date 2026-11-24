import json

import qrcode

from qrshield.cli import main


def _make_qr(path, text):
    image = qrcode.make(text, box_size=8, border=4)
    image.save(path)
    return path


def test_cli_url_json_and_exit_code(capsys):
    code = main(["--no-history", "url", "https://paypa1.com/login", "--json"])
    payload = json.loads(capsys.readouterr().out)
    assert code == 1
    assert payload["verdict"] == "malicious"


def test_cli_safe_url_exits_zero(capsys):
    code = main(["--no-history", "url", "https://www.google.com/", "--json"])
    payload = json.loads(capsys.readouterr().out)
    assert code == 0
    assert payload["verdict"] in ("safe", "allowlisted")


def test_cli_scan_image(capsys, tmp_path):
    image = _make_qr(tmp_path / "qr.png", "http://192.168.1.10:8080/bank/login.php")
    code = main(["--no-history", "scan", str(image), "--json"])
    payload = json.loads(capsys.readouterr().out)
    assert code == 1
    assert payload["ok"] is True
    assert payload["overall"]["verdict"] == "malicious"


def test_cli_batch_json_and_csv(capsys, tmp_path):
    _make_qr(tmp_path / "safe.png", "https://www.google.com/")
    _make_qr(tmp_path / "bad.png", "https://paypa1.com/login")
    csv_path = tmp_path / "report.csv"
    code = main([
        "--no-history", "batch", str(tmp_path), "--json", "--csv", str(csv_path),
    ])
    payload = json.loads(capsys.readouterr().out)
    assert code == 1
    assert payload["count"] == 2
    assert payload["by_verdict"]["malicious"] == 1
    assert csv_path.exists()
    assert "paypa1.com" in csv_path.read_text(encoding="utf-8")


def test_cli_batch_fail_on_none(capsys, tmp_path):
    _make_qr(tmp_path / "safe.png", "https://www.google.com/")
    code = main(["--no-history", "batch", str(tmp_path), "--fail-on", "none", "--json"])
    assert code == 0
    capsys.readouterr()


def test_cli_info(capsys):
    assert main(["info"]) == 0
    info = json.loads(capsys.readouterr().out)
    assert info["features"] == 78
    assert 0 < info["thresholds"]["suspicious"] < info["thresholds"]["malicious"] < 1
