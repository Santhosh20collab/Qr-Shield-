"""Measure QR decoding robustness under realistic camera distortions.

    python scripts/benchmark_qr.py

Generates QR codes locally, applies blur/rotation/glare/JPEG/perspective and
reports the decode rate. Results are written to artifacts/reports/.
"""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path
from typing import List, Tuple

import cv2
import numpy as np
import qrcode

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from qrshield.config import REPORTS_DIR  # noqa: E402
from qrshield.qr_decode import decode_qr  # noqa: E402

SAMPLE_URLS = [
    "https://www.google.com/",
    "https://www.amazon.co.uk/dp/B08N5WRWNW",
    "https://github.com/openai",
    "https://www.netflix.com/browse",
    "http://paypal.com.secure-login.xyz/verify?id=123",
    "https://paypa1.com/login",
    "http://192.168.1.10:8080/bank/login.php",
    "https://bit.ly/abc123",
    "https://www.hdfcbank.com/personal/pay/cards",
    "https://example.com/redirect?url=https%3A%2F%2Fevil.example",
]


def _qr(text: str, px: int = 420) -> np.ndarray:
    img = qrcode.make(text, box_size=10, border=4).convert("RGB")
    img = img.resize((px, px))
    return cv2.cvtColor(np.array(img), cv2.COLOR_RGB2BGR)


def _perspective(img: np.ndarray, strength: float = 0.10) -> np.ndarray:
    h, w = img.shape[:2]
    d = int(min(h, w) * strength)
    src = np.float32([[0, 0], [w, 0], [w, h], [0, h]])
    dst = np.float32([[d, d // 2], [w - d // 2, 0], [w, h - d], [0, h - d // 2]])
    matrix = cv2.getPerspectiveTransform(src, dst)
    return cv2.warpPerspective(img, matrix, (w, h), borderValue=(255, 255, 255))


def _distortions(img: np.ndarray) -> List[Tuple[str, np.ndarray]]:
    h, w = img.shape[:2]
    out: List[Tuple[str, np.ndarray]] = [("clean", img)]

    out.append(("gaussian_blur", cv2.GaussianBlur(img, (7, 7), 2.0)))
    out.append(("motion_blur", cv2.filter2D(img, -1, np.ones((7, 7), np.float32) / 49)))
    out.append(("low_contrast", (img.astype(np.float32) * 0.35 + 140).clip(0, 255).astype(np.uint8)))
    out.append(("dark", (img.astype(np.float32) * 0.45).clip(0, 255).astype(np.uint8)))
    out.append(("rotated_90", cv2.rotate(img, cv2.ROTATE_90_CLOCKWISE)))
    out.append(("small_160", cv2.resize(img, (160, 160), interpolation=cv2.INTER_AREA)))
    out.append(("perspective", _perspective(img)))

    ok, encoded = cv2.imencode(".jpg", img, [int(cv2.IMWRITE_JPEG_QUALITY), 30])
    if ok:
        out.append(("jpeg_q30", cv2.imdecode(encoded, cv2.IMREAD_COLOR)))

    rng = np.random.default_rng(7)
    noisy = np.clip(img.astype(np.int16) + rng.normal(0, 16, img.shape), 0, 255).astype(np.uint8)
    out.append(("sensor_noise", noisy))

    glare = np.tile(np.linspace(0, 110, w, dtype=np.float32), (h, 1))
    glare = np.dstack([glare, glare, glare])
    out.append(("glare_gradient", np.clip(img.astype(np.float32) + glare, 0, 255).astype(np.uint8)))
    return out


def main() -> None:
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    rows = []
    total_time = 0.0
    total_runs = 0

    for name, img in _distortions(_qr(SAMPLE_URLS[0])):
        t = time.time()
        result = decode_qr(img)
        elapsed = time.time() - t
        total_time += elapsed
        total_runs += 1
        rows.append({
            "distortion": name,
            "decoded": result["count"] > 0,
            "payload": result["payloads"][0]["data"] if result["count"] else None,
            "method": result["payloads"][0]["method"] if result["count"] else None,
            "seconds": round(elapsed, 3),
        })
        print(f"{name:18s} {'OK ' if result['count'] else 'MISS'} "
              f"{elapsed:5.2f}s  {result['payloads'][0]['data'] if result['count'] else ''}")

    print(f"\nSingle-code decode rate: {sum(r['decoded'] for r in rows)}/{len(rows)}")
    print(f"Mean decode time: {total_time / total_runs:.3f}s")

    multi = np.full((440, 860, 3), 255, dtype=np.uint8)
    multi[30:410, 30:410] = _qr("https://one.example/a", 380)
    multi[30:410, 450:830] = _qr("https://two.example/b", 380)
    t = time.time()
    multi_result = decode_qr(multi)
    multi_seconds = time.time() - t
    print(f"Two-code image: decoded {multi_result['count']} in {multi_seconds:.2f}s")

    report = {
        "single_code": rows,
        "decode_rate": sum(r["decoded"] for r in rows) / len(rows),
        "mean_seconds": round(total_time / total_runs, 3),
        "multi_code": {
            "decoded": multi_result["count"],
            "seconds": round(multi_seconds, 3),
        },
    }
    path = REPORTS_DIR / "qr_decode_benchmark.json"
    path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(f"Report -> {path}")


if __name__ == "__main__":
    main()
