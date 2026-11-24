"""Measure model load time, per-URL latency and throughput.

    python scripts/model_benchmark.py

Writes artifacts/reports/model_benchmark.json. Numbers are machine-specific;
run on the same machine when comparing versions.
"""

from __future__ import annotations

import json
import platform
import statistics
import sys
import time
from pathlib import Path
from typing import List

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from qrshield.config import MODEL_PATH, REPORTS_DIR  # noqa: E402
from qrshield.model import load_model  # noqa: E402
from qrshield.scanner import scan_url  # noqa: E402

BRAND_DOMAINS = [
    "google.com", "amazon.com", "amazon.co.uk", "paypal.com", "netflix.com",
    "github.com", "microsoft.com", "apple.com", "facebook.com", "instagram.com",
    "linkedin.com", "dropbox.com", "dhl.com", "usps.com", "coinbase.com",
    "binance.com", "hdfcbank.com", "icicibank.com", "flipkart.com", "phonepe.com",
]
PATHS = [
    "/", "/login", "/account/settings", "/products?page=2", "/help/contact",
    "/tracking?id=12345", "/billing/invoices", "/security/verify",
]
PHISH_TEMPLATES = [
    "http://{brand}.secure-login.xyz/verify?id={n}",
    "https://{brand}-account.top/signin/{n}",
    "http://{brand}.com.verify-account.info/login?session={n}",
    "https://login-{brand}.netlify.app/confirm/{n}",
    "http://192.168.{n}.10:8080/{brand}/login.php",
]


def build_corpus(size: int = 400) -> List[str]:
    urls: List[str] = []
    index = 0
    while len(urls) < size:
        for domain in BRAND_DOMAINS:
            if len(urls) >= size:
                break
            urls.append(f"https://www.{domain}{PATHS[index % len(PATHS)]}")
        for template in PHISH_TEMPLATES:
            if len(urls) >= size:
                break
            brand = BRAND_DOMAINS[index % len(BRAND_DOMAINS)].split(".")[0]
            urls.append(template.format(brand=brand, n=1000 + index))
        index += 1
    return urls


def _percentile(values: List[float], fraction: float) -> float:
    ordered = sorted(values)
    if not ordered:
        return 0.0
    position = min(len(ordered) - 1, int(round(fraction * (len(ordered) - 1))))
    return ordered[position]


def main() -> None:
    if not MODEL_PATH.exists():
        raise SystemExit(f"No model at {MODEL_PATH}. Train it first.")

    started = time.perf_counter()
    model = load_model(use_cache=False)
    load_seconds = time.perf_counter() - started

    corpus = build_corpus(400)
    # Warm up vectorizers and caches before timing.
    model.predict_one(corpus[0])
    model.predict_one(corpus[0])

    single_times: List[float] = []
    for url in corpus:
        start = time.perf_counter()
        model.predict_one(url)
        single_times.append((time.perf_counter() - start) * 1000)

    batch_start = time.perf_counter()
    probabilities = model.predict_proba(corpus)
    batch_seconds = time.perf_counter() - batch_start
    throughput = len(corpus) / batch_seconds if batch_seconds else 0.0

    scan_times: List[float] = []
    for url in corpus[:100]:
        start = time.perf_counter()
        scan_url(url, model=model)
        scan_times.append((time.perf_counter() - start) * 1000)

    report = {
        "model_path": str(MODEL_PATH.relative_to(PROJECT_ROOT)) if MODEL_PATH.is_relative_to(PROJECT_ROOT) else MODEL_PATH.name,
        "model_size_mb": round(MODEL_PATH.stat().st_size / 1e6, 2),
        "features": model.info()["features"],
        "thresholds": model.thresholds,
        "environment": {
            "python": platform.python_version(),
            "platform": platform.platform(),
        },
        "load_seconds": round(load_seconds, 3),
        "corpus_size": len(corpus),
        "single_url_ms": {
            "mean": round(statistics.mean(single_times), 3),
            "median": round(statistics.median(single_times), 3),
            "p95": round(_percentile(single_times, 0.95), 3),
            "max": round(max(single_times), 3),
        },
        "batch": {
            "urls": len(corpus),
            "seconds": round(batch_seconds, 3),
            "throughput_urls_per_second": round(throughput, 1),
        },
        "full_scan_ms": {
            "mean": round(statistics.mean(scan_times), 3),
            "p95": round(_percentile(scan_times, 0.95), 3),
        },
        "prediction_range": [
            round(float(probabilities.min()), 6),
            round(float(probabilities.max()), 6),
        ],
    }

    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    path = REPORTS_DIR / "model_benchmark.json"
    path.write_text(json.dumps(report, indent=2), encoding="utf-8")

    print(f"Model load       : {load_seconds:.3f}s ({report['model_size_mb']} MB)")
    print(f"Single URL       : mean {report['single_url_ms']['mean']:.2f} ms  "
          f"p95 {report['single_url_ms']['p95']:.2f} ms")
    print(f"Batch throughput : {report['batch']['throughput_urls_per_second']:,.0f} URLs/s "
          f"({len(corpus)} URLs in {batch_seconds:.3f}s)")
    print(f"Full scan_url    : mean {report['full_scan_ms']['mean']:.2f} ms  "
          f"p95 {report['full_scan_ms']['p95']:.2f} ms")
    print(f"Report -> {path}")


if __name__ == "__main__":
    main()
