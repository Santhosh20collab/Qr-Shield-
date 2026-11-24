"""Command-line interface for QR Shield."""

from __future__ import annotations

import argparse
import csv
import json
import sys
from pathlib import Path
from typing import Dict, Iterable, List, Optional

from . import history
from .model import ModelNotFoundError, load_model
from .scanner import scan_image, scan_url

IMAGE_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".webp", ".bmp", ".gif", ".tif", ".tiff", ".heic",
}

_VERDICT_MARK = {
    "safe": "[ OK ]",
    "allowlisted": "[ OK ]",
    "suspicious": "[ !! ]",
    "malicious": "[ XX ]",
    "unknown": "[ ?? ]",
}


def _load(model_path: Optional[str] = None, required: bool = False):
    try:
        return load_model(model_path)
    except ModelNotFoundError as exc:
        if required:
            raise SystemExit(str(exc))
        print(f"warning: {exc}", file=sys.stderr)
        return None


def _record(result: Dict, source: str, filename: Optional[str], args) -> None:
    if getattr(args, "no_history", False):
        return
    try:
        history.record_scan(result, source=source, filename=filename)
    except Exception as exc:  # history must never break a scan
        print(f"warning: could not record history: {exc}", file=sys.stderr)


def _print_result(result: Dict, index: int = 0) -> None:
    verdict = result.get("verdict", "unknown")
    mark = _VERDICT_MARK.get(verdict, "[ ?? ]")
    print(f"\n{mark} {verdict.upper()}  risk {result.get('score', 0):.1f}/100")
    print(f"  payload : {result.get('payload', '')[:180]}")
    if result.get("url_info"):
        info = result["url_info"]
        print(f"  host    : {info.get('host')}  (registered: {info.get('registered_domain')})")
        print(f"  https   : {'yes' if info.get('is_https') else 'no'}")
    if result.get("decode_method"):
        print(f"  decoded : {result['decode_method']} / {result.get('decode_variant')}")
    reasons = result.get("reasons", [])
    if reasons:
        print("  reasons :")
        for reason in reasons[:8]:
            print(f"    - [{reason['severity']}] {reason['message']}")
    tokens = result.get("top_tokens", [])
    if tokens:
        print("  strong tokens: " + ", ".join(t["token"] for t in tokens[:6]))
    if result.get("model", {}).get("used"):
        print(f"  model p : {result['model']['probability']:.4f}")


def cmd_url(args) -> int:
    model = _load(args.model, required=False)
    result = scan_url(args.url, model=model)
    _record(result, "url", None, args)
    if args.json:
        print(json.dumps(result, indent=2, ensure_ascii=False))
    else:
        _print_result(result)
        if result.get("url_info") and not result["url_info"].get("is_https"):
            print("\n  tip: this link is not encrypted (HTTP). Do not enter credentials.")
    return 0 if result["verdict"] in ("safe", "allowlisted") else 1


def cmd_scan(args) -> int:
    path = Path(args.image)
    if not path.exists():
        raise SystemExit(f"Image not found: {path}")
    model = _load(args.model, required=False)
    result = scan_image(path, model=model)
    for item in result.get("results") or []:
        _record(item, "image", path.name, args)
    if not result.get("results"):
        _record({"payload": f"(no QR decoded) {path.name}", "verdict": "unknown",
                 "score": 0.0, "reasons": []}, "image", path.name, args)

    verdict = (result.get("overall") or {}).get("verdict", "unknown")
    exit_code = 0 if result.get("ok") and verdict in ("safe", "allowlisted") else 1
    if args.json:
        print(json.dumps(result, indent=2, ensure_ascii=False))
        return exit_code
    if not result.get("ok"):
        print(f"No QR decoded: {result.get('error')}")
        for warning in result.get("image", {}).get("warnings", []):
            print(f"  ! {warning}")
        return exit_code
    print(f"Decoded {result.get('decoded_count', 0)} QR code(s)")
    for warning in result.get("overall", {}).get("warnings", []):
        print(f"  ! {warning}")
    for i, item in enumerate(result["results"], 1):
        if len(result["results"]) > 1:
            print(f"\n--- QR {i} ---")
        _print_result(item, i)
    overall = result.get("overall", {})
    print(f"\nOverall: {overall.get('verdict', 'unknown').upper()} "
          f"(risk {overall.get('score', 0):.1f}/100)")
    return exit_code


def _iter_images(targets: Iterable[str]) -> List[Path]:
    found: List[Path] = []
    for target in targets:
        path = Path(target)
        if path.is_dir():
            found.extend(
                sorted(
                    p for p in path.rglob("*")
                    if p.is_file() and p.suffix.lower() in IMAGE_EXTENSIONS
                )
            )
        elif path.is_file():
            found.append(path)
        else:
            print(f"warning: not found: {path}", file=sys.stderr)
    return found


def _batch_row(path: Path, result: Dict) -> Dict:
    overall = result.get("overall") or {}
    first = (result.get("results") or [{}])[0]
    codes = [r.get("code") for r in (first.get("reasons") or []) if r.get("code")]
    return {
        "file": path.name,
        "path": str(path),
        "decoded": int(result.get("decoded_count") or 0),
        "verdict": overall.get("verdict", "unknown"),
        "score": float(overall.get("score") or 0.0),
        "payload": (first.get("payload") or result.get("error") or "")[:300],
        "payload_type": first.get("payload_type") or "",
        "host": ((first.get("url_info") or {}).get("host")) or "",
        "reasons": ";".join(codes[:5]),
    }


def cmd_batch(args) -> int:
    images = _iter_images(args.paths)
    if not images:
        raise SystemExit("No images found. Pass image files or a folder.")
    if args.limit and len(images) > args.limit:
        print(f"warning: limiting to the first {args.limit} images", file=sys.stderr)
        images = images[: args.limit]

    model = _load(args.model, required=False)
    rows: List[Dict] = []
    payloads: List[Dict] = []
    for path in images:
        result = scan_image(path, model=model)
        for item in result.get("results") or []:
            _record(item, "batch", path.name, args)
        if not result.get("results"):
            _record({"payload": f"(no QR decoded) {path.name}", "verdict": "unknown",
                     "score": 0.0, "reasons": []}, "batch", path.name, args)
        row = _batch_row(path, result)
        rows.append(row)
        payloads.append({"file": str(path), "summary": row, "result": result})

    counts: Dict[str, int] = {}
    for row in rows:
        counts[row["verdict"]] = counts.get(row["verdict"], 0) + 1

    if args.csv:
        out = Path(args.csv)
        with out.open("w", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
            writer.writeheader()
            writer.writerows(rows)
        print(f"CSV written -> {out}", file=sys.stderr)

    if args.json:
        print(json.dumps(
            {"count": len(rows), "by_verdict": counts, "files": payloads},
            indent=2, ensure_ascii=False,
        ))
    else:
        width = max((len(r["file"]) for r in rows), default=4)
        print(f"{'FILE'.ljust(width)}  {'VERDICT':10s}  SCORE  PAYLOAD")
        for row in rows:
            print(f"{row['file'].ljust(width)}  {row['verdict']:10s}  {row['score']:5.1f}  "
                  f"{row['payload'][:70]}")
        print("\nSummary: " + ", ".join(f"{k}={v}" for k, v in sorted(counts.items())))

    failed_on = args.fail_on
    if failed_on == "none":
        return 0
    bad = {"malicious"} if failed_on == "malicious" else {"malicious", "suspicious"}
    return 1 if any(row["verdict"] in bad for row in rows) else 0


def cmd_history(args) -> int:
    if args.clear:
        removed = history.clear_history()
        if args.json:
            print(json.dumps({"deleted": removed}))
        else:
            print(f"Cleared {removed} scan(s).")
        return 0

    if args.stats:
        data = history.stats()
        if args.json:
            print(json.dumps(data, indent=2, ensure_ascii=False))
        else:
            print(f"Total scans : {data['total']}  (today: {data['today']})")
            print(f"Malicious   : {data['by_verdict'].get('malicious', 0)} "
                  f"({data['malicious_rate'] * 100:.1f}%)")
            print(f"Average risk: {data['average_score']}/100")
            for item in data["top_reasons"]:
                print(f"  {item['count']:4d}  {item['code']}")
        return 0

    page = history.list_scans(limit=args.limit, offset=args.offset,
                              verdict=args.verdict, query=args.query)
    if args.json:
        print(json.dumps(page, indent=2, ensure_ascii=False))
        return 0
    if not page["items"]:
        print("No scans recorded yet.")
        return 0
    print(f"Showing {len(page['items'])} of {page['total']} scan(s)")
    for item in page["items"]:
        mark = _VERDICT_MARK.get(item["verdict"], "[ ?? ]")
        when = item["created_at"].replace("T", " ")[:19]
        payload = (item.get("payload") or "").replace("\n", " ")[:72]
        print(f"{item['id']:5d}  {when}  {mark} {item['verdict']:10s} "
              f"{item['score']:5.1f}  {payload}")
    return 0


def cmd_info(args) -> int:
    model = _load(args.model, required=True)
    info = model.info()
    print(json.dumps(info, indent=2, ensure_ascii=False))
    return 0


def cmd_serve(args) -> int:
    try:
        import uvicorn
    except ImportError:
        raise SystemExit("Install the web dependencies: pip install -r requirements.txt")
    uvicorn.run(
        "app.main:app",
        host=args.host,
        port=args.port,
        reload=args.reload,
        log_level=args.log_level,
    )
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="qrshield",
        description="Scan QR codes and links for phishing (quishing) attempts.",
    )
    parser.add_argument("--model", help="path to a trained .joblib model")
    parser.add_argument("--no-history", action="store_true",
                        help="do not store this scan in the local history")
    sub = parser.add_subparsers(dest="command", required=True)

    p_url = sub.add_parser("url", help="analyse a URL")
    p_url.add_argument("url")
    p_url.add_argument("--json", action="store_true")
    p_url.set_defaults(func=cmd_url)

    p_scan = sub.add_parser("scan", help="decode and analyse a QR image")
    p_scan.add_argument("image")
    p_scan.add_argument("--json", action="store_true")
    p_scan.set_defaults(func=cmd_scan)

    p_batch = sub.add_parser("batch", help="scan a folder of QR images")
    p_batch.add_argument("paths", nargs="+", help="image files and/or folders")
    p_batch.add_argument("--json", action="store_true")
    p_batch.add_argument("--csv", metavar="FILE", help="write a CSV report")
    p_batch.add_argument("--limit", type=int, default=500,
                         help="maximum images to scan (default 500)")
    p_batch.add_argument("--fail-on", choices=("malicious", "suspicious", "none"),
                         default="malicious", help="verdict that makes the exit code 1")
    p_batch.set_defaults(func=cmd_batch)

    p_hist = sub.add_parser("history", help="inspect or clear local scan history")
    p_hist.add_argument("--limit", type=int, default=20)
    p_hist.add_argument("--offset", type=int, default=0)
    p_hist.add_argument("--verdict", help="filter by verdict")
    p_hist.add_argument("--query", "-q", help="search payload, host or filename")
    p_hist.add_argument("--stats", action="store_true", help="show aggregates")
    p_hist.add_argument("--clear", action="store_true", help="delete all history")
    p_hist.add_argument("--json", action="store_true")
    p_hist.set_defaults(func=cmd_history)

    p_info = sub.add_parser("info", help="show model metadata and metrics")
    p_info.set_defaults(func=cmd_info)

    p_serve = sub.add_parser("serve", help="run the local web app")
    p_serve.add_argument("--host", default="127.0.0.1")
    p_serve.add_argument("--port", type=int, default=8000)
    p_serve.add_argument("--reload", action="store_true")
    p_serve.add_argument("--log-level", default="info")
    p_serve.set_defaults(func=cmd_serve)
    return parser


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
