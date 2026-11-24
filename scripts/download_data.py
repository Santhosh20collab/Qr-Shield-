"""Download public datasets used to train QR Shield.

    python scripts/download_data.py
    python scripts/download_data.py --force

Everything is cached in data/raw/. Downloads can be large (PhiUSIIL ~15 MB,
Tranco ~23 MB); rerunning is safe and skips existing files unless --force.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
import urllib.request
import zipfile
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from qrshield.config import RAW_DIR  # noqa: E402

PHIUSIIL_URL = "https://archive.ics.uci.edu/static/public/967/phiusiil+phishing+url+dataset.zip"
ARMY_URL = "https://phishing.army/download/phishing_army_blocklist_extended.txt"
OPENPHISH_URL = "https://openphish.com/feed.txt"
TRANCO_API = "https://tranco-list.eu/api/lists/date/latest"
UA = {"User-Agent": "Mozilla/5.0 (QRShield dataset downloader)"}


def _download(url: str, dest: Path, force: bool = False, expected: str = "") -> None:
    if dest.exists() and dest.stat().st_size > 0 and not force:
        print(f"  [skip] {dest.name} ({dest.stat().st_size / 1e6:.1f} MB)")
        return
    print(f"  [get ] {url}")
    t = time.time()
    req = urllib.request.Request(url, headers=UA)
    tmp = dest.with_suffix(dest.suffix + ".part")
    try:
        with urllib.request.urlopen(req, timeout=120) as r, open(tmp, "wb") as f:
            while True:
                chunk = r.read(1 << 20)
                if not chunk:
                    break
                f.write(chunk)
        tmp.replace(dest)
    except Exception as exc:
        if tmp.exists():
            tmp.unlink()
        raise RuntimeError(
            f"Could not download {url}: {exc}\n"
            "Some feeds block automated clients intermittently; retry later or "
            "download the file manually into data/raw/."
        ) from exc
    print(f"  [ ok ] {dest.name} ({dest.stat().st_size / 1e6:.1f} MB, {time.time() - t:.1f}s)")
    if expected and expected not in dest.name:
        raise RuntimeError(f"Unexpected filename for {url}")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--force", action="store_true", help="re-download existing files")
    args = parser.parse_args()

    RAW_DIR.mkdir(parents=True, exist_ok=True)

    print("PhiUSIIL phishing URL dataset")
    _download(PHIUSIIL_URL, RAW_DIR / "phiusiil.zip", args.force)
    try:
        with zipfile.ZipFile(RAW_DIR / "phiusiil.zip") as z:
            names = z.namelist()
            if not any(n.endswith(".csv") for n in names):
                raise RuntimeError("PhiUSIIL archive does not contain a CSV")
    except zipfile.BadZipFile as exc:
        raise RuntimeError("PhiUSIIL download is not a valid zip; use --force to retry") from exc

    print("\nPhishing Army blocklist")
    _download(ARMY_URL, RAW_DIR / "phishing_army.txt", args.force)

    print("\nOpenPhish live feed (external evaluation only)")
    _download(OPENPHISH_URL, RAW_DIR / "openphish_feed.txt", args.force)

    print("\nTranco popular domains")
    tranco_dest = RAW_DIR / "tranco_top1m.csv"
    if tranco_dest.exists() and not args.force:
        print(f"  [skip] {tranco_dest.name} ({tranco_dest.stat().st_size / 1e6:.1f} MB)")
    else:
        req = urllib.request.Request(TRANCO_API, headers=UA)
        with urllib.request.urlopen(req, timeout=60) as r:
            meta = json.load(r)
        print(f"  list {meta.get('list_id')} created {meta.get('created_on')}")
        _download(meta["download"], tranco_dest, force=True)

    print("\nDone. Next: python scripts/prepare_data.py")


if __name__ == "__main__":
    main()
