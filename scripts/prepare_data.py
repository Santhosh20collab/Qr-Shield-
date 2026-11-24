"""Build the training dataset from public sources.

Sources
-------
* PhiUSIIL (UCI 967): 235,795 labelled phishing/legitimate URLs.
* Phishing Army: live domain blocklist (PhishTank, OpenPhish, CERT.PL, ...).
* Tranco: top popular domains, used as benign seeds.
* OpenPhish: live feed used only for the external holdout.

The split is grouped by registrable domain so the model can never memorise a
domain that also appears in the test set. External holdout domains are removed
from training entirely.
"""

from __future__ import annotations

import io
import sys
import zipfile
from pathlib import Path
from typing import Dict

import joblib
import numpy as np
import pandas as pd

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from qrshield.brands import OFFICIAL_BRAND_DOMAINS  # noqa: E402
from qrshield.config import PROCESSED_DIR, RAW_DIR  # noqa: E402
from qrshield.features import ensure_scheme, is_ip_host, split_host, url_info  # noqa: E402

DATASET_PATH = PROCESSED_DIR / "dataset.joblib"
SEED = 42
MAX_URL_LEN = 2048

# Paths that normal (benign) sites commonly expose. Used to prevent the model
# from learning "has a path = phishing", which would be a dangerous shortcut.
BENIGN_PATHS = [
    "", "about", "contact", "products", "blog", "news", "support", "help",
    "careers", "shop", "store", "privacy", "terms", "account", "login",
    "services", "solutions", "company", "pricing", "docs", "faq", "team",
]
PHISH_PATHS = [
    "", "login", "verify", "account", "secure", "update", "signin",
    "auth", "billing", "payment", "confirm", "unlock",
]


def _stable_index(text: str, modulo: int) -> int:
    return sum(ord(c) for c in text) % modulo


def _valid_url(url: str) -> bool:
    if not isinstance(url, str):
        return False
    url = url.strip()
    if not (6 <= len(url) <= MAX_URL_LEN) or any(c.isspace() for c in url):
        return False
    try:
        info = url_info(url)
    except Exception:
        return False
    host = info["host"]
    if not host:
        return False
    if host in ("localhost",) or host.endswith(".local"):
        return False
    return "." in host or is_ip_host(host)


def _clean_url(url: str) -> str:
    return ensure_scheme(url.strip())


def load_phiusiil() -> pd.DataFrame:
    path = RAW_DIR / "phiusiil.zip"
    if not path.exists():
        raise FileNotFoundError(
            f"{path} not found. Run: python scripts/download_data.py"
        )
    with zipfile.ZipFile(path) as z:
        name = next(n for n in z.namelist() if n.endswith(".csv"))
        with z.open(name) as fh:
            df = pd.read_csv(io.BytesIO(fh.read()), usecols=["URL", "label"])
    df = df.rename(columns={"URL": "url"})
    # PhiUSIIL: label 1 = legitimate, 0 = phishing.
    df["label"] = (df["label"] == 0).astype(np.int8)
    df["source"] = "phiusiil"
    df["url"] = df["url"].map(_clean_url)
    return df[["url", "label", "source"]]


def load_phishing_army(max_domains: int = 160_000) -> pd.DataFrame:
    path = RAW_DIR / "phishing_army.txt"
    if not path.exists():
        raise FileNotFoundError(
            f"{path} not found. Run: python scripts/download_data.py"
        )
    domains = []
    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        # Some feeds append "; comment" metadata.
        token = line.split(";")[0].strip().split()[0]
        token = token.lower().rstrip(".")
        if token in ("amiprotected.it", "www.amiprotected.it"):
            continue
        if token.count(".") == 0:
            continue
        domains.append(token)
    domains = sorted(set(domains))[:max_domains]
    # Do not let the model learn "http = phishing": roughly 40% of modern
    # phishing sites serve HTTPS, so assign schemes deterministically.
    # Half of the domains also get a typical campaign path.
    urls = []
    for d in domains:
        bucket = _stable_index(d, 5)
        scheme = "https" if bucket < 2 else "http"
        if _stable_index(d, 2) == 0:
            path = PHISH_PATHS[_stable_index(d, len(PHISH_PATHS))]
            urls.append(f"{scheme}://{d}/{path}" if path else f"{scheme}://{d}/")
        else:
            urls.append(f"{scheme}://{d}/")
    df = pd.DataFrame({"url": urls})
    df["label"] = np.int8(1)
    df["source"] = "phishing_army"
    return df


def with_benign_paths(df: pd.DataFrame) -> pd.DataFrame:
    """Give roughly half of the benign seed domains a realistic page path."""
    urls = []
    for url in df["url"]:
        domain = url.split("://", 1)[-1].rstrip("/")
        path = BENIGN_PATHS[_stable_index(domain, len(BENIGN_PATHS))]
        if path:
            suffix = f"/{path}"
            if _stable_index(domain, 5) == 0:
                suffix += "?utm_source=qr"
            urls.append(f"https://{domain}{suffix}")
        else:
            urls.append(f"https://{domain}/")
    out = df.copy()
    out["url"] = urls
    out["label"] = np.int8(0)
    out["source"] = "tranco"
    return out


def official_brand_benign() -> pd.DataFrame:
    """Benign pages on official brand domains.

    Without these, a URL classifier sees brand names almost exclusively in
    phishing domains and learns "brand name = phishing". That produces
    embarrassing false positives on amazon.com, netflix.com, github.com, etc.
    """
    bases = sorted({d for d in OFFICIAL_BRAND_DOMAINS if split_host(d)[1] == d})
    paths = [
        "", "login", "account", "about", "contact", "products", "help",
        "support", "security", "privacy", "terms", "signin", "billing",
        "orders", "settings", "blog", "news", "careers",
    ]
    subs = ["", "www", "account", "login", "secure", "support", "help", "m"]
    rows = []
    for base in bases:
        for sub in subs:
            host = f"{sub}.{base}" if sub else base
            for path in paths[:6] if sub else paths:
                suffix = f"/{path}" if path else "/"
                rows.append((f"https://{host}{suffix}", 0, "brand_official"))
        rows.append((f"https://{base}/?utm_source=qr", 0, "brand_official"))
    df = pd.DataFrame(rows, columns=["url", "label", "source"])
    df["label"] = df["label"].astype(np.int8)
    return df.drop_duplicates("url").reset_index(drop=True)


def load_tranco(max_domains: int = 300_000) -> pd.DataFrame:
    path = RAW_DIR / "tranco_top1m.csv"
    if not path.exists():
        raise FileNotFoundError(
            f"{path} not found. Run: python scripts/download_data.py"
        )
    df = pd.read_csv(path, header=None, names=["rank", "domain"], encoding="utf-8")
    df["domain"] = df["domain"].astype(str).str.strip().str.lower()
    df = df[df["domain"].str.contains(r"\.", regex=True, na=False)]
    df = df.drop_duplicates("domain").head(max_domains)
    out = pd.DataFrame({"url": "https://" + df["domain"] + "/"})
    out["label"] = np.int8(0)
    out["source"] = "tranco"
    return out


def load_openphish() -> pd.DataFrame:
    path = RAW_DIR / "openphish_feed.txt"
    if not path.exists():
        return pd.DataFrame(columns=["url", "label", "source"])
    urls = []
    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = line.strip()
        if line.startswith(("http://", "https://")):
            urls.append(line)
    df = pd.DataFrame({"url": sorted(set(urls))})
    df["label"] = np.int8(1)
    df["source"] = "openphish"
    return df


def _drop_conflicts(df: pd.DataFrame) -> pd.DataFrame:
    """Drop exact duplicates and hosts that carry both labels."""
    df = df.copy()
    df["_key"] = df["url"].str.lower().str.rstrip("/")
    df["_host"] = df["url"].map(lambda u: url_info(u)["host"])

    # A URL cannot be both benign and phishing.
    conflicts = df.groupby("_key")["label"].nunique()
    bad = set(conflicts[conflicts > 1].index)
    if bad:
        df = df[~df["_key"].isin(bad)]

    # Nor can the same hostname (hacked site / contradictory feed entry).
    host_conflicts = df.groupby("_host")["label"].nunique()
    bad_hosts = set(host_conflicts[host_conflicts > 1].index)
    if bad_hosts:
        df = df[~df["_host"].isin(bad_hosts)]

    df = df.drop_duplicates("_key", keep="first").drop(columns=["_key", "_host"])
    return df.reset_index(drop=True)


def build_dataset(
    max_army: int = 160_000,
    max_tranco: int = 300_000,
    seed: int = SEED,
) -> Dict:
    print("Loading PhiUSIIL ...")
    phi = load_phiusiil()
    print(f"  {len(phi):,} rows ({int(phi.label.sum()):,} phishing)")

    print("Loading Phishing Army ...")
    army = load_phishing_army(max_army)
    print(f"  {len(army):,} domains")

    print("Loading Tranco ...")
    tranco = load_tranco(max_tranco)
    print(f"  {len(tranco):,} domains")

    # Reserve 10% of live-feed domains for the external holdout.
    army_shuffled = army.sample(frac=1.0, random_state=seed).reset_index(drop=True)
    n_army_ext = max(1, int(len(army_shuffled) * 0.10))
    army_ext = army_shuffled.iloc[:n_army_ext].copy()
    army_train = army_shuffled.iloc[n_army_ext:].copy()

    tranco_shuffled = tranco.sample(frac=1.0, random_state=seed).reset_index(drop=True)
    n_tranco_ext = max(1, int(len(tranco_shuffled) * 0.10))
    tranco_ext = tranco_shuffled.iloc[:n_tranco_ext].copy()
    tranco_train = tranco_shuffled.iloc[n_tranco_ext:].copy()

    # Realistic page paths for both training and holdout benign URLs.
    tranco_train = with_benign_paths(tranco_train)
    ext_benign = with_benign_paths(tranco_ext)
    ext_benign["source"] = "tranco_holdout"

    openphish = load_openphish()

    brand_benign = official_brand_benign()
    print(f"Official-brand benign pages: {len(brand_benign):,}")

    combined = pd.concat([phi, army_train, tranco_train, brand_benign], ignore_index=True)
    combined = combined[combined["url"].map(_valid_url)]
    combined = _drop_conflicts(combined)
    combined["url"] = combined["url"].str.slice(0, MAX_URL_LEN)
    combined["domain"] = combined["url"].map(lambda u: split_host(url_info(u)["host"])[1])

    print(f"Combined training pool: {len(combined):,} rows, "
          f"{combined['domain'].nunique():,} domains")

    # Domain-grouped, class-stratified 80/10/10 split.
    from sklearn.model_selection import StratifiedGroupKFold

    sgkf = StratifiedGroupKFold(n_splits=10, shuffle=True, random_state=seed)
    fold_ids = np.zeros(len(combined), dtype=np.int8)
    for fold, (_, idx) in enumerate(sgkf.split(combined, combined["label"], groups=combined["domain"])):
        fold_ids[idx] = fold
    combined = combined.assign(_fold=fold_ids)
    train = combined[combined["_fold"] >= 2].drop(columns="_fold").reset_index(drop=True)
    val = combined[combined["_fold"] == 1].drop(columns="_fold").reset_index(drop=True)
    test = combined[combined["_fold"] == 0].drop(columns="_fold").reset_index(drop=True)

    # External holdout: remove anything whose domain appears in train/val/test.
    known_domains = set(train["domain"]) | set(val["domain"]) | set(test["domain"])
    ext = pd.concat([army_ext, ext_benign, openphish], ignore_index=True)
    ext = ext[ext["url"].map(_valid_url)]
    ext = _drop_conflicts(ext)
    ext["domain"] = ext["url"].map(lambda u: split_host(url_info(u)["host"])[1])
    ext = ext[~ext["domain"].isin(known_domains)]
    ext = ext.drop_duplicates("url").reset_index(drop=True)

    print(f"Split: train={len(train):,} val={len(val):,} test={len(test):,} "
          f"external={len(ext):,}")
    for name, part in (("train", train), ("val", val), ("test", test), ("external", ext)):
        print(f"  {name}: {int(part.label.sum()):,} phishing / "
              f"{int((1 - part.label).sum()):,} benign, "
              f"{part['domain'].nunique():,} domains")

    payload = {
        "train": train.drop(columns="domain"),
        "val": val.drop(columns="domain"),
        "test": test.drop(columns="domain"),
        "external": ext.drop(columns="domain"),
        "meta": {
            "seed": seed,
            "counts": {
                "train": len(train), "val": len(val), "test": len(test),
                "external": len(ext),
            },
            "sources": {
                "train": train["source"].value_counts().to_dict(),
                "test": test["source"].value_counts().to_dict(),
                "external": ext["source"].value_counts().to_dict(),
            },
        },
    }
    return payload


def main() -> None:
    PROCESSED_DIR.mkdir(parents=True, exist_ok=True)
    payload = build_dataset()
    joblib.dump(payload, DATASET_PATH, compress=3)
    print(f"\nSaved dataset -> {DATASET_PATH}")


if __name__ == "__main__":
    main()
