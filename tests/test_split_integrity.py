import pytest

from qrshield.config import PROCESSED_DIR

DATASET_PATH = PROCESSED_DIR / "dataset.joblib"


def _hosts(frame):
    from urllib.parse import urlsplit

    hosts = set()
    for url in frame["url"].astype(str):
        try:
            host = urlsplit(url).hostname
        except ValueError:
            host = None
        if host:
            hosts.add(host.lower().rstrip("."))
    return hosts


@pytest.fixture(scope="module")
def splits():
    if not DATASET_PATH.exists():
        pytest.skip("dataset.joblib not built; run scripts/prepare_data.py")
    import joblib

    data = joblib.load(DATASET_PATH)
    assert {"train", "val", "test", "external"} <= set(data)
    return data


def test_no_host_leases_across_splits(splits):
    names = ["train", "val", "test", "external"]
    hosts = {name: _hosts(splits[name]) for name in names}
    for i, left in enumerate(names):
        for right in names[i + 1:]:
            overlap = hosts[left] & hosts[right]
            assert not overlap, (
                f"{len(overlap)} host(s) leak between {left} and {right}, "
                f"e.g. {sorted(overlap)[:5]}"
            )


def test_registrable_domains_are_disjoint_on_sample(splits):
    from qrshield.features import split_host

    names = ["train", "val", "test", "external"]
    domains = {}
    for name in names:
        sample = sorted(_hosts(splits[name]))[:30000]
        domains[name] = {split_host(host)[1] for host in sample}
    for i, left in enumerate(names):
        for right in names[i + 1:]:
            overlap = domains[left] & domains[right]
            assert not overlap, (
                f"registrable domains leak between {left} and {right}: {sorted(overlap)[:5]}"
            )


def test_class_balance_is_sane(splits):
    for name in ("train", "val", "test", "external"):
        labels = splits[name]["label"]
        assert set(labels.unique()) <= {0, 1}
        phishing_share = float(labels.mean())
        assert 0.15 <= phishing_share <= 0.55, f"{name} phishing share is {phishing_share}"


def test_split_sizes_and_sources(splits):
    sizes = {name: len(splits[name]) for name in ("train", "val", "test", "external")}
    assert sizes["train"] > sizes["val"] > 1000
    assert sizes["train"] > sizes["test"] > 1000
    assert sizes["external"] > 1000
    sources = set(splits["external"]["source"].unique())
    assert "tranco_holdout" in sources
    assert {"phishing_army", "openphish"} & sources
