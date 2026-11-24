import numpy as np
import pytest

from qrshield.config import MODEL_PATH
from qrshield.model import load_model

pytestmark = pytest.mark.skipif(not MODEL_PATH.exists(), reason="model not trained")


@pytest.fixture(scope="module")
def model():
    return load_model()


def test_artifact_metadata_and_thresholds(model):
    info = model.info()
    assert info["features"] == 78
    thresholds = info["thresholds"]
    assert 0 < thresholds["suspicious"] < thresholds["malicious"] < 1
    weights = info["weights"]
    assert weights["linear"] + weights["gradient_boosting"] + weights["extra_trees"] == pytest.approx(1.0, abs=1e-6)
    assert info["train_size"] > 100000


def test_predict_proba_shapes_and_range(model):
    urls = [
        "https://www.google.com/",
        "https://www.amazon.co.uk/dp/B08N5WRWNW",
        "http://paypal.com.secure-login.xyz/verify",
    ]
    probs = model.predict_proba(urls)
    assert probs.shape == (3,)
    assert np.all((probs >= 0) & (probs <= 1))
    single = model.predict_proba(urls[0])
    assert single.shape == (1,)
    assert single[0] == pytest.approx(probs[0])


def test_official_vs_lookalike_separation(model):
    official = model.predict_one("https://www.paypal.com/signin")
    impersonation = model.predict_one("http://paypal.com.secure-login.xyz/verify")
    assert official < 0.3
    assert impersonation > 0.8
    assert impersonation - official > 0.5


def test_explanations_are_ranked(model):
    tokens = model.top_tokens("https://paypa1.com/login", k=6)
    assert tokens
    weights = [item["weight"] for item in tokens]
    assert weights == sorted(weights, reverse=True)
    contributions = model.numeric_contributions("http://192.168.1.10:8080/bank/login.php")
    assert contributions
    assert all(item["weight"] > 0 for item in contributions)


def test_empty_batch_is_safe(model):
    assert model.predict_proba([]).shape == (0,)
