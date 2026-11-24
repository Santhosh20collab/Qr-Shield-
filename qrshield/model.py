"""Model wrapper: loads the trained artifact and scores URLs."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Union

import joblib
import numpy as np
from scipy.sparse import hstack

from .config import MODEL_PATH
from .features import (
    FEATURE_NAMES,
    extract_features,
    text_for_model,
)

_URL_SPLIT_RE = re.compile(r"[^a-z0-9]+")


class ModelNotFoundError(RuntimeError):
    pass


class QRShieldModel:
    """Ensemble of a char/word n-gram linear model and numeric tree models."""

    def __init__(self, artifact: Dict):
        required = {
            "char_vectorizer", "word_vectorizer", "numeric_scaler",
            "linear_model", "gbm_model", "et_model", "weights",
        }
        missing = required - set(artifact)
        if missing:
            raise ValueError(f"Model artifact is missing keys: {sorted(missing)}")
        self.artifact = artifact
        self.char_vectorizer = artifact["char_vectorizer"]
        self.word_vectorizer = artifact["word_vectorizer"]
        self.numeric_scaler = artifact["numeric_scaler"]
        self.linear_model = artifact["linear_model"]
        self.gbm_model = artifact["gbm_model"]
        self.et_model = artifact.get("et_model")
        self.weights = np.asarray(artifact["weights"], dtype=np.float64)
        self.calibrator = artifact.get("calibrator")
        self.thresholds = artifact.get("thresholds", {
            "malicious": 0.65, "suspicious": 0.35,
        })
        self.metadata = artifact.get("metadata", {})
        self.metrics = artifact.get("metrics", {})
        self.feature_names = artifact.get("feature_names", FEATURE_NAMES)
        self._char_names = self.char_vectorizer.get_feature_names_out()
        self._word_names = self.word_vectorizer.get_feature_names_out()
        self._linear_numeric_dim = int(artifact.get("linear_numeric_dim", len(self.feature_names)))

    # ------------------------------------------------------------------
    @classmethod
    def load(cls, path: Optional[Union[str, Path]] = None) -> "QRShieldModel":
        path = Path(path) if path else MODEL_PATH
        if not path.exists():
            raise ModelNotFoundError(
                f"No trained model at {path}. Run: python scripts/train_model.py"
            )
        return cls(joblib.load(path))

    def info(self) -> Dict:
        return {
            "version": self.metadata.get("version"),
            "trained_at": self.metadata.get("trained_at"),
            "train_size": self.metadata.get("train_size"),
            "features": len(self.feature_names),
            "weights": {
                "linear": float(self.weights[0]),
                "gradient_boosting": float(self.weights[1]),
                "extra_trees": float(self.weights[2]),
            },
            "thresholds": self.thresholds,
            "test_metrics": self.metrics.get("test", {}),
            "external_metrics": self.metrics.get("external", {}),
            "sklearn_version": self.metadata.get("sklearn_version"),
        }

    # ------------------------------------------------------------------
    def _parts(self, urls: Sequence[str]):
        X_num = np.asarray([extract_features(u) for u in urls], dtype=np.float32)
        texts = [text_for_model(u) for u in urls]
        X_char = self.char_vectorizer.transform(texts)
        X_word = self.word_vectorizer.transform(texts)
        X_num_scaled = self.numeric_scaler.transform(X_num)
        X_linear = hstack([X_num_scaled, X_char, X_word], format="csr")
        return X_num, X_linear, X_char, X_word

    def predict_proba(self, urls: Union[str, Iterable[str]]) -> np.ndarray:
        """Return P(phishing) for one URL or a list of URLs."""
        single = isinstance(urls, str)
        urls = [urls] if single else list(urls)
        if not urls:
            return np.array([], dtype=np.float64)
        X_num, X_linear, _, _ = self._parts(urls)
        p_lin = self.linear_model.predict_proba(X_linear)[:, 1]
        p_gbm = self.gbm_model.predict_proba(X_num)[:, 1]
        probs = [p_lin, p_gbm]
        weights = [self.weights[0], self.weights[1]]
        if self.et_model is not None:
            probs.append(self.et_model.predict_proba(X_num)[:, 1])
            weights.append(self.weights[2])
        p = np.column_stack(probs) @ np.asarray(weights, dtype=np.float64)
        if self.calibrator is not None:
            if hasattr(self.calibrator, "predict_proba"):
                eps = 1e-6
                clipped = np.clip(p, eps, 1 - eps)
                logits = np.log(clipped / (1 - clipped)).reshape(-1, 1)
                p = self.calibrator.predict_proba(logits)[:, 1]
            else:
                p = self.calibrator.predict(p)
        p = np.clip(p, 0.0, 1.0)
        return p if not single else np.asarray([p[0]])

    def predict_one(self, url: str) -> float:
        return float(self.predict_proba(url)[0])

    def top_tokens(self, url: str, k: int = 8) -> List[Dict[str, float]]:
        """Most influential char/word n-grams for the linear model."""
        text = text_for_model(url)
        Xc = self.char_vectorizer.transform([text])
        Xw = self.word_vectorizer.transform([text])
        coef = np.asarray(self.linear_model.coef_).ravel()
        n_char = len(self._char_names)
        offset_word = self._linear_numeric_dim + n_char
        contribs = []

        for idx, value in zip(Xc.indices, Xc.data):
            contribs.append((float(value * coef[self._linear_numeric_dim + idx]),
                             str(self._char_names[idx])))
        for idx, value in zip(Xw.indices, Xw.data):
            contribs.append((float(value * coef[offset_word + idx]),
                             str(self._word_names[idx])))
        contribs.sort(key=lambda x: x[0], reverse=True)

        out = []
        seen = set()
        for weight, token in contribs:
            token = token.strip()
            if not token or token in seen:
                continue
            seen.add(token)
            out.append({"token": token, "weight": round(weight, 4)})
            if len(out) >= k:
                break
        return out

    def numeric_contributions(self, url: str, k: int = 6) -> List[Dict[str, float]]:
        """Largest positive numeric-feature contributions from the linear model."""
        vec = extract_features(url).reshape(1, -1)
        scaled = self.numeric_scaler.transform(vec).ravel()
        coef = np.asarray(self.linear_model.coef_).ravel()[: len(self.feature_names)]
        contrib = scaled * coef
        order = np.argsort(contrib)[::-1]
        out = []
        for idx in order[:k]:
            if contrib[idx] <= 0:
                break
            out.append({
                "feature": self.feature_names[idx],
                "value": round(float(vec[0, idx]), 4),
                "weight": round(float(contrib[idx]), 4),
            })
        return out


_MODEL_CACHE: Dict[str, QRShieldModel] = {}


def load_model(path: Optional[Union[str, Path]] = None,
               use_cache: bool = True) -> QRShieldModel:
    key = str(Path(path) if path else MODEL_PATH)
    if use_cache and key in _MODEL_CACHE:
        return _MODEL_CACHE[key]
    model = QRShieldModel.load(path)
    if use_cache:
        _MODEL_CACHE[key] = model
    return model
