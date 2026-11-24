"""Train the QR Shield phishing URL model.

Usage
-----
    python scripts/train_model.py
    python scripts/train_model.py --linear sgd --n-jobs 8
    python scripts/train_model.py --sample 200000 --no-cache

The trained artifact contains every component needed for offline inference:
char/word TF-IDF vectorizers, numeric scaler, three classifiers, blend weights,
an isotonic calibrator, verdict thresholds and evaluation metrics.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import platform
import sys
import time
from pathlib import Path
from typing import Dict, Optional, Tuple

import joblib
import numpy as np
import pandas as pd
import sklearn
from scipy.sparse import hstack
from sklearn.ensemble import ExtraTreesClassifier, HistGradientBoostingClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression, SGDClassifier
from sklearn.metrics import (
    accuracy_score,
    average_precision_score,
    brier_score_loss,
    confusion_matrix,
    f1_score,
    matthews_corrcoef,
    precision_recall_curve,
    precision_score,
    recall_score,
    roc_auc_score,
    roc_curve,
)
from sklearn.preprocessing import MaxAbsScaler

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from qrshield.config import (  # noqa: E402
    ARTIFACTS_DIR,
    METRICS_PATH,
    MODEL_PATH,
    PROCESSED_DIR,
    REPORTS_DIR,
)
from qrshield.features import FEATURE_NAMES, features_to_matrix, text_for_model  # noqa: E402

DATASET_PATH = PROCESSED_DIR / "dataset.joblib"
FEATURE_CACHE = PROCESSED_DIR / "numeric_features.joblib"
SEED = 42


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _fingerprint(dfs: Dict[str, pd.DataFrame]) -> str:
    h = hashlib.sha256()
    for name in sorted(dfs):
        h.update(name.encode())
        h.update("|".join(dfs[name]["url"].tolist()).encode("utf-8", errors="ignore"))
    return h.hexdigest()


def numeric_features(dfs: Dict[str, pd.DataFrame], n_jobs: int, use_cache: bool = True) -> Dict[str, np.ndarray]:
    key = _fingerprint(dfs)
    if use_cache and FEATURE_CACHE.exists():
        try:
            cached = joblib.load(FEATURE_CACHE)
            if cached.get("key") == key:
                print(f"Loaded cached numeric features ({key[:10]})")
                return cached["features"]
        except Exception:
            pass
    out = {}
    for name, df in dfs.items():
        t = time.time()
        out[name] = features_to_matrix(df["url"].tolist(), n_jobs=n_jobs)
        print(f"  numeric {name}: {out[name].shape} in {time.time() - t:.1f}s")
    try:
        joblib.dump({"key": key, "features": out}, FEATURE_CACHE, compress=3)
    except Exception as exc:
        print(f"  (could not cache features: {exc})")
    return out


def _jsonable(value):
    if isinstance(value, dict):
        return {str(k): _jsonable(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_jsonable(v) for v in value]
    if isinstance(value, (np.integer,)):
        return int(value)
    if isinstance(value, (np.floating,)):
        return float(value)
    if isinstance(value, np.ndarray):
        return value.tolist()
    return value


def metrics_at(y: np.ndarray, p: np.ndarray, threshold: float) -> Dict:
    yhat = (p >= threshold).astype(np.int8)
    tn, fp, fn, tp = confusion_matrix(y, yhat, labels=[0, 1]).ravel()
    out = {
        "threshold": round(float(threshold), 4),
        "accuracy": float(accuracy_score(y, yhat)),
        "precision": float(precision_score(y, yhat, zero_division=0)),
        "recall": float(recall_score(y, yhat, zero_division=0)),
        "f1": float(f1_score(y, yhat, zero_division=0)),
        "specificity": float(tn / max(tn + fp, 1)),
        "false_positive_rate": float(fp / max(fp + tn, 1)),
        "false_negative_rate": float(fn / max(fn + tp, 1)),
        "mcc": float(matthews_corrcoef(y, yhat)),
        "confusion_matrix": {"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)},
    }
    return out


def ranking_metrics(y: np.ndarray, p: np.ndarray) -> Dict:
    out = {
        "roc_auc": float(roc_auc_score(y, p)),
        "average_precision": float(average_precision_score(y, p)),
        "brier": float(brier_score_loss(y, p)),
    }
    return out


def choose_operating_points(y: np.ndarray, p: np.ndarray) -> Dict:
    """Pick thresholds for a balanced and a conservative deployment."""
    qs = np.unique(np.quantile(p, np.linspace(0.002, 0.999, 400)))
    rows = []
    for t in qs:
        row = metrics_at(y, p, float(t))
        rows.append(row)
    frame = pd.DataFrame(rows)

    balanced = frame.loc[frame["f1"].idxmax()]
    hp_candidates = frame[frame["precision"] >= 0.99]
    if len(hp_candidates):
        high_precision = hp_candidates.loc[hp_candidates["recall"].idxmax()]
    else:
        high_precision = frame.loc[frame["precision"].idxmax()]
    hr_candidates = frame[frame["recall"] >= 0.97]
    if len(hr_candidates):
        high_recall = hr_candidates.loc[hr_candidates["precision"].idxmax()]
    else:
        high_recall = balanced
    sus_candidates = frame[frame["precision"] >= 0.90]
    if len(sus_candidates):
        suspicious = sus_candidates.loc[sus_candidates["recall"].idxmax()]
    else:
        suspicious = balanced

    malicious_t = max(float(balanced["threshold"]), float(high_precision["threshold"]))
    # Keep a meaningful warning band even when the model is extremely
    # confident (otherwise "suspicious" collapses to a near-zero score).
    suspicious_t = max(0.05, min(0.40, malicious_t * 0.5))
    suspicious_t = min(suspicious_t, max(0.01, malicious_t - 0.03))

    def clean(row) -> Dict:
        keys = ["threshold", "accuracy", "precision", "recall", "f1",
                "false_positive_rate", "false_negative_rate"]
        return {k: float(row[k]) for k in keys}

    return {
        "malicious": malicious_t,
        "suspicious": suspicious_t,
        "balanced": clean(balanced),
        "high_precision": clean(high_precision),
        "high_recall": clean(high_recall),
        "suspicious_operating": clean(suspicious),
    }


def choose_blend_weights(y: np.ndarray, probs: np.ndarray, step: float = 0.05) -> Tuple[np.ndarray, float]:
    best_w = np.array([1 / 3, 1 / 3, 1 / 3])
    best_ap = -1.0
    grid = np.arange(0.0, 1.0001, step)
    for w1 in grid:
        for w2 in grid:
            if w1 + w2 > 1.0001:
                continue
            w3 = 1.0 - w1 - w2
            blended = probs @ np.array([w1, w2, w3])
            ap = average_precision_score(y, blended)
            if ap > best_ap:
                best_ap = ap
                best_w = np.array([w1, w2, w3])
    return best_w, float(best_ap)


def _fit_linear(kind: str, X, y, sample_weight=None):
    if kind == "sgd":
        model = SGDClassifier(
            loss="log_loss", alpha=1e-6, max_iter=50, tol=1e-4,
            class_weight="balanced", random_state=SEED, n_jobs=-1,
        )
    else:
        model = LogisticRegression(
            C=4.0, solver="liblinear", max_iter=300, tol=1e-4,
            class_weight="balanced", random_state=SEED,
        )
    model.fit(X, y, sample_weight=sample_weight)
    return model


# ---------------------------------------------------------------------------
# Plots
# ---------------------------------------------------------------------------

def make_plots(y: np.ndarray, p: np.ndarray, thresholds: Dict, metrics: Dict,
               external_y: Optional[np.ndarray] = None,
               external_p: Optional[np.ndarray] = None) -> None:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    REPORTS_DIR.mkdir(parents=True, exist_ok=True)

    # ROC
    fpr, tpr, _ = roc_curve(y, p)
    plt.figure(figsize=(6, 5))
    plt.plot(fpr, tpr, label=f"Test (AUC={roc_auc_score(y, p):.4f})")
    if external_y is not None and len(np.unique(external_y)) == 2:
        efpr, etpr, _ = roc_curve(external_y, external_p)
        plt.plot(efpr, etpr, label=f"External (AUC={roc_auc_score(external_y, external_p):.4f})")
    plt.plot([0, 1], [0, 1], "--", color="gray", linewidth=0.8)
    plt.xlabel("False positive rate")
    plt.ylabel("True positive rate")
    plt.title("QR Shield - ROC")
    plt.legend(loc="lower right")
    plt.tight_layout()
    plt.savefig(REPORTS_DIR / "roc_curve.png", dpi=140)
    plt.close()

    # Precision-recall
    prec, rec, _ = precision_recall_curve(y, p)
    plt.figure(figsize=(6, 5))
    plt.plot(rec, prec, label=f"Test (AP={average_precision_score(y, p):.4f})")
    if external_y is not None and len(np.unique(external_y)) == 2:
        eprec, erec, _ = precision_recall_curve(external_y, external_p)
        plt.plot(erec, eprec, label=f"External (AP={average_precision_score(external_y, external_p):.4f})")
    plt.xlabel("Recall")
    plt.ylabel("Precision")
    plt.title("QR Shield - Precision/Recall")
    plt.legend(loc="lower left")
    plt.tight_layout()
    plt.savefig(REPORTS_DIR / "precision_recall.png", dpi=140)
    plt.close()

    # Score distribution
    plt.figure(figsize=(7, 4))
    bins = np.linspace(0, 1, 60)
    plt.hist(p[y == 0], bins=bins, alpha=0.6, label="Benign", color="#2e7d32")
    plt.hist(p[y == 1], bins=bins, alpha=0.6, label="Phishing", color="#c62828")
    plt.axvline(thresholds["suspicious"], color="#f57c00", linestyle="--", label="Suspicious")
    plt.axvline(thresholds["malicious"], color="#b71c1c", linestyle="--", label="Malicious")
    plt.xlabel("Phishing probability")
    plt.ylabel("Count")
    plt.title("Score distribution (test set)")
    plt.legend()
    plt.tight_layout()
    plt.savefig(REPORTS_DIR / "score_distribution.png", dpi=140)
    plt.close()

    # Confusion matrix at malicious threshold
    cm = metrics["test_at_malicious"]["confusion_matrix"]
    matrix = np.array([[cm["tn"], cm["fp"]], [cm["fn"], cm["tp"]]])
    plt.figure(figsize=(4.6, 4))
    plt.imshow(matrix, cmap="Blues")
    for i in range(2):
        for j in range(2):
            plt.text(j, i, f"{matrix[i, j]:,}", ha="center", va="center",
                     color="white" if matrix[i, j] > matrix.max() / 2 else "black")
    plt.xticks([0, 1], ["Benign", "Phishing"])
    plt.yticks([0, 1], ["Benign", "Phishing"])
    plt.xlabel("Predicted")
    plt.ylabel("Actual")
    plt.title("Test set confusion matrix")
    plt.tight_layout()
    plt.savefig(REPORTS_DIR / "confusion_matrix.png", dpi=140)
    plt.close()


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(description="Train the QR Shield URL model")
    parser.add_argument("--linear", choices=["logreg", "sgd"], default="logreg")
    parser.add_argument("--n-jobs", type=int, default=8)
    parser.add_argument("--sample", type=int, default=0,
                        help="Use only N training rows (0 = all)")
    parser.add_argument("--no-cache", action="store_true")
    parser.add_argument("--max-char-features", type=int, default=200_000)
    parser.add_argument("--max-word-features", type=int, default=60_000)
    parser.add_argument("--quick", action="store_true",
                        help="Small models for smoke testing")
    args = parser.parse_args()

    ARTIFACTS_DIR.mkdir(parents=True, exist_ok=True)
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)

    if not DATASET_PATH.exists():
        raise FileNotFoundError(
            f"{DATASET_PATH} not found. Run: python scripts/prepare_data.py"
        )
    dataset = joblib.load(DATASET_PATH)
    splits = {name: dataset[name] for name in ("train", "val", "test", "external")}
    if args.sample and args.sample < len(splits["train"]):
        splits["train"] = splits["train"].sample(args.sample, random_state=SEED)
        splits["val"] = splits["val"].sample(
            min(len(splits["val"]), max(10_000, args.sample // 4)), random_state=SEED)
        print(f"Sampled training set: {len(splits['train']):,} rows")

    print("\nExtracting numeric features ...")
    numeric = numeric_features(splits, n_jobs=args.n_jobs, use_cache=not args.no_cache)

    print("\nFitting TF-IDF vectorizers ...")
    train_texts = [text_for_model(u) for u in splits["train"]["url"]]
    val_texts = [text_for_model(u) for u in splits["val"]["url"]]
    test_texts = [text_for_model(u) for u in splits["test"]["url"]]
    ext_texts = [text_for_model(u) for u in splits["external"]["url"]]

    t = time.time()
    char_vec = TfidfVectorizer(
        analyzer="char_wb", ngram_range=(2, 5), min_df=4,
        max_features=args.max_char_features, sublinear_tf=True,
        lowercase=True, dtype=np.float32,
    )
    Xc_train = char_vec.fit_transform(train_texts)
    Xc_val = char_vec.transform(val_texts)
    Xc_test = char_vec.transform(test_texts)
    Xc_ext = char_vec.transform(ext_texts)
    print(f"  char TF-IDF: {Xc_train.shape}, nnz={Xc_train.nnz:,} ({time.time() - t:.1f}s)")

    t = time.time()
    word_vec = TfidfVectorizer(
        analyzer="word", token_pattern=r"[a-zA-Z0-9_]+", ngram_range=(1, 2),
        min_df=5, max_features=args.max_word_features, sublinear_tf=True,
        lowercase=True, dtype=np.float32,
    )
    Xw_train = word_vec.fit_transform(train_texts)
    Xw_val = word_vec.transform(val_texts)
    Xw_test = word_vec.transform(test_texts)
    Xw_ext = word_vec.transform(ext_texts)
    print(f"  word TF-IDF: {Xw_train.shape}, nnz={Xw_train.nnz:,} ({time.time() - t:.1f}s)")

    scaler = MaxAbsScaler()
    N_train = scaler.fit_transform(numeric["train"])
    N_val = scaler.transform(numeric["val"])
    N_test = scaler.transform(numeric["test"])
    N_ext = scaler.transform(numeric["external"])

    X_train = hstack([N_train, Xc_train, Xw_train], format="csr")
    X_val = hstack([N_val, Xc_val, Xw_val], format="csr")
    X_test = hstack([N_test, Xc_test, Xw_test], format="csr")
    X_ext = hstack([N_ext, Xc_ext, Xw_ext], format="csr")

    y_train = splits["train"]["label"].values.astype(np.int8)
    y_val = splits["val"]["label"].values.astype(np.int8)
    y_test = splits["test"]["label"].values.astype(np.int8)
    y_ext = splits["external"]["label"].values.astype(np.int8)

    sample_weight = np.ones(len(y_train), dtype=np.float32)
    if "source" in splits["train"].columns:
        official = (splits["train"]["source"] == "brand_official").values
        sample_weight[official] = 20.0
        print(f"Weighting {int(official.sum()):,} official-brand benign pages by 20x")

    print("\nTraining models ...")
    if args.quick:
        gbm_params = dict(max_iter=80, learning_rate=0.1, max_leaf_nodes=31)
        et_params = dict(n_estimators=80)
        linear_kind = "sgd"
    else:
        gbm_params = dict(
            max_iter=500, learning_rate=0.07, max_leaf_nodes=63,
            min_samples_leaf=40, l2_regularization=1.0,
            early_stopping=True, validation_fraction=0.1,
            n_iter_no_change=30,
        )
        et_params = dict(n_estimators=400, min_samples_leaf=3, max_features="sqrt")
        linear_kind = args.linear

    t = time.time()
    linear = _fit_linear(linear_kind, X_train, y_train, sample_weight=sample_weight)
    print(f"  linear ({linear_kind}): {time.time() - t:.1f}s")

    t = time.time()
    gbm = HistGradientBoostingClassifier(
        random_state=SEED, class_weight="balanced", **gbm_params
    )
    gbm.fit(numeric["train"], y_train, sample_weight=sample_weight)
    print(f"  gradient boosting: {time.time() - t:.1f}s "
          f"({getattr(gbm, 'n_iter_', '?')} iters)")

    t = time.time()
    et = ExtraTreesClassifier(
        random_state=SEED, n_jobs=args.n_jobs,
        class_weight="balanced_subsample", **et_params
    )
    et.fit(numeric["train"], y_train, sample_weight=sample_weight)
    print(f"  extra trees: {time.time() - t:.1f}s")

    print("\nBlending on validation set ...")
    val_probs = np.column_stack([
        linear.predict_proba(X_val)[:, 1],
        gbm.predict_proba(numeric["val"])[:, 1],
        et.predict_proba(numeric["val"])[:, 1],
    ])
    weights, val_ap = choose_blend_weights(y_val, val_probs)
    print(f"  weights (linear/gbm/et): {np.round(weights, 3)}  val AP={val_ap:.5f}")

    blended_val = val_probs @ weights
    print("Calibrating probabilities ...")
    eps = 1e-6
    clipped = np.clip(blended_val, eps, 1 - eps)
    logits = np.log(clipped / (1 - clipped)).reshape(-1, 1)
    from sklearn.linear_model import LogisticRegression as _Platt
    calibrator = _Platt(C=1e6, solver="lbfgs", max_iter=1000)
    calibrator.fit(logits, y_val)
    cal_val = calibrator.predict_proba(logits)[:, 1]
    # Guard against a degenerate calibrator.
    if len(np.unique(np.round(cal_val, 6))) < 25:
        print("  calibrator collapsed; keeping uncalibrated blend")
        calibrator = None
        cal_val = blended_val

    operating = choose_operating_points(y_val, cal_val)
    malicious_t = operating["malicious"]
    suspicious_t = operating["suspicious"]
    print(f"  thresholds: suspicious={suspicious_t:.3f}, malicious={malicious_t:.3f}")

    def blend_predict(X, N):
        p = np.column_stack([
            linear.predict_proba(X)[:, 1],
            gbm.predict_proba(N)[:, 1],
            et.predict_proba(N)[:, 1],
        ]) @ weights
        if calibrator is not None:
            if hasattr(calibrator, "predict_proba"):
                e = 1e-6
                cl = np.clip(p, e, 1 - e)
                lg = np.log(cl / (1 - cl)).reshape(-1, 1)
                p = calibrator.predict_proba(lg)[:, 1]
            else:
                p = calibrator.predict(p)
        return np.clip(p, 0, 1)

    print("\nEvaluating ...")
    test_p = blend_predict(X_test, numeric["test"])
    ext_p = blend_predict(X_ext, numeric["external"])

    test_metrics = {
        "ranking": ranking_metrics(y_test, test_p),
        "test_at_05": metrics_at(y_test, test_p, 0.5),
        "test_at_malicious": metrics_at(y_test, test_p, malicious_t),
        "test_at_suspicious": metrics_at(y_test, test_p, suspicious_t),
    }
    ext_metrics = {
        "ranking": ranking_metrics(y_ext, ext_p),
        "at_malicious": metrics_at(y_ext, ext_p, malicious_t),
        "at_suspicious": metrics_at(y_ext, ext_p, suspicious_t),
    }
    ext_metrics["by_source"] = {}
    ext_df = splits["external"]
    for source in sorted(ext_df["source"].unique()):
        mask = (ext_df["source"] == source).values
        ys, ps = y_ext[mask], ext_p[mask]
        if len(ys) == 0:
            continue
        ext_metrics["by_source"][source] = {
            "count": int(len(ys)),
            "phishing_share": float(ys.mean()),
            "at_malicious": {
                "flag_rate": float((ps >= malicious_t).mean()),
                "mean_probability": float(ps.mean()),
            },
            "at_suspicious": {
                "flag_rate": float((ps >= suspicious_t).mean()),
                "mean_probability": float(ps.mean()),
            },
        }
        if len(np.unique(ys)) == 2:
            ext_metrics["by_source"][source]["ranking"] = ranking_metrics(ys, ps)

    val_p = blend_predict(X_val, numeric["val"])
    validation_metrics = {
        "ranking": ranking_metrics(y_val, val_p),
        "at_malicious": metrics_at(y_val, val_p, malicious_t),
        "at_suspicious": metrics_at(y_val, val_p, suspicious_t),
    }

    metrics = {
        "validation": validation_metrics,
        "test": test_metrics,
        "external": ext_metrics,
        "operating_points": operating,
        "weights": {
            "linear": float(weights[0]),
            "gradient_boosting": float(weights[1]),
            "extra_trees": float(weights[2]),
        },
        "thresholds": {"suspicious": suspicious_t, "malicious": malicious_t},
        "counts": dataset["meta"]["counts"],
    }

    print("\nTest @ malicious threshold:")
    m = test_metrics["test_at_malicious"]
    print(f"  accuracy={m['accuracy']:.4f} precision={m['precision']:.4f} "
          f"recall={m['recall']:.4f} f1={m['f1']:.4f} fpr={m['false_positive_rate']:.4f}")
    print("External @ malicious threshold:")
    m = ext_metrics["at_malicious"]
    print(f"  accuracy={m['accuracy']:.4f} precision={m['precision']:.4f} "
          f"recall={m['recall']:.4f} f1={m['f1']:.4f} fpr={m['false_positive_rate']:.4f}")

    print("\nSaving reports ...")
    METRICS_PATH.write_text(json.dumps(_jsonable(metrics), indent=2), encoding="utf-8")
    make_plots(y_test, test_p, metrics["thresholds"], test_metrics, y_ext, ext_p)

    # Error analysis
    test_df = splits["test"].copy()
    test_df["probability"] = test_p
    test_df["prediction"] = (test_p >= malicious_t).astype(int)
    errors = test_df[test_df["label"] != test_df["prediction"]].copy()
    errors["margin"] = np.abs(errors["probability"] - malicious_t)
    errors = errors.sort_values("margin", ascending=False)
    errors.to_csv(REPORTS_DIR / "misclassified.csv", index=False)

    print("Saving model artifact ...")
    # ExtraTrees is large (~90 MB) and sometimes receives zero blend weight.
    # Keep it only when it actually contributes to the ensemble.
    et_saved = et
    if float(weights[2]) < 0.005:
        et_saved = None
        weights = np.array([weights[0], weights[1], 0.0])
        metrics["weights"]["extra_trees"] = 0.0
        print("  ExtraTrees contributed no weight; omitting it from the artifact")
    metadata = {
        "version": "1.0.0",
        "trained_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "train_size": int(len(splits["train"])),
        "val_size": int(len(splits["val"])),
        "test_size": int(len(splits["test"])),
        "external_size": int(len(splits["external"])),
        "n_features": len(FEATURE_NAMES),
        "weights": metrics["weights"],
        "linear_kind": linear_kind,
        "char_features": int(Xc_train.shape[1]),
        "word_features": int(Xw_train.shape[1]),
        "sklearn_version": sklearn.__version__,
        "python_version": platform.python_version(),
        "platform": platform.platform(),
        "dataset_sources": dataset["meta"].get("sources", {}),
    }
    artifact = {
        "version": "1.0.0",
        "feature_names": FEATURE_NAMES,
        "char_vectorizer": char_vec,
        "word_vectorizer": word_vec,
        "numeric_scaler": scaler,
        "linear_model": linear,
        "gbm_model": gbm,
        "et_model": et_saved,
        "weights": weights,
        "calibrator": calibrator,
        "linear_numeric_dim": len(FEATURE_NAMES),
        "thresholds": {"suspicious": suspicious_t, "malicious": malicious_t},
        "operating_points": operating,
        "metadata": metadata,
        "metrics": metrics,
    }
    joblib.dump(artifact, MODEL_PATH, compress=3)
    print(f"Model saved -> {MODEL_PATH} ({MODEL_PATH.stat().st_size / 1e6:.1f} MB)")
    print(f"Metrics -> {METRICS_PATH}")
    print(f"Reports -> {REPORTS_DIR}")


if __name__ == "__main__":
    main()
