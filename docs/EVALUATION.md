# Evaluation

This document explains how the model is evaluated, what the numbers mean, and
where it fails. Raw metrics are in [`artifacts/metrics.json`](../artifacts/metrics.json);
plots and the error report are in [`artifacts/reports/`](../artifacts/reports/).

## Methodology

### Splits

All URLs are grouped by **registrable domain** before splitting. A domain and
all of its subdomains land in exactly one split, so test performance reflects
unseen domains rather than memorised hosts.

| Split | Rows | Phishing share | Purpose |
|---|---|---|---|
| Train | 525,823 | 35.7% | fit vectorizers, linear model, GBM |
| Validation | 62,003 | 31.9% | blend weights, calibration, thresholds |
| Test | 62,673 | 32.7% | held-out evaluation |
| External | 37,600 | 27.1% | later feeds + unseen Tranco domains |

The external split is deliberately different: it contains Phishing Army domains
and OpenPhish entries collected after the training snapshot, plus Tranco
domains that were excluded from training. This tests temporal and distribution
shift, not just held-out rows.

`tests/test_split_integrity.py` asserts that no host or registrable domain
appears in two splits. It runs locally against the built dataset and in the
scheduled **Data integrity** workflow, which rebuilds the splits from the
public feeds; a data-pipeline regression that leaks domains fails that job.

### Metrics

- **ROC-AUC** and **average precision** measure ranking quality, independent of
  a threshold.
- **Precision / recall / F1** are reported at the shipped thresholds and at 0.5.
- **False positive rate** is the share of benign URLs flagged malicious; it is
  the metric users feel most directly.
- **Brier score** measures calibration: lower is better, and it penalises
  confident mistakes.

### Operating points

Thresholds are chosen on validation data, never test:

| Operating point | Threshold | Precision | Recall | FPR |
|---|---|---|---|---|
| Balanced (best F1) | 0.5077 | 0.9859 | 0.9843 | 0.0066 |
| High precision (shipped `malicious`) | 0.6627 | 0.9924 | 0.9752 | 0.0035 |
| High recall | 0.7437 | 0.9954 | 0.9704 | 0.0021 |

The shipped `malicious` threshold is the high-precision point. The `suspicious`
threshold (`0.33135`) is set below it so that the combined `suspicious +
malicious` band catches more than 99% of validation phishing while keeping the
hard-flag rate low.

## Results

### Test split

| Metric | At `malicious` (0.6627) | At 0.5 | At `suspicious` (0.3313) |
|---|---|---|---|
| Accuracy | 0.9898 | 0.9904 | 0.9895 |
| Precision | 0.9926 | 0.9854 | 0.9757 |
| Recall | 0.9761 | 0.9853 | 0.9925 |
| F1 | 0.9843 | 0.9854 | 0.9840 |
| Specificity | 0.9964 | 0.9929 | 0.9880 |
| False positive rate | 0.0036 | 0.0071 | 0.0120 |
| MCC | 0.9768 | 0.9782 | 0.9763 |

Confusion matrix at `malicious`: TN 42,037 · FP 150 · FN 489 · TP 19,997.

Ranking: ROC-AUC 0.99947, average precision 0.99907, Brier 0.0067.

### External holdout

| Metric | At `malicious` | At `suspicious` |
|---|---|---|
| Accuracy | 0.9878 | 0.9842 |
| Precision | 0.9869 | 0.9515 |
| Recall | 0.9678 | 0.9922 |
| F1 | 0.9773 | 0.9715 |
| False positive rate | 0.0048 | 0.0188 |

Ranking: ROC-AUC 0.99944, average precision 0.99851, Brier 0.0086.

By source:

| Source | Rows | Flag rate at `malicious` | Mean probability |
|---|---|---|---|
| Phishing Army (phishing) | 10,123 | 96.8% | 0.971 |
| OpenPhish (phishing) | 70 | 92.9% | 0.939 |
| Tranco holdout (benign) | 27,407 | 0.48% | 0.014 |

The drop from test to external (F1 0.984 → 0.977, FPR 0.36% → 0.48%) is the
honest cost of temporal drift. It is small, but it is why the project ships a
retraining script rather than a frozen model.

### Calibration

The Brier score is 0.0067 on test and 0.0086 on external. Reliability is good in
the tails (most predictions are near 0 or 1); the middle of the distribution is
slightly overconfident, which is expected for tree ensembles. The Platt
calibrator fitted on validation reduces this compared with the raw blend.

## QR decoding benchmark

`scripts/benchmark_qr.py` generates QR images and applies realistic phone-photo
distortions. Results on the current decoder:

| Distortion | Decoded | Method | Time |
|---|---|---|---|
| clean | yes | opencv_single | 0.42 s |
| gaussian blur | yes | opencv_multi | 0.51 s |
| motion blur | yes | opencv_single | 0.66 s |
| low contrast | yes | opencv_single | 0.49 s |
| dark | yes | opencv_single | 0.70 s |
| rotated 90° | yes | opencv_single | 0.77 s |
| small (160 px) | yes | opencv_single | 0.23 s |
| perspective | yes | opencv_multi | 0.84 s |
| JPEG q30 | yes | opencv_single | 0.76 s |
| sensor noise | yes | opencv_single | 0.95 s |
| glare gradient | yes | opencv_multi | 0.80 s |

Decode rate: **11/11**, mean 0.65 s. A frame with two codes decoded both in
2.66 s. The multi-variant strategy is slower than a single OpenCV pass but
handles the distortions real users produce.

## Latency

From `scripts/model_benchmark.py` (400 URLs, Windows 10, Python 3.9):

| Operation | Mean | p95 |
|---|---|---|
| Single URL inference | 3.96 ms | 5.67 ms |
| Full `scan_url` (model + rules) | 5.73 ms | 6.91 ms |
| Batch inference | 5,354 URLs/s | — |

Model load is 1.82 s and the artifact is 4.54 MB. QR decoding dominates
end-to-end latency; inference is not the bottleneck.

## Error analysis

All 639 test errors were inspected (`artifacts/reports/misclassified.csv`).

### False negatives (489)

**479 of 489 are bare root domains with no path**, e.g. `https://www.in.mt`,
`https://www.oivac.com`, `https://www.church4.in`. These are PhiUSIIL rows
labelled phishing but consisting only of a domain name. URL text alone carries
almost no signal: no suspicious path, no brand token, no redirect. Many are
likely dead or parked domains whose label no longer reflects their content.

This is a fundamental limit of static URL-only detection. The fix is not a
better classifier; it is more signal (DNS age, certificate history, page
content) or cleaner labels.

### False positives (150)

**All 150 are bare root domains on abused TLDs**: `.cyou`, `.site`, `.info`,
`.top`, `.pro`, `.click`, `.store`. Examples: `shrikesanopias.cyou`,
`rpki-measurement.site`, `secure-mobiles.com`. These are Tranco-popular benign
domains that look structurally like phishing domains.

The model is behaving as trained: random-looking names on cheap TLDs are
statistically associated with phishing. Lowering the false-positive rate here
would require reputation or popularity features, which the local-first design
intentionally avoids.

### What this means

- On URLs with paths and query strings — the realistic QR payload — performance
  is better than the aggregate numbers suggest.
- Bare-domain scans should be treated as lower-confidence. The UI shows the
  score and reasons, and users can verify before opening.
- Label noise in public datasets is real; the error report is shipped so the
  numbers can be audited rather than taken on faith.

## Reproducing

```powershell
python scripts/download_data.py
python scripts/prepare_data.py
python scripts/train_model.py --n-jobs 8
python scripts/model_benchmark.py
python scripts/benchmark_qr.py
python -m pytest -q
```

Training is deterministic given the same raw data and seed. The split integrity
test guards against accidental domain leakage. To compare a new model, run
`model_benchmark.py` on the same machine and diff the JSON reports.
