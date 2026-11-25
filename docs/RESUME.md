# Resume & Interview Kit

Copy-paste material for applications, portfolio pages, and interviews. Every
number here is reproducible from the repository.

## One-line pitch

**QR Shield** — a local-first quishing detector that decodes QR images, scores
the destination with a calibrated ML ensemble plus explainable rules, and ships
with a CLI, web dashboard, scan history, tests, CI, and Docker.

## Resume bullets

Pick 3–5; keep the numbers.

- Built an end-to-end QR phishing (quishing) detector in Python that decodes
  QR images under blur, rotation, perspective, glare, and JPEG artifacts
  (11/11 distortion benchmark), then classifies the payload before anything is
  opened.
- Trained a calibrated ensemble of character/word TF-IDF logistic regression
  and histogram gradient-boosted trees over 78 URL features, reaching **0.984
  F1 / 0.36% FPR** on a domain-disjoint test set and **0.977 F1** on a temporal
  external holdout of 37.6k URLs.
- Designed a **domain-grouped splitting pipeline** over 688k URLs from PhiUSIIL,
  Phishing Army, and Tranco; added a split-integrity test and a scheduled
  data-integrity workflow that fail if any host leaks across
  train/validation/test.
- Implemented an explainability layer that surfaces rule-level reasons, model
  attention tokens, and numeric feature contributions, so every verdict is
  auditable rather than a black-box score.
- Built a FastAPI service and a one-step vanilla-JS interface: paste, drop, or
  camera scanning, batch results, live statistics, 7-day trends, and searchable
  SQLite history shared between the CLI, web UI, and a Manifest V3 browser
  extension.
- Added a `qrshield` CLI (`url`, `scan`, `batch`, `history`, `info`, `serve`)
  with JSON/CSV reports and meaningful exit codes for scripting and pre-open
  hooks.
- Containerized the app with a non-root Docker image and healthcheck; added
  GitHub Actions CI across Python 3.9–3.12 with ruff, pytest, coverage, and
  wheel/sdist builds.
- Kept scanning fully local: no URL fetching, no telemetry, bounded uploads,
  parameterised SQL, escaped output, and opt-out history for privacy.

## Project summary (portfolio page)

> QR codes hide their destination, which makes them ideal for phishing. QR
> Shield decodes the image locally, identifies what the payload actually is
> (URL, Wi-Fi join, UPI payment, `javascript:` scheme, nested redirect), and
> scores it with a calibrated ML model plus auditable rules. It never opens or
> fetches the link. The result is a verdict, a probability, and a plain-English
> explanation, available through a CLI, a JSON API, a one-step web interface,
> local scan history, and a Manifest V3 browser extension.

## STAR stories

### 1. Fixing inflated accuracy with grouped splits

**Situation:** Initial random train/test splits reported near-perfect accuracy,
but manual checks flagged obvious false positives.

**Task:** Make evaluation reflect unseen domains.

**Action:** Grouped URLs by registrable domain before splitting, rebuilt the
pipeline, added `tests/test_split_integrity.py`, and re-trained. Also added
official brand pages with 20× sample weight so legitimate login pages stopped
being penalised for containing a brand name.

**Result:** Honest test F1 of 0.984 and external F1 of 0.977; the integrity test
and scheduled data-integrity job now catch future leakage.

### 2. Making QR decoding survive phone photos

**Situation:** A single OpenCV `detectAndDecode` pass failed on rotated, blurry,
and low-contrast images.

**Task:** Improve real-world decode rate without a heavy ML dependency.

**Action:** Built a multi-variant decoder: upscaling, CLAHE, adaptive/Otsu
thresholding, sharpening, inversion, rotations, multi-code masking, and
overlapping tiles. Added ZXing-C++ as a second engine and an optional WeChat
detector hook. Wrote a benchmark that applies 11 distortions and measures
per-method timing.

**Result:** 11/11 distortions decoded, 0.26 s mean, and two codes found in a
single frame.

### 3. Explaining model decisions

**Situation:** A probability alone is not actionable for a user deciding
whether to open a link.

**Task:** Turn the ensemble into something a non-ML user can trust.

**Action:** Combined the model score with severity-weighted rules, exposed the
linear model's top character/word n-grams, computed standardized numeric
feature contributions, and rendered all of it in the UI as a ranked breakdown.

**Result:** Every verdict now answers "why?", and the rule layer catches
brand-impersonation patterns that the model alone scored as borderline.

### 4. Shipping it like a product

**Situation:** The core detector worked, but it was a script with no repeatable
workflow.

**Task:** Make it installable, testable, and deployable.

**Action:** Added `pyproject.toml` with a console entry point, pinned
requirements, 59 tests (features, scanner, decoder, model, API, CLI, history,
split integrity), ruff linting, coverage, GitHub Actions across four Python
versions, a non-root Dockerfile with healthcheck, docker-compose, Makefile, a
Manifest V3 extension, and full documentation (README, model card,
architecture, evaluation, security).

**Result:** `pip install .` exposes `qrshield`; `docker compose up` runs the
app; CI catches lint, test, and packaging regressions.

## Numbers to remember

| Claim | Value |
|---|---|
| Dataset size | 688,099 URLs |
| Features | 78 numeric + char/word n-grams |
| Test F1 / FPR | 0.9843 / 0.36% |
| External F1 / FPR | 0.9773 / 0.48% |
| OpenPhish flag rate | 92.9% |
| ROC-AUC | 0.9995 test, 0.9994 external |
| Model size / load | 4.54 MB / 1.82 s |
| Inference latency | 3.96 ms mean, 5.67 ms p95 |
| Batch throughput | ~5,350 URLs/s |
| QR decode benchmark | 11/11, 0.26 s mean |
| Tests | 59 passing |

## Likely interview questions

**"Why not just use a URL reputation API?"**
It leaks the scanned URL to a third party, fails offline, and gives no
explanation. Local inference is private, fast, and auditable. A reputation API
would be a good *additional* signal, not a replacement.

**"How did you avoid overfitting?"**
Domain-grouped splits, a separate validation set for blend weights,
calibration, and thresholds, a temporal external holdout, and an error report
that ships every misclassification for inspection. The split-integrity test
prevents accidental leakage.

**"Why an ensemble instead of one model?"**
Character n-grams capture obfuscation, numeric features capture structure, and
trees capture interactions. The blend weights are chosen on validation average
precision, and Extra Trees is dropped when it earns no weight — smaller artifact,
same decisions.

**"How do you handle false positives?"**
The shipped malicious threshold is the high-precision operating point (0.36%
FPR). Borderline scores become `suspicious`, not `malicious`, and the UI shows
the reasons so a user can judge. All test false positives were benign root
domains on cheap TLDs, which is a known limitation of URL-only features.

**"What would you do with more time?"**
Add DNS/certificate age and redirect-chain signals as optional enrichment,
introduce a confidence penalty for bare root domains, evaluate on a
brand-specific holdout, and add active-learning feedback from user-reported
false positives.

**"What was the hardest bug?"**
Bare-domain parsing: `http://1975.canadawaterfilters.ca#example@example.com`
contains `@`, which naive host splitting treats as userinfo, producing a bogus
host and a false split-integrity failure. Fixed by using `urlsplit().hostname`
and adding a regression test.

## Demo script (2 minutes)

1. `python -m qrshield url "https://www.paypal.com/signin"` → safe, official
   brand recognized.
2. `python -m qrshield url "http://paypal.com.secure-login.xyz/verify"` →
   malicious, with impersonation reasons.
3. Open the web app, drop `artifacts/demo_qr.png` anywhere on the page → the
   scan starts automatically with decoded payload, verdict, and risk breakdown.
4. Drop several images at once → per-file results and a worst-case summary.
5. Show the dashboard: today's scans, 7-day chart, top triggers, searchable
   history.
6. Open the extension popup and scan the same link; right-click a QR image on a
   page to show the context-menu flow.
7. `python -m qrshield batch samples/ --csv report.csv --fail-on malicious` →
   exit code 1 for CI/pre-open hooks.
