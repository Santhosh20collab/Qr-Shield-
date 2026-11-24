# Model Card — QR Shield URL Classifier

## Model details

| Field | Value |
|---|---|
| Name | QR Shield URL classifier (`qrshield_model.joblib`) |
| Version | 1.0.0 |
| Type | Calibrated ensemble: char/word TF-IDF linear model + histogram gradient-boosted trees |
| Task | Binary classification of URL text as phishing (1) or benign (0) |
| Input | A single URL string, parsed as text only — never fetched |
| Output | Probability in `[0, 1]`, mapped to `safe` / `suspicious` / `malicious` |
| Size | 4.54 MB |
| Runtime | CPU only; ~4 ms per URL, ~5,350 URLs/s in batch |
| License | MIT |

### Architecture

```
URL ──┬─► char 3–5 gram TF-IDF ─┐
      ├─► word 1–2 gram TF-IDF ─┼─► LogisticRegression (C=4.0) ─┐
      └─► 78 numeric features ──┴─► StandardScaler ─────────────┤
                                                                 ├─► weighted blend ─► Platt calibration ─► probability
          78 numeric features ─────► HistGradientBoosting ───────┘
```

The blend weights are chosen on the validation split by maximizing average
precision over a simplex grid. The final blend is calibrated with a logistic
(Platt) calibrator fitted on validation scores, so the output behaves like a
probability rather than an arbitrary score.

Extra Trees is trained during experiments but dropped from the shipped artifact
when it receives no blend weight; this keeps the artifact small without
changing decisions.

## Intended use

**Use it for:**

- Warning users before they open a QR code or link.
- Triaging reported URLs in a SOC / helpdesk workflow.
- Pre-screening links in email, chat, or ticketing pipelines.
- Teaching and portfolio demonstrations of applied ML for security.

**Do not use it as:**

- The only control protecting a production network.
- A guarantee that a URL is safe — static URL text cannot see page content,
  JavaScript, redirect chains, or post-login behaviour.
- A reputation service for domains that did not exist when the model was
  trained.

## Training data

| Source | Role | Rows used |
|---|---|---|
| [PhiUSIIL](https://archive.ics.uci.edu/dataset/967/phiusiil+phishing+url+dataset) | labelled phishing / benign URLs | 231,493 |
| [Phishing Army](https://phishing.army/) | fresh phishing domains, campaign paths | 141,256 |
| [Tranco](https://tranco-list.eu/) | popular benign domains and paths | 297,288 |
| Official brand pages | benign login/checkout pages for 100+ brands | 17,992 |
| [OpenPhish](https://openphish.com/) | external-only live feed | 70 |

Split sizes after deduplication and grouping:

| Split | Rows | Purpose |
|---|---|---|
| Train | 525,823 | model fitting |
| Validation | 62,003 | blend weights, calibration, thresholds |
| Test | 62,673 | held-out evaluation |
| External | 37,600 | later live feeds + unseen Tranco domains |

Splits are **grouped by registrable domain** before assignment, so no host or
registrable domain appears in more than one split. This is verified in
`tests/test_split_integrity.py`. Without grouping, near-duplicate URLs inflate
accuracy by several points and hide real-world failure modes.

Benign Tranco domains are augmented with realistic paths, query strings, and
`https://www.` prefixes; phishing domains are augmented with mixed schemes and
campaign-style paths. Official brand pages are up-weighted 20× so the model
learns that `paypal.com/signin` is not phishing merely because it contains a
brand name.

## Features

78 numeric features, all computed locally from the URL string:

- **Lexical** — length, digit/letter/symbol counts and ratios, entropy, longest
  token, vowel/consonant ratio, repeated characters.
- **Host** — label count, TLD, risky TLD flag, IP-literal host, port, punycode,
  hyphen count, host entropy, subdomain depth, `user@host` credentials.
- **Path/query** — depth, length, parameter count, encoded characters, double
  encoding, executable extensions, redirect parameters, nested URL.
- **Brand signals** — exact brand token, brand in subdomain/path, lookalike
  spelling (Levenshtein / homoglyph), official-domain match.
- **Content signals** — login, payment, urgency, crypto keywords; HTTP scheme;
  shortener and free-hosting membership.

The linear member additionally sees the raw URL as character and word n-grams,
which captures patterns the hand-written features miss.

## Evaluation

Metrics at the shipped operating point (malicious threshold `0.6627`):

| Split | Accuracy | Precision | Recall | F1 | FPR | ROC-AUC |
|---|---|---|---|---|---|---|
| Validation | 0.9897 | 0.9924 | 0.9753 | 0.9838 | 0.0035 | 0.9996 |
| Test | 0.9898 | 0.9926 | 0.9761 | 0.9843 | 0.0036 | 0.9995 |
| External holdout | 0.9878 | 0.9869 | 0.9678 | 0.9773 | 0.0048 | 0.9994 |

External holdout by source:

| Source | Rows | Flag rate at malicious threshold |
|---|---|---|
| Phishing Army (phishing) | 10,123 | 96.8% |
| OpenPhish (phishing) | 70 | 92.9% |
| Tranco holdout (benign) | 27,407 | 0.48% false positives |

Full per-threshold metrics, confusion matrices, calibration (Brier score), and
plots are in [`artifacts/metrics.json`](artifacts/metrics.json) and
[`artifacts/reports/`](artifacts/reports/). Methodology and error analysis:
[`docs/EVALUATION.md`](docs/EVALUATION.md).

## Thresholds

| Verdict | Threshold | Behaviour |
|---|---|---|
| `safe` | `< 0.33135` | no meaningful signal |
| `suspicious` | `0.33135 – 0.6627` | real warning signs, not conclusive |
| `malicious` | `≥ 0.6627` | strong evidence of phishing |

Thresholds are selected on validation data. `malicious` is the high-precision
operating point (FPR ≈ 0.35%); `suspicious` is chosen so that the recall at
that band exceeds 99%. Both are stored in the artifact so CLI, API, and UI
cannot disagree.

## Limitations

- **Text-only.** The model never fetches the URL. A clean URL can still serve
  malware, and a benign URL can redirect to a phishing page.
- **Temporal drift.** Phishing domains are short-lived. Retrain monthly or
  quarterly against fresh feeds for best results.
- **Language and TLD coverage.** Training data is skewed toward English-language
  brands and common gTLDs. Rare ccTLDs and regional brands are less reliable.
- **Lookalikes are hard.** A brand-new homoglyph domain with no structural red
  flags may score below the malicious threshold; the rule engine raises it to
  `suspicious`, not always `malicious`.
- **No page content.** Login-form detection, JavaScript analysis, and
  screenshot comparison are explicitly out of scope.

## Ethical considerations

- URLs are personal data. History is local-only and can be disabled with
  `--no-history` or cleared from the UI/CLI.
- No telemetry, analytics, or third-party calls are made at scan time.
- The model is a warning aid, not an accusation. False positives should be
  surfaced as "verify before opening", never as a block without appeal.
- Do not deploy as a sole gatekeeper for safety-critical or financial flows.

## Retraining

```powershell
python scripts/download_data.py     # refresh raw feeds
python scripts/prepare_data.py      # rebuild domain-grouped splits
python scripts/train_model.py --n-jobs 8
python scripts/model_benchmark.py
python -m pytest -q
```

Retraining is deterministic given the same raw data and seed. Bump the version
in `qrshield/__init__.py` and update this card when metrics change materially.
