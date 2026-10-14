# PhishGuard - AI-Based Phishing Website Detection System

A complete, runnable implementation of the Review 1 project: a Random Forest model that
reads a website link and predicts **phishing** or **legitimate**, served through a clean web page.
It looks only at the text of the link (27 features); it never visits the website.

## 1. Quick start

You need Python 3.10 or newer.

**Windows:** double-click `run.bat` (or run it from a terminal).
**Mac / Linux:** `sh run.sh`

Or by hand:

```
pip install -r requirements.txt
cd app
python app.py            # use python3 on Mac/Linux
```

Open **http://localhost:5050**, paste a link, click **Check link**.
Stop the server with `Ctrl + C`.

## 2. What is in the folder

| Path | What it is |
|---|---|
| `app/app.py` | Flask web server and the `/api/predict` endpoint |
| `app/feature_extractor.py` | Link validation and the 27 URL features |
| `app/trusted_domains.py` | 106 real domains used to correct a dataset bias |
| `app/train.py` | Cleans data, trains and evaluates the model, saves it |
| `app/export_distilled.py` | Exports a smaller 50-tree model for the in-browser version |
| `templates/`, `static/` | The web page (HTML, CSS, JavaScript) |
| `model/` | Trained model (`.joblib`), `metrics.json`, feature list |
| `data/phishing_site_urls.csv` | Training data (549,846 labelled URLs) |
| `tests/test_pipeline.py` | 13 automated tests (the report's TC01-TC10 plus regressions) |
| `artifact/PhishGuard.jsx` | Stand-alone browser version (no server needed) |
| `docs/` | Review 1 report, dataset description, dataset workbook |

## 3. How it works

```
Link -> validate -> extract 27 features -> Random Forest (150 trees vote) -> label + confidence + risk level
```

Training: `data` -> remove corrupted rows -> remove duplicates -> sample 60,000 per class ->
add 4,000 legitimate examples from trusted domains -> extract features -> 80/20 split -> train -> evaluate -> save.

Risk level: Low for legitimate results. For phishing results, High at 85% confidence or more, Medium at 60-84%, otherwise Low.

## 4. Results (measured, not estimated)

Held-out test set of 24,800 URLs that the model never saw, duplicates removed:

| Metric | Value |
|---|---|
| Accuracy | 88.9% |
| Precision | 90.2% |
| Recall | 86.4% |
| F1-score | 88.2% |
| ROC-AUC | 0.959 |

Confusion matrix (rows = actual, columns = predicted; order legitimate, phishing):
`[[11671, 1129], [1635, 10365]]`. That is 1,129 legitimate links wrongly flagged (false positives) and 1,635 phishing links missed (false negatives).

Numbers change slightly each time you retrain (`python train.py`) because of random sampling.
The browser version uses a smaller 50-tree model with about 84% accuracy so that it fits in one file.

## 5. Tests

From the project root:

```
python -m unittest discover -s tests -v
```

13 tests cover: legitimate link, phishing-style link, IP-address link, suspicious keywords, special characters,
shortened link, invalid input, empty input, very long link, unseen link, a homepage-bias check
(google.com, github.com, nasa.gov must stay legitimate), a check that http vs https does not decide the result,
and the health/home pages.

## 6. API

`POST /api/predict` with `{"url": "http://bit.ly/3xKq9zT"}` returns
`ok, url, label, confidence (0-100), risk_level, reasons[], features{}`.
Errors return HTTP 400 with an `error` message. `GET /health` returns `{"status": "ok"}`.

## 7. Security properties (maps to report section 7.5)

| Property | Status in this prototype |
|---|---|
| Confidentiality | Implemented: server listens on 127.0.0.1 only, links are processed in memory and never stored or logged |
| Integrity | Partly: inputs are length-limited and validated. Not implemented: checksum check on the model file |
| Availability | Partly: requests over 16 KB or links over 2,048 characters are rejected. Not implemented: rate limiting, load balancing |
| Authentication / Authorization | Not implemented: there is no admin dashboard, so nothing needs a login (future work) |
| Threat detection | Implemented: the Random Forest classifier |

## 8. Known limitations (say these in the review)

- **Link text only.** No page content, domain age, WHOIS or certificate checks. A phishing page on a short, clean-looking link can be missed.
- **Dataset origin unconfirmed.** The data was downloaded from a GitHub copy and I could not verify who collected it, when, or how. See `docs/PhishGuard_Dataset_Description.pdf`.
- **Dataset biases found and handled.** Legitimate homepages were almost missing (fixed with the trusted-domain list), duplicates leaked between train and test (fixed by de-duplication), and the source has no http/https information (scheme assigned at random so it carries no signal).
- **Remaining weaknesses.** The training data contains no IP-address hosts, so the IP signal is not learned (IP links in tests were flagged because of words like login/verify). Some "bad" labels are not true phishing (for example ad trackers). The data is undated and will age.
- **The "warning signs" list is rule-based**, not a readout of the model's reasoning.
- **Not a guarantee.** About 1 in 9 test links is classified wrongly. Treat results as one input to a security decision.
- The model is a student prototype and should not be used as a real security control.

## 9. Ideas for next steps

Domain age and WHOIS lookup, page-content analysis, a browser extension, checking links against PhishTank, explainability (SHAP),
admin login with role-based access, periodic retraining on fresh data.

## 10. Troubleshooting

- `ModuleNotFoundError`: run `pip install -r requirements.txt`.
- Error when loading the model (version mismatch): run `cd app && python train.py` once, then start the app again.
- Port 5050 in use: change the port at the bottom of `app/app.py`.
