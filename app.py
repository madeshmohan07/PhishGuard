"""
app.py
------
Flask backend for the AI-Based Phishing Website Detection System.
Implements the runtime detection pipeline described in Section 6 of
the project report: URL Input -> Validation -> Feature Extraction ->
Preprocessing -> Trained ML Model -> Classification -> Risk Score ->
Result Display.
"""

import json
from pathlib import Path

import joblib
import pandas as pd
from flask import Flask, render_template, request, jsonify

from feature_extractor import extract_features, is_valid_url, explain_suspicious, FEATURE_NAMES

BASE_DIR = Path(__file__).resolve().parent.parent
MODEL_PATH = BASE_DIR / "model" / "phishing_rf_model.joblib"
METRICS_PATH = BASE_DIR / "model" / "metrics.json"

MAX_URL_LENGTH = 2048

app = Flask(
    __name__,
    template_folder=str(BASE_DIR / "templates"),
    static_folder=str(BASE_DIR / "static"),
)

app.config["MAX_CONTENT_LENGTH"] = 16 * 1024  # reject oversized requests (availability)

print(f"Loading model from {MODEL_PATH} ...")
model = joblib.load(MODEL_PATH)
print("Model loaded.")

METRICS = {}
if METRICS_PATH.exists():
    with open(METRICS_PATH) as f:
        METRICS = json.load(f)


def risk_level(confidence: float, label: str) -> str:
    if label == "legitimate":
        return "Low"
    if confidence >= 0.85:
        return "High"
    if confidence >= 0.6:
        return "Medium"
    return "Low"


@app.route("/")
def index():
    acc = METRICS.get("metrics", {}).get("accuracy")
    return render_template("index.html",
                           accuracy=f"{acc*100:.1f}%" if acc else "N/A",
                           n_trees=len(model.estimators_))


@app.route("/health")
def health():
    return jsonify({"status": "ok", "trees": len(model.estimators_)})


@app.route("/api/predict", methods=["POST"])
def predict():
    data = request.get_json(silent=True) or {}
    raw_url = (data.get("url") or "").strip()

    # ---- Step: URL Validation ----
    if not raw_url:
        return jsonify({"ok": False, "error": "Please enter a URL."}), 400
    if len(raw_url) > MAX_URL_LENGTH:
        return jsonify({"ok": False, "error": "URL is too long."}), 400
    if not is_valid_url(raw_url):
        return jsonify({"ok": False, "error": "Invalid URL format."}), 400

    # ---- Step: Feature Extraction + Preprocessing ----
    features = extract_features(raw_url)
    X = pd.DataFrame([[features[name] for name in FEATURE_NAMES]], columns=FEATURE_NAMES)

    # ---- Step: Trained ML Model -> Classification ----
    pred = model.predict(X)[0]
    proba = model.predict_proba(X)[0]
    phishing_confidence = float(proba[1])
    label = "phishing" if pred == 1 else "legitimate"
    confidence = phishing_confidence if label == "phishing" else float(proba[0])

    reasons = explain_suspicious(features) if label == "phishing" else []

    return jsonify({
        "ok": True,
        "url": raw_url,
        "label": label,
        "confidence": round(confidence * 100, 1),
        "risk_level": risk_level(confidence, label),
        "reasons": reasons,
        "features": features,
    })


@app.route("/api/model-info")
def model_info():
    return jsonify(METRICS)


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5050, debug=False)  # local only: URLs never leave this machine
