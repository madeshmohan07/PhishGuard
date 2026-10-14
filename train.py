"""
train.py
--------
Loads the labelled URL dataset, extracts the lexical/structural
feature set defined in feature_extractor.py, trains a Random Forest
classifier, evaluates it with standard metrics, and saves the trained
model + a metrics report to disk.

Dataset: phishing_site_urls.csv (549,846 URLs, columns: URL, Label
in {good, bad}), sourced from a public GitHub/Kaggle mirror
(cyberholics/Malicious-URL-detector). See report Section 7.2.
"""

import re
import json
import time
import joblib
import numpy as np
import pandas as pd
from pathlib import Path

from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    roc_auc_score, confusion_matrix, classification_report,
)

from feature_extractor import extract_features, FEATURE_NAMES
from trusted_domains import TRUSTED_DOMAINS, COMMON_PATHS

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_PATH = BASE_DIR / "data" / "phishing_site_urls.csv"
MODEL_DIR = BASE_DIR / "model"
MODEL_DIR.mkdir(exist_ok=True)

# Cap the number of rows used for feature extraction so this runs in a
# reasonable time on a laptop/CPU. A stratified sample keeps the class
# balance intact while still giving the model plenty of data.
SAMPLE_SIZE = 120000
RANDOM_STATE = 42

# ---- Row-level cleaning (Section 5.4 - Data Preprocessing: Cleaning) ----
# The public source file contains a small fraction of corrupted /
# non-UTF8 rows (binary garbage mislabeled as URLs, confirmed by manual
# inspection). These are detected and removed before feature extraction
# and training, rather than silently left in the "legitimate" class
# where they would inject label noise near the decision boundary.
_CONTROL_CHAR_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]")
_DOMAIN_START_RE = re.compile(r"^[a-zA-Z0-9]([a-zA-Z0-9\-\.]{0,255})\.[a-zA-Z]{2,24}([/:?#].*)?$")


def _looks_like_a_url(u) -> bool:
    """A row is kept only if it starts with a plausible hostname
    (label.label...tld) and contains no control characters and only a
    small proportion of non-ASCII bytes. This removes corrupted rows
    without relying on any external validation service."""
    if not isinstance(u, str):
        return False
    if len(u) > 2048 or len(u) < 4:
        return False
    if _CONTROL_CHAR_RE.search(u):
        return False
    non_ascii = sum(1 for c in u if ord(c) > 127)
    if non_ascii / len(u) > 0.05:
        return False
    if not _DOMAIN_START_RE.match(u.strip("'\"")):
        return False
    return True


def load_dataset():
    print(f"Loading dataset from {DATA_PATH} ...")
    df = pd.read_csv(DATA_PATH)
    df.columns = [c.strip() for c in df.columns]
    df = df.dropna(subset=["URL", "Label"])
    df["Label"] = df["Label"].str.strip().str.lower()
    df = df[df["Label"].isin(["good", "bad"])]
    print(f"Rows after label cleaning: {len(df)}")

    before = len(df)
    valid_mask = df["URL"].apply(_looks_like_a_url)
    df = df[valid_mask]
    n_dropped = before - len(df)
    print(f"Dropped {n_dropped} corrupted/non-URL rows during cleaning "
          f"({n_dropped / before:.2%} of dataset).")

    # ---- De-duplication (prevents the same URL landing in both the
    # training and test sets, which would inflate the test scores) ----
    n0 = len(df)
    conflicting = df.groupby("URL")["Label"].nunique()
    conflicting = set(conflicting[conflicting > 1].index)
    df = df[~df["URL"].isin(conflicting)]
    df = df.drop_duplicates(subset="URL").reset_index(drop=True)
    print(f"Removed {n0 - len(df)} duplicate / conflicting-label rows.")
    print(f"Usable rows: {len(df)}  |  class counts:\n{df['Label'].value_counts()}")

    if SAMPLE_SIZE and len(df) > SAMPLE_SIZE:
        per_class = SAMPLE_SIZE // 2
        parts = []
        for label in ["good", "bad"]:
            sub = df[df["Label"] == label]
            n = min(len(sub), per_class)
            parts.append(sub.sample(n=n, random_state=RANDOM_STATE))
        df = pd.concat(parts, ignore_index=True)
        df = df.sample(frac=1.0, random_state=RANDOM_STATE).reset_index(drop=True)
        print(f"Sampled down to {len(df)} rows for feature extraction.")

    # ---- Scheme neutralisation ----
    # The source file records no http/https scheme (only ~0.02% of rows
    # have one), so the scheme is unknown for these URLs. To stop the
    # model learning a false link between the scheme and the label, the
    # scheme is assigned at random (50/50), independently of the class.
    rng = np.random.default_rng(RANDOM_STATE)
    has_scheme = df["URL"].str.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://")
    pick = rng.random(len(df)) < 0.5
    prefix = np.where(pick, "https://", "http://")
    df["URL"] = np.where(has_scheme, df["URL"], prefix + df["URL"])
    return df


def build_feature_matrix(df):
    print("Extracting features from URLs (this may take a minute)...")
    t0 = time.time()
    rows = []
    bad_idx = []
    for i, u in enumerate(df["URL"].astype(str).values):
        try:
            rows.append(extract_features(u))
        except Exception:
            bad_idx.append(i)
            rows.append({k: 0 for k in FEATURE_NAMES})
    X = pd.DataFrame(rows, columns=FEATURE_NAMES)
    y = (df["Label"].values == "bad").astype(int)  # 1 = phishing, 0 = legitimate
    print(f"Feature extraction done in {time.time() - t0:.1f}s. "
          f"{len(bad_idx)} rows failed extraction (filled with zeros).")
    return X, y


def build_trusted_augmentation():
    """
    Build additional, correctly-labelled legitimate examples from a
    curated real-domain list, to correct the sampling bias identified
    during evaluation: the source dataset's "good" class contains
    almost no bare-homepage URLs, causing the model to associate a
    short path with phishing. See trusted_domains.py for details.
    """
    import itertools
    rows = []
    for domain in TRUSTED_DOMAINS:
        for prefix in ["", "www."]:
            for scheme in ["https://", "http://"]:
                for path in COMMON_PATHS:
                    rows.append(f"{scheme}{prefix}{domain}{path}")
    df_aug = pd.DataFrame({"URL": rows, "Label": "good"})
    # de-duplicate and keep a manageable, non-dominant sample size
    df_aug = df_aug.drop_duplicates(subset="URL").sample(
        n=min(4000, len(df_aug)), random_state=RANDOM_STATE
    ).reset_index(drop=True)
    print(f"Built {len(df_aug)} augmented legitimate examples from {len(TRUSTED_DOMAINS)} trusted domains.")
    return df_aug


def main():
    df = load_dataset()
    df_aug = build_trusted_augmentation()
    df = pd.concat([df, df_aug], ignore_index=True)
    df = df.sample(frac=1.0, random_state=RANDOM_STATE).reset_index(drop=True)
    print(f"Total rows after augmentation: {len(df)}")

    X, y = build_feature_matrix(df)

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=RANDOM_STATE, stratify=y
    )
    print(f"Train size: {len(X_train)}  Test size: {len(X_test)}")

    model = RandomForestClassifier(
        n_estimators=150,
        max_depth=18,
        min_samples_leaf=5,
        n_jobs=-1,
        random_state=RANDOM_STATE,
        class_weight="balanced",
    )
    print("Training RandomForestClassifier...")
    t0 = time.time()
    model.fit(X_train, y_train)
    print(f"Training done in {time.time() - t0:.1f}s")

    y_pred = model.predict(X_test)
    y_proba = model.predict_proba(X_test)[:, 1]

    metrics = {
        "accuracy": accuracy_score(y_test, y_pred),
        "precision": precision_score(y_test, y_pred),
        "recall": recall_score(y_test, y_pred),
        "f1_score": f1_score(y_test, y_pred),
        "roc_auc": roc_auc_score(y_test, y_proba),
    }
    cm = confusion_matrix(y_test, y_pred).tolist()
    report = classification_report(y_test, y_pred, target_names=["legitimate", "phishing"])

    print("\n===== EVALUATION METRICS =====")
    for k, v in metrics.items():
        print(f"{k:10s}: {v:.4f}")
    print("\nConfusion Matrix [ [TN, FP], [FN, TP] ]:")
    print(cm)
    print("\n" + report)

    feature_importance = sorted(
        zip(FEATURE_NAMES, model.feature_importances_),
        key=lambda x: -x[1],
    )
    print("\nTop feature importances:")
    for name, imp in feature_importance[:10]:
        print(f"  {name:25s} {imp:.4f}")

    # ---- Save artifacts ----
    joblib.dump(model, MODEL_DIR / "phishing_rf_model.joblib")
    with open(MODEL_DIR / "feature_names.json", "w") as f:
        json.dump(FEATURE_NAMES, f, indent=2)
    with open(MODEL_DIR / "metrics.json", "w") as f:
        json.dump({
            "metrics": metrics,
            "confusion_matrix": cm,
            "classification_report": report,
            "feature_importance": [(n, float(v)) for n, v in feature_importance],
            "train_size": len(X_train),
            "test_size": len(X_test),
            "sample_size_used": len(df),
        }, f, indent=2)
    print(f"\nSaved model to {MODEL_DIR / 'phishing_rf_model.joblib'}")
    print(f"Saved metrics to {MODEL_DIR / 'metrics.json'}")


if __name__ == "__main__":
    main()
