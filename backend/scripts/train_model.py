"""
Train the CyberNeura URL threat classification model.

Usage:
    cd backend
    python scripts/train_model.py
    # Or specify custom dataset:
    python scripts/train_model.py --dataset ../PhiUSIIL_Phishing_URL_Dataset.csv

This script:
1. Automatically discovers and loads PhiUSIIL_Phishing_URL_Dataset.csv
   (or falls back to ml/datasets/urls.csv)
2. Normalizes labels (0 = safe, 1 = malicious/phishing)
3. Augments legitimate URLs to eliminate 'www.' collection bias
4. Merges curated benchmark URLs from ml/datasets/urls.csv
5. Extracts 28 structural, security, and Shannon entropy features
6. Trains a high-performance RandomForestClassifier
7. Evaluates accuracy, precision, recall, F1-score
8. Saves model to ml/models/url_model.joblib
9. Saves metadata to ml/models/model_metadata.json
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
from datetime import date
from pathlib import Path

# Allow imports from parent
sys.path.insert(0, str(Path(__file__).parent.parent))

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)
from sklearn.model_selection import train_test_split

from app.services.feature_extractor import (
    FEATURE_ORDER,
    extract_features,
    get_feature_vector,
)

MODEL_PATH = Path("ml/models/url_model.joblib")
METADATA_PATH = Path("ml/models/model_metadata.json")
MODEL_VERSION = "2.0.0"


def find_dataset(custom_path: str | None = None) -> Path:
    """Find the best available dataset path."""
    if custom_path:
        p = Path(custom_path)
        if p.exists():
            return p
        print(f"[WARNING] Specified dataset {custom_path} not found.")

    candidates = [
        Path("ml/datasets/PhiUSIIL_Phishing_URL_Dataset.csv"),
        Path("../PhiUSIIL_Phishing_URL_Dataset.csv"),
        Path("PhiUSIIL_Phishing_URL_Dataset.csv"),
        Path("../../PhiUSIIL_Phishing_URL_Dataset.csv"),
        Path("ml/datasets/urls.csv"),
    ]
    for c in candidates:
        if c.exists():
            return c

    print("[ERROR] No dataset found.")
    print("Please place PhiUSIIL_Phishing_URL_Dataset.csv in the workspace root or backend/ml/datasets/.")
    sys.exit(1)


def load_and_preprocess_dataset(path: Path) -> pd.DataFrame:
    """Load dataset, map labels, augment apex domains, and merge curated URLs."""
    print(f"[INFO] Loading dataset from: {path.resolve()}")
    df = pd.read_csv(path, low_memory=False)
    print(f"[INFO] Raw records loaded: {len(df):,}")

    # Standardize column names
    col_map = {c: c.strip().lower() for c in df.columns}
    df = df.rename(columns=col_map)

    url_col = "url" if "url" in df.columns else df.columns[1]
    label_col = "label" if "label" in df.columns else df.columns[-1]

    df = df[[url_col, label_col]].dropna().copy()
    df.columns = ["url", "raw_label"]
    df["url"] = df["url"].astype(str).str.strip()

    # Detect PhiUSIIL dataset vs legacy dataset
    # In PhiUSIIL: 1 = legitimate, 0 = phishing
    # We map: 0 = safe (legitimate), 1 = malicious (phishing)
    is_phiusiil = "phiusiil" in path.name.lower() or len(df) > 50000

    if is_phiusiil:
        print("[INFO] Detected PhiUSIIL Phishing URL Dataset format.")
        # Map: 1 -> 0 (safe), 0 -> 1 (malicious)
        df["label"] = df["raw_label"].apply(lambda v: 0 if int(v) == 1 else 1)

        # Deduplicate raw URLs
        df = df.drop_duplicates(subset=["url"]).copy()
        print(f"[INFO] Unique URLs in PhiUSIIL: {len(df):,}")

        # Domain & Path Augmentation:
        # In PhiUSIIL, 100% of legitimate URLs have 'www.' and 0% have paths or trailing slashes.
        # To avoid the false shortcuts that non-www URLs or URLs with paths are phishing,
        # we add apex domain equivalents, root trailing slashes, and diverse legitimate paths.
        legit = df[df["label"] == 0].copy()
        legit_nowww = legit[legit["url"].str.contains("://www\\.", regex=True)].copy()
        legit_nowww["url"] = legit_nowww["url"].str.replace("://www.", "://", regex=False)
        legit_nowww = legit_nowww.drop_duplicates(subset=["url"])

        # Legitimate paths and trailing slashes
        legit_all = pd.concat([legit, legit_nowww]).drop_duplicates(subset=["url"])
        
        # Trailing slashes:
        legit_slash = legit_all.sample(n=min(30000, len(legit_all)), random_state=42).copy()
        legit_slash["url"] = legit_slash["url"] + "/"

        # Realistic legitimate paths & queries:
        common_paths = [
            "/about", "/help", "/docs", "/login", "/privacy", "/contact", "/blog",
            "/faq", "/terms", "/app", "/api", "/products", "/auth/login", "/explore",
            "/docs/quickstart", "/user/profile", "/search?q=test", "/wiki/Article",
            "/en/download", "/services", "/pricing", "/features",
        ]
        legit_paths = legit_all.sample(n=min(40000, len(legit_all)), random_state=42).copy()
        legit_paths["url"] = [
            u.rstrip("/") + common_paths[i % len(common_paths)]
            for i, u in enumerate(legit_paths["url"])
        ]

        print(f"[INFO] Augmenting with {len(legit_nowww):,} apex, {len(legit_slash):,} trailing-slash, and {len(legit_paths):,} path-diverse legitimate URLs...")
        df = pd.concat([df, legit_nowww, legit_slash, legit_paths], ignore_index=True)
        df = df.drop_duplicates(subset=["url"]).copy()

    else:
        print("[INFO] Detected standard URLs dataset format.")
        # If legacy has 0=safe, 1=suspicious, 2=malicious:
        # Map: 0 -> 0 (safe), 1 -> 1 (malicious), 2 -> 1 (malicious) for binary training
        df["label"] = df["raw_label"].apply(lambda v: 0 if int(v) == 0 else 1)
        df = df.drop_duplicates(subset=["url"]).copy()

    # Merge top-1m.csv legitimate domains if present in datasets directory
    top1m_path = Path("ml/datasets/top-1m.csv")
    if not top1m_path.exists():
        top1m_path = Path("../ml/datasets/top-1m.csv")
    if not top1m_path.exists():
        top1m_path = Path("datasets/top-1m.csv")

    if top1m_path.exists():
        try:
            print(f"[INFO] Ingesting legitimate domains from: {top1m_path.resolve()}")
            top_df = pd.read_csv(top1m_path, header=None, names=["rank", "domain"], nrows=50000)
            clean_domains = top_df["domain"].dropna().astype(str).str.strip().tolist()
            
            top1m_urls = []
            for i, d in enumerate(clean_domains):
                # Distribute protocols and apex/www variations
                if i % 3 == 0:
                    top1m_urls.append(f"https://{d}")
                elif i % 3 == 1:
                    top1m_urls.append(f"https://www.{d}")
                else:
                    top1m_urls.append(f"http://{d}")
                
                # Sample diverse standard paths for 20% of domains
                if i % 5 == 0:
                    top1m_urls.append(f"https://{d}/about")
                elif i % 7 == 0:
                    top1m_urls.append(f"https://{d}/login")
                elif i % 11 == 0:
                    top1m_urls.append(f"https://{d}/help")

            top1m_data = pd.DataFrame({"url": top1m_urls, "label": 0})
            df = pd.concat([df[["url", "label"]], top1m_data], ignore_index=True)
            df = df.drop_duplicates(subset=["url"]).copy()
            print(f"[INFO] Merged {len(top1m_urls):,} legitimate URLs from top-1m dataset.")
        except Exception as exc:
            print(f"[WARNING] Could not merge top-1m dataset: {exc}")

    # Merge benchmark curated samples if available and not already identical
    curated_path = Path("ml/datasets/urls.csv")
    if curated_path.resolve() != path.resolve() and curated_path.exists():
        try:
            curated = pd.read_csv(curated_path)
            curated["url"] = curated["url"].astype(str).str.strip()
            curated["label"] = curated["label"].apply(lambda v: 0 if int(v) == 0 else 1)
            df = pd.concat([df[["url", "label"]], curated[["url", "label"]]], ignore_index=True)
            df = df.drop_duplicates(subset=["url"]).copy()
            print(f"[INFO] Merged {len(curated)} benchmark curated URLs.")
        except Exception as exc:
            print(f"[WARNING] Could not merge curated dataset: {exc}")

    safe_count = int((df["label"] == 0).sum())
    malicious_count = int((df["label"] == 1).sum())
    print(f"[INFO] Final dataset size: {len(df):,} (Safe: {safe_count:,}, Malicious: {malicious_count:,})")
    return df


def build_feature_matrix(df: pd.DataFrame) -> tuple[np.ndarray, np.ndarray]:
    """Extract 28 structural, security, and Shannon entropy features from all URLs."""
    print(f"[INFO] Extracting features for {len(df):,} URLs using 28-dimensional pipeline...")
    t0 = time.time()

    urls = df["url"].tolist()
    labels = df["label"].to_numpy(dtype=np.int32)

    features_list = []
    # Fast iteration
    for i, u in enumerate(urls):
        feat = extract_features(u)
        vec = get_feature_vector(feat)
        features_list.append(vec)
        if (i + 1) % 50000 == 0:
            elapsed = time.time() - t0
            rate = (i + 1) / elapsed
            print(f"  Processed {i+1:,}/{len(urls):,} URLs ({rate:,.0f} URLs/sec)...")

    X = np.array(features_list, dtype=np.float32)
    elapsed = time.time() - t0
    print(f"[INFO] Feature extraction completed in {elapsed:.2f}s ({len(urls)/elapsed:,.0f} URLs/sec).")
    return X, labels


def train(X: np.ndarray, y: np.ndarray) -> tuple[RandomForestClassifier, dict]:
    """Train RandomForestClassifier and compute comprehensive evaluation metrics."""
    print(f"[INFO] Splitting dataset into train/test (80/20 stratified)...")
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.20, random_state=42, stratify=y
    )
    print(f"[INFO] Training set: {len(X_train):,} samples | Test set: {len(X_test):,} samples")

    print("[INFO] Training RandomForestClassifier (n_estimators=150, max_depth=18, parallel n_jobs=-1)...")
    t0 = time.time()
    clf = RandomForestClassifier(
        n_estimators=150,
        max_depth=18,
        min_samples_split=4,
        class_weight="balanced",
        random_state=42,
        n_jobs=-1,
    )
    clf.fit(X_train, y_train)
    fit_time = time.time() - t0
    print(f"[INFO] Model fitting finished in {fit_time:.2f}s.")

    print("[INFO] Evaluating on holdout test set...")
    y_pred = clf.predict(X_test)
    acc = float(accuracy_score(y_test, y_pred))
    prec = float(precision_score(y_test, y_pred, average="weighted", zero_division=0))
    rec = float(recall_score(y_test, y_pred, average="weighted", zero_division=0))
    f1 = float(f1_score(y_test, y_pred, average="weighted", zero_division=0))

    cm = confusion_matrix(y_test, y_pred)
    print(f"\n{'='*60}")
    print(f"  CYBERNEURA MODEL EVALUATION RESULTS (v{MODEL_VERSION})")
    print(f"{'='*60}")
    print(f"  Accuracy:  {acc:.4f} ({acc*100:.2f}%)")
    print(f"  Precision: {prec:.4f}")
    print(f"  Recall:    {rec:.4f}")
    print(f"  F1 Score:  {f1:.4f}")
    print(f"  Confusion Matrix:\n{cm}")
    print(f"{'='*60}")
    print("\nClassification Report:")
    print(classification_report(y_test, y_pred, target_names=["safe", "malicious"], zero_division=0))

    metadata = {
        "version": MODEL_VERSION,
        "algorithm": "RandomForestClassifier",
        "accuracy": round(acc, 4),
        "precision": round(prec, 4),
        "recall": round(rec, 4),
        "f1_score": round(f1, 4),
        "training_samples": int(len(X_train)),
        "test_samples": int(len(X_test)),
        "training_date": date.today().isoformat(),
        "deployment_status": "production",
        "n_estimators": 150,
        "dataset": "PhiUSIIL Phishing URL Dataset + Cisco Umbrella Top-1M + Curated Benchmark",
        "classes": ["safe", "malicious"],
        "feature_importance": {},
    }
    return clf, metadata


def save_model(clf: RandomForestClassifier, metadata: dict) -> None:
    """Save trained model joblib and metadata JSON."""
    MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(clf, MODEL_PATH, compress=3)
    print(f"[INFO] Model successfully saved to {MODEL_PATH.resolve()}")

    # Compute and rank feature importances according to FEATURE_ORDER
    importances = clf.feature_importances_.tolist()
    fi = dict(zip(FEATURE_ORDER, importances))
    metadata["feature_importance"] = {
        k: round(v, 6) for k, v in sorted(fi.items(), key=lambda x: x[1], reverse=True)
    }

    with open(METADATA_PATH, "w") as f:
        json.dump(metadata, f, indent=2)
    print(f"[INFO] Model metadata saved to {METADATA_PATH.resolve()}")


def verify_inference(clf: RandomForestClassifier) -> None:
    """Verify inference on representative real-world test URLs."""
    print(f"\n{'='*60}")
    print("  VERIFICATION INFERENCE ON SAMPLE TEST URLs")
    print(f"{'='*60}")
    test_cases = [
        ("https://www.google.com", "Safe benchmark"),
        ("https://google.com", "Safe apex domain"),
        ("https://github.com", "Safe apex developer platform"),
        ("https://www.apple.com", "Safe brand domain"),
        ("https://cloudflare.com", "Safe infrastructure domain"),
        ("http://paypal-verification-security-update.xyz/login", "Phishing simulation"),
        ("http://apple-support-login-secure.tk", "Phishing TLD + keyword"),
        ("http://192.168.1.1/admin", "IP hostname"),
    ]
    for url, desc in test_cases:
        feat = extract_features(url)
        vec = get_feature_vector(feat)
        proba = clf.predict_proba([vec])[0]
        p_phish = proba[1]
        category = "malicious" if p_phish >= 0.7 else ("suspicious" if p_phish >= 0.3 else "safe")
        print(f"  [{category.upper():<10}] P(phish)={p_phish:.4f} | {url} ({desc})")
    print(f"{'='*60}\n")


def main():
    parser = argparse.ArgumentParser(description="Train CyberNeura URL threat classifier.")
    parser.add_argument("--dataset", type=str, default=None, help="Path to URL dataset CSV")
    args = parser.parse_args()

    print(f"\n{'='*60}")
    print(f"  CyberNeura ML Model Trainer v{MODEL_VERSION}")
    print(f"{'='*60}\n")

    dataset_path = find_dataset(args.dataset)
    df = load_and_preprocess_dataset(dataset_path)
    X, y = build_feature_matrix(df)
    clf, metadata = train(X, y)
    save_model(clf, metadata)
    verify_inference(clf)

    print(f"[SUCCESS] Training complete. Model v{MODEL_VERSION} is active and ready for production!")


if __name__ == "__main__":
    main()

