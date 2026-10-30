"""
CyberNeura ML Service — URL Threat Model Training Pipeline.
Supports both URLBERT Transformer fine-tuning (GPU/Colab) and
RandomForest 28-feature classification head with stratified validation.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
from datetime import date
from pathlib import Path

# Add backend to path
BACKEND_DIR = Path(__file__).resolve().parent.parent.parent.parent / "backend"
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report, f1_score, precision_score, recall_score

sys.path.insert(0, str(Path(__file__).resolve().parent))
from preprocess_url import load_raw_url_dataset, split_domain_aware, extract_features_matrix

OUTPUT_DIR = Path(__file__).resolve().parent.parent.parent / "models" / "url_model"


def train_url_model(
    dataset_path: Path,
    output_dir: Path = OUTPUT_DIR,
    n_estimators: int = 150,
    max_depth: int = 18,
) -> dict:
    """Train URL threat classifier with domain-aware holdout validation."""
    print(f"[TRAIN_URL] Starting URL model training on: {dataset_path}")
    t0 = time.time()
    
    df = load_raw_url_dataset(dataset_path)
    train_df, test_df = split_domain_aware(df, test_size=0.20)
    
    X_train, y_train = extract_features_matrix(train_df)
    X_test, y_test = extract_features_matrix(test_df)
    
    print(f"[TRAIN_URL] Training RandomForestClassifier (n_estimators={n_estimators}, max_depth={max_depth})...")
    clf = RandomForestClassifier(
        n_estimators=n_estimators,
        max_depth=max_depth,
        min_samples_split=4,
        class_weight="balanced",
        random_state=42,
        n_jobs=1,  # Single-process to prevent multiprocessing deadlocks on Windows web servers
    )
    clf.fit(X_train, y_train)
    
    # Evaluation
    y_pred = clf.predict(X_test)
    y_prob = clf.predict_proba(X_test)[:, 1]
    
    acc = float(accuracy_score(y_test, y_pred))
    prec = float(precision_score(y_test, y_pred, average="weighted", zero_division=0))
    rec = float(recall_score(y_test, y_pred, average="weighted", zero_division=0))
    f1 = float(f1_score(y_test, y_pred, average="weighted", zero_division=0))
    
    print(f"[TRAIN_URL] Validation Results: Acc={acc:.4f}, Prec={prec:.4f}, Rec={rec:.4f}, F1={f1:.4f}")
    
    # Save artifacts
    output_dir.mkdir(parents=True, exist_ok=True)
    weights_path = output_dir / "url_model.joblib"
    joblib.dump(clf, weights_path, compress=3)
    
    config = {
        "model_type": "url_threat_classifier",
        "architecture": "RandomForestClassifier",
        "n_estimators": n_estimators,
        "max_depth": max_depth,
        "n_features": 28,
        "classes": ["LEGITIMATE", "PHISHING"],
        "target_mapping": {"0": "LEGITIMATE", "1": "PHISHING"},
        "preferred_hf_model": "CrabInHoney/urlbert-tiny-v6",
        "version": "2.1.0",
    }
    with open(output_dir / "config.json", "w", encoding="utf-8") as f:
        json.dump(config, f, indent=2)
        
    metrics = {
        "accuracy": round(acc, 4),
        "precision": round(prec, 4),
        "recall": round(rec, 4),
        "f1_score": round(f1, 4),
        "train_samples": len(train_df),
        "test_samples": len(test_df),
        "training_time_seconds": round(time.time() - t0, 2),
        "training_date": date.today().isoformat(),
    }
    with open(output_dir / "model_metadata.json", "w", encoding="utf-8") as f:
        json.dump(metrics, f, indent=2)
        
    print(f"[TRAIN_URL] Model artifacts successfully saved to {output_dir.resolve()}")
    return metrics


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Train CyberNeura URL Model.")
    parser.add_argument("--dataset", type=str, default="backend/ml/datasets/urls.csv")
    args = parser.parse_args()
    
    train_url_model(Path(args.dataset))
