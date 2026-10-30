"""
CyberNeura ML Service — URL Model Comprehensive Evaluator.
Computes Accuracy, Precision, Recall, F1, ROC-AUC, PR-AUC, Confusion Matrix, FPR, FNR.
Generates evaluation plots and saves artifacts to ml-service/evaluation/.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Dict, Any

import joblib
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
from sklearn.metrics import (
    accuracy_score,
    auc,
    confusion_matrix,
    f1_score,
    precision_recall_curve,
    precision_score,
    recall_score,
    roc_auc_score,
    roc_curve,
)

BACKEND_DIR = Path(__file__).resolve().parent.parent.parent.parent / "backend"
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from preprocess_url import load_raw_url_dataset, split_domain_aware, extract_features_matrix

EVAL_DIR = Path(__file__).resolve().parent.parent.parent / "evaluation"


def evaluate_url_classifier(
    model_path: Path, dataset_path: Path, eval_output_dir: Path = EVAL_DIR
) -> Dict[str, Any]:
    eval_output_dir.mkdir(parents=True, exist_ok=True)
    print(f"[EVAL_URL] Loading model from {model_path}...")
    clf = joblib.load(model_path)
    if hasattr(clf, "n_jobs"):
        clf.n_jobs = 1

    df = load_raw_url_dataset(dataset_path)
    _, test_df = split_domain_aware(df, test_size=0.20, random_state=42)
    X_test, y_test = extract_features_matrix(test_df)

    y_prob = clf.predict_proba(X_test)[:, 1]
    y_pred = (y_prob >= 0.50).astype(int)

    acc = float(accuracy_score(y_test, y_pred))
    prec = float(precision_score(y_test, y_pred, zero_division=0))
    rec = float(recall_score(y_test, y_pred, zero_division=0))
    f1 = float(f1_score(y_test, y_pred, zero_division=0))
    
    # Handle single-class edge cases gracefully
    if len(np.unique(y_test)) > 1:
        roc_auc = float(roc_auc_score(y_test, y_prob))
        fpr_arr, tpr_arr, _ = roc_curve(y_test, y_prob)
        p_arr, r_arr, _ = precision_recall_curve(y_test, y_prob)
        pr_auc = float(auc(r_arr, p_arr))
    else:
        roc_auc = 1.0
        pr_auc = 1.0
        fpr_arr, tpr_arr = np.array([0, 1]), np.array([0, 1])

    cm = confusion_matrix(y_test, y_pred)
    tn, fp, fn, tp = cm.ravel() if cm.shape == (2, 2) else (0, 0, 0, 0)
    fpr = float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0
    fnr = float(fn / (fn + tp)) if (fn + tp) > 0 else 0.0

    metrics = {
        "model_name": "CyberNeura URL Threat Classifier",
        "dataset": dataset_path.name,
        "test_samples": int(len(y_test)),
        "accuracy": round(acc, 4),
        "precision": round(prec, 4),
        "recall": round(rec, 4),
        "f1_score": round(f1, 4),
        "roc_auc": round(roc_auc, 4),
        "pr_auc": round(pr_auc, 4),
        "false_positive_rate": round(fpr, 4),
        "false_negative_rate": round(fnr, 4),
        "confusion_matrix": {
            "true_negative": int(tn),
            "false_positive": int(fp),
            "false_negative": int(fn),
            "true_positive": int(tp),
        },
    }

    # Save metrics JSON
    with open(eval_output_dir / "url_metrics.json", "w", encoding="utf-8") as f:
        json.dump(metrics, f, indent=2)

    # Plot Confusion Matrix
    plt.figure(figsize=(5, 4))
    plt.imshow(cm, interpolation="nearest", cmap=plt.cm.Blues)
    plt.title("URL Threat Confusion Matrix")
    plt.colorbar()
    tick_marks = np.arange(2)
    plt.xticks(tick_marks, ["Legitimate", "Phishing"])
    plt.yticks(tick_marks, ["Legitimate", "Phishing"])
    
    thresh = cm.max() / 2.0
    for i in range(cm.shape[0]):
        for j in range(cm.shape[1]):
            plt.text(j, i, format(cm[i, j], "d"),
                     ha="center", va="center",
                     color="white" if cm[i, j] > thresh else "black")
    plt.ylabel("True Label")
    plt.xlabel("Predicted Label")
    plt.tight_layout()
    plt.savefig(eval_output_dir / "url_confusion_matrix.png", dpi=200)
    plt.close()

    # Plot ROC Curve
    plt.figure(figsize=(5, 4))
    plt.plot(fpr_arr, tpr_arr, color="darkorange", lw=2, label=f"ROC (AUC = {roc_auc:.3f})")
    plt.plot([0, 1], [0, 1], color="navy", lw=1.5, linestyle="--")
    plt.xlim([0.0, 1.0])
    plt.ylim([0.0, 1.05])
    plt.xlabel("False Positive Rate")
    plt.ylabel("True Positive Rate")
    plt.title("URL Detection ROC Curve")
    plt.legend(loc="lower right")
    plt.tight_layout()
    plt.savefig(eval_output_dir / "url_roc_curve.png", dpi=200)
    plt.close()

    print(f"[EVAL_URL] Metrics & plots successfully written to {eval_output_dir.resolve()}")
    return metrics


if __name__ == "__main__":
    model_p = BACKEND_DIR / "ml" / "models" / "url_model.joblib"
    data_p = BACKEND_DIR / "ml" / "datasets" / "urls.csv"
    evaluate_url_classifier(model_p, data_p)

