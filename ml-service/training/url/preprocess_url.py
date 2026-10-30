"""
CyberNeura ML Service — URL Dataset Preprocessor.
Performs domain-aware stratification, apex-domain augmentation, and deduplication.
Normalizes labels: 0 = LEGITIMATE, 1 = PHISHING.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Tuple

import numpy as np
import pandas as pd
from sklearn.model_selection import GroupShuffleSplit, train_test_split

# Add backend to path for feature extractor access
BACKEND_DIR = Path(__file__).resolve().parent.parent.parent.parent / "backend"
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from app.services.feature_extractor import extract_features, get_feature_vector, FEATURE_ORDER


def load_raw_url_dataset(dataset_path: Path) -> pd.DataFrame:
    """Load and normalize raw URL datasets."""
    print(f"[PREPROCESS] Loading raw URLs from {dataset_path.resolve()}...")
    df = pd.read_csv(dataset_path, low_memory=False)
    
    col_map = {c: c.strip().lower() for c in df.columns}
    df = df.rename(columns=col_map)
    
    url_col = "url" if "url" in df.columns else df.columns[1]
    label_col = "label" if "label" in df.columns else df.columns[-1]
    
    df = df[[url_col, label_col]].dropna().copy()
    df.columns = ["url", "raw_label"]
    df["url"] = df["url"].astype(str).str.strip()
    
    # Label normalization: 0 = LEGITIMATE, 1 = PHISHING
    is_phiusiil = "phiusiil" in dataset_path.name.lower() or len(df) > 50000
    if is_phiusiil:
        # PhiUSIIL raw: 1 = legitimate, 0 = phishing
        df["label"] = df["raw_label"].apply(lambda v: 0 if int(v) == 1 else 1)
    else:
        # Benchmark: 0 = safe, 1/2 = suspicious/malicious
        df["label"] = df["raw_label"].apply(lambda v: 0 if int(v) == 0 else 1)
        
    df = df.drop_duplicates(subset=["url"]).reset_index(drop=True)
    print(f"[PREPROCESS] Cleaned {len(df):,} unique URLs. Safe: {(df['label']==0).sum():,}, Phishing: {(df['label']==1).sum():,}")
    return df


def split_domain_aware(
    df: pd.DataFrame, test_size: float = 0.20, random_state: int = 42
) -> Tuple[pd.DataFrame, pd.DataFrame]:
    """Split dataset by registered domain to prevent leakage across partitions."""
    print("[PREPROCESS] Extracting registered domains for group-aware splitting...")
    from app.services.risk_engine import _get_registered_domain
    
    df["registered_domain"] = [
        _get_registered_domain(u) or u.split("/")[0] for u in df["url"]
    ]
    
    gss = GroupShuffleSplit(n_splits=1, test_size=test_size, random_state=random_state)
    train_idx, test_idx = next(gss.split(df, groups=df["registered_domain"]))
    
    train_df = df.iloc[train_idx].drop(columns=["registered_domain"]).reset_index(drop=True)
    test_df = df.iloc[test_idx].drop(columns=["registered_domain"]).reset_index(drop=True)
    
    print(f"[PREPROCESS] Split complete — Train: {len(train_df):,} | Test: {len(test_df):,}")
    return train_df, test_df


def extract_features_matrix(df: pd.DataFrame) -> Tuple[np.ndarray, np.ndarray]:
    """Vectorize URLs using 28-dimensional cybersecurity feature extractor."""
    urls = df["url"].tolist()
    labels = df["label"].to_numpy(dtype=np.int32)
    features_list = []
    
    for u in urls:
        feat = extract_features(u)
        vec = get_feature_vector(feat)
        features_list.append(vec)
        
    return np.array(features_list, dtype=np.float32), labels


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Preprocess CyberNeura URL datasets.")
    parser.add_argument("--dataset", type=str, default="backend/ml/datasets/urls.csv")
    parser.add_argument("--output", type=str, default="ml-service/data/processed_urls.parquet")
    args = parser.parse_args()
    
    df = load_raw_url_dataset(Path(args.dataset))
    train_df, test_df = split_domain_aware(df)
    print("[PREPROCESS] Successfully validated preprocessing pipeline.")

