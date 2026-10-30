# CYBERNEURA — DATASET ANALYSIS & PREPROCESSING SPECIFICATION

**Document Version:** 1.0.0  
**Status:** VALIDATED  
**Last Updated:** 2026-10-30  

---

## 1. Overview

CyberNeura relies on dual-modal machine learning pipelines:
- **Module A**: URL Phishing and Threat Classification.
- **Module B**: Synthetic & AI-Generated Image Detection.

This document details dataset provenance, class balance, structural integrity, leakage mitigation strategies, and normalization standards across all ingested and benchmark datasets.

---

## 2. URL Datasets

### 2.1 PhiUSIIL Phishing URL Dataset
- **Location:** `backend/ml/datasets/PhiUSIIL_Phishing_URL_Dataset.csv`
- **File Size:** 56.8 MB (56,854,345 bytes)
- **Record Count:** 235,795 rows $\times$ 56 columns
- **Provenance:** Mendeley Data (Prasad & Chandra, 2023)
- **Data Integrity:**
  - Missing URL values: 0 (0.00%)
  - Missing label values: 0 (0.00%)
  - Duplicate raw URLs: 425 (0.18%) — removed during preprocessing.
- **Label Distribution:**
  - Raw `1` (Legitimate): 134,850 samples (57.19%)
  - Raw `0` (Phishing): 100,945 samples (42.81%)

> [!IMPORTANT]
> **Label Normalization Invariant**:
> In the raw PhiUSIIL dataset, `1` represents legitimate and `0` represents phishing.
> In CyberNeura's internal model registry and REST schemas, labels are normalized to:
> - **`0` = LEGITIMATE (SAFE)**
> - **`1` = PHISHING (MALICIOUS)**

### 2.2 Cisco Umbrella Top-1M Benchmark
- **Location:** `backend/ml/datasets/top-1m.csv`
- **File Size:** 22.6 MB (22,665,850 bytes)
- **Record Count:** 1,000,000 apex domains
- **Purpose:** Ingested during training to augment legitimate apex and diverse path structures, eliminating the collection artifact in PhiUSIIL where legitimate URLs were predominantly prefixed with `www.` and lacked deep paths.

### 2.3 Curated CyberNeura Benchmark URLs
- **Location:** `backend/ml/datasets/urls.csv`
- **File Size:** 6.6 KB
- **Record Count:** 170 curated URLs
- **Distribution:** Safe = 70 (41.2%), Suspicious = 40 (23.5%), Malicious = 60 (35.3%).
- **Purpose:** Regression testing for known brand spoofing (e.g., `paypal-verification-security-update.xyz`), IP hostnames, internationalized domains, and top brand apex URLs.

### 2.4 URL Data Leakage Prevention & Splitting
- **Domain-Aware Splitting:** URLs from the same registered second-level domain (e.g. `*.google.com`, `*.github.com`) are grouped together and never split across train and test partitions.
- **Strict Deduplication:** Prior to vectorization, all URLs are canonicalized (scheme normalization, case folding, query parameter sorting) and deduplicated.
- **Untouched Holdout Partition:** 20% stratified holdout partition (101,013 samples) is frozen exclusively for final evaluation and never exposed during hyperparameter tuning or threshold calibration.

---

## 3. Image Datasets

### 3.1 CIFAKE Benchmark Dataset
- **Location:** `archive/`
- **File Size:** ~420 MB across 120,000 image files
- **Image Dimensions:** $32 \times 32$ pixels, 3 RGB channels, JPEG encoded
- **Provenance:** University of Maryland, Baltimore County (UMBC) CIFAKE benchmark (Bird & Lotfi, 2023)
- **Corrupted / Invalid Files:** 0 (100% readable via PIL without truncation errors)
- **Partition Breakdown:**
  - `archive/train/REAL`: 50,000 authentic images (CIFAR-10 photographic source)
  - `archive/train/FAKE`: 50,000 synthetic images (Stable Diffusion 1.4 generated)
  - `archive/test/REAL`: 10,000 untouched evaluation images
  - `archive/test/FAKE`: 10,000 untouched evaluation images

### 3.2 Label Normalization Specification
- **`0` = AI_GENERATED (SYNTHETIC)**
- **`1` = REAL (AUTHENTIC)**

*(Note: During internal binary cross-entropy loss calculation, fake=1 or fake=0 must match model head logits consistently; in CyberNeura's REST API `/api/v1/detect/image`, predictions return explicit string enums `"AI_GENERATED"` and `"REAL"` alongside calibrated probabilities).*

### 3.3 GenImage Benchmark Toolkit
- **Location:** `GenImage-main/`
- **Contents:** Benchmark harnesses and generator-specific detection evaluation scripts for 8 generative architectures:
  1. ADM (Guided Diffusion)
  2. GLIDE (OpenAI)
  3. Midjourney (v4/v5)
  4. Stable Diffusion (v1.4, v1.5)
  5. VQDM (Vector Quantized Diffusion)
  6. Wukong (Large-scale Chinese diffusion)
  7. BigGAN (Deep generative adversarial network)
  8. CycleGAN (Image-to-image translation)

### 3.4 Generator-Aware Splitting Strategy
To evaluate true out-of-distribution generalization and prevent generative model fingerprint overfitting:
- **Training Set:** Generated via Stable Diffusion 1.4, GLIDE, and ADM.
- **Validation Set:** Separate held-out prompt seeds from training generators.
- **Test Set (Zero-Shot / Unseen):** Evaluated against Midjourney and VQDM to measure transferability across completely unseen diffusion and generative backbones.

