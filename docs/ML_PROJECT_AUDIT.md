# CYBERNEURA — COMPLETE MACHINE LEARNING PROJECT AUDIT

**Audit Date:** 2026-10-30  
**Auditor:** Senior ML Engineer & Cybersecurity Systems Architect  
**Platform Version:** CyberNeura 2.0.0 / Phase 7 (AI Media Security)  
**Workspace:** `E:\CyberNeura`  
**Execution Environment:** Windows 11, Python 3.10.11 (CPU-only, CUDA Unavailable), Node v24.11.1, npm 11.6.2  

---

## 1. Executive Summary

CyberNeura is an enterprise-grade AI cybersecurity intelligence platform. A deep inspection of the entire codebase revealed a mature, highly developed architecture combining **URL Threat Detection (Phases 1–6)** and **Multimodal AI Media Security (Phase 7)**.

Two fully functional ML models with saved weights and metadata exist in the project:
1. **URL Threat Classifier**: A 150-tree `RandomForestClassifier` trained on 404,050 samples from the **PhiUSIIL Phishing Dataset**, **Cisco Umbrella Top-1M**, and curated benchmarks, achieving **98.29% accuracy** on 28 structural/entropy/lexical features.
2. **AI-Generated Image Synthetic Detector**: A 4-stage residual convolutional neural network (`CyberNeuraSyntheticDetectorCNN`) trained with PyTorch on the **CIFAKE / GenImage** benchmark (120,000 images in `archive/`), achieving **94.73% accuracy** and **0.9864 ROC-AUC**.

However, several critical gaps and discrepancies exist against the target specifications:
- The current URL model is a tabular **RandomForest**, not the preferred **URLBERT Tiny v6** or **TinyBERT** transformer.
- The current image model is a custom **32x32 PyTorch CNN**, not the preferred pretrained **CapCheck ViT** (`aaronkantrowitz/ai-image-detection`) or **Smaug AI Image Detector**.
- A critical concurrency bug was identified: `url_model.joblib` was serialized with `n_jobs=-1`, which causes `joblib.Parallel` / `loky` process pool deadlocks inside the FastAPI `asyncio` event loop on Windows.
- There is currently **no standalone Node.js API Gateway** (the React frontend communicates directly with FastAPI at `http://localhost:8000/api/v1`).
- The standalone `ml-service/` directory, training notebooks (`notebooks/*.ipynb`), and standalone evaluation curve artifacts (`ml-service/evaluation/`) are missing.

---

## 2. Component Inventory & Status Matrix

| ID | Component | Status | Location / Artifact | Notes |
|:---|:---|:---|:---|:---|
| **A** | **URL Threat Model** | **COMPLETED** (Tabular) / **NEEDS IMPROVEMENT** (Transformer) | `backend/ml/models/url_model.joblib` (22.2 MB)<br>`backend/ml/models/model_metadata.json` | 150-tree RandomForest on 28 features (98.29% acc). Needs URLBERT Tiny v6 implementation. |
| **B** | **AI Image Detection Model** | **COMPLETED** (CNN) / **NEEDS IMPROVEMENT** (ViT) | `backend/ml/models/image_detector.pth` (9.7 MB)<br>`backend/ml/models/image_model_metadata.json` | PyTorch ResNet CNN trained on CIFAKE (94.73% acc). Needs CapCheck ViT implementation. |
| **C** | **Dataset Preprocessing** | **COMPLETED** (Backend) / **PARTIALLY COMPLETED** (Modular) | `backend/scripts/train_model.py`<br>`backend/scripts/train_image_model.py`<br>`backend/app/services/feature_extractor.py` | Full 28-feature extractor, domain normalization, and image normalization pipeline exist. |
| **D** | **Fine-Tuning / Training Scripts** | **COMPLETED** (Local Scripts) / **MISSING** (Modular & Colab) | `backend/scripts/train_model.py`<br>`backend/scripts/train_image_model.py` | Training scripts exist for RF and CNN. Missing Colab notebooks for GPU transformer fine-tuning. |
| **E** | **Evaluation Scripts & Curves** | **PARTIALLY COMPLETED** | Inside training scripts & metadata JSON | Metrics recorded in JSON; missing standalone evaluation script, ROC/PR curves, and confusion matrix PNGs. |
| **F** | **Saved Model Artifacts** | **COMPLETED** (Existing) / **MISSING** (Hugging Face) | `backend/ml/models/url_model.joblib`<br>`backend/ml/models/image_detector.pth` | Verified binary weights exist and pass inference validation tests. |
| **G** | **FastAPI Prediction Endpoints** | **COMPLETED** | `backend/app/api/routes/scan.py`<br>`backend/app/api/routes/media.py` | `/scan` and `/media/images/analyze` operational. Missing aliases `/api/v1/scan/url` & `/api/v1/detect/image`. |
| **H** | **Node.js Backend Gateway** | **MISSING** | N/A | React frontend currently connects directly to FastAPI. No intermediate Node.js gateway currently exists. |
| **I** | **Frontend Integration** | **COMPLETED** | `frontend/src/pages/URLLogs/`<br>`frontend/src/pages/MediaSecurity/`<br>`frontend/src/lib/api/` | URL Scanner and Media Security UI (55 KB component) are fully wired to backend APIs. |
| **J** | **Prediction History & Reporting** | **COMPLETED** | `backend/app/services/scan_store.py`<br>`backend/scripts/migration_phase*.sql` | In-memory ring buffer with disk sync + Supabase PostgreSQL schema and migration scripts. |

---

## 3. Existing Models Discovered

### Model 1: CyberNeura URL Threat Classifier (v2.0.0)
- **Framework:** `scikit-learn` (`RandomForestClassifier`)
- **Weights File:** `backend/ml/models/url_model.joblib` (22,195,497 bytes / 22.2 MB)
- **Metadata File:** `backend/ml/models/model_metadata.json`
- **Architecture Details:**
  - `n_estimators`: 150
  - `max_depth`: 18
  - `min_samples_split`: 4
  - `class_weight`: "balanced"
  - `features`: 28 structural, security, lexical, and Shannon entropy features (e.g., `uses_https`, `url_entropy`, `domain_entropy`, `subdomain_depth`, `is_suspicious_tld`)
- **Training Samples:** 404,050
- **Test Samples:** 101,013 (Stratified holdout)
- **Performance:**
  - Accuracy: **98.29%**
  - Precision: **98.28%**
  - Recall: **98.29%**
  - F1-Score: **98.27%**
- **Top 5 Features by Importance:**
  1. `uses_https`: 30.93%
  2. `url_length`: 12.03%
  3. `url_entropy`: 9.58%
  4. `num_digits_in_hostname`: 6.97%
  5. `domain_entropy`: 6.63%

### Model 2: CyberNeura Synthetic Detector CNN (v1.1.0)
- **Framework:** PyTorch (`CyberNeuraSyntheticDetectorCNN`)
- **Weights File:** `backend/ml/models/image_detector.pth` (9,726,461 bytes / 9.7 MB)
- **Metadata File:** `backend/ml/models/image_model_metadata.json`
- **Architecture Details:**
  - Input: $3 \times 32 \times 32$ tensor (RGB normalized)
  - Initial Stem: Conv2d(3, 32, 3x3) + BatchNorm + LeakyReLU
  - 4 Residual Stages: `ConvResidualBlock` with skip connections and residual pooling (Channels: 32 -> 64 -> 128 -> 256 -> 256)
  - Global Average Pooling (AdaptiveAvgPool2d(1, 1))
  - Classifier Head: Linear(256, 128) -> LeakyReLU -> Dropout(0.35) -> Linear(128, 1) -> Sigmoid
- **Training Samples:** 12,000 (Balanced 6k Real, 6k Fake)
- **Test Samples:** 3,000
- **Performance:**
  - Accuracy: **94.73%**
  - Precision: **93.91%**
  - Recall: **95.67%**
  - F1-Score: **94.78%**
  - ROC-AUC: **0.9864**

---

## 4. Datasets Discovered & Analysis

| Dataset Path | Size | Records / Files | Format & Columns | Status & Quality |
|:---|:---|:---|:---|:---|
| `backend/ml/datasets/PhiUSIIL_Phishing_URL_Dataset.csv` | 56.8 MB | ~235,795 URLs | CSV (56 columns including `URL`, `label`, `URLLength`, `Domain`) | **Verified**. Label mapping: raw `1` = legitimate, `0` = phishing. Cleaned in `train_model.py`. |
| `backend/ml/datasets/top-1m.csv` | 22.6 MB | 1,000,000 domains | CSV (Rank, Domain) | **Verified**. Cisco Umbrella top domains used for legitimate domain augmentation. |
| `backend/ml/datasets/urls.csv` | 6.6 KB | 171 URLs | CSV (`url`, `label`) | **Verified**. Curated benchmark URLs (0 = Safe, 1 = Suspicious, 2 = Malicious). |
| `archive/train/REAL/` | ~175 MB | 50,000 images | JPG/PNG (32x32) | **Verified**. Authentic photographic samples (CIFAKE / CIFAR-10). |
| `archive/train/FAKE/` | ~175 MB | 50,000 images | JPG/PNG (32x32) | **Verified**. Synthetic diffusion-generated samples (CIFAKE / Stable Diffusion 1.4). |
| `archive/test/REAL/` | ~35 MB | 10,000 images | JPG/PNG (32x32) | **Verified**. Independent evaluation holdout (real). |
| `archive/test/FAKE/` | ~35 MB | 10,000 images | JPG/PNG (32x32) | **Verified**. Independent evaluation holdout (synthetic). |
| `GenImage-main/` | ~1.2 GB | Benchmark scripts & samples | Official GenImage codebase | **Codebase only**. Contains generation code and evaluation harnesses for 8 generators. |

---

## 5. Existing Errors, Invariants & Defect Log

### 1. `n_jobs=-1` Multiprocessing Deadlock in Joblib Model
- **Severity:** HIGH / LATENT BUG
- **Diagnosis:** `url_model.joblib` was trained with `n_jobs=-1`. When loaded inside a FastAPI web process on Windows, calling `clf.predict_proba()` triggers `joblib.Parallel` which spawns `loky` worker processes. Inside an `asyncio` event loop, this locks semaphores and causes thread deadlocks or startup hangs.
- **Remedy:** Automatically enforce `clf.n_jobs = 1` immediately upon unpickling in `app.ml.predictor`.

### 2. Working Directory Sensitivity for Model Paths
- **Severity:** MEDIUM
- **Diagnosis:** When running tests or commands from workspace root (`E:\CyberNeura`), `settings.model_path = "ml/models/url_model.joblib"` resolves to `E:\CyberNeura\ml\...` instead of `E:\CyberNeura\backend\ml\...`.
- **Remedy:** Use absolute resolution relative to backend root: `Path(__file__).resolve().parent.parent / "ml/models/..."`.

### 3. Missing `transformers` in Local Python
- **Severity:** INFORMATIONAL
- **Diagnosis:** The local environment has `torch==2.10.0` and `scikit-learn==1.3.1`, but `transformers` is not installed.
- **Hardware Constraint:** `torch.cuda.is_available() == False` (CPU-only).
- **Remedy:** Adhere strictly to Rule 18: Generate standalone Google Colab GPU notebooks (`notebooks/CyberNeura_URL_Model_Training.ipynb` and `notebooks/CyberNeura_Image_Model_Training.ipynb`) with Google Drive mounting and free T4 GPU support, while providing seamless CPU/mock inference fallbacks locally.

### 4. `tldextract` Deprecation Warning
- **Severity:** LOW
- **Diagnosis:** `feature_extractor.py` accesses `ext.registered_domain`, which is deprecated in `tldextract>=5.0` in favor of `ext.top_domain_under_public_suffix`.
- **Remedy:** Update to use `top_domain_under_public_suffix` with fallback to `registered_domain`.

---

## 6. Proposed Implementation Plan

### Step 1: Fix Existing Model Loading & Resolve `n_jobs` Concurrency
- Enforce `_model.n_jobs = 1` in `app/ml/predictor.py` on load.
- Ensure model file path resolution works regardless of invocation directory.
- Verify all existing 162 backend unit tests pass cleanly.

### Step 2: Implement Modular ML Service Structure (`ml-service/`)
- Create `ml-service/` structure without breaking existing backend:
  - `ml-service/training/url/` (preprocess, train, evaluate, inference)
  - `ml-service/training/image/` (preprocess, train, evaluate, inference)
  - `ml-service/models/` (model weights, configs, metadata)
  - `ml-service/evaluation/` (JSON metrics, confusion matrices, ROC/PR plots)

### Step 3: URL Model Enhancements (URLBERT Tiny v6 & Transformer Integration)
- Create `ml-service/training/url/preprocess_url.py` with domain-aware and stratified splitting.
- Create `ml-service/training/url/train_url.py` supporting Hugging Face `CrabInHoney/urlbert-tiny-v6` with CPU fallback and checkpointing.
- Generate `notebooks/CyberNeura_URL_Model_Training.ipynb` for Google Colab GPU training.
- Generate comprehensive evaluation curves (`url_confusion_matrix.png`, `url_roc_curve.png`, `url_metrics.json`).

### Step 4: AI Image Model Enhancements (CapCheck ViT & Multi-Generator Benchmarking)
- Create `ml-service/training/image/preprocess_image.py` supporting CIFAKE & GenImage generators.
- Create `ml-service/training/image/train_image.py` supporting `aaronkantrowitz/ai-image-detection` (CapCheck ViT) and residual CNN fine-tuning.
- Generate `notebooks/CyberNeura_Image_Model_Training.ipynb` for Google Colab GPU training.
- Generate image evaluation curves (`image_confusion_matrix.png`, `image_roc_curve.png`, `image_metrics.json`).

### Step 5: FastAPI Prediction Endpoints
- Implement requested standardized endpoints:
  - `GET /health`
  - `GET /api/v1/models/info`
  - `POST /api/v1/scan/url`
  - `POST /api/v1/detect/image`
- Retain all existing Phase 2–7 endpoints (`/scan`, `/media/images/analyze`, `/agent/*`, `/risk/*`).

### Step 6: Node.js API Gateway Integration
- Create Node.js backend (`backend-node/` or gateway module) configured with `ML_SERVICE_URL=http://localhost:8000`.
- Implement URL scan controller, Image detection controller, file validation, and error forwarding.

### Step 7: Frontend & Dashboard Wiring
- Verify and enhance URL Scan results (Legitimate/Phishing, probability, risk assessment, evidence).
- Verify and enhance Image Detection results (Preview, Real/AI probability, C2PA provenance, ELA forensics).

### Step 8: Complete Testing & Deployment Documentation
- Run automated tests across all endpoints.
- Generate `docs/ML_MODEL_EVALUATION.md`.
- Update `README.md` and create `runproject.md` with step-by-step execution instructions.

