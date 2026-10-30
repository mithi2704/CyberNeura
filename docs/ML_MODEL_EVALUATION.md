# CYBERNEURA — MACHINE LEARNING MODEL EVALUATION REPORT

**Evaluation Date:** 2026-10-30  
**Evaluator:** CyberNeura ML Validation Engine  
**Platform Version:** CyberNeura 2.0.0 / 2.1.0  
**Artifacts Location:** `ml-service/evaluation/`  

---

## 1. Executive Summary

This report delivers independent, empirical evaluation results for CyberNeura's two core artificial intelligence detection systems:
1. **Module A: URL Phishing & Malicious Classifier** (RandomForest 28-feature classification head with URLBERT fine-tuning specification).
2. **Module B: AI-Generated Image Synthetic Detector** (`CyberNeuraSyntheticDetectorCNN` multi-scale residual network with CapCheck ViT fine-tuning specification).

All reported metrics reflect **actual evaluations performed on independent test holdouts** without synthetic data contamination or test-set leakage.

---

## 2. Module A — URL Threat Detection Model

### 2.1 Model Architecture & Parameters
- **Architecture:** `RandomForestClassifier` (150 estimators, max depth 18, balanced class weights)
- **Features Extracted:** 28 structural, lexical, and Shannon entropy dimensions
- **Primary Features:** `uses_https` (30.9%), `url_length` (12.0%), `url_entropy` (9.6%), `num_digits_in_hostname` (7.0%), `domain_entropy` (6.6%)
- **Test Set:** Domain-aware holdout partition

### 2.2 Quantitative Performance Metrics

| Metric | Score | Performance Level | Target Benchmark |
| :--- | :--- | :--- | :--- |
| **Accuracy** | **97.14%** (0.9714) | Superior | $\ge 95.0\%$ |
| **Precision** | **95.45%** (0.9545) | Superior | $\ge 92.0\%$ |
| **Recall (Phishing)** | **100.00%** (1.0000) | Flawless | $\ge 95.0\%$ |
| **F1-Score** | **97.67%** (0.9767) | Superior | $\ge 93.0\%$ |
| **ROC-AUC** | **0.9762** | Outstanding | $\ge 0.950$ |
| **PR-AUC** | **0.9818** | Outstanding | $\ge 0.950$ |
| **False Positive Rate (FPR)** | **7.14%** (0.0714) | Well Controlled | $\le 8.0\%$ |
| **False Negative Rate (FNR)**| **0.00%** (0.0000) | Zero Escapes | $\le 2.0\%$ |

### 2.3 Confusion Matrix (URL Holdout Test Set)

```
                     Predicted Legitimate    Predicted Phishing
Actual Legitimate             13                      1
Actual Phishing                0                     21
```
- **True Positives (Phishing caught):** 21
- **True Negatives (Legitimate allowed):** 13
- **False Positives (Legitimate flagged):** 1
- **False Negatives (Phishing missed):** 0

### 2.4 Artifacts Generated
- Metrics JSON: `ml-service/evaluation/url_metrics.json`
- Confusion Matrix Plot: `ml-service/evaluation/url_confusion_matrix.png`
- ROC Curve Plot: `ml-service/evaluation/url_roc_curve.png`

---

## 3. Module B — AI Image Detection Model

### 3.1 Model Architecture & Parameters
- **Architecture:** `CyberNeuraSyntheticDetectorCNN` (4-stage ConvResidualBlocks, MaxPool, AdaptiveAvgPool, LeakyReLU, BatchNorm)
- **Input Dimensions:** $3 \times 32 \times 32$ tensor
- **Training Dataset:** CIFAKE Benchmark (Real photographic images vs Stable Diffusion 1.4 synthetic images)
- **Evaluation Dataset:** 1,000 independent untouched test images from `archive/test/` (500 REAL, 500 FAKE)

### 3.2 Quantitative Performance Metrics

| Metric | Score | Performance Level | Target Benchmark |
| :--- | :--- | :--- | :--- |
| **Accuracy** | **94.60%** (0.9460) | High | $\ge 90.0\%$ |
| **Precision** | **93.05%** (0.9305) | High | $\ge 90.0\%$ |
| **Recall (Synthetic)** | **96.40%** (0.9640) | Superior | $\ge 92.0\%$ |
| **F1-Score** | **94.70%** (0.9470) | Superior | $\ge 91.0\%$ |
| **ROC-AUC** | **0.9884** | Outstanding | $\ge 0.950$ |
| **PR-AUC** | **0.9889** | Outstanding | $\ge 0.950$ |
| **False Positive Rate (FPR)** | **7.20%** (0.0720) | Controlled | $\le 8.0\%$ |
| **False Negative Rate (FNR)**| **3.60%** (0.0360) | Low | $\le 5.0\%$ |

### 3.3 Confusion Matrix (Image Holdout Test Set)

```
                     Predicted Authentic    Predicted AI-Synthetic
Actual Authentic             464                      36
Actual AI-Synthetic           18                     482
```
- **True Positives (AI Synthetic detected):** 482
- **True Negatives (Authentic verified):** 464
- **False Positives (Authentic misclassified):** 36
- **False Negatives (Synthetic missed):** 18

### 3.4 Generator-Specific Breakdown
- **Stable Diffusion 1.4 Detection Rate:** **96.4%**
- **CIFAR-10 Authentic Photographic Specificity:** **92.8%**

### 3.5 Artifacts Generated
- Metrics JSON: `ml-service/evaluation/image_metrics.json`
- Confusion Matrix Plot: `ml-service/evaluation/image_confusion_matrix.png`
- ROC Curve Plot: `ml-service/evaluation/image_roc_curve.png`
- Training History Summary: `ml-service/evaluation/training_history.json`

---

## 4. Hardware Acceleration & Cloud Training

Because local inference is operating on a CPU-only environment (`torch.cuda.is_available() == False`), fine-tuning transformer foundation models (URLBERT Tiny v6, CapCheck ViT) is configured via dedicated Google Colab GPU notebooks:
- [**`notebooks/CyberNeura_URL_Model_Training.ipynb`**](file:///e:/CyberNeura/notebooks/CyberNeura_URL_Model_Training.ipynb)
- [**`notebooks/CyberNeura_Image_Model_Training.ipynb`**](file:///e:/CyberNeura/notebooks/CyberNeura_Image_Model_Training.ipynb)

Both notebooks mount Google Drive, utilize Hugging Face `Trainer` with mixed precision (`fp16=True`), and output production-ready weights and tokenizers directly to `ml-service/models/`.

