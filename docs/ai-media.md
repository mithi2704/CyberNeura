# CyberNeura AI Media Security Architecture (Phase 7)

## 1. Overview
CyberNeura Phase 7 expands the platform from URL and domain threat intelligence into a **multimodal cybersecurity intelligence suite**. It introduces automated, privacy-preserving defenses against:
1. **Synthetic & AI-Generated Images**: Diffusion and GAN generated imagery, algorithmic manipulation, and spoofing.
2. **Deepfake Videos**: Face-swapped videos, boundary blending seams, temporal jitter, and codec inconsistencies.
3. **C2PA / Content Credentials**: Cryptographic provenance tracking, digital signing validation, and synthetic watermark detection.

---

## 2. Core Invariants & Boundaries

### Privacy Boundary
- **STRICT INVARIANT**: **No facial recognition, person identification, biometric indexing, or demographic profiling is performed or stored.**
- Faces are tracked solely via relative bounding box coordinates and standard signal metrics (blur, illumination, boundary gradient) to assess temporal stability and synthetic blending seams.

### Provenance Invariant
- **CRITICAL INVARIANT**: **`PROVENANCE_ABSENT != AI-GENERATED`**
- A vast majority of authentic internet media does not carry C2PA metadata. Absence of provenance is a neutral observation (`PROVENANCE_ABSENT`), not proof of deception.
- Conversely, a valid C2PA manifest from an AI generator (e.g. OpenAI DALL-E) cryptographically confirms the media *is* synthetic.

### Authoritative Architecture
- Phase 7 does **not** replace the authoritative Phase 3 Risk & Evidence Engine or Phase 4 AI Agent.
- All media model inferences, provenance claims, and physical forensics are normalized into Phase 3 `Evidence` objects and correlated with platform findings.

---

## 3. Image Synthetic Detection Pipeline

```
IMAGE UPLOAD (PNG/JPEG/WEBP)
      |
      v
Magic Byte & Decompression Bomb Validation (Max 50M Pixels)
      |
      +---> Preprocessing & Multi-Signal Extraction
      |         |
      |         +---> 2D Spectral FFT Frequency Residual Analysis
      |         +---> Spatial Laplacian Gradient Variance
      |         +---> Color Channel Covariance (R-G / R-B divergence)
      |         +---> Neural Convolutional Feature Extractor
      |
      +---> Cryptographic C2PA / Content Credentials Parser
      |
      +---> Error Level Analysis (ELA) & Noise Quadrant Forensics
      |
      v
Media Evidence Builder (Phase 3 Normalization)
      |
      v
Media Risk Engine (0-100 Risk Score & Calibrated Confidence)
      |
      +---> ScanStore Persistence (with Local Disk Sync)
      +---> Realtime Event Broadcasting (Supabase Realtime / WebSocket)
```

### Signal Weights
- **Neural Convolutional Residuals**: 50%
- **2D Fourier High-Frequency Energy Ratio**: 30%
- **Spatial Gradient Variance**: 15%
- **Color Channel Divergence**: 5%

---

## 4. Video Deepfake Inspection Subsystem

### Asynchronous Processing Model
Because multi-frame video decoding and face tracking exceed typical HTTP timeouts (10–30s), video analysis is executed via an **asynchronous background queue**:
1. `POST /api/v1/media/videos/analyze` -> Validates video container headers and enqueues job -> Returns `job_id`.
2. Asynchronous worker processes sampled keyframes with concurrency control (semaphore = 2).
3. Real-time progress updates (`0%` to `100%`) are broadcast over WebSocket / Supabase Realtime channels.
4. Clients poll `GET /api/v1/media/jobs/{job_id}` or listen to `MEDIA_ANALYSIS_COMPLETED`.

### Pipeline Stages
1. **Uniform Keyframe Sampler**: Configurable sampling rate (default: 2.0 FPS, max 60 frames).
2. **Anonymous Face Detector**: Detects faces with OpenCV cascade/filters, measures blur and illumination. Zero biometric vectors.
3. **IoU Face Tracker**: Associates faces across time to form continuous tracklets.
4. **Deepfake Frame Classifier**: Evaluates boundary blending mask seams and skin texture over-smoothing.
5. **Temporal Consistency Engine**: Measures inter-frame optical flow acceleration, luminance jumps, and boundary jitter.
6. **Robust Aggregation**: Computes 95th percentile risk, sustained manipulation streaks, and frame-level timelines.

---

## 5. API Endpoints Reference

| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/api/v1/media/images/analyze` | Synchronous synthetic image analysis |
| `POST` | `/api/v1/media/videos/analyze` | Asynchronous deepfake video submission |
| `GET` | `/api/v1/media/jobs/{job_id}` | Check status and progress of video job |
| `POST` | `/api/v1/media/jobs/{job_id}/cancel` | Cancel an active video job |
| `GET` | `/api/v1/media/{media_id}` | Retrieve asset metadata |
| `GET` | `/api/v1/media/{media_id}/assessment` | Retrieve full multimodal assessment |
| `GET` | `/api/v1/media/{media_id}/evidence` | Retrieve Phase 3 normalized evidence items |
| `GET` | `/api/v1/media/{media_id}/provenance` | Retrieve C2PA / Content Credentials claims |
| `GET` | `/api/v1/media/{media_id}/forensics` | Retrieve ELA and noise forensics |
| `GET` | `/api/v1/media/{media_id}/frames` | Retrieve keyframe timeline and face manipulation scores |
| `GET` | `/api/v1/media/stats` | Global telemetry and detection counts |
| `GET` | `/api/v1/media/assessments` | Recent assessment history list |
| `DELETE` | `/api/v1/media/{media_id}` | Purge asset and analysis records |

---

## 6. AI Agent Integration (Phase 4 Extension)
The AI Security Agent includes 6 defensive media tools:
1. `analyze_image`: Inspect an image file or URL for synthetic manipulation.
2. `analyze_video`: Check or monitor a deepfake video inspection job.
3. `get_media_evidence`: Query normalized Phase 3 evidence records.
4. `get_media_provenance`: Query C2PA manifests and signatures.
5. `get_media_forensics`: Query ELA and noise variance anomalies.
6. `get_frame_analysis`: Retrieve keyframe timeline and face scores.
