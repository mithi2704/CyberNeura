# CyberNeura Deepfake Video Detection Architecture & Signal Engineering

## 1. Algorithmic Overview
Detecting modern face-swap, neural reenactment, and generative video manipulations requires a multi-layered signal pipeline combining spatial boundary forensics with temporal consistency tracking.

The CyberNeura Deepfake Engine runs on a 5-stage pipeline:

```
[ Video Bitstream ]
        |
        v
1. Safe Decoding & Keyframe Extraction (OpenCV / PyTorch)
        |
        v
2. Privacy-Preserving Face Detection & Tracking (IoU Association)
        |
        v
3. Spatial Boundary Seam & Skin Residual Classifier
        |
        v
4. Temporal Optical Flow & Trajectory Stability Analysis
        |
        v
5. Robust Aggregation & Risk Scoring
```

---

## 2. Face Boundary Seam Analysis
Face swap generators (e.g. DeepFaceLab, SimSwap, RoOP) place a synthesized face onto a target head and blend the perimeter using Gaussian or Poisson blending masks.

This leaves unnatural boundary gradients:
$$\nabla I_{\text{boundary}} = \frac{1}{|M|} \sum_{(x,y) \in M} |\nabla I(x, y)|$$
Where $M$ is the rectangular border margin around the candidate face box. The engine samples pixels immediately inside and outside the perimeter; sharp gradient transitions or unnatural blur rings indicate blending artifacts.

---

## 3. Privacy-Preserving Invariants
- **No Face Recognition**: The engine operates purely on geometric bounding boxes: `{"x": int, "y": int, "w": int, "h": int}`.
- **Zero Vector Embeddings**: No ArcFace, FaceNet, or identity embeddings are extracted, cached, or persisted.
- **No Demographics**: The system does not classify gender, race, age, or any personal characteristics.

---

## 4. Temporal Trajectory Analysis
Natural human motion in video follows smooth physical trajectories. Algorithmic face replacement creates inter-frame jitter:
1. **Luminance Variance**:
   $$\Delta L = \frac{1}{H \times W} \sum_{x,y} |L_{t}(x,y) - L_{t-1}(x,y)|$$
2. **Track Jitter (Second-Order Difference)**:
   $$\vec{a}_t = \vec{p}_{t+1} - 2\vec{p}_t + \vec{p}_{t-1}$$
   Unnatural spikes in second-order acceleration $\vec{a}_t$ across continuous face tracks flag algorithmic alignment shudder.

---

## 5. Decision Aggregation & Thresholds

| Risk Score | Classification | Action / Advisory |
|---|---|---|
| `0.0 – 34.9` | `LIKELY_AUTHENTIC` | Standard video; no significant synthetic artifacts observed. |
| `35.0 – 69.9` | `SUSPICIOUS` | Boundary seams or temporal anomalies detected; human review advised. |
| `70.0 – 100.0` | `LIKELY_DEEPFAKE` | Multiple confirmed manipulation signals detected across contiguous keyframes. |
| *Low Confidence* | `INCONCLUSIVE` | Blurry frames or low resolution prevents confident assessment. |
