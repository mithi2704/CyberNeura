# CyberNeura Phase 3: Risk + Evidence Engine Specification

## 1. Executive Summary & Architecture

The CyberNeura Risk + Evidence Engine unifies disparate security telemetry—machine-learning inference, authoritative threat intelligence, DNS resolution records, WHOIS domain registration, lexical URL features, and historical scan telemetry—into a deterministic, fully explainable security assessment.

### Architectural Invariants
1. **Deterministic & Rule-Based**: Does not use an LLM or autonomous agent for scoring, explanations, or recommendations.
2. **Strict Separation of Concepts**:
   - **ML Prediction**: Neural lexical inference.
   - **Threat Intelligence**: Authoritative external database feeds (Google Web Risk, PhishTank, URLhaus).
   - **DNS / WHOIS**: Infrastructure resilience and registration anomalies.
   - **Historical Evidence**: Prior observations with exponential time-decay.
   - **Evidence**: Normalized security facts across all sources.
   - **Risk Score**: Deterministic weighted points (0–100).
   - **Confidence**: Strength and completeness of evidence (0–100%).
   - **Final Assessment**: Classification (`SAFE`, `SUSPICIOUS`, `MALICIOUS`), threat category, and audit explanation.
3. **Fail-Safe Invariant (`UNAVAILABLE != SAFE`)**: Any upstream provider timeout, HTTP 429, or failure is strictly treated as inconclusive (`UNAVAILABLE`), never `SAFE`.
4. **Verified Threat Floor**: Any verified match by an external intelligence source sets a mandatory risk floor of **>= 85/100**.

---

## 2. Signal Pipeline

```
                    Target URL
                         |
      +------------------+------------------+------------------+
      |                  |                  |                  |
      v                  v                  v                  v
Existing ML        Phase 2 Threat       DNS & WHOIS       Historical
Feature Engine      Intelligence       Infrastructure     Scan Data
 (LightGBM)        (Google/PT/UH)       (dnspython/whois) (Scan Store)
      |                  |                  |                  |
      +------------------+------------------+------------------+
                         |
                         v
              EVIDENCE NORMALIZER
       (Standardized Evidence Objects)
                         |
                         v
             EVIDENCE CORRELATION ENGINE
       (Multi-Source Correlated Findings)
                         |
                         v
               RISK SCORING ENGINE
       (Weighted Risk Factors & Contributions)
                         |
       +-----------------+-----------------+
       |                                   |
       v                                   v
CONFIDENCE ENGINE                 EXPLANATION & RECOMMENDATIONS
(Evidence completeness &          (Deterministic audit statements
 contradiction handling)           and structured remediation steps)
       |                                   |
       +-----------------+-----------------+
                         |
                         v
             FINAL SECURITY ASSESSMENT
    (Risk Score, Severity, Factors, Findings, Versioning)
                         |
           +-------------+-------------+
           |             |             |
           v             v             v
       Dashboard     URL Logs       Reports
```

---

## 3. Evidence Taxonomy & Data Model

Every security fact is normalized into an `Evidence` object:

| Field | Type | Description |
| :--- | :--- | :--- |
| `id` | UUID | Unique identifier |
| `scan_id` | UUID | Associated scan identifier |
| `source` | Enum | `ML`, `GOOGLE_WEB_RISK`, `PHISHTANK`, `URLHAUS`, `DNS`, `WHOIS`, `URL_FEATURES`, `HISTORY` |
| `evidence_type` | Enum | Specific signal type (e.g. `ml_prediction`, `phishing_database_match`, `domain_age`) |
| `category` | String | Threat category (e.g. `PHISHING`, `MALWARE`, `SOCIAL_ENGINEERING`) |
| `severity` | Enum | `INFO`, `LOW`, `MEDIUM`, `HIGH`, `CRITICAL` |
| `state` | Enum | `CONFIRMED`, `SUPPORTING`, `CONTRADICTING`, `UNKNOWN`, `UNAVAILABLE` |
| `value` | Any | Raw evaluated value (e.g. "3 days", "185.220.101.5") |
| `score` | Float | Normalized risk contribution (0.0 to 1.0) |
| `confidence` | Float | Confidence in this specific observation (0.0 to 1.0) |
| `supports_risk` | Boolean | `true` if evidence increases risk, `false` if neutral or risk-reducing |
| `description` | String | Human-readable explanation of the evidence |
| `metadata` | JSONB | Raw telemetry context |

---

## 4. Deterministic Correlation Rules

The Evidence Correlation Engine applies deterministic consensus rules:

- **RULE 1 (`HIGH_CONFIDENCE_PHISHING`)**: IF ML probability >= 0.85 AND Google Web Risk detects `SOCIAL_ENGINEERING` -> Emits CRITICAL finding with 98% confidence.
- **RULE 2 (`CONFIRMED_PHISHING`)**: IF PhishTank verifies an active phish -> Emits CRITICAL finding with PhishTank verification confidence.
- **RULE 3 (`CONFIRMED_MALWARE`)**: IF URLhaus confirms active malware host/payload -> Emits CRITICAL finding.
- **RULE 4 (`ML_DATABASE_CONFIRMATION`)**: IF ML probability >= 0.85 AND PhishTank verified -> Emits CRITICAL consensus finding (99% confidence).
- **RULE 5 (`MULTI_SOURCE_CONFIRMATION`)**: IF 2+ distinct external intelligence providers confirm the threat -> Consensus threat emitted, scaling risk score to >= 94.
- **RULE 6 (`PROVIDER_UNAVAILABLE_ISOLATION`)**: IF provider times out or errors -> Records `UNAVAILABLE` evidence without reducing security posture.
- **RULE 7 (`DNS_ANOMALY_SUPPORTING`)**: IF DNS resolution fails -> Recorded as supporting anomaly; domain age or DNS failure alone cannot classify a URL as malicious.
- **RULE 8 (`YOUNG_DOMAIN_SUSPICIOUS_CHARACTERISTICS`)**: IF domain age < 30 days AND URL has high entropy/keywords AND ML risk is elevated -> Emits HIGH severity composite finding.
- **RULE 9 (`PERSISTENT_HISTORICAL_THREAT`)**: IF historical scans repeatedly identified the target as malicious -> Escalates risk score based on decay factor.
- **RULE 10 (`EXPONENTIAL_TIME_DECAY`)**: Historical events decay over time: 1.0 (<=24h), 0.9 (<=7d), 0.75 (<=30d), 0.5 (<=90d), 0.25 (>90d).

---

## 5. Risk Scoring Methodology

Risk scores range from **0 to 100** using configurable weighted factors:

| Component | Default Weight | Max Points | Evaluation Logic |
| :--- | :---: | :---: | :--- |
| **Machine Learning** | 30% | 30.0 | Non-linear curve: probs <0.2 contribute negligible points; probs >0.8 contribute full weight. |
| **Threat Intelligence** | 30% | 30.0 | 0 confirmed = 0 pts; 1 confirmed = 28.5 pts; 2+ confirmed = 30.0 pts. |
| **DNS Infrastructure** | 10% | 10.0 | Clean resolution = 0 pts; No A record = 5.0 pts; DNS anomaly = 6.0 pts. |
| **WHOIS Domain** | 10% | 10.0 | Age > 365d = 0 pts; Age < 30d = 4.0 pts; Age < 7d = 7.0 pts. |
| **URL Features** | 10% | 10.0 | Evaluates IP-hostname (+8.0), Suspicious TLD (+6.0), High entropy (+5.0), keywords (+6.0). |
| **Scan History** | 10% | 10.0 | Prior malicious detections scaled by exponential time-decay (+8.5 * decay). |

### Invariant Rules
- **Verified Match Floor**: If any external provider has a confirmed match, final score is clamped to **>= 85/100**.
- **Multi-Source Boost**: If 2+ external providers confirm, final score is clamped to **>= 94/100**.

---

## 6. Confidence Engine

Confidence (0–100%) measures evidence volume, consistency, and completeness, **distinct from risk score**:

- **Corroboration Bonus**: +25% confidence when multiple providers concur.
- **Telemetry Gap Penalty**: -10% per unavailable external provider (-30% if all 3 fail).
- **Contradiction Penalty**: -18% when ML is high (>=80%) but external feeds are clean; additional -10% if the domain is mature (>1 year old).
- **Consensus Safe Bonus**: +20% when ML is safe (<=15%), all feeds are clean, and domain is mature.

---

## 7. Versioning & Auditability

Every assessment records:
- `risk_engine_version`: Engine logic version (e.g. `1.0.0`).
- `config_version`: Active weights & thresholds version (e.g. `2026.09.1`).
- `risk_factors`: Complete list of factor names, normalized values, point contributions, and directions.
- `correlated_findings`: Rule IDs, corroborating sources, and confidence metrics.
- `created_at`: UTC ISO timestamp.
