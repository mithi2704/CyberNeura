import pytest
from app.ml.predictor import predict
from app.services.feature_extractor import extract_features
from app.services.risk_engine import is_verified_authority_domain, _get_registered_domain
from app.risk.scoring import RiskScoringEngine
from app.evidence.models import Evidence, EvidenceSource, EvidenceState, EvidenceType, EvidenceSeverity

@pytest.mark.parametrize("safe_url", [
    "https://developers.cloudflare.com/radar/investigate/url-scanner/?utm_source=chatgpt.com",
    "https://student.sairam.edu.in/reports/details?category=Exam&subCategory=CAT%20Performance&reportSubId=1",
    "https://supabase.com/dashboard/project/oswczmrcjjpbsvdejzwp",
    "https://www.canva.com/design/DAHUkreTPAI/b7xKKLGEV5l59zTD0GUqVA/edit",
    "https://github.com/GenImage-Dataset/GenImage?utm_source=chatgpt.com",
    "https://huggingface.co/umm-maybe/AI-image-detector",
    "https://research.google/blog/a-connectomics-milestone-mapping-the-complete-male-fruit-fly-brain/",
    "https://pals.retool.com/embedded/public/8835581c-9ae4-49fc-84ef-c9d3ebe777f9?ref_id=4a6e41c5",
    "https://www.google.com/search?q=MCA&oq=MCA",
])
def test_safe_domains_classified_as_safe(safe_url):
    # 1. Authority extraction
    dom = _get_registered_domain(safe_url)
    assert is_verified_authority_domain(dom) is True

    # 2. ML model prediction
    features = extract_features(safe_url)
    pred, prob, conf, _ = predict(features)
    assert pred == "safe"
    assert prob <= 0.05

    # 3. Deterministic Risk Scoring
    engine = RiskScoringEngine()
    ev_ml = Evidence(
        scan_id="s-test",
        source=EvidenceSource.ML,
        evidence_type=EvidenceType.ML_PREDICTION,
        value="Safe inference",
        score=prob,
        confidence=conf / 100.0,
        severity=EvidenceSeverity.INFO,
        state=EvidenceState.CONFIRMED,
        description="Machine learning prediction",
        supports_risk=False,
    )
    score, factors = engine.compute_risk(
        scan_id="s-test",
        evidence_list=[ev_ml],
        correlated_findings=[],
        url=safe_url,
    )
    assert score == 0


@pytest.mark.parametrize("phish_url", [
    "https://paypal-security-update.com/login",
    "https://paypal-security-update-account.com/login.php",
    "https://signin.eby.de.zukruygxctzmmqi.civpro.co.za",
])
def test_malicious_urls_detected(phish_url):
    dom = _get_registered_domain(phish_url)
    assert is_verified_authority_domain(dom) is False

    features = extract_features(phish_url)
    pred, prob, conf, _ = predict(features)
    assert pred in ("suspicious", "malicious")
    assert prob >= 0.70
