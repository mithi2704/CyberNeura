"""
Risk thresholds and band classifications for CyberNeura Phase 3.
"""
from __future__ import annotations

from typing import Dict
from app.risk.models import RiskBand
from app.evidence.models import EvidenceSeverity

DEFAULT_THRESHOLDS: Dict[str, int] = {
    "safe": 20,         # 0-19: SAFE
    "low": 40,          # 20-39: LOW
    "suspicious": 60,   # 40-59: SUSPICIOUS
    "high": 80,         # 60-79: HIGH
    "malicious": 80,    # 80-100: CRITICAL / MALICIOUS
}


def score_to_band(score: int) -> RiskBand:
    """Map 0-100 score to fine-grained RiskBand."""
    if score < 20:
        return RiskBand.SAFE
    if score < 40:
        return RiskBand.LOW
    if score < 60:
        return RiskBand.SUSPICIOUS
    if score < 80:
        return RiskBand.HIGH
    return RiskBand.CRITICAL


def score_to_severity(score: int) -> EvidenceSeverity:
    """Map 0-100 score to EvidenceSeverity."""
    if score < 20:
        return EvidenceSeverity.INFO
    if score < 40:
        return EvidenceSeverity.LOW
    if score < 60:
        return EvidenceSeverity.MEDIUM
    if score < 80:
        return EvidenceSeverity.HIGH
    return EvidenceSeverity.CRITICAL


def score_to_prediction(score: int, independent_confirmations: int = 0) -> str:
    """
    Map score to legacy frontend 3-state prediction ('safe', 'suspicious', 'malicious').
    Preserves existing UI contracts.
    """
    if independent_confirmations >= 1 or score >= 80:
        return "malicious"
    if score >= 40:
        return "suspicious"
    return "safe"
