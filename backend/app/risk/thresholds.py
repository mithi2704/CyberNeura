"""
Risk thresholds and band classifications for CyberNeura Phase 3.
"""
from __future__ import annotations

from typing import Dict
from app.risk.models import RiskBand
from app.evidence.models import EvidenceSeverity

DEFAULT_THRESHOLDS: Dict[str, int] = {
    "safe": 30,         # 0-29: SAFE
    "low": 45,          # 30-44: LOW
    "suspicious": 60,   # 45-69: SUSPICIOUS
    "high": 70,         # 70-84: HIGH
    "malicious": 70,    # 70-100: CRITICAL / MALICIOUS
}


def score_to_band(score: int) -> RiskBand:
    """Map 0-100 score to fine-grained RiskBand."""
    if score < 30:
        return RiskBand.SAFE
    if score < 45:
        return RiskBand.LOW
    if score < 60:
        return RiskBand.SUSPICIOUS
    if score < 70:
        return RiskBand.HIGH
    return RiskBand.CRITICAL


def score_to_severity(score: int) -> EvidenceSeverity:
    """Map 0-100 score to EvidenceSeverity."""
    if score < 30:
        return EvidenceSeverity.INFO
    if score < 45:
        return EvidenceSeverity.LOW
    if score < 60:
        return EvidenceSeverity.MEDIUM
    if score < 70:
        return EvidenceSeverity.HIGH
    return EvidenceSeverity.CRITICAL


def score_to_prediction(score: int, independent_confirmations: int = 0) -> str:
    """
    Map score to legacy frontend 3-state prediction ('safe', 'suspicious', 'malicious').
    Preserves existing UI contracts:
    - Score < 30: 'safe'
    - Score 30-69: 'suspicious'
    - Score >= 70 or confirmed threat intel: 'malicious'
    """
    if independent_confirmations >= 1 or score >= 70:
        return "malicious"
    if score >= 30:
        return "suspicious"
    return "safe"

