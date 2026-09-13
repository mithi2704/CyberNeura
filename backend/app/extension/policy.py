"""
Deterministic Policy Engine for CyberNeura Browser Extension (Phase 6).
Converts multidimensional risk assessments, threat intelligence, and confidence
into authoritative browser enforcement decisions: ALLOW, WARN, or BLOCK.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple
from app.config import settings
from app.extension.models import ExtensionDecision


class PolicyEngine:
    """
    Authoritative Policy Engine translating SecurityAssessments into
    client-side enforcement actions (ALLOW, WARN, BLOCK).
    """
    def __init__(
        self,
        safe_threshold: Optional[int] = None,
        suspicious_threshold: Optional[int] = None,
        strict_mode: Optional[bool] = None,
        allow_override: Optional[bool] = None,
        policy_version: str = "1.0.0",
    ):
        self.safe_threshold = safe_threshold or settings.risk_threshold_safe
        self.suspicious_threshold = suspicious_threshold or settings.risk_threshold_suspicious
        self.strict_mode = strict_mode if strict_mode is not None else settings.extension_strict_mode
        self.allow_override = allow_override if allow_override is not None else settings.extension_allow_override
        self.policy_version = policy_version

    def evaluate(
        self,
        risk_score: int,
        prediction: str,
        confidence: float,
        threat_category: Optional[str] = None,
        severity: Optional[str] = None,
        threat_intel: Optional[Dict[str, Any]] = None,
    ) -> Tuple[ExtensionDecision, bool, List[str], List[str]]:
        """
        Evaluates risk signals and produces:
        - decision: ExtensionDecision (ALLOW, WARN, BLOCK)
        - allow_override: bool
        - reasons: List[str] explaining the decision
        - recommendations: List[str] defensive user action guidance
        """
        reasons: List[str] = []
        recommendations: List[str] = []
        prediction_upper = (prediction or "SAFE").upper()
        severity_upper = (severity or "LOW").upper()

        # Check for verified external threat intelligence match
        has_intel_match = False
        if threat_intel:
            for p_key in ("google_webrisk", "phishtank", "urlhaus"):
                p_data = threat_intel.get(p_key)
                if isinstance(p_data, dict) and p_data.get("matched"):
                    has_intel_match = True
                    provider_name = p_key.replace("_", " ").title()
                    reasons.append(f"Confirmed malicious by threat intelligence provider ({provider_name})")

        # 1. Critical / High-Confidence Malicious Threat -> BLOCK
        if has_intel_match or severity_upper in ("CRITICAL", "HIGH") or (risk_score >= self.suspicious_threshold and prediction_upper == "MALICIOUS"):
            if confidence >= 65.0 or has_intel_match or self.strict_mode:
                decision = ExtensionDecision.BLOCK
                # High-confidence confirmed malicious blocks cannot be bypassed unless policy explicitly permits
                can_override = self.allow_override and not has_intel_match and severity_upper != "CRITICAL"
                if not reasons:
                    reasons.append(f"High risk score ({risk_score}/100) indicates active cyber threat")
                if prediction_upper == "MALICIOUS":
                    reasons.append("Machine learning model detected malicious attack patterns")
                recommendations.append("Do not proceed to this website.")
                recommendations.append("Close this browser tab immediately to avoid compromise.")
                return decision, can_override, reasons, recommendations

            # Malicious but low confidence without threat intel confirmation -> WARN
            decision = ExtensionDecision.WARN
            can_override = True
            reasons.append(f"Elevated risk score ({risk_score}/100) detected with moderate confidence ({int(confidence)}%)")
            recommendations.append("Exercise extreme caution before continuing.")
            recommendations.append("Do not enter login credentials, passwords, or payment cards.")
            return decision, can_override, reasons, recommendations

        # 2. Suspicious / Elevated Risk -> WARN
        # Only assign WARN if prediction is actually SUSPICIOUS or risk score is elevated with non-safe prediction
        if (prediction_upper == "SUSPICIOUS") or (risk_score >= self.suspicious_threshold and prediction_upper != "SAFE") or (severity_upper == "MEDIUM" and prediction_upper != "SAFE"):
            decision = ExtensionDecision.WARN
            can_override = True
            reasons.append(f"Suspicious signals detected with risk score {risk_score}/100")
            if threat_category:
                reasons.append(f"Associated threat category: {threat_category}")
            recommendations.append("Do not enter personal or financial information on this site.")
            recommendations.append("Verify the URL address carefully before interacting.")
            return decision, can_override, reasons, recommendations


        # 3. Safe / Benign -> ALLOW
        decision = ExtensionDecision.ALLOW
        can_override = False
        reasons.append(f"URL evaluated as safe with risk score {risk_score}/100")
        recommendations.append("No immediate threats detected. Proceed normally.")
        return decision, can_override, reasons, recommendations

    def get_rules_description(self) -> Dict[str, str]:
        return {
            "RULE_ALLOW_SAFE": f"Risk < {self.safe_threshold} and prediction SAFE => ALLOW",
            "RULE_WARN_SUSPICIOUS": f"Risk {self.safe_threshold}-{self.suspicious_threshold - 1} or prediction SUSPICIOUS => WARN (override allowed)",
            "RULE_BLOCK_MALICIOUS_HIGH_CONF": f"Risk >= {self.suspicious_threshold} and prediction MALICIOUS with confidence >= 65% => BLOCK",
            "RULE_BLOCK_THREAT_INTEL": "Confirmed external Threat Intelligence match => BLOCK",
            "RULE_WARN_MALICIOUS_LOW_CONF": f"Risk >= {self.suspicious_threshold} with confidence < 65% (non-strict) => WARN",
            "RULE_FAIL_SAFE": "Backend timeout or connection failure => ALLOW (unless strict mode enabled)",
        }


# Singleton policy engine instance
policy_engine = PolicyEngine()
