"""
Evidence Correlator for CyberNeura Phase 3.
Evaluates normalized Evidence against deterministic correlation rules, identifies
multi-source consensus findings, and prevents double-counting.
"""
from __future__ import annotations

from typing import List, Optional
from app.evidence.models import Evidence, CorrelatedFinding
from app.evidence.rules import ALL_CORRELATION_RULES, CorrelationRule
from app.utils.logger import get_logger

logger = get_logger(__name__)


class EvidenceCorrelator:
    def __init__(self, rules: Optional[List[CorrelationRule]] = None):
        self._rules = rules or ALL_CORRELATION_RULES

    def correlate(
        self,
        evidence_list: List[Evidence],
        scan_id: Optional[str] = None,
    ) -> List[CorrelatedFinding]:
        """
        Evaluate all registered correlation rules against the provided evidence list.
        Deduplicates findings by finding_type to prevent duplicate outputs.
        """
        findings: List[CorrelatedFinding] = []
        seen_types = set()

        for rule in self._rules:
            try:
                finding = rule.evaluate(evidence_list, scan_id=scan_id)
                if finding and finding.finding_type not in seen_types:
                    findings.append(finding)
                    seen_types.add(finding.finding_type)
            except Exception as exc:
                logger.error(f"Error evaluating rule {getattr(rule, 'rule_id', '?')}: {exc}")

        return findings

    def get_independent_confirmation_count(self, evidence_list: List[Evidence]) -> int:
        """Count distinct confirmed threat intelligence sources."""
        intel_sources = {"GOOGLE_WEB_RISK", "PHISHTANK", "URLHAUS"}
        confirmed = {
            e.source.value for e in evidence_list
            if e.source.value in intel_sources and e.state.value == "CONFIRMED"
        }
        return len(confirmed)


correlator = EvidenceCorrelator()
