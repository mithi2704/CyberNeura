"""
Fluent builder helpers for creating sanitized Evidence and CorrelatedFinding records.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from app.evidence.models import (
    Evidence,
    EvidenceSeverity,
    EvidenceSource,
    EvidenceState,
    EvidenceType,
    CorrelatedFinding,
)


class EvidenceBuilder:
    def __init__(self, source: EvidenceSource, evidence_type: EvidenceType):
        self._id = str(uuid.uuid4())
        self._scan_id: Optional[str] = None
        self._source = source
        self._evidence_type = evidence_type
        self._category: Optional[str] = None
        self._severity = EvidenceSeverity.INFO
        self._state = EvidenceState.SUPPORTING
        self._value: Any = None
        self._score: float = 0.0
        self._confidence: float = 1.0
        self._weight: float = 1.0
        self._supports_risk: bool = True
        self._description: str = ""
        self._metadata: Dict[str, Any] = {}
        self._created_at = datetime.now(timezone.utc).isoformat()

    def with_scan_id(self, scan_id: Optional[str]) -> EvidenceBuilder:
        self._scan_id = scan_id
        return self

    def with_category(self, category: Optional[str]) -> EvidenceBuilder:
        self._category = category
        return self

    def with_severity(self, severity: EvidenceSeverity) -> EvidenceBuilder:
        self._severity = severity
        return self

    def with_state(self, state: EvidenceState) -> EvidenceBuilder:
        self._state = state
        return self

    def with_value(self, value: Any) -> EvidenceBuilder:
        self._value = value
        return self

    def with_score(self, score: float) -> EvidenceBuilder:
        self._score = max(0.0, min(1.0, float(score)))
        return self

    def with_confidence(self, confidence: float) -> EvidenceBuilder:
        self._confidence = max(0.0, min(1.0, float(confidence)))
        return self

    def with_weight(self, weight: float) -> EvidenceBuilder:
        self._weight = max(0.0, float(weight))
        return self

    def supports_risk(self, supports: bool = True) -> EvidenceBuilder:
        self._supports_risk = supports
        return self

    def with_description(self, description: str) -> EvidenceBuilder:
        self._description = description
        return self

    def with_metadata(self, metadata: Dict[str, Any]) -> EvidenceBuilder:
        self._metadata.update(metadata)
        return self

    def build(self) -> Evidence:
        return Evidence(
            id=self._id,
            scan_id=self._scan_id,
            source=self._source,
            evidence_type=self._evidence_type,
            category=self._category,
            severity=self._severity,
            state=self._state,
            value=self._value,
            score=self._score,
            confidence=self._confidence,
            weight=self._weight,
            supports_risk=self._supports_risk,
            description=self._description,
            metadata=self._metadata,
            created_at=self._created_at,
        )


class CorrelatedFindingBuilder:
    def __init__(self, finding_type: str, severity: EvidenceSeverity):
        self._id = str(uuid.uuid4())
        self._scan_id: Optional[str] = None
        self._finding_type = finding_type
        self._severity = severity
        self._confidence: float = 0.9
        self._description: str = ""
        self._sources: List[str] = []
        self._evidence_ids: List[str] = []
        self._rule_id: Optional[str] = None
        self._created_at = datetime.now(timezone.utc).isoformat()

    def with_scan_id(self, scan_id: Optional[str]) -> CorrelatedFindingBuilder:
        self._scan_id = scan_id
        return self

    def with_confidence(self, confidence: float) -> CorrelatedFindingBuilder:
        self._confidence = max(0.0, min(1.0, float(confidence)))
        return self

    def with_description(self, description: str) -> CorrelatedFindingBuilder:
        self._description = description
        return self

    def with_sources(self, sources: List[str]) -> CorrelatedFindingBuilder:
        self._sources = list(dict.fromkeys(sources))
        return self

    def with_evidence_ids(self, evidence_ids: List[str]) -> CorrelatedFindingBuilder:
        self._evidence_ids = list(dict.fromkeys(evidence_ids))
        return self

    def with_rule_id(self, rule_id: Optional[str]) -> CorrelatedFindingBuilder:
        self._rule_id = rule_id
        return self

    def build(self) -> CorrelatedFinding:
        return CorrelatedFinding(
            id=self._id,
            scan_id=self._scan_id,
            finding_type=self._finding_type,
            severity=self._severity,
            confidence=self._confidence,
            description=self._description,
            sources=self._sources,
            evidence_ids=self._evidence_ids,
            rule_id=self._rule_id,
            created_at=self._created_at,
        )
