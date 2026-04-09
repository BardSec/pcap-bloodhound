"""Domain model for evidence-based findings, indicators, and investigation threads."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class Indicator:
    """Atomic signal contributing to a finding's confidence score.

    Each indicator represents a single measurable condition (e.g., 'low CV timing',
    'high entropy subdomain') with a weight that determines how much it contributes
    to the parent finding's confidence score.
    """
    name: str
    description: str
    weight: float           # 0.0–1.0, contribution to confidence
    met: bool               # Whether this indicator was triggered
    value: Any = None       # The measured value (e.g., 0.08 for CV)
    threshold: Any = None   # The threshold used (e.g., 0.15 for CV)
    detail: str = ""        # Extra context shown in the UI

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "weight": self.weight,
            "met": self.met,
            "value": self.value,
            "threshold": self.threshold,
            "detail": self.detail,
        }


@dataclass
class Finding:
    """Evidence-based detection with structured confidence scoring.

    A finding is a hypothesis, not a conclusion. The confidence score is computed
    from weighted indicators, and alternative explanations are always provided
    so analysts can make informed judgments.
    """
    id: str                 # Unique ID, e.g. "c2_beacon:10.1.5.23->203.0.113.45:443"
    analyzer: str           # Source analyzer name, e.g. "c2_beaconing"
    title: str              # Short hypothesis, e.g. "Possible C2 beaconing"
    description: str        # One-sentence explanation of what was observed
    confidence: int         # 0–100, computed from indicators
    severity: str           # CRITICAL, HIGH, MEDIUM, LOW, INFO
    indicators: list[Indicator] = field(default_factory=list)
    entities: list[str] = field(default_factory=list)       # IPs, domains involved
    entity_roles: dict[str, str] = field(default_factory=dict)  # entity -> role
    alternative_explanations: list[str] = field(default_factory=list)
    first_seen: float | None = None     # Epoch timestamp
    last_seen: float | None = None
    raw_data: dict[str, Any] = field(default_factory=dict)  # Original analyzer output

    @staticmethod
    def compute_confidence(indicators: list[Indicator]) -> int:
        """Compute confidence from weighted indicators. Returns 0–100."""
        if not indicators:
            return 0
        total_weight = sum(ind.weight for ind in indicators)
        if total_weight == 0:
            return 0
        met_weight = sum(ind.weight for ind in indicators if ind.met)
        return min(100, round((met_weight / total_weight) * 100))

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "analyzer": self.analyzer,
            "title": self.title,
            "description": self.description,
            "confidence": self.confidence,
            "severity": self.severity,
            "indicators": [ind.to_dict() for ind in self.indicators],
            "entities": self.entities,
            "entity_roles": self.entity_roles,
            "alternative_explanations": self.alternative_explanations,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
        }


@dataclass
class TimelineEvent:
    """Single event on an investigation timeline."""
    timestamp: float
    event_type: str         # "dns_query", "connection", "detection", "flow_start", etc.
    description: str
    source_analyzer: str
    severity: str = "INFO"
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "event_type": self.event_type,
            "description": self.description,
            "source_analyzer": self.source_analyzer,
            "severity": self.severity,
        }


@dataclass
class InvestigationThread:
    """Entity-centric grouping of findings and events.

    A thread aggregates everything the tool knows about a single entity (host,
    domain, or external endpoint) into a unified investigation view with
    narrative summary, risk rollup, and timeline.
    """
    entity: str             # e.g. "10.1.5.23" or "evil.example.com"
    entity_type: str        # "internal_host", "external_host", "domain"
    summary: str            # Auto-generated narrative
    risk_score: int         # 0–100, derived from findings
    findings: list[Finding] = field(default_factory=list)
    timeline: list[TimelineEvent] = field(default_factory=list)
    related_entities: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)  # Host stats, etc.

    @staticmethod
    def compute_risk_score(findings: list[Finding]) -> int:
        """Aggregate risk from findings. Highest confidence dominates, others add diminishing weight."""
        if not findings:
            return 0
        sorted_f = sorted(findings, key=lambda f: f.confidence, reverse=True)
        score = sorted_f[0].confidence
        for f in sorted_f[1:]:
            # Each additional finding adds a fraction of its confidence
            score += f.confidence * 0.2
        return min(100, round(score))

    def to_dict(self) -> dict[str, Any]:
        return {
            "entity": self.entity,
            "entity_type": self.entity_type,
            "summary": self.summary,
            "risk_score": self.risk_score,
            "findings": [f.to_dict() for f in self.findings],
            "timeline": [e.to_dict() for e in self.timeline],
            "related_entities": self.related_entities,
            "metadata": self.metadata,
        }
