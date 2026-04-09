"""Tests for the findings domain model and confidence scoring."""

import pytest

from app.analysis.findings import Finding, Indicator, InvestigationThread, TimelineEvent


class TestIndicator:
    def test_to_dict(self):
        ind = Indicator(
            name="test_indicator",
            description="A test",
            weight=0.5,
            met=True,
            value=42,
            threshold=30,
        )
        d = ind.to_dict()
        assert d["name"] == "test_indicator"
        assert d["met"] is True
        assert d["weight"] == 0.5

    def test_unmet_indicator(self):
        ind = Indicator(name="x", description="x", weight=0.3, met=False, value=10, threshold=20)
        assert ind.met is False


class TestFinding:
    def test_compute_confidence_all_met(self):
        indicators = [
            Indicator(name="a", description="a", weight=0.5, met=True),
            Indicator(name="b", description="b", weight=0.5, met=True),
        ]
        assert Finding.compute_confidence(indicators) == 100

    def test_compute_confidence_none_met(self):
        indicators = [
            Indicator(name="a", description="a", weight=0.5, met=False),
            Indicator(name="b", description="b", weight=0.5, met=False),
        ]
        assert Finding.compute_confidence(indicators) == 0

    def test_compute_confidence_partial(self):
        indicators = [
            Indicator(name="a", description="a", weight=0.3, met=True),
            Indicator(name="b", description="b", weight=0.3, met=True),
            Indicator(name="c", description="c", weight=0.4, met=False),
        ]
        # Met weight = 0.6, total = 1.0 → 60%
        assert Finding.compute_confidence(indicators) == 60

    def test_compute_confidence_empty(self):
        assert Finding.compute_confidence([]) == 0

    def test_compute_confidence_weighted(self):
        indicators = [
            Indicator(name="a", description="a", weight=0.8, met=True),
            Indicator(name="b", description="b", weight=0.2, met=False),
        ]
        # Met = 0.8, total = 1.0 → 80%
        assert Finding.compute_confidence(indicators) == 80

    def test_confidence_caps_at_100(self):
        indicators = [
            Indicator(name="a", description="a", weight=0.6, met=True),
            Indicator(name="b", description="b", weight=0.6, met=True),
        ]
        # Met = 1.2, total = 1.2 → 100% (capped)
        assert Finding.compute_confidence(indicators) == 100

    def test_to_dict(self):
        f = Finding(
            id="test:1",
            analyzer="test",
            title="Test Finding",
            description="A test",
            confidence=75,
            severity="HIGH",
            entities=["10.0.0.1"],
            alternative_explanations=["Could be benign"],
        )
        d = f.to_dict()
        assert d["id"] == "test:1"
        assert d["confidence"] == 75
        assert d["severity"] == "HIGH"
        assert "Could be benign" in d["alternative_explanations"]


class TestInvestigationThread:
    def test_compute_risk_score_single(self):
        findings = [
            Finding(id="a", analyzer="x", title="", description="", confidence=70, severity="HIGH"),
        ]
        assert InvestigationThread.compute_risk_score(findings) == 70

    def test_compute_risk_score_multiple(self):
        findings = [
            Finding(id="a", analyzer="x", title="", description="", confidence=80, severity="HIGH"),
            Finding(id="b", analyzer="y", title="", description="", confidence=60, severity="MEDIUM"),
        ]
        # 80 + (60 * 0.2) = 92
        score = InvestigationThread.compute_risk_score(findings)
        assert score == 92

    def test_compute_risk_score_caps_at_100(self):
        findings = [
            Finding(id="a", analyzer="x", title="", description="", confidence=90, severity="CRITICAL"),
            Finding(id="b", analyzer="y", title="", description="", confidence=85, severity="HIGH"),
            Finding(id="c", analyzer="z", title="", description="", confidence=80, severity="HIGH"),
        ]
        score = InvestigationThread.compute_risk_score(findings)
        assert score == 100

    def test_compute_risk_score_empty(self):
        assert InvestigationThread.compute_risk_score([]) == 0

    def test_to_dict(self):
        thread = InvestigationThread(
            entity="10.0.0.1",
            entity_type="internal_host",
            summary="Test thread",
            risk_score=75,
        )
        d = thread.to_dict()
        assert d["entity"] == "10.0.0.1"
        assert d["risk_score"] == 75


class TestTimelineEvent:
    def test_to_dict(self):
        event = TimelineEvent(
            timestamp=1700000000.0,
            event_type="detection",
            description="Found something",
            source_analyzer="c2_beaconing",
            severity="HIGH",
        )
        d = event.to_dict()
        assert d["event_type"] == "detection"
        assert d["severity"] == "HIGH"
