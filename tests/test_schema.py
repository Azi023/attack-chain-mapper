"""Tests for src/ingestion/schema.py"""
import pytest
from pydantic import ValidationError

from src.ingestion.schema import Finding, Engagement


class TestFinding:
    def test_valid_finding_minimal(self):
        f = Finding(id="f-001", title="Test Finding", severity=5.0, severity_label="MEDIUM")
        assert f.id == "f-001"
        assert f.title == "Test Finding"
        assert f.severity == 5.0
        assert f.severity_label == "MEDIUM"
        assert f.enabled_by == []
        assert f.ai_detail is None

    def test_valid_finding_full(self):
        f = Finding(
            id="f-full",
            title="Full Finding",
            severity=9.8,
            severity_label="CRITICAL",
            mitre_technique="T1557.001",
            step_index=5,
            timestamp_offset_s=3600,
            enabled_by=["f-001", "f-002"],
            evidence="proof text",
            host="10.0.0.1",
            ai_detail="AI analysis here",
            ai_remediation="Fix steps here",
            ai_confidence=0.95,
        )
        assert f.severity == 9.8
        assert f.mitre_technique == "T1557.001"
        assert f.enabled_by == ["f-001", "f-002"]
        assert f.ai_confidence == 0.95

    def test_severity_boundary_min(self):
        f = Finding(id="f", title="t", severity=0.0, severity_label="INFO")
        assert f.severity == 0.0

    def test_severity_boundary_max(self):
        f = Finding(id="f", title="t", severity=10.0, severity_label="CRITICAL")
        assert f.severity == 10.0

    def test_severity_below_range_raises(self):
        with pytest.raises(ValidationError):
            Finding(id="f", title="t", severity=-0.1, severity_label="INFO")

    def test_severity_above_range_raises(self):
        with pytest.raises(ValidationError):
            Finding(id="f", title="t", severity=10.1, severity_label="CRITICAL")

    def test_severity_label_normalised_to_upper(self):
        f = Finding(id="f", title="t", severity=5.0, severity_label="medium")
        assert f.severity_label == "MEDIUM"

    def test_severity_label_invalid_raises(self):
        with pytest.raises(ValidationError):
            Finding(id="f", title="t", severity=5.0, severity_label="EXTREME")

    def test_severity_label_all_valid_values(self):
        for label in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
            f = Finding(id="f", title="t", severity=5.0, severity_label=label)
            assert f.severity_label == label

    def test_missing_id_raises(self):
        with pytest.raises(ValidationError):
            Finding(title="t", severity=5.0, severity_label="MEDIUM")

    def test_missing_title_raises(self):
        with pytest.raises(ValidationError):
            Finding(id="f", severity=5.0, severity_label="MEDIUM")

    def test_enabled_by_defaults_to_empty_list(self):
        f = Finding(id="f", title="t", severity=5.0, severity_label="MEDIUM")
        assert f.enabled_by == []

    def test_enabled_by_accepts_list(self):
        f = Finding(id="f", title="t", severity=5.0, severity_label="MEDIUM", enabled_by=["a", "b"])
        assert f.enabled_by == ["a", "b"]


class TestEngagement:
    def test_valid_engagement(self):
        f = Finding(id="f-001", title="Test", severity=5.0, severity_label="MEDIUM")
        e = Engagement(engagement_id="eng-001", findings=[f])
        assert e.engagement_id == "eng-001"
        assert len(e.findings) == 1
        assert e.metadata == {}

    def test_engagement_with_metadata(self):
        e = Engagement(
            engagement_id="eng-002",
            target_name="Acme Corp",
            findings=[],
            metadata={"operator": "tester"},
        )
        assert e.target_name == "Acme Corp"
        assert e.metadata["operator"] == "tester"

    def test_engagement_empty_findings_valid(self):
        e = Engagement(engagement_id="eng-003", findings=[])
        assert e.findings == []

    def test_missing_engagement_id_raises(self):
        with pytest.raises(ValidationError):
            Engagement(findings=[])
