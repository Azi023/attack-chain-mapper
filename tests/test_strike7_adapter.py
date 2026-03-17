"""Tests for src/ingestion/adapters/strike7.py"""
import json
from pathlib import Path
import pytest

from src.ingestion.adapters.strike7 import Strike7Adapter, _parse_severity
from src.ingestion.schema import Engagement, Finding

FIXTURE = Path(__file__).parent / "fixtures" / "strike7_sample.json"


def load_fixture():
    with FIXTURE.open() as fh:
        return json.load(fh)


class TestStrike7Adapter:
    def setup_method(self):
        self.adapter = Strike7Adapter()
        self.data = load_fixture()

    def test_can_handle_benchmark_run_id(self):
        assert Strike7Adapter.can_handle({"benchmark_run_id": "r1"}) is True

    def test_can_handle_agent_steps(self):
        assert Strike7Adapter.can_handle({"agent_steps": []}) is True

    def test_can_handle_run_id_and_steps(self):
        assert Strike7Adapter.can_handle({"run_id": "r1", "steps": []}) is True

    def test_cannot_handle_generic(self):
        assert Strike7Adapter.can_handle({"findings": []}) is False

    def test_cannot_handle_list(self):
        assert Strike7Adapter.can_handle([{"id": "f"}]) is False

    def test_parse_returns_engagement(self):
        engagement = self.adapter.parse(self.data)
        assert isinstance(engagement, Engagement)

    def test_engagement_id_from_benchmark_run_id(self):
        engagement = self.adapter.parse(self.data)
        assert engagement.engagement_id == "s7-run-2024-003"

    def test_target_name_extracted(self):
        engagement = self.adapter.parse(self.data)
        assert engagement.target_name == "GOAD AD Lab (Strike7 Run)"

    def test_findings_from_agent_steps(self):
        """Findings embedded in agent_steps should be extracted."""
        engagement = self.adapter.parse(self.data)
        ids = {f.id for f in engagement.findings}
        assert "s7-recon-001" in ids
        assert "s7-ldap-001" in ids
        assert "s7-relay-001" in ids

    def test_findings_from_top_level_vulnerabilities(self):
        """Top-level vulnerabilities key should also be ingested."""
        engagement = self.adapter.parse(self.data)
        ids = {f.id for f in engagement.findings}
        assert "s7-vuln-kerberoast" in ids

    def test_severity_string_label_converted(self):
        """String severity labels must be converted to float."""
        engagement = self.adapter.parse(self.data)
        recon = next(f for f in engagement.findings if f.id == "s7-recon-001")
        assert recon.severity == 0.5  # INFO → 0.5
        assert recon.severity_label == "INFO"

    def test_severity_float_preserved(self):
        engagement = self.adapter.parse(self.data)
        relay = next(f for f in engagement.findings if f.id == "s7-relay-001")
        assert relay.severity == 9.2
        assert relay.severity_label == "CRITICAL"

    def test_field_aliases_resolved(self):
        """name→title, technique→mitre_technique, target→host, output→evidence."""
        engagement = self.adapter.parse(self.data)
        ldap = next(f for f in engagement.findings if f.id == "s7-ldap-001")
        assert ldap.title == "Unauthenticated LDAP enumeration successful"
        assert ldap.mitre_technique == "T1087.002"
        assert ldap.host == "192.168.56.10"
        assert ldap.evidence is not None

    def test_step_index_injected_from_agent_step(self):
        engagement = self.adapter.parse(self.data)
        recon = next(f for f in engagement.findings if f.id == "s7-recon-001")
        assert recon.step_index == 1

    def test_timestamp_injected_from_agent_step(self):
        engagement = self.adapter.parse(self.data)
        ldap = next(f for f in engagement.findings if f.id == "s7-ldap-001")
        assert ldap.timestamp_offset_s == 450

    def test_missing_optional_fields_use_none(self):
        """No crash on missing optional fields."""
        minimal = {"benchmark_run_id": "r1", "agent_steps": [
            {"step_index": 1, "findings": [{"id": "f1", "title": "T", "severity": "HIGH"}]}
        ]}
        engagement = self.adapter.parse(minimal)
        f = engagement.findings[0]
        assert f.ai_detail is None
        assert f.evidence is None

    def test_never_crashes_on_empty_steps(self):
        data = {"benchmark_run_id": "r1", "agent_steps": []}
        engagement = self.adapter.parse(data)
        assert isinstance(engagement, Engagement)

    def test_all_findings_are_finding_objects(self):
        engagement = self.adapter.parse(self.data)
        assert all(isinstance(f, Finding) for f in engagement.findings)

    def test_load_from_file(self):
        engagement = self.adapter.load(FIXTURE)
        assert len(engagement.findings) >= 3

    def test_describe_mapping(self):
        mapping = self.adapter.describe_mapping(self.data)
        assert mapping["adapter"] == "strike7"
        assert "sample_count" in mapping


class TestParseSeverity:
    def test_float_input(self):
        score, label = _parse_severity(7.5)
        assert score == 7.5
        assert label == "HIGH"

    def test_int_input(self):
        score, label = _parse_severity(9)
        assert score == 9.0
        assert label == "CRITICAL"

    def test_string_critical(self):
        score, label = _parse_severity("CRITICAL")
        assert score == 9.5
        assert label == "CRITICAL"

    def test_string_high(self):
        score, label = _parse_severity("HIGH")
        assert score == 7.5
        assert label == "HIGH"

    def test_string_medium(self):
        score, label = _parse_severity("MEDIUM")
        assert score == 5.0
        assert label == "MEDIUM"

    def test_string_low(self):
        score, label = _parse_severity("LOW")
        assert score == 2.5
        assert label == "LOW"

    def test_string_info(self):
        score, label = _parse_severity("INFO")
        assert score == 0.5
        assert label == "INFO"

    def test_string_informational(self):
        score, label = _parse_severity("informational")
        assert score == 0.5

    def test_none_input(self):
        score, label = _parse_severity(None)
        assert score == 0.0
        assert label == "INFO"

    def test_out_of_range_clamped(self):
        score, _ = _parse_severity(15.0)
        assert score == 10.0

    def test_negative_clamped(self):
        score, _ = _parse_severity(-1.0)
        assert score == 0.0

    def test_case_insensitive(self):
        score, label = _parse_severity("critical")
        assert label == "CRITICAL"
        score2, label2 = _parse_severity("CRITICAL")
        assert label == label2
