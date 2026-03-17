"""Tests for src/ingestion/adapters/generic.py and detector.py"""
import json
import tempfile
from pathlib import Path

import pytest

from src.ingestion.adapters.generic import GenericAdapter, _normalise_finding, _infer_severity_label
from src.ingestion.adapters import get_adapter, ADAPTER_REGISTRY
from src.ingestion.detector import detect_format, detect_format_from_file
from src.ingestion.schema import Engagement, Finding

FIXTURE_PATH = Path(__file__).parent / "fixtures" / "generic_sample.json"
GOAD_FIXTURE = Path(__file__).parent.parent / "demo" / "fixtures" / "goad_sample.json"


class TestGenericAdapter:
    def setup_method(self):
        self.adapter = GenericAdapter()

    def test_load_fixture(self):
        engagement = self.adapter.load(FIXTURE_PATH)
        assert isinstance(engagement, Engagement)
        assert engagement.engagement_id == "test-engagement-001"
        assert len(engagement.findings) == 3

    def test_fixture_finding_fields(self):
        engagement = self.adapter.load(FIXTURE_PATH)
        f = engagement.findings[0]
        assert f.id == "f-001"
        assert f.title == "Open Admin Port"
        assert f.severity == 2.5
        assert f.severity_label == "LOW"
        assert f.mitre_technique == "T1046"

    def test_fixture_enabled_by_preserved(self):
        engagement = self.adapter.load(FIXTURE_PATH)
        f = engagement.findings[1]
        assert f.enabled_by == ["f-001"]

    def test_parse_list_input(self):
        data = [
            {"id": "f-a", "title": "A", "severity": 5.0, "severity_label": "MEDIUM"},
            {"id": "f-b", "title": "B", "severity": 9.0, "severity_label": "CRITICAL", "enabled_by": ["f-a"]},
        ]
        engagement = self.adapter.parse(data)
        assert len(engagement.findings) == 2

    def test_parse_nested_findings_key(self):
        data = {
            "engagement_id": "e-001",
            "findings": [
                {"id": "f-1", "title": "Test", "severity": 5.0, "severity_label": "MEDIUM"}
            ]
        }
        engagement = self.adapter.parse(data)
        assert engagement.engagement_id == "e-001"
        assert len(engagement.findings) == 1

    def test_parse_alternative_wrapper_keys(self):
        for key in ("results", "vulnerabilities", "issues", "vulns", "items"):
            data = {key: [{"id": "f-1", "title": "T", "severity": 5.0, "severity_label": "MEDIUM"}]}
            engagement = self.adapter.parse(data)
            assert len(engagement.findings) == 1

    def test_missing_optional_fields_use_none(self):
        data = [{"id": "f-1", "title": "Minimal", "severity": 5.0, "severity_label": "MEDIUM"}]
        engagement = self.adapter.parse(data)
        f = engagement.findings[0]
        assert f.mitre_technique is None
        assert f.step_index is None
        assert f.evidence is None
        assert f.ai_detail is None

    def test_missing_id_auto_generated(self):
        data = [{"title": "No ID", "severity": 5.0, "severity_label": "MEDIUM"}]
        engagement = self.adapter.parse(data)
        assert engagement.findings[0].id == "finding-0"

    def test_severity_clamped_to_valid_range(self):
        data = [{"id": "f", "title": "t", "severity": 15.0, "severity_label": "CRITICAL"}]
        engagement = self.adapter.parse(data)
        assert engagement.findings[0].severity == 10.0

    def test_field_aliases_resolved(self):
        data = [{"finding_id": "f-alias", "name": "By Alias", "cvss": 7.5, "risk_label": "HIGH"}]
        engagement = self.adapter.parse(data)
        f = engagement.findings[0]
        assert f.id == "f-alias"
        assert f.title == "By Alias"
        assert f.severity == 7.5

    def test_enabled_by_string_coerced_to_list(self):
        data = [{"id": "f", "title": "t", "severity": 5.0, "severity_label": "MEDIUM", "enabled_by": "f-prereq"}]
        engagement = self.adapter.parse(data)
        assert engagement.findings[0].enabled_by == ["f-prereq"]

    def test_unknown_fields_ignored(self):
        data = [{"id": "f", "title": "t", "severity": 5.0, "severity_label": "MEDIUM", "foo_bar": "ignored"}]
        engagement = self.adapter.parse(data)
        assert len(engagement.findings) == 1

    def test_describe_mapping_structure(self):
        with FIXTURE_PATH.open() as fh:
            data = json.load(fh)
        mapping = self.adapter.describe_mapping(data)
        assert "adapter" in mapping
        assert "sample_count" in mapping
        assert "mapped_fields" in mapping
        assert "unmapped_fields" in mapping
        assert mapping["sample_count"] == 3

    def test_load_goad_fixture(self):
        engagement = self.adapter.load(GOAD_FIXTURE)
        assert len(engagement.findings) == 6
        assert engagement.engagement_id == "goad-2024-demo-001"


class TestSeverityInference:
    def test_infer_from_score_critical(self):
        assert _infer_severity_label(9.5, None) == "CRITICAL"

    def test_infer_from_score_high(self):
        assert _infer_severity_label(7.5, None) == "HIGH"

    def test_infer_from_score_medium(self):
        assert _infer_severity_label(5.0, None) == "MEDIUM"

    def test_infer_from_score_low(self):
        assert _infer_severity_label(2.0, None) == "LOW"

    def test_infer_from_score_info(self):
        assert _infer_severity_label(0.0, None) == "INFO"

    def test_label_takes_precedence_when_valid(self):
        # Even with a high score, if label says LOW, use LOW
        assert _infer_severity_label(8.0, "low") == "LOW"


class TestAdapterRegistry:
    def test_generic_registered(self):
        assert "generic" in ADAPTER_REGISTRY

    def test_get_adapter_returns_class(self):
        cls = get_adapter("generic")
        assert cls is GenericAdapter

    def test_get_adapter_unknown_raises(self):
        with pytest.raises(ValueError, match="Unknown adapter"):
            get_adapter("nonexistent_format")


class TestFormatDetector:
    def test_detect_list_is_generic(self):
        assert detect_format([{"id": "f"}]) == "generic"

    def test_detect_dict_with_findings_is_generic(self):
        assert detect_format({"findings": []}) == "generic"

    def test_detect_dict_with_results_is_generic(self):
        assert detect_format({"results": []}) == "generic"

    def test_detect_strike7_by_benchmark_key(self):
        assert detect_format({"benchmark_run_id": "run-1", "agent_steps": []}) == "strike7"

    def test_detect_from_file_goad_fixture(self):
        fmt, data = detect_format_from_file(GOAD_FIXTURE)
        assert fmt == "generic"
        assert isinstance(data, dict)

    def test_detect_from_file_generic_fixture(self):
        fmt, data = detect_format_from_file(FIXTURE_PATH)
        assert fmt == "generic"

    def test_detect_empty_dict_fallback_generic(self):
        assert detect_format({}) == "generic"
