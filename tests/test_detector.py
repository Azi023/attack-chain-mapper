"""Tests for src/ingestion/detector.py"""
from pathlib import Path
import pytest

from src.ingestion.detector import detect_format, detect_format_from_file, describe_field_mapping

GOAD_FIXTURE = Path(__file__).parent.parent / "demo" / "fixtures" / "goad_sample.json"
GENERIC_FIXTURE = Path(__file__).parent / "fixtures" / "generic_sample.json"


class TestDetectFormat:
    def test_list_is_generic(self):
        assert detect_format([{"id": "f", "title": "t"}]) == "generic"

    def test_dict_with_findings_key_is_generic(self):
        assert detect_format({"findings": []}) == "generic"

    def test_dict_with_results_key_is_generic(self):
        assert detect_format({"results": []}) == "generic"

    def test_dict_with_vulnerabilities_key_is_generic(self):
        assert detect_format({"vulnerabilities": []}) == "generic"

    def test_empty_dict_fallback_generic(self):
        assert detect_format({}) == "generic"

    def test_strike7_benchmark_run_id(self):
        assert detect_format({"benchmark_run_id": "run-1", "findings": []}) == "strike7"

    def test_strike7_agent_steps(self):
        assert detect_format({"agent_steps": [], "findings": []}) == "strike7"

    def test_strike7_run_id_and_steps(self):
        assert detect_format({"run_id": "r1", "steps": []}) == "strike7"

    def test_strike7_benchmark_id_with_flags(self):
        assert detect_format({"benchmark_id": "b1", "flags_captured": 3, "steps": []}) == "strike7"

    def test_goad_fixture_is_generic(self):
        fmt, _ = detect_format_from_file(GOAD_FIXTURE)
        assert fmt == "generic"

    def test_generic_fixture_is_generic(self):
        fmt, _ = detect_format_from_file(GENERIC_FIXTURE)
        assert fmt == "generic"


class TestDescribeFieldMapping:
    def test_goad_mapping_structure(self):
        import json
        with GOAD_FIXTURE.open() as fh:
            data = json.load(fh)
        mapping = describe_field_mapping(data, "generic")
        assert "format" in mapping
        assert "sample_count" in mapping
        assert "mapped_fields" in mapping
        assert "missing_critical" in mapping
        assert "chain_note" in mapping

    def test_goad_has_all_critical_fields_mapped(self):
        import json
        with GOAD_FIXTURE.open() as fh:
            data = json.load(fh)
        mapping = describe_field_mapping(data, "generic")
        # GOAD fixture has explicit enabled_by, id, title, severity
        mapped_names = {m["canonical"] for m in mapping["mapped_fields"]}
        assert "id" in mapped_names
        assert "title" in mapped_names
        assert "severity" in mapped_names

    def test_goad_has_no_missing_critical(self):
        import json
        with GOAD_FIXTURE.open() as fh:
            data = json.load(fh)
        mapping = describe_field_mapping(data, "generic")
        assert "id" not in mapping["missing_critical"]
        assert "title" not in mapping["missing_critical"]

    def test_chain_note_present(self):
        import json
        with GOAD_FIXTURE.open() as fh:
            data = json.load(fh)
        mapping = describe_field_mapping(data, "generic")
        assert "chain" in mapping["chain_note"].lower() or "enabled_by" in mapping["chain_note"].lower()

    def test_goad_enabled_by_found(self):
        """GOAD fixture has explicit enabled_by so no chain inference needed."""
        import json
        with GOAD_FIXTURE.open() as fh:
            data = json.load(fh)
        mapping = describe_field_mapping(data, "generic")
        assert mapping["needs_chain_inference"] is False

    def test_data_without_enabled_by_needs_inference(self):
        data = {
            "findings": [
                {"id": "f1", "title": "T", "severity": 5.0, "severity_label": "MEDIUM"}
            ]
        }
        mapping = describe_field_mapping(data, "generic")
        assert mapping["needs_chain_inference"] is True

    def test_sample_count(self):
        import json
        with GOAD_FIXTURE.open() as fh:
            data = json.load(fh)
        mapping = describe_field_mapping(data, "generic")
        assert mapping["sample_count"] == 6

    def test_strike7_format_mapping(self):
        data = {
            "benchmark_run_id": "r1",
            "agent_steps": [
                {
                    "step_index": 1,
                    "findings": [
                        {"id": "f1", "title": "T", "severity": "HIGH"}
                    ]
                }
            ]
        }
        mapping = describe_field_mapping(data, "strike7")
        assert mapping["format"] == "strike7"
