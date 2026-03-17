"""Tests for src/ingestion/validator.py"""
import pytest
from src.ingestion.validator import validate, ValidationResult


def _make_finding(**kwargs):
    base = {
        "id": "f-001",
        "title": "Test Finding",
        "severity": 5.0,
        "severity_label": "MEDIUM",
        "enabled_by": [],
    }
    base.update(kwargs)
    return base


# ---------------------------------------------------------------------------
# Error cases
# ---------------------------------------------------------------------------

class TestErrors:
    def test_empty_findings_list_gives_error(self):
        result, findings = validate({"findings": []})
        assert not result.valid
        codes = [e.code for e in result.errors]
        assert "EMPTY_FINDINGS" in codes
        assert findings == []

    def test_missing_findings_key_gives_error(self):
        result, findings = validate({"other_key": []})
        assert not result.valid
        assert any(e.code == "EMPTY_FINDINGS" for e in result.errors)

    def test_empty_findings_has_fix_hint(self):
        result, _ = validate({"findings": []})
        errors = [e for e in result.errors if e.code == "EMPTY_FINDINGS"]
        assert errors
        assert "findings" in errors[0].fix_hint.lower() or "vulnerabilities" in errors[0].fix_hint.lower()

    def test_duplicate_ids_caught(self):
        data = {"findings": [
            _make_finding(id="f-001"),
            _make_finding(id="f-002", title="Second"),
            _make_finding(id="f-001", title="Duplicate"),
        ]}
        result, _ = validate(data)
        assert not result.valid
        errors = [e for e in result.errors if e.code == "DUPLICATE_IDS"]
        assert errors
        assert "f-001" in errors[0].message

    def test_duplicate_ids_includes_index_references(self):
        data = {"findings": [
            _make_finding(id="f-dup", title="A"),
            _make_finding(id="f-dup", title="B"),
        ]}
        result, _ = validate(data)
        errors = [e for e in result.errors if e.code == "DUPLICATE_IDS"]
        # field should mention both indexes
        assert "0" in errors[0].field and "1" in errors[0].field

    def test_circular_enabled_by_detected(self):
        data = {"findings": [
            _make_finding(id="f-001", enabled_by=["f-002"]),
            _make_finding(id="f-002", title="B", enabled_by=["f-001"]),
        ]}
        result, _ = validate(data)
        assert not result.valid
        assert any(e.code == "CIRCULAR_ENABLED_BY" for e in result.errors)

    def test_circular_enabled_by_message_names_both_parties(self):
        data = {"findings": [
            _make_finding(id="a", enabled_by=["b"]),
            _make_finding(id="b", title="B", enabled_by=["a"]),
        ]}
        result, _ = validate(data)
        err = next(e for e in result.errors if e.code == "CIRCULAR_ENABLED_BY")
        assert "a" in err.message and "b" in err.message


# ---------------------------------------------------------------------------
# Warning cases
# ---------------------------------------------------------------------------

class TestWarnings:
    def test_missing_enabled_by_gives_warning(self):
        data = {"findings": [
            _make_finding(id="f-001", enabled_by=[]),
            _make_finding(id="f-002", title="B", enabled_by=[]),
        ]}
        result, _ = validate(data)
        assert result.valid
        codes = [w.code for w in result.warnings]
        assert "MISSING_ENABLED_BY" in codes

    def test_thin_evidence_triggers_warning(self):
        """More than 60% thin evidence triggers THIN_EVIDENCE warning."""
        data = {"findings": [
            _make_finding(id=f"f-{i:03d}", title=f"Finding {i}", evidence="short") for i in range(10)
        ]}
        result, _ = validate(data)
        codes = [w.code for w in result.warnings]
        assert "THIN_EVIDENCE" in codes

    def test_rich_evidence_does_not_trigger_thin_warning(self):
        long_ev = "x" * 200
        data = {"findings": [
            _make_finding(id=f"f-{i:03d}", title=f"Finding {i}", evidence=long_ev) for i in range(10)
        ]}
        result, _ = validate(data)
        codes = [w.code for w in result.warnings]
        assert "THIN_EVIDENCE" not in codes

    def test_missing_step_index_warning(self):
        data = {"findings": [
            _make_finding(id="f-001"),
            _make_finding(id="f-002", title="B"),
        ]}
        result, _ = validate(data)
        codes = [w.code for w in result.warnings]
        assert "MISSING_STEP_INDEX" in codes

    def test_has_step_index_no_warning(self):
        data = {"findings": [
            _make_finding(id="f-001", step_index=1),
            _make_finding(id="f-002", title="B", step_index=2),
        ]}
        result, _ = validate(data)
        codes = [w.code for w in result.warnings]
        assert "MISSING_STEP_INDEX" not in codes

    def test_unknown_enabled_by_ref_gives_warning_and_auto_fix(self):
        data = {"findings": [
            _make_finding(id="f-001", enabled_by=["does-not-exist"]),
        ]}
        result, fixed = validate(data)
        assert result.valid
        codes = [w.code for w in result.warnings]
        assert "UNKNOWN_ENABLED_BY_REF" in codes
        # Auto-fix should remove the bad ref
        assert fixed[0]["enabled_by"] == []

    def test_null_severity_auto_fixed_to_info(self):
        data = {"findings": [
            _make_finding(id="f-001", severity=None, severity_label="MEDIUM"),
        ]}
        result, fixed = validate(data)
        assert result.valid
        assert fixed[0]["severity"] == 0.0
        assert fixed[0]["severity_label"] == "INFO"


# ---------------------------------------------------------------------------
# Auto-fix cases
# ---------------------------------------------------------------------------

class TestAutoFixes:
    def test_severity_clamped_out_of_range(self):
        data = {"findings": [
            _make_finding(id="f-001", severity=15.0),
        ]}
        result, fixed = validate(data)
        assert fixed[0]["severity"] == 10.0

    def test_severity_clamped_below_zero(self):
        data = {"findings": [
            _make_finding(id="f-001", severity=-1.0),
        ]}
        result, fixed = validate(data)
        assert fixed[0]["severity"] == 0.0

    def test_whitespace_trimmed_from_strings(self):
        data = {"findings": [
            _make_finding(id="f-001", title="  Trimmed  "),
        ]}
        _, fixed = validate(data)
        assert fixed[0]["title"] == "Trimmed"

    def test_severity_label_uppercased(self):
        data = {"findings": [
            _make_finding(id="f-001", severity_label="medium"),
        ]}
        _, fixed = validate(data)
        assert fixed[0]["severity_label"] == "MEDIUM"

    def test_none_host_becomes_empty_string(self):
        data = {"findings": [
            _make_finding(id="f-001", host=None),
        ]}
        _, fixed = validate(data)
        assert fixed[0]["host"] == ""

    def test_duplicate_enabled_by_refs_deduped(self):
        data = {"findings": [
            _make_finding(id="f-001"),
            _make_finding(id="f-002", title="B", enabled_by=["f-001", "f-001"]),
        ]}
        result, fixed = validate(data)
        assert fixed[1]["enabled_by"] == ["f-001"]
        assert any("duplicate" in af.lower() for af in result.auto_fixed)

    def test_missing_title_auto_fixed(self):
        data = {"findings": [
            _make_finding(id="f-001", title=""),
        ]}
        result, fixed = validate(data)
        assert "f-001" in fixed[0]["title"]


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------

class TestValidData:
    def test_clean_data_passes_with_no_errors_or_warnings(self):
        long_ev = "x" * 150
        data = {"findings": [
            {
                "id": "f-001",
                "title": "Entry Point",
                "severity": 2.5,
                "severity_label": "LOW",
                "enabled_by": [],
                "step_index": 1,
                "evidence": long_ev,
            },
            {
                "id": "f-002",
                "title": "Crown Jewel",
                "severity": 9.5,
                "severity_label": "CRITICAL",
                "enabled_by": ["f-001"],
                "step_index": 2,
                "evidence": long_ev,
            },
        ]}
        result, fixed = validate(data)
        assert result.valid
        assert len(result.errors) == 0
        # MISSING_ENABLED_BY should not fire since f-002 has enabled_by
        assert "MISSING_ENABLED_BY" not in [w.code for w in result.warnings]

    def test_list_input_accepted(self):
        """Top-level list (not dict) is valid input."""
        data = [
            _make_finding(id="f-001"),
            _make_finding(id="f-002", title="B"),
        ]
        result, fixed = validate(data)
        assert len(fixed) == 2

    def test_alternative_keys_accepted(self):
        """'vulnerabilities' and 'results' keys work in place of 'findings'."""
        for key in ("vulnerabilities", "results", "issues"):
            data = {key: [_make_finding(id="f-001")]}
            result, fixed = validate(data)
            assert len(fixed) == 1, f"key={key} failed"

    def test_summary_format(self):
        data = {"findings": [_make_finding(id="f-001", severity=None)]}
        result, _ = validate(data)
        summary = result.summary()
        assert isinstance(summary, str)


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------

class TestEdgeCases:
    def test_single_valid_finding(self):
        data = {"findings": [_make_finding(id="f-001")]}
        result, fixed = validate(data)
        assert len(fixed) == 1

    def test_auto_fixed_list_populated(self):
        data = {"findings": [_make_finding(id="f-001", severity=None)]}
        result, _ = validate(data)
        assert len(result.auto_fixed) > 0
