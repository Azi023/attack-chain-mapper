"""Tests for AI-powered format detection (src/ingestion/detector.ai_detect_and_adapt)."""
import json
from unittest.mock import MagicMock, patch

import pytest

from src.ingestion.detector import ai_detect_and_adapt, AdaptationReport
from src.ingestion.schema import Finding


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _mock_anthropic_response(findings_list: list) -> MagicMock:
    """Build a mock anthropic.messages.create return value."""
    content = MagicMock()
    content.text = json.dumps(findings_list)
    message = MagicMock()
    message.content = [content]
    return message


SAMPLE_FINDINGS_RESPONSE = [
    {
        "id": "vuln-001",
        "title": "SQL Injection in login form",
        "severity": 9.0,
        "severity_label": "CRITICAL",
        "mitre_technique": "T1190",
        "step_index": 1,
        "timestamp_offset_s": None,
        "enabled_by": [],
        "evidence": "' OR 1=1 -- returned 200 OK",
        "host": "192.168.1.10",
        "ai_detail": None,
        "ai_remediation": None,
        "ai_confidence": None,
    },
    {
        "id": "vuln-002",
        "title": "Weak Password Policy",
        "severity": 5.0,
        "severity_label": "MEDIUM",
        "mitre_technique": None,
        "step_index": 2,
        "timestamp_offset_s": None,
        "enabled_by": ["vuln-001"],
        "evidence": None,
        "host": "192.168.1.10",
        "ai_detail": None,
        "ai_remediation": None,
        "ai_confidence": None,
    },
]

UNKNOWN_FORMAT_DATA = {
    "scan_results": [
        {"vuln_id": "v1", "name": "XSS", "risk": "high", "proof": "alert(1) triggered"},
        {"vuln_id": "v2", "name": "CSRF", "risk": "medium", "proof": "form submission intercepted"},
    ]
}


# ---------------------------------------------------------------------------
# Happy path: mock Claude response
# ---------------------------------------------------------------------------

class TestAiDetectHappyPath:
    def test_mock_response_returns_finding_list(self):
        mock_msg = _mock_anthropic_response(SAMPLE_FINDINGS_RESPONSE)

        with patch("anthropic.Anthropic") as MockAnthropicCls:
            instance = MockAnthropicCls.return_value
            instance.messages.create.return_value = mock_msg

            findings, report = ai_detect_and_adapt(UNKNOWN_FORMAT_DATA, api_key="sk-fake")

        assert len(findings) == 2
        assert all(isinstance(f, Finding) for f in findings)

    def test_correct_finding_fields_extracted(self):
        mock_msg = _mock_anthropic_response(SAMPLE_FINDINGS_RESPONSE)

        with patch("anthropic.Anthropic") as MockAnthropicCls:
            instance = MockAnthropicCls.return_value
            instance.messages.create.return_value = mock_msg

            findings, report = ai_detect_and_adapt(UNKNOWN_FORMAT_DATA, api_key="sk-fake")

        f = findings[0]
        assert f.id == "vuln-001"
        assert f.title == "SQL Injection in login form"
        assert f.severity == 9.0
        assert f.severity_label == "CRITICAL"
        assert f.host == "192.168.1.10"

    def test_report_includes_finding_count(self):
        mock_msg = _mock_anthropic_response(SAMPLE_FINDINGS_RESPONSE)

        with patch("anthropic.Anthropic") as MockAnthropicCls:
            instance = MockAnthropicCls.return_value
            instance.messages.create.return_value = mock_msg

            findings, report = ai_detect_and_adapt(UNKNOWN_FORMAT_DATA, api_key="sk-fake")

        assert report.finding_count == 2
        assert not report.fallback_used

    def test_enabled_by_chains_preserved(self):
        mock_msg = _mock_anthropic_response(SAMPLE_FINDINGS_RESPONSE)

        with patch("anthropic.Anthropic") as MockAnthropicCls:
            instance = MockAnthropicCls.return_value
            instance.messages.create.return_value = mock_msg

            findings, _ = ai_detect_and_adapt(UNKNOWN_FORMAT_DATA, api_key="sk-fake")

        f2 = next(f for f in findings if f.id == "vuln-002")
        assert "vuln-001" in f2.enabled_by


# ---------------------------------------------------------------------------
# Severity label → numeric normalization
# ---------------------------------------------------------------------------

class TestSeverityNormalization:
    @pytest.mark.parametrize("label,expected_score,expected_label", [
        ("Critical", 9.5, "CRITICAL"),
        ("High", 7.5, "HIGH"),
        ("Medium", 5.0, "MEDIUM"),
        ("Low", 2.5, "LOW"),
        ("Info", 0.5, "INFO"),
        ("Informational", 0.5, "INFO"),
    ])
    def test_string_severity_mapped_to_numeric(self, label, expected_score, expected_label):
        raw = [{
            "id": "v1", "title": "Test", "severity": label,
            "severity_label": None, "mitre_technique": None,
            "step_index": None, "timestamp_offset_s": None,
            "enabled_by": [], "evidence": None, "host": None,
            "ai_detail": None, "ai_remediation": None, "ai_confidence": None,
        }]
        mock_msg = _mock_anthropic_response(raw)

        with patch("anthropic.Anthropic") as MockAnthropicCls:
            instance = MockAnthropicCls.return_value
            instance.messages.create.return_value = mock_msg

            findings, _ = ai_detect_and_adapt({}, api_key="sk-fake")

        assert findings[0].severity == expected_score
        assert findings[0].severity_label == expected_label

    def test_numeric_severity_clamped(self):
        raw = [{
            "id": "v1", "title": "Test", "severity": 15.0,
            "severity_label": "CRITICAL", "mitre_technique": None,
            "step_index": None, "timestamp_offset_s": None,
            "enabled_by": [], "evidence": None, "host": None,
            "ai_detail": None, "ai_remediation": None, "ai_confidence": None,
        }]
        mock_msg = _mock_anthropic_response(raw)

        with patch("anthropic.Anthropic") as MockAnthropicCls:
            instance = MockAnthropicCls.return_value
            instance.messages.create.return_value = mock_msg

            findings, _ = ai_detect_and_adapt({}, api_key="sk-fake")

        assert findings[0].severity == 10.0


# ---------------------------------------------------------------------------
# Malformed Claude response → fallback
# ---------------------------------------------------------------------------

class TestFallback:
    def test_malformed_json_falls_back_to_generic_adapter(self):
        # Claude returns garbage
        content = MagicMock()
        content.text = "I cannot process this file."
        message = MagicMock()
        message.content = [content]

        generic_data = {"findings": [
            {"id": "f-1", "title": "Test", "severity": 5.0, "severity_label": "MEDIUM", "enabled_by": []}
        ]}

        with patch("anthropic.Anthropic") as MockAnthropicCls:
            instance = MockAnthropicCls.return_value
            instance.messages.create.return_value = message

            findings, report = ai_detect_and_adapt(generic_data, api_key="sk-fake")

        assert report.fallback_used is True

    def test_empty_array_response_returns_empty_list(self):
        mock_msg = _mock_anthropic_response([])

        with patch("anthropic.Anthropic") as MockAnthropicCls:
            instance = MockAnthropicCls.return_value
            instance.messages.create.return_value = mock_msg

            findings, report = ai_detect_and_adapt({}, api_key="sk-fake")

        assert findings == []

    def test_api_exception_falls_back_gracefully(self):
        with patch("anthropic.Anthropic") as MockAnthropicCls:
            instance = MockAnthropicCls.return_value
            instance.messages.create.side_effect = Exception("Network error")

            generic_data = {"findings": [
                {"id": "f-1", "title": "Test", "severity": 5.0, "severity_label": "MEDIUM", "enabled_by": []}
            ]}
            findings, report = ai_detect_and_adapt(generic_data, api_key="sk-fake")

        assert report.fallback_used is True
        assert len(report.warnings) > 0


# ---------------------------------------------------------------------------
# No API key → falls back without calling AI
# ---------------------------------------------------------------------------

class TestNoApiKey:
    def test_no_api_key_uses_generic_adapter(self):
        generic_data = {"findings": [
            {"id": "f-1", "title": "Test", "severity": 5.0, "severity_label": "MEDIUM", "enabled_by": []}
        ]}

        # Ensure no ANTHROPIC_API_KEY in env
        with patch.dict("os.environ", {}, clear=True):
            findings, report = ai_detect_and_adapt(generic_data, api_key=None)

        assert report.fallback_used is True
        assert len(findings) == 1

    def test_no_api_key_report_has_warning(self):
        generic_data = {"findings": [
            {"id": "f-1", "title": "Test", "severity": 5.0, "severity_label": "MEDIUM", "enabled_by": []}
        ]}

        with patch.dict("os.environ", {}, clear=True):
            _, report = ai_detect_and_adapt(generic_data, api_key=None)

        assert any("No API key" in w or "no api key" in w.lower() for w in report.warnings)


# ---------------------------------------------------------------------------
# Report structure
# ---------------------------------------------------------------------------

class TestAdaptationReport:
    def test_adaptation_report_is_dataclass(self):
        report = AdaptationReport(
            finding_count=3,
            fields_mapped=["id", "title", "severity"],
            format_guess="nessus",
        )
        assert report.finding_count == 3
        assert report.format_guess == "nessus"
        assert report.fallback_used is False

    def test_markdown_stripped_from_response(self):
        """AI sometimes wraps JSON in markdown fences — strip them."""
        raw_with_fences = "```json\n" + json.dumps(SAMPLE_FINDINGS_RESPONSE) + "\n```"
        content = MagicMock()
        content.text = raw_with_fences
        message = MagicMock()
        message.content = [content]

        with patch("anthropic.Anthropic") as MockAnthropicCls:
            instance = MockAnthropicCls.return_value
            instance.messages.create.return_value = message

            findings, _ = ai_detect_and_adapt(UNKNOWN_FORMAT_DATA, api_key="sk-fake")

        assert len(findings) == 2
