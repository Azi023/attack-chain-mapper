"""Tests for src/ai/client.py — AIClient class."""
import asyncio
import pytest

from src.ai.client import AIClient, DEFAULT_MODEL
from src.ingestion.schema import Finding


def make_finding(id: str, ai_detail: str = None, ai_remediation: str = None, ai_confidence: float = None) -> Finding:
    return Finding(
        id=id,
        title=f"Finding {id}",
        severity=5.0,
        severity_label="MEDIUM",
        ai_detail=ai_detail,
        ai_remediation=ai_remediation,
        ai_confidence=ai_confidence,
    )


class TestAIClientAvailability:
    def test_no_api_key_not_available(self, monkeypatch):
        monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
        client = AIClient(api_key=None)
        assert client.available is False

    def test_explicit_empty_string_not_available(self, monkeypatch):
        monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
        client = AIClient(api_key="")
        assert client.available is False

    def test_default_model(self):
        client = AIClient()
        assert client.model == DEFAULT_MODEL

    def test_custom_model(self):
        client = AIClient(model="claude-opus-4-6")
        assert client.model == "claude-opus-4-6"


class TestGenerateFindingDetailNoKey:
    def setup_method(self):
        self.finding = make_finding("f-1")

    def test_returns_dict_with_correct_keys(self, monkeypatch):
        monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
        client = AIClient()
        result = asyncio.run(client.generate_finding_detail(self.finding, {}))
        assert isinstance(result, dict)
        assert "detail" in result
        assert "remediation" in result
        assert "confidence" in result

    def test_returns_empty_strings_when_no_fixture_data(self, monkeypatch):
        monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
        client = AIClient()
        result = asyncio.run(client.generate_finding_detail(self.finding, {}))
        assert result["detail"] == ""
        assert result["remediation"] == ""
        assert result["confidence"] == 0.0

    def test_returns_fixture_ai_detail_when_present(self, monkeypatch):
        monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
        client = AIClient()
        finding_with_data = make_finding(
            "f-2",
            ai_detail="Pre-written detail",
            ai_remediation="Pre-written remediation",
            ai_confidence=0.9,
        )
        result = asyncio.run(client.generate_finding_detail(finding_with_data, {}))
        assert result["detail"] == "Pre-written detail"
        assert result["remediation"] == "Pre-written remediation"
        assert result["confidence"] == 0.9

    def test_never_raises(self, monkeypatch):
        """generate_finding_detail must never raise, even with bad input."""
        monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
        client = AIClient()
        # Should not raise even with an empty finding
        result = asyncio.run(client.generate_finding_detail(self.finding, {}))
        assert isinstance(result, dict)


class TestEnrichFindings:
    def test_enrich_preserves_fixture_data_when_no_key(self, monkeypatch):
        monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
        client = AIClient()
        findings = [
            make_finding("f-1", ai_detail="existing detail"),
            make_finding("f-2"),
        ]
        import networkx as nx
        G = nx.DiGraph()
        for f in findings:
            G.add_node(f.id)
        result = client.enrich_findings_sync(findings, G)
        assert len(result) == 2
        assert result[0].ai_detail == "existing detail"

    def test_enrich_returns_finding_objects(self, monkeypatch):
        monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
        client = AIClient()
        findings = [make_finding("f-1")]
        import networkx as nx
        G = nx.DiGraph()
        G.add_node("f-1")
        result = client.enrich_findings_sync(findings, G)
        assert all(isinstance(f, Finding) for f in result)

    def test_enrich_does_not_mutate_original(self, monkeypatch):
        monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
        client = AIClient()
        original = make_finding("f-1")
        original_detail = original.ai_detail
        import networkx as nx
        G = nx.DiGraph()
        G.add_node("f-1")
        client.enrich_findings_sync([original], G)
        assert original.ai_detail == original_detail  # unchanged
