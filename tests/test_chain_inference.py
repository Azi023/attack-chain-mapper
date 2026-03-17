"""Tests for src/graph/inference.py — chain inference for missing enabled_by."""
import pytest
import networkx as nx

from src.ingestion.schema import Finding
from src.graph.inference import (
    needs_inference,
    infer_enabled_by,
    mark_inferred_edges,
    infer_and_build,
)
from src.graph.builder import build_graph


def make_finding(id: str, severity: float = 5.0, step_index: int = None,
                 enabled_by=None, host: str = None) -> Finding:
    label = "CRITICAL" if severity >= 9 else "HIGH" if severity >= 7 else "MEDIUM" if severity >= 4 else "LOW" if severity >= 1 else "INFO"
    return Finding(
        id=id,
        title=f"Finding {id}",
        severity=severity,
        severity_label=label,
        step_index=step_index,
        enabled_by=enabled_by or [],
        host=host,
    )


class TestNeedsInference:
    def test_single_finding_no_inference(self):
        findings = [make_finding("a")]
        assert needs_inference(findings) is False

    def test_all_have_enabled_by_no_inference(self):
        findings = [
            make_finding("a"),
            make_finding("b", enabled_by=["a"]),
        ]
        assert needs_inference(findings) is False

    def test_some_missing_enabled_by_needs_inference(self):
        findings = [make_finding("a"), make_finding("b")]
        assert needs_inference(findings) is True

    def test_all_missing_enabled_by_needs_inference(self):
        findings = [make_finding("a"), make_finding("b"), make_finding("c")]
        assert needs_inference(findings) is True


class TestInferEnabledBy:
    def test_first_finding_is_entry_point(self):
        findings = [
            make_finding("a", severity=1.0, step_index=1),
            make_finding("b", severity=5.0, step_index=2),
        ]
        enriched, inferred = infer_enabled_by(findings)
        entry = next(f for f in enriched if f.id == "a")
        assert entry.enabled_by == []
        assert "a" not in inferred

    def test_second_finding_gets_inferred_link(self):
        findings = [
            make_finding("a", severity=1.0, step_index=1),
            make_finding("b", severity=5.0, step_index=2),
        ]
        enriched, inferred = infer_enabled_by(findings)
        b = next(f for f in enriched if f.id == "b")
        assert b.enabled_by == ["a"]
        assert "b" in inferred

    def test_explicit_enabled_by_not_overridden(self):
        findings = [
            make_finding("a"),
            make_finding("b", enabled_by=["a"]),
            make_finding("c", severity=7.0),
        ]
        enriched, inferred = infer_enabled_by(findings)
        b = next(f for f in enriched if f.id == "b")
        assert b.enabled_by == ["a"]
        assert "b" not in inferred

    def test_severity_ordering_respected(self):
        """Higher severity finding should be linked to a lower-severity predecessor."""
        findings = [
            make_finding("low", severity=2.0, step_index=1),
            make_finding("high", severity=8.0, step_index=2),
        ]
        enriched, inferred = infer_enabled_by(findings)
        high = next(f for f in enriched if f.id == "high")
        assert "low" in high.enabled_by

    def test_three_step_chain(self):
        findings = [
            make_finding("recon", severity=0.0, step_index=1),
            make_finding("foothold", severity=3.0, step_index=2),
            make_finding("escalate", severity=9.0, step_index=3),
        ]
        enriched, inferred = infer_enabled_by(findings)
        escalate = next(f for f in enriched if f.id == "escalate")
        # Should be chained to something before it
        assert len(escalate.enabled_by) > 0
        assert "escalate" in inferred

    def test_inferred_graph_is_acyclic(self):
        """Inferred chains must never produce cycles."""
        findings = [
            make_finding("a", severity=1.0, step_index=1),
            make_finding("b", severity=3.0, step_index=2),
            make_finding("c", severity=7.0, step_index=3),
            make_finding("d", severity=9.5, step_index=4),
        ]
        enriched, _ = infer_enabled_by(findings)
        G = build_graph(enriched)
        assert nx.is_directed_acyclic_graph(G)

    def test_preserves_all_findings(self):
        findings = [make_finding(str(i), severity=float(i), step_index=i) for i in range(5)]
        enriched, _ = infer_enabled_by(findings)
        assert len(enriched) == 5

    def test_host_based_grouping(self):
        """Findings on the same host are more likely to be linked."""
        findings = [
            make_finding("a", severity=2.0, step_index=1, host="10.0.0.1"),
            make_finding("b", severity=5.0, step_index=2, host="10.0.0.1"),
            make_finding("c", severity=7.0, step_index=3, host="10.0.0.2"),
        ]
        enriched, inferred = infer_enabled_by(findings)
        b = next(f for f in enriched if f.id == "b")
        # b should link to a (same host)
        assert "a" in b.enabled_by

    def test_no_self_reference_in_inferred(self):
        findings = [make_finding(str(i), step_index=i) for i in range(3)]
        enriched, _ = infer_enabled_by(findings)
        for f in enriched:
            assert f.id not in f.enabled_by


class TestMarkInferredEdges:
    def test_inferred_edges_marked(self):
        findings = [
            make_finding("a", severity=1.0),
            make_finding("b", severity=5.0, enabled_by=["a"]),
        ]
        G = build_graph(findings)
        mark_inferred_edges(G, {"b"})
        assert G["a"]["b"].get("inferred") is True

    def test_non_inferred_edges_not_marked(self):
        findings = [
            make_finding("a"),
            make_finding("b", enabled_by=["a"]),
        ]
        G = build_graph(findings)
        mark_inferred_edges(G, set())  # no inferred IDs
        assert G["a"]["b"].get("inferred") is None

    def test_missing_node_handled_gracefully(self):
        findings = [make_finding("a")]
        G = build_graph(findings)
        # Should not raise even with an ID not in the graph
        mark_inferred_edges(G, {"nonexistent"})


class TestInferAndBuild:
    def test_no_inference_needed_returns_unchanged(self):
        findings = [
            make_finding("a"),
            make_finding("b", enabled_by=["a"]),
        ]
        result, inferred = infer_and_build(findings)
        assert inferred == set()
        assert result is findings  # same object, no modification

    def test_inference_applied_when_needed(self):
        findings = [
            make_finding("a", step_index=1),
            make_finding("b", step_index=2),
        ]
        result, inferred = infer_and_build(findings)
        assert len(inferred) > 0

    def test_result_is_acyclic_graph(self):
        findings = [
            make_finding("a", severity=0.0, step_index=1),
            make_finding("b", severity=5.0, step_index=2),
            make_finding("c", severity=9.0, step_index=3),
        ]
        enriched, _ = infer_and_build(findings)
        G = build_graph(enriched)
        assert nx.is_directed_acyclic_graph(G)
