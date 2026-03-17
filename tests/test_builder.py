"""Tests for src/graph/builder.py"""
import pytest
import networkx as nx

from src.ingestion.schema import Finding
from src.graph.builder import build_graph, get_node_finding, all_findings_from_graph


def make_finding(id: str, severity: float = 5.0, enabled_by=None) -> Finding:
    label = "CRITICAL" if severity >= 9 else "HIGH" if severity >= 7 else "MEDIUM" if severity >= 4 else "LOW" if severity >= 1 else "INFO"
    return Finding(
        id=id,
        title=f"Finding {id}",
        severity=severity,
        severity_label=label,
        enabled_by=enabled_by or [],
    )


class TestBuildGraph:
    def test_empty_findings(self):
        G = build_graph([])
        assert G.number_of_nodes() == 0
        assert G.number_of_edges() == 0

    def test_single_finding_no_edges(self):
        f = make_finding("f-001")
        G = build_graph([f])
        assert G.number_of_nodes() == 1
        assert G.number_of_edges() == 0
        assert "f-001" in G

    def test_two_findings_linked(self):
        f1 = make_finding("f-001")
        f2 = make_finding("f-002", enabled_by=["f-001"])
        G = build_graph([f1, f2])
        assert G.number_of_edges() == 1
        assert G.has_edge("f-001", "f-002")

    def test_chain_three_nodes(self):
        findings = [
            make_finding("a"),
            make_finding("b", enabled_by=["a"]),
            make_finding("c", enabled_by=["b"]),
        ]
        G = build_graph(findings)
        assert G.number_of_nodes() == 3
        assert G.number_of_edges() == 2
        assert G.has_edge("a", "b")
        assert G.has_edge("b", "c")

    def test_diamond_shape(self):
        """a → b, a → c, b → d, c → d"""
        findings = [
            make_finding("a"),
            make_finding("b", enabled_by=["a"]),
            make_finding("c", enabled_by=["a"]),
            make_finding("d", enabled_by=["b", "c"]),
        ]
        G = build_graph(findings)
        assert G.number_of_nodes() == 4
        assert G.number_of_edges() == 4

    def test_cycle_detection_raises(self):
        """a → b → c → a should raise ValueError"""
        findings = [
            make_finding("a", enabled_by=["c"]),
            make_finding("b", enabled_by=["a"]),
            make_finding("c", enabled_by=["b"]),
        ]
        with pytest.raises(ValueError, match="cycle"):
            build_graph(findings)

    def test_orphan_prerequisite_creates_placeholder(self):
        """A finding references a prerequisite that doesn't exist in the list."""
        f = make_finding("f-002", enabled_by=["f-999"])
        G = build_graph([f])
        assert "f-999" in G
        assert get_node_finding(G, "f-999") is None

    def test_edge_weight_equals_destination_severity(self):
        f1 = make_finding("a")
        f2 = make_finding("b", severity=8.5, enabled_by=["a"])
        G = build_graph([f1, f2])
        assert G["a"]["b"]["weight"] == 8.5

    def test_node_stores_finding_object(self):
        f = make_finding("f-001", severity=7.0)
        G = build_graph([f])
        stored = get_node_finding(G, "f-001")
        assert stored is f

    def test_all_findings_from_graph_excludes_placeholders(self):
        f1 = make_finding("a")
        f2 = make_finding("b", enabled_by=["a", "missing-ref"])
        G = build_graph([f1, f2])
        all_f = all_findings_from_graph(G)
        assert len(all_f) == 2
        ids = {f.id for f in all_f}
        assert "a" in ids and "b" in ids
        assert "missing-ref" not in ids

    def test_is_dag(self):
        findings = [
            make_finding("a"),
            make_finding("b", enabled_by=["a"]),
            make_finding("c", enabled_by=["a"]),
            make_finding("d", enabled_by=["b", "c"]),
        ]
        G = build_graph(findings)
        assert nx.is_directed_acyclic_graph(G)
