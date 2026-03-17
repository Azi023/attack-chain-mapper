"""Graph builder — constructs a NetworkX DAG from a list of findings.

The DAG represents the attack chain:
- Nodes are findings (identified by their `id`)
- Directed edges flow FROM a prerequisite finding TO the finding it enables
  i.e., if finding B has enabled_by=["A"], there is an edge A → B
- Edge weight = severity of the destination node (higher severity = more valuable path)
"""
from __future__ import annotations

from typing import Any

import networkx as nx

from src.ingestion.schema import Finding


def build_graph(findings: list[Finding]) -> nx.DiGraph:
    """Build a directed acyclic graph from findings.

    Raises:
        ValueError: if the graph contains a cycle (findings list is inconsistent).
    """
    G = nx.DiGraph()

    # Add all nodes first
    for f in findings:
        G.add_node(
            f.id,
            finding=f,
            severity=f.severity,
            label=f.title,
            severity_label=f.severity_label,
        )

    # Add edges: prerequisite → dependent
    for f in findings:
        for prereq_id in f.enabled_by:
            if prereq_id not in G:
                # Orphan reference — add a placeholder node
                G.add_node(prereq_id, finding=None, severity=0.0, label=f"[missing: {prereq_id}]", severity_label="INFO")
            # Weight on edge = destination severity (for path-weight maximisation)
            G.add_edge(prereq_id, f.id, weight=f.severity)

    if not nx.is_directed_acyclic_graph(G):
        cycles = list(nx.simple_cycles(G))
        raise ValueError(f"Finding dependency graph contains cycles: {cycles}")

    return G


def get_node_finding(G: nx.DiGraph, node_id: str) -> Finding | None:
    """Return the Finding object for a node, or None for placeholder nodes."""
    return G.nodes[node_id].get("finding")


def all_findings_from_graph(G: nx.DiGraph) -> list[Finding]:
    """Return all non-placeholder Finding objects from the graph."""
    result = []
    for node_id in G.nodes:
        f = get_node_finding(G, node_id)
        if f is not None:
            result.append(f)
    return result
