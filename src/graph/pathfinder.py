"""Pathfinder — identifies primary and secondary chains from the attack DAG.

Primary chain = longest weighted path through the DAG (sum of edge weights = sum of
destination node severities). This captures the most impactful sequence of exploits.

Secondary findings = all findings NOT in the primary chain.
"""
from __future__ import annotations

import networkx as nx

from src.ingestion.schema import Finding
from src.graph.builder import get_node_finding


def _longest_weighted_path(G: nx.DiGraph) -> list[str]:
    """Return node IDs of the longest-weighted path in the DAG.

    Uses topological sort + dynamic programming for O(V+E) time.
    Path weight = sum of edge weights (= sum of destination node severities).
    """
    if G.number_of_nodes() == 0:
        return []

    topo_order = list(nx.topological_sort(G))

    # dp[node] = (best_weight_to_node, predecessor_node)
    dp: dict[str, tuple[float, str | None]] = {node: (0.0, None) for node in G.nodes}

    for node in topo_order:
        for successor in G.successors(node):
            edge_weight = G[node][successor].get("weight", 0.0)
            candidate = dp[node][0] + edge_weight
            if candidate > dp[successor][0]:
                dp[successor] = (candidate, node)

    if not dp:
        return []

    # Find the end node with the highest accumulated weight
    best_end = max(dp, key=lambda n: dp[n][0])

    # If no edges, best_end might be a disconnected node with weight 0
    # In that case, pick the highest-severity node as the chain
    if dp[best_end][0] == 0.0 and G.number_of_edges() == 0:
        # Return all nodes ordered by severity
        all_findings = [
            node for node in G.nodes
            if get_node_finding(G, node) is not None
        ]
        return sorted(all_findings, key=lambda n: G.nodes[n].get("severity", 0.0))

    # Reconstruct path by walking predecessors
    path: list[str] = []
    current: str | None = best_end
    while current is not None:
        path.append(current)
        current = dp[current][1]

    return list(reversed(path))


def find_primary_chain(G: nx.DiGraph) -> list[Finding]:
    """Return the primary attack chain as an ordered list of Finding objects.

    Ordered from entry point (lowest index) to crown jewel (highest index).
    Only includes nodes that have a corresponding Finding (no placeholders).
    """
    path_ids = _longest_weighted_path(G)
    chain = []
    for node_id in path_ids:
        f = get_node_finding(G, node_id)
        if f is not None:
            chain.append(f)
    return chain


def find_secondary_findings(G: nx.DiGraph, primary_chain: list[Finding]) -> list[Finding]:
    """Return findings that are NOT in the primary chain, sorted by severity descending."""
    primary_ids = {f.id for f in primary_chain}
    secondary = []
    for node_id in G.nodes:
        if node_id not in primary_ids:
            f = get_node_finding(G, node_id)
            if f is not None:
                secondary.append(f)
    return sorted(secondary, key=lambda f: f.severity, reverse=True)
