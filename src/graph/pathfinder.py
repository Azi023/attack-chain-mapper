"""Pathfinder — identifies primary and secondary chains from the attack DAG.

Primary chain = longest weighted path through the DAG (sum of edge weights = sum of
destination node severities). This captures the most impactful sequence of exploits.

Secondary findings = all findings NOT in the primary chain.
"""
from __future__ import annotations

from dataclasses import dataclass

import networkx as nx

from src.ingestion.schema import Finding
from src.graph.builder import get_node_finding


@dataclass
class ChainResult:
    """Represents a single independent attack chain detected in the graph."""

    chain_index: int               # 1-based (Chain 1, Chain 2, ...)
    primary_path: list[str]        # finding IDs in order entry→crown
    crown_jewel_id: str            # last node in primary path
    entry_point_id: str            # first node in primary path
    secondary_findings: list[str]  # in this component but not on primary path
    chain_risk_score: float
    component_size: int            # total real findings in this component
    label: str                     # e.g. "Chain 1 — Domain Admin via NTLM Relay"
    inferred: bool = False         # True when all edges in component are inferred


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


def find_all_chains(G: nx.DiGraph) -> list[ChainResult]:
    """Find all independent attack chains in the graph.

    1. Find all weakly connected components in the DAG
    2. For each component with more than 1 node: find its longest weighted path
       → that component's primary sub-chain
    3. For each component with exactly 1 node: it's a standalone finding
    4. Sort components by their sub-chain risk score descending
       → highest-scoring chain = Chain 1

    Returns list of ChainResult, sorted by risk score descending.
    """
    if G.number_of_nodes() == 0:
        return []

    # Lazy import to avoid circular dependency at module load time
    from src.graph.scorer import compute_chain_risk_score

    components = list(nx.weakly_connected_components(G))
    chain_results: list[ChainResult] = []

    for component in components:
        sub_G = G.subgraph(component)
        path_ids = _longest_weighted_path(sub_G)

        # Filter to only real findings (skip placeholder nodes)
        real_path = [nid for nid in path_ids if get_node_finding(G, nid) is not None]
        if not real_path:
            continue

        path_id_set = set(real_path)
        secondary = sorted(
            [
                nid for nid in component
                if nid not in path_id_set and get_node_finding(G, nid) is not None
            ],
            key=lambda nid: G.nodes[nid].get("severity", 0.0),
            reverse=True,
        )

        crown_id = real_path[-1]
        entry_id = real_path[0]

        path_findings: list[Finding] = []
        for nid in real_path:
            f = get_node_finding(G, nid)
            if f is not None:
                path_findings.append(f)

        risk_score = compute_chain_risk_score(path_findings)

        # Check if all edges in this component are inferred
        all_inferred = (
            sub_G.number_of_edges() > 0
            and all(sub_G[u][v].get("inferred", False) for u, v in sub_G.edges())
        )

        component_real_size = sum(
            1 for nid in component if get_node_finding(G, nid) is not None
        )

        chain_results.append(ChainResult(
            chain_index=0,   # set after sorting
            primary_path=real_path,
            crown_jewel_id=crown_id,
            entry_point_id=entry_id,
            secondary_findings=secondary,
            chain_risk_score=risk_score,
            component_size=component_real_size,
            label="",        # set after sorting
            inferred=all_inferred,
        ))

    # Sort by risk score descending (highest-risk chain = Chain 1)
    chain_results.sort(key=lambda c: c.chain_risk_score, reverse=True)

    # Assign 1-based indices and generate auto-labels
    for i, cr in enumerate(chain_results):
        cr.chain_index = i + 1
        crown_finding = get_node_finding(G, cr.crown_jewel_id)
        crown_title = crown_finding.title if crown_finding else cr.crown_jewel_id
        truncated = crown_title[:40] + ("\u2026" if len(crown_title) > 40 else "")
        cr.label = f"Chain {i + 1} \u2014 {truncated}"

    return chain_results


def find_primary_chain(G: nx.DiGraph) -> list[Finding]:
    """Return the primary attack chain as an ordered list of Finding objects.

    Backward-compatible alias: returns findings from the highest-risk chain.
    Only includes nodes that have a corresponding Finding (no placeholders).
    """
    chains = find_all_chains(G)
    if not chains:
        return []
    result: list[Finding] = []
    for nid in chains[0].primary_path:
        f = get_node_finding(G, nid)
        if f is not None:
            result.append(f)
    return result


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
