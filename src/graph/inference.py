"""Chain inference — heuristic enabled_by for findings that lack explicit relationships.

Most real-world tool outputs (including Strike7, Burp, Nessus) do NOT include
explicit enabled_by relationships. This module infers them from:
  1. Step ordering (step_index or array position)
  2. Severity progression (lower severity findings are assumed to be prerequisites)
  3. Host overlap (findings on the same host are more likely to be related)

Inferred edges are marked with inferred=True in the graph so downstream code can
flag them appropriately. Explicit relationships are NEVER overridden.
"""
from __future__ import annotations

import networkx as nx

from src.ingestion.schema import Finding


def needs_inference(findings: list[Finding]) -> bool:
    """Return True if non-entry findings lack enabled_by.

    A single finding without enabled_by is the entry point — that's expected and fine.
    More than one finding without enabled_by means intermediate nodes are unlinked.
    """
    if len(findings) <= 1:
        return False
    unlinked_count = sum(1 for f in findings if not f.enabled_by)
    # More than one unlinked finding means intermediate nodes need inference
    # (exactly one unlinked = entry point only, no inference needed)
    return unlinked_count > 1


def _sorted_by_step(findings: list[Finding]) -> list[Finding]:
    """Sort findings by step_index (None = discovered later), then by array position."""
    return sorted(findings, key=lambda f: (f.step_index is None, f.step_index or 0, f.severity))


def _host_compatible(a: Finding, b: Finding) -> bool:
    """Return True if findings could plausibly be on the same attack path by host."""
    if a.host is None or b.host is None:
        return True  # unknown host — don't rule it out
    if a.host == b.host:
        return True
    # Same /24 subnet (rough heuristic)
    a_parts = a.host.split(".")
    b_parts = b.host.split(".")
    if len(a_parts) == 4 and len(b_parts) == 4:
        return a_parts[:3] == b_parts[:3]
    return False


def infer_enabled_by(findings: list[Finding]) -> tuple[list[Finding], set[str]]:
    """Infer enabled_by for findings that lack it.

    Returns:
        (enriched_findings, inferred_ids)
        - enriched_findings: new Finding objects (explicit ones unchanged)
        - inferred_ids: set of finding IDs that had enabled_by inferred
    """
    sorted_f = _sorted_by_step(findings)
    inferred_ids: set[str] = set()
    result: list[Finding] = []

    for i, f in enumerate(sorted_f):
        if f.enabled_by:
            # Explicit relationship — respect it
            result.append(f)
            continue

        if i == 0:
            # Entry point — no predecessor
            result.append(f)
            continue

        # Find best predecessor from all earlier findings
        candidates = []
        for prev in sorted_f[:i]:
            if prev.id == f.id:
                continue
            # Prerequisite heuristic: previous in step order, not higher severity than target
            if prev.severity <= f.severity and _host_compatible(prev, f):
                candidates.append(prev)

        if candidates:
            # Best candidate: highest severity among valid predecessors
            # (most impactful step that "opened the door")
            best = max(candidates, key=lambda c: (c.severity, c.step_index or 0))
            new_f = f.model_copy(update={"enabled_by": [best.id]})
        else:
            # Fallback: chain to the immediately preceding finding regardless of severity
            prev = sorted_f[i - 1]
            new_f = f.model_copy(update={"enabled_by": [prev.id]})

        inferred_ids.add(f.id)
        result.append(new_f)

    # Preserve original order
    id_to_new = {f.id: f for f in result}
    return [id_to_new[f.id] for f in findings], inferred_ids


def mark_inferred_edges(G: nx.DiGraph, inferred_ids: set[str]) -> None:
    """Mark edges into inferred nodes with inferred=True in-place on the graph."""
    for fid in inferred_ids:
        if fid not in G:
            continue
        for pred_id in G.predecessors(fid):
            G[pred_id][fid]["inferred"] = True


def infer_and_build(
    findings: list[Finding],
) -> tuple[list[Finding], set[str]]:
    """Convenience: run inference only if needed.

    Returns (possibly_modified_findings, inferred_ids).
    If no inference was needed, returns the SAME list object and an empty set.
    """
    if not needs_inference(findings):
        return findings, set()
    return infer_enabled_by(findings)
