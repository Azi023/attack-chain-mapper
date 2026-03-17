# attack-chain-mapper
"""
Public API for PIL F7 integration:

    from attack_chain_mapper import build_chain

    chain = build_chain(
        engagement_data=dict_or_list,
        adapter=None,          # auto-detect if None
        api_key=None,          # optional — enriches with AI details
        model="claude-sonnet-4-5",
        infer_chain=True,      # auto-infer enabled_by when missing
    )
    html = chain.render_html()       # str: complete HTML
    data = chain.to_json()           # dict: machine-readable
    path = chain.primary_path        # list[Finding]
"""
from __future__ import annotations
from dataclasses import dataclass
from typing import Optional, Any

from src.ingestion.schema import Finding, Engagement
from src.ingestion.detector import detect_format
from src.ingestion.adapters import get_adapter
from src.graph.builder import build_graph
from src.graph.inference import infer_and_build, mark_inferred_edges
from src.graph.pathfinder import find_primary_chain, find_secondary_findings
from src.graph.scorer import compute_chain_risk_score
from src.renderer.html import render_html
from src.renderer.json_export import export_graph_json


@dataclass
class AttackChain:
    engagement: Engagement
    primary_path: list[Finding]
    secondary_findings: list[Finding]
    chain_risk_score: float
    inferred_ids: set[str]

    def render_html(self) -> str:
        return render_html(
            self.engagement,
            self.primary_path,
            self.secondary_findings,
            self.chain_risk_score,
        )

    def to_json(self) -> dict:
        return export_graph_json(
            self.engagement,
            self.primary_path,
            self.secondary_findings,
            self.chain_risk_score,
        )


def build_chain(
    engagement_data: Any,
    adapter=None,
    api_key: Optional[str] = None,
    model: str = "claude-sonnet-4-5",
    infer_chain: bool = True,
) -> AttackChain:
    """Build an attack chain from raw engagement data.

    Args:
        engagement_data: dict or list of findings (any supported format)
        adapter: adapter instance; auto-detected if None
        api_key: Anthropic API key for AI enrichment; skipped if None
        model: Anthropic model ID
        infer_chain: if True, auto-infer enabled_by when not present in data

    Returns:
        AttackChain with primary_path, secondary_findings, render_html(), to_json()
    """
    if adapter is None:
        fmt = detect_format(engagement_data)
        adapter = get_adapter(fmt)()

    engagement = adapter.parse(engagement_data)
    findings = engagement.findings
    inferred_ids: set[str] = set()

    if infer_chain:
        findings, inferred_ids = infer_and_build(findings)
        if inferred_ids:
            engagement = Engagement(
                engagement_id=engagement.engagement_id,
                target_name=engagement.target_name,
                findings=findings,
                metadata=engagement.metadata,
            )

    G = build_graph(engagement.findings)
    if inferred_ids:
        mark_inferred_edges(G, inferred_ids)

    if api_key:
        from src.ai.client import AIClient
        ai = AIClient(api_key=api_key, model=model)
        findings = ai.enrich_findings_sync(engagement.findings, G)
        engagement = Engagement(
            engagement_id=engagement.engagement_id,
            target_name=engagement.target_name,
            findings=findings,
            metadata=engagement.metadata,
        )
        G = build_graph(engagement.findings)
        if inferred_ids:
            mark_inferred_edges(G, inferred_ids)

    primary = find_primary_chain(G)
    secondary = find_secondary_findings(G, primary)
    risk_score = compute_chain_risk_score(primary)

    return AttackChain(
        engagement=engagement,
        primary_path=primary,
        secondary_findings=secondary,
        chain_risk_score=risk_score,
        inferred_ids=inferred_ids,
    )
