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
    html = chain.render_html()              # str: complete HTML
    data = chain.to_json()                  # dict: machine-readable
    path = chain.primary_path               # list[Finding] (highest-risk chain)
    chains = chain.chains                   # list[ChainResult] (all chains)
    total_risk = chain.total_engagement_risk  # weighted engagement risk
"""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import Optional, Any

from src.ingestion.schema import Finding, Engagement
from src.ingestion.detector import detect_format
from src.ingestion.adapters import get_adapter
from src.graph.builder import build_graph
from src.graph.inference import infer_and_build, mark_inferred_edges
from src.graph.pathfinder import find_all_chains, find_secondary_findings, ChainResult
from src.graph.scorer import score_all_chains, total_engagement_risk as calc_total_risk
from src.renderer.html import render_html
from src.renderer.json_export import export_graph_json


@dataclass
class AttackChain:
    engagement: Engagement
    primary_path: list[Finding]          # backward compat: highest-risk chain findings
    secondary_findings: list[Finding]    # findings not in any chain's primary path
    chain_risk_score: float              # backward compat: highest-risk chain score
    inferred_ids: set[str]
    chains: list[ChainResult] = field(default_factory=list)  # all detected chains
    total_engagement_risk: float = 0.0   # weighted sum across all chains
    chain_count: int = 0                 # number of distinct chains

    @property
    def findings(self) -> list[Finding]:
        """All findings in the engagement (for renderer duck-typing)."""
        return self.engagement.findings

    @property
    def primary_chain(self) -> ChainResult | None:
        """Highest-risk ChainResult, or None if no chains detected."""
        return self.chains[0] if self.chains else None

    def render_html(self) -> str:
        title = self.engagement.target_name or self.engagement.engagement_id
        return render_html(self, engagement_title=title)

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
    store: bool = True,
    db_path: Optional[str] = None,
) -> AttackChain:
    """Build an attack chain from raw engagement data.

    Args:
        engagement_data: dict or list of findings (any supported format)
        adapter: adapter instance; auto-detected if None
        api_key: Anthropic API key for AI enrichment; skipped if None
        model: Anthropic model ID
        infer_chain: if True, auto-infer enabled_by when not present in data
        store: if True (default), auto-save the chain to SQLite
        db_path: override the default DB path (~/.attack-chain-mapper/chains.db)

    Returns:
        AttackChain with chains, primary_path, render_html(), to_json()
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

    chains = find_all_chains(G)
    findings_by_id = {f.id: f for f in engagement.findings}
    chains = score_all_chains(chains, findings_by_id)

    primary = []
    if chains:
        from src.graph.builder import get_node_finding
        for nid in chains[0].primary_path:
            f = get_node_finding(G, nid)
            if f is not None:
                primary.append(f)

    # Secondary = findings not in any chain's primary path
    all_primary_ids: set[str] = set()
    for cr in chains:
        all_primary_ids.update(cr.primary_path)
    secondary = [
        f for f in engagement.findings
        if f.id not in all_primary_ids
    ]
    secondary.sort(key=lambda f: f.severity, reverse=True)

    risk_score = chains[0].chain_risk_score if chains else 0.0
    eng_risk = calc_total_risk(chains)

    attack_chain = AttackChain(
        engagement=engagement,
        primary_path=primary,
        secondary_findings=secondary,
        chain_risk_score=risk_score,
        inferred_ids=inferred_ids,
        chains=chains,
        total_engagement_risk=eng_risk,
        chain_count=len(chains),
    )

    if store:
        try:
            from src.storage.store import ChainStore
            chain_store = ChainStore(db_path=db_path)
            chain_store.save_chain(attack_chain, engagement)
            chain_store.close()
        except Exception:
            pass  # Storage failures never block chain generation

    return attack_chain
