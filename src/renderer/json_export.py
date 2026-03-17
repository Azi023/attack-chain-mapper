"""JSON graph export — machine-readable output."""
from __future__ import annotations

import json
from pathlib import Path

from src.ingestion.schema import Engagement, Finding


def export_graph_json(
    engagement: Engagement,
    primary_chain: list[Finding],
    secondary_findings: list[Finding],
    chain_risk_score: float,
) -> dict:
    """Return a machine-readable graph dict."""
    return {
        "engagement_id": engagement.engagement_id,
        "target_name": engagement.target_name,
        "chain_risk_score": chain_risk_score,
        "primary_chain": [f.model_dump() for f in primary_chain],
        "secondary_findings": [f.model_dump() for f in secondary_findings],
        "all_findings": [f.model_dump() for f in engagement.findings],
        "metadata": engagement.metadata,
    }


def export_to_file(data: dict, path: str | Path) -> Path:
    out = Path(path)
    out.write_text(json.dumps(data, indent=2), encoding="utf-8")
    return out
