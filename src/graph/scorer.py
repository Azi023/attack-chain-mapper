"""Chain risk scorer — aggregates severity into a single chain risk score.

Risk score = Σ (severity_i × step_weight_i)
where step_weight_i increases for later steps in the chain (crown jewels weigh more).
"""
from __future__ import annotations

import math

from src.ingestion.schema import Finding


def compute_chain_risk_score(chain: list[Finding]) -> float:
    """Compute the chain risk score for an ordered list of findings.

    Later findings in the chain receive a higher multiplier because they represent
    greater business impact (closer to crown jewels).

    Returns a float rounded to 2 decimal places.
    """
    if not chain:
        return 0.0

    n = len(chain)
    total = 0.0
    for i, finding in enumerate(chain):
        # Step weight: 1.0 for entry point, up to 2.0 for crown jewel
        step_weight = 1.0 + (i / max(n - 1, 1))
        total += finding.severity * step_weight

    return round(total, 2)


def severity_color(severity: float) -> str:
    """Return the hex colour for a given severity score."""
    if severity >= 9.0:
        return "#e74c3c"  # CRITICAL red
    if severity >= 7.0:
        return "#e67e22"  # HIGH orange
    if severity >= 4.0:
        return "#f39c12"  # MEDIUM amber
    if severity >= 1.0:
        return "#7f8c8d"  # LOW gray
    return "#95a5a6"  # INFO light gray


def label_color(label: str) -> str:
    """Return the hex colour for a severity label string."""
    colors = {
        "CRITICAL": "#e74c3c",
        "HIGH": "#e67e22",
        "MEDIUM": "#f39c12",
        "LOW": "#7f8c8d",
        "INFO": "#95a5a6",
    }
    return colors.get(label.upper(), "#95a5a6")


def risk_score_color(score: float, max_score: float = 100.0) -> str:
    """Return a colour for a chain risk score."""
    ratio = min(score / max(max_score, 1.0), 1.0)
    if ratio >= 0.7:
        return "#e74c3c"
    if ratio >= 0.4:
        return "#e67e22"
    if ratio >= 0.2:
        return "#f39c12"
    return "#7f8c8d"


def score_all_chains(chains: list, findings_by_id: dict) -> list:
    """Score each ChainResult using its path findings. Mutates chain_risk_score in-place.

    Args:
        chains: list of ChainResult objects
        findings_by_id: dict mapping finding ID → Finding object

    Returns the same list with updated chain_risk_score values.
    """
    for cr in chains:
        path_findings = [findings_by_id[nid] for nid in cr.primary_path if nid in findings_by_id]
        cr.chain_risk_score = compute_chain_risk_score(path_findings)
    return chains


def total_engagement_risk(chains: list) -> float:
    """Compute engagement-level risk as a weighted sum of all chain scores.

    Chain 1 weight = 1.0, Chain 2 = 0.8, Chain 3 = 0.6, etc. (min 0.2).
    This prevents a long tail of minor chains inflating the total.
    """
    total = 0.0
    for i, cr in enumerate(chains):
        weight = max(1.0 - i * 0.2, 0.2)
        total += cr.chain_risk_score * weight
    return round(total, 2)
