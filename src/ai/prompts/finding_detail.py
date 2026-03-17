"""Prompt template for AI finding detail generation."""
from __future__ import annotations

from src.ingestion.schema import Finding


def build_finding_detail_prompt(
    finding: Finding,
    chain_context: dict,
) -> str:
    """Build the prompt for generating AI detail for a single finding.

    chain_context contains:
      - enabled_by_titles: list of titles of findings that enabled this one
      - enables_titles: list of titles of findings this one enabled
    """
    enabled_by_str = (
        ", ".join(chain_context.get("enabled_by_titles", []))
        or "None (entry point)"
    )
    enables_str = (
        ", ".join(chain_context.get("enables_titles", []))
        or "None (terminal finding)"
    )

    mitre_str = f"MITRE Technique: {finding.mitre_technique}" if finding.mitre_technique else ""
    evidence_str = f"Evidence snippet:\n{finding.evidence}" if finding.evidence else ""
    host_str = f"Target host: {finding.host}" if finding.host else ""

    prompt = f"""You are a senior penetration test report writer creating a CISO-grade finding detail.

FINDING: {finding.title}
Severity: {finding.severity}/10 ({finding.severity_label})
{mitre_str}
{host_str}

ATTACK CHAIN CONTEXT:
- This finding was made possible by: {enabled_by_str}
- This finding enabled: {enables_str}

{evidence_str}

Write a JSON response with exactly these three keys:
- "detail": 2–3 paragraph technical description of what this finding is, why it exists, and how the attacker exploited it. Be specific and actionable. No filler text.
- "remediation": Concrete, prioritised remediation steps. Number them. Include specific configuration changes, patches, or architectural fixes.
- "confidence": Your confidence (0.0–1.0) that this finding represents a true positive based on the context given.

Respond with ONLY the JSON object, no markdown fences."""

    return prompt


SYSTEM_PROMPT = (
    "You are a senior penetration testing expert writing CISO-grade security reports. "
    "Your finding details are technically precise, actionable, and suitable for board-level reporting. "
    "Never produce placeholder or generic text — every finding detail must be specific to the context provided."
)
