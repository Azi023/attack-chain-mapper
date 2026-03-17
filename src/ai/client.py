"""Anthropic API wrapper — BYOK, async, non-blocking.

Users provide their own API key via ANTHROPIC_API_KEY env var or --api-key CLI flag.
One call per finding. Never raises — failures return fixture data or empty strings.
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
from typing import Optional

from src.ingestion.schema import Finding
from src.ai.prompts.finding_detail import build_finding_detail_prompt, SYSTEM_PROMPT

logger = logging.getLogger(__name__)

DEFAULT_MODEL = "claude-sonnet-4-5"


class AIClient:
    """Async Anthropic client wrapper. Safe to instantiate with no API key."""

    def __init__(
        self,
        api_key: Optional[str] = None,
        model: str = DEFAULT_MODEL,
    ):
        self.api_key = api_key or os.environ.get("ANTHROPIC_API_KEY")
        self.model = model
        self._client = None

        if self.api_key:
            try:
                import anthropic
                self._client = anthropic.AsyncAnthropic(api_key=self.api_key)
            except ImportError:
                logger.warning("anthropic package not installed — AI enrichment unavailable")
                self._client = None

    @property
    def available(self) -> bool:
        """True if an API key is configured and the anthropic package is installed."""
        return self._client is not None

    async def generate_finding_detail(
        self,
        finding: Finding,
        chain_context: dict,
    ) -> dict:
        """Generate AI detail for a single finding.

        Returns: {"detail": str, "remediation": str, "confidence": float}

        When unavailable (no API key or package missing), returns the finding's
        existing ai_detail/ai_remediation/ai_confidence if present, otherwise
        returns empty strings and confidence 0.0. Never raises.
        """
        if not self.available:
            return {
                "detail": finding.ai_detail or "",
                "remediation": finding.ai_remediation or "",
                "confidence": finding.ai_confidence or 0.0,
            }

        prompt = build_finding_detail_prompt(finding, chain_context)
        raw_response = ""
        try:
            message = await self._client.messages.create(
                model=self.model,
                max_tokens=1024,
                system=SYSTEM_PROMPT,
                messages=[{"role": "user", "content": prompt}],
            )
            raw_response = message.content[0].text
            logger.debug("Raw AI response for %s: %s", finding.id, raw_response)
            result = json.loads(raw_response)
            # Handle remediation as list or string
            remediation = result.get("remediation", "")
            if isinstance(remediation, list):
                remediation = "\n".join(str(r) for r in remediation)
            return {
                "detail": result.get("detail", ""),
                "remediation": remediation,
                "confidence": float(result.get("confidence", 0.0)),
                "reasoning_mode": result.get("reasoning_mode", "unknown"),
            }
        except json.JSONDecodeError:
            logger.error(
                "AI response for finding %s was not valid JSON: %r", finding.id, raw_response
            )
            return {"detail": finding.ai_detail or "", "remediation": finding.ai_remediation or "", "confidence": 0.0}
        except Exception as e:
            logger.error("AI call failed for finding %s: %s", finding.id, e)
            return {"detail": finding.ai_detail or "", "remediation": finding.ai_remediation or "", "confidence": 0.0}

    async def enrich_findings(
        self,
        findings: list[Finding],
        graph,
    ) -> list[Finding]:
        """Enrich all findings with AI-generated detail. Non-blocking, concurrent.

        Returns new Finding objects — originals are never mutated.
        """
        title_by_id = {f.id: f.title for f in findings}
        total_steps = len(findings)

        # Identify crown jewel: node with no successors that is in the primary path
        # (approximated as the node with highest severity among terminal nodes)
        terminal_nodes = [
            f.id for f in findings
            if f.id in graph and len(list(graph.successors(f.id))) == 0
        ]
        crown_jewel_id = None
        if terminal_nodes:
            finding_by_id = {f.id: f for f in findings}
            crown_jewel_id = max(
                terminal_nodes,
                key=lambda fid: finding_by_id[fid].severity if fid in finding_by_id else 0,
            )

        async def enrich_one(finding: Finding) -> Finding:
            predecessors = list(graph.predecessors(finding.id)) if finding.id in graph else []
            successors = list(graph.successors(finding.id)) if finding.id in graph else []
            context = {
                "enabled_by_titles": [title_by_id.get(p, p) for p in predecessors],
                "enables_titles": [title_by_id.get(s, s) for s in successors],
                "total_steps": total_steps,
                "is_crown_jewel": finding.id == crown_jewel_id,
            }
            result = await self.generate_finding_detail(finding, context)
            return finding.model_copy(update={
                "ai_detail": result["detail"] or finding.ai_detail,
                "ai_remediation": result["remediation"] or finding.ai_remediation,
                "ai_confidence": result["confidence"] if result["confidence"] else finding.ai_confidence,
            })

        enriched = await asyncio.gather(*[enrich_one(f) for f in findings])
        return list(enriched)

    def enrich_findings_sync(
        self,
        findings: list[Finding],
        graph,
    ) -> list[Finding]:
        """Synchronous wrapper around enrich_findings."""
        return asyncio.run(self.enrich_findings(findings, graph))


# ── Legacy function-based API (kept for backwards compatibility) ──────────────

async def enrich_findings_async(
    findings: list[Finding],
    graph,
    api_key: Optional[str] = None,
    model: str = DEFAULT_MODEL,
) -> list[Finding]:
    client = AIClient(api_key=api_key, model=model)
    return await client.enrich_findings(findings, graph)


def enrich_findings_sync(
    findings: list[Finding],
    graph,
    api_key: Optional[str] = None,
    model: str = DEFAULT_MODEL,
) -> list[Finding]:
    client = AIClient(api_key=api_key, model=model)
    return client.enrich_findings_sync(findings, graph)
