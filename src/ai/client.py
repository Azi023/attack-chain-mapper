"""Anthropic API wrapper — BYOK, async, non-blocking.

Users provide their own API key via ANTHROPIC_API_KEY env var or explicit argument.
One call per finding. Never retries silently — failures are logged and ai_detail is set to None.
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


def _get_client(api_key: Optional[str] = None):
    """Return an Anthropic async client."""
    try:
        import anthropic
    except ImportError as e:
        raise ImportError("anthropic package is required for AI features. pip install anthropic") from e

    key = api_key or os.environ.get("ANTHROPIC_API_KEY")
    if not key:
        raise ValueError(
            "No API key provided. Set ANTHROPIC_API_KEY env var or pass --api-key. "
            "Demo mode works without an API key — AI details will use pre-written fixture data."
        )
    return anthropic.AsyncAnthropic(api_key=key)


async def _generate_finding_detail(
    client,
    finding: Finding,
    chain_context: dict,
    model: str,
) -> dict:
    """Make a single API call and return parsed JSON result."""
    prompt = build_finding_detail_prompt(finding, chain_context)
    raw_response = ""
    try:
        message = await client.messages.create(
            model=model,
            max_tokens=1024,
            system=SYSTEM_PROMPT,
            messages=[{"role": "user", "content": prompt}],
        )
        raw_response = message.content[0].text
        logger.debug("Raw AI response for %s: %s", finding.id, raw_response)
        return json.loads(raw_response)
    except json.JSONDecodeError:
        logger.error("AI response for finding %s was not valid JSON: %r", finding.id, raw_response)
        return {}
    except Exception as e:
        logger.error("AI call failed for finding %s: %s", finding.id, e)
        return {}


async def enrich_findings_async(
    findings: list[Finding],
    graph,
    api_key: Optional[str] = None,
    model: str = DEFAULT_MODEL,
) -> list[Finding]:
    """Enrich a list of findings with AI-generated detail fields.

    Returns a new list of Finding objects with ai_detail, ai_remediation, ai_confidence set.
    Failures produce None fields — never crashes.
    """
    client = _get_client(api_key)

    # Build title lookup for context
    title_by_id = {f.id: f.title for f in findings}

    async def enrich_one(finding: Finding) -> Finding:
        predecessors = list(graph.predecessors(finding.id)) if finding.id in graph else []
        successors = list(graph.successors(finding.id)) if finding.id in graph else []
        context = {
            "enabled_by_titles": [title_by_id.get(p, p) for p in predecessors],
            "enables_titles": [title_by_id.get(s, s) for s in successors],
        }
        result = await _generate_finding_detail(client, finding, context, model)

        return finding.model_copy(update={
            "ai_detail": result.get("detail"),
            "ai_remediation": result.get("remediation"),
            "ai_confidence": result.get("confidence"),
        })

    enriched = await asyncio.gather(*[enrich_one(f) for f in findings])
    return list(enriched)


def enrich_findings_sync(
    findings: list[Finding],
    graph,
    api_key: Optional[str] = None,
    model: str = DEFAULT_MODEL,
) -> list[Finding]:
    """Synchronous wrapper around enrich_findings_async."""
    return asyncio.run(enrich_findings_async(findings, graph, api_key, model))
