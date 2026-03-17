"""Format detector — auto-detects input format from JSON structure."""
from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, List, Optional, Tuple

from src.ingestion.schema import Finding

logger = logging.getLogger(__name__)


def _load_json(path: Path | str) -> Any:
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def detect_format(data: Any) -> str:
    """Return the best-match adapter format name for the given parsed JSON data.

    Detection order matters — more specific signatures first.
    """
    if isinstance(data, dict):
        # Strike7 signature: benchmark run keys
        if (
            "benchmark_run_id" in data
            or "agent_steps" in data
            or ("run_id" in data and "steps" in data)
            or ("benchmark_id" in data and ("flags_captured" in data or "steps" in data))
        ):
            return "strike7"

        # Generic: has a recognisable findings-list key
        if "findings" in data or any(
            k in data for k in ("results", "vulnerabilities", "issues", "vulns", "items")
        ):
            return "generic"

    if isinstance(data, list) and data and isinstance(data[0], dict):
        return "generic"

    return "generic"


def detect_format_from_file(path: Path | str) -> tuple[str, Any]:
    """Load JSON from path and return (format_name, parsed_data)."""
    data = _load_json(path)
    return detect_format(data), data


_CRITICAL_FIELDS = {"id", "title", "severity", "enabled_by"}
_OPTIONAL_FIELDS = {
    "severity_label", "mitre_technique", "step_index",
    "timestamp_offset_s", "evidence", "host",
}

# Field aliases for both generic and strike7 formats
_ALL_ALIASES: dict[str, str] = {
    "finding_id": "id", "vuln_id": "id", "vulnerability_id": "id",
    "name": "title", "vulnerability": "title", "vuln_name": "title", "description": "title",
    "cvss": "severity", "cvss_score": "severity", "risk_score": "severity", "risk": "severity",
    "severity_rating": "severity_label", "risk_label": "severity_label",
    "mitre": "mitre_technique", "technique": "mitre_technique", "mitre_id": "mitre_technique",
    "step": "step_index", "step_number": "step_index",
    "timestamp": "timestamp_offset_s", "time_offset": "timestamp_offset_s", "elapsed_s": "timestamp_offset_s",
    "depends_on": "enabled_by", "prerequisites": "enabled_by", "requires": "enabled_by",
    "proof": "evidence", "output": "evidence", "raw_output": "evidence",
    "target": "host", "ip": "host", "hostname": "host",
}


def describe_field_mapping(data: Any, format_name: str) -> dict:
    """Return a detailed field mapping report for the given data.

    Used by `acm discover` to show exactly what the adapter will map and what's missing.
    """
    # Get a sample finding
    sample: dict = {}
    if isinstance(data, list) and data and isinstance(data[0], dict):
        sample = data[0]
    elif isinstance(data, dict):
        for key in ("findings", "results", "vulnerabilities", "issues", "vulns", "items"):
            if isinstance(data.get(key), list) and data[key]:
                raw = data[key][0]
                if isinstance(raw, dict):
                    sample = raw
                    break
        # Strike7: look inside agent_steps
        steps = data.get("agent_steps") or data.get("steps") or []
        if not sample and steps:
            for step in steps:
                if isinstance(step, dict):
                    for k in ("findings", "vulnerabilities"):
                        if isinstance(step.get(k), list) and step[k]:
                            sample = step[k][0]
                            break
                if sample:
                    break

    # Resolve sample keys to canonical names
    canonical = {_ALL_ALIASES.get(k, k): k for k in sample}

    finding_fields = set(Finding.model_fields.keys())
    mapped = []
    missing_critical = []
    missing_optional = []

    for field in sorted(finding_fields):
        if field in canonical:
            mapped.append({"canonical": field, "source_field": canonical[field], "status": "found"})
        elif field in _CRITICAL_FIELDS:
            missing_critical.append(field)
        else:
            missing_optional.append(field)

    # Fields in sample that didn't map to anything
    unmapped = []
    for src_key in sample:
        canonical_key = _ALL_ALIASES.get(src_key, src_key)
        if canonical_key not in finding_fields:
            unmapped.append(src_key)

    # Check if chain inference will be needed
    has_enabled_by = "enabled_by" in canonical or "depends_on" in canonical or "prerequisites" in canonical
    chain_note = (
        "✓ explicit chain relationships found"
        if has_enabled_by
        else "✗ missing — chain inference will be applied automatically"
    )

    return {
        "format": format_name,
        "sample_count": _count_findings(data),
        "mapped_fields": mapped,
        "missing_critical": missing_critical,
        "missing_optional": missing_optional,
        "unmapped_source_fields": unmapped,
        "chain_note": chain_note,
        "needs_chain_inference": not has_enabled_by,
    }


def _count_findings(data: Any) -> int:
    if isinstance(data, list):
        return len(data)
    if isinstance(data, dict):
        for key in ("findings", "results", "vulnerabilities", "issues", "vulns", "items"):
            if isinstance(data.get(key), list):
                return len(data[key])
    return 0


# ---------------------------------------------------------------------------
# Universal AI adapter
# ---------------------------------------------------------------------------

FORMAT_DETECTION_PROMPT = """You are analyzing a JSON file from a security tool.
Your job is to extract security findings from whatever structure is present.

JSON structure (first 3000 chars):
{json_sample}

TASK:
1. Identify where findings/vulnerabilities/issues live in this structure
2. For each finding, extract these fields if present (use null if absent):
   - id (unique identifier)
   - title or name of the vulnerability
   - severity (numeric 0-10 OR string label)
   - mitre_technique (T-number if present)
   - evidence or proof
   - affected host/target
   - step number or sequence position
   - what this finding depends on or was caused by

3. Map every finding to this exact JSON schema:
[
  {{
    "id": "...",
    "title": "...",
    "severity": 0.0,
    "severity_label": "CRITICAL|HIGH|MEDIUM|LOW|INFO",
    "mitre_technique": null,
    "step_index": null,
    "timestamp_offset_s": null,
    "enabled_by": [],
    "evidence": null,
    "host": null,
    "ai_detail": null,
    "ai_remediation": null,
    "ai_confidence": null
  }}
]

SEVERITY MAPPING if source uses labels:
Critical/P1 → 9.5 CRITICAL
High/P2 → 7.5 HIGH
Medium/P3 → 5.0 MEDIUM
Low/P4 → 2.5 LOW
Info/P5/Informational → 0.5 INFO
Use your judgment for unlabeled severity fields.

Respond ONLY with the JSON array. No explanation, no markdown fences.
If you cannot identify any findings, respond with: []"""


@dataclass
class AdaptationReport:
    """Report returned by ai_detect_and_adapt describing what was found."""
    finding_count: int
    fields_mapped: List[str]
    format_guess: str
    warnings: List[str] = field(default_factory=list)
    fallback_used: bool = False


def _normalize_ai_finding(raw: dict) -> Optional[Finding]:
    """Convert a raw dict from AI detection into a Finding, returning None on failure."""
    SEVERITY_LABEL_MAP = {
        "critical": ("CRITICAL", 9.5),
        "high": ("HIGH", 7.5),
        "medium": ("MEDIUM", 5.0),
        "low": ("LOW", 2.5),
        "info": ("INFO", 0.5),
        "informational": ("INFO", 0.5),
    }

    try:
        fid = str(raw.get("id") or "").strip() or None
        title = str(raw.get("title") or "").strip() or "Untitled Finding"

        severity_raw = raw.get("severity")
        severity_label_raw = str(raw.get("severity_label") or "").upper()

        if isinstance(severity_raw, str):
            key = severity_raw.lower().strip()
            if key in SEVERITY_LABEL_MAP:
                severity_label_raw, severity_raw = SEVERITY_LABEL_MAP[key]
            else:
                severity_raw = 0.5
        if severity_raw is None:
            severity_raw = 0.5
        severity = max(0.0, min(10.0, float(severity_raw)))

        if severity_label_raw not in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
            if severity >= 9.0:
                severity_label_raw = "CRITICAL"
            elif severity >= 7.0:
                severity_label_raw = "HIGH"
            elif severity >= 4.0:
                severity_label_raw = "MEDIUM"
            elif severity >= 1.0:
                severity_label_raw = "LOW"
            else:
                severity_label_raw = "INFO"

        return Finding(
            id=fid or title.lower().replace(" ", "-")[:40],
            title=title,
            severity=severity,
            severity_label=severity_label_raw,
            mitre_technique=raw.get("mitre_technique"),
            step_index=raw.get("step_index"),
            timestamp_offset_s=raw.get("timestamp_offset_s"),
            enabled_by=raw.get("enabled_by") or [],
            evidence=raw.get("evidence"),
            host=raw.get("host"),
            ai_detail=raw.get("ai_detail"),
            ai_remediation=raw.get("ai_remediation"),
            ai_confidence=raw.get("ai_confidence"),
        )
    except Exception as exc:
        logger.warning("ai_detect: failed to normalize finding: %s — %s", raw, exc)
        return None


def ai_detect_and_adapt(
    raw_data: Any,
    api_key: Optional[str] = None,
) -> Tuple[List[Finding], AdaptationReport]:
    """Use Claude to inspect any arbitrary JSON structure and extract findings.

    Returns (findings, AdaptationReport).
    Never crashes — if AI detection fails, falls back to generic adapter.
    """
    import os
    effective_key = api_key or os.environ.get("ANTHROPIC_API_KEY")

    if not effective_key:
        from src.ingestion.adapters import get_adapter
        adapter = get_adapter("generic")()
        from src.ingestion.schema import Engagement as Eng
        try:
            eng = adapter.parse(raw_data)
            return eng.findings, AdaptationReport(
                finding_count=len(eng.findings),
                fields_mapped=[],
                format_guess="generic",
                fallback_used=True,
                warnings=["No API key — fell back to generic adapter"],
            )
        except Exception:
            return [], AdaptationReport(
                finding_count=0,
                fields_mapped=[],
                format_guess="unknown",
                fallback_used=True,
                warnings=["No API key and generic adapter failed"],
            )

    json_sample = json.dumps(raw_data, indent=2)[:3000]
    prompt = FORMAT_DETECTION_PROMPT.format(json_sample=json_sample)

    try:
        import anthropic
        client = anthropic.Anthropic(api_key=effective_key)
        message = client.messages.create(
            model="claude-sonnet-4-5",
            max_tokens=4096,
            messages=[{"role": "user", "content": prompt}],
        )
        raw_text = message.content[0].text.strip()
        logger.debug("ai_detect raw response: %s", raw_text[:500])

        # Strip markdown fences if present
        if raw_text.startswith("```"):
            lines = raw_text.splitlines()
            raw_text = "\n".join(lines[1:-1] if lines[-1].strip() == "```" else lines[1:])

        raw_findings = json.loads(raw_text)
        if not isinstance(raw_findings, list):
            raise ValueError(f"Expected list, got {type(raw_findings)}")

        findings = [_normalize_ai_finding(f) for f in raw_findings]
        findings = [f for f in findings if f is not None]

        # Identify which fields were mapped
        fields_mapped = []
        if raw_findings:
            sample = raw_findings[0]
            for k, v in sample.items():
                if v is not None and k not in ("ai_detail", "ai_remediation", "ai_confidence"):
                    fields_mapped.append(k)

        # Guess format from raw_data structure
        if isinstance(raw_data, dict):
            format_guess = next(
                (k for k in ("nessus", "nuclei", "openvas", "burp", "acunetix") if k in str(raw_data).lower()[:200]),
                "unknown",
            )
        else:
            format_guess = "unknown"

        return findings, AdaptationReport(
            finding_count=len(findings),
            fields_mapped=fields_mapped,
            format_guess=format_guess,
        )

    except (ImportError, Exception) as exc:
        logger.error("ai_detect failed: %s — falling back to generic adapter", exc)
        from src.ingestion.adapters import get_adapter
        adapter = get_adapter("generic")()
        try:
            eng = adapter.parse(raw_data)
            return eng.findings, AdaptationReport(
                finding_count=len(eng.findings),
                fields_mapped=[],
                format_guess="generic",
                fallback_used=True,
                warnings=[f"AI detection failed ({exc}) — fell back to generic adapter"],
            )
        except Exception as exc2:
            return [], AdaptationReport(
                finding_count=0,
                fields_mapped=[],
                format_guess="unknown",
                fallback_used=True,
                warnings=[f"AI detection failed ({exc}) and generic adapter also failed ({exc2})"],
            )
