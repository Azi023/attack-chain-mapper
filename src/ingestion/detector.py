"""Format detector — auto-detects input format from JSON structure."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from src.ingestion.schema import Finding


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
