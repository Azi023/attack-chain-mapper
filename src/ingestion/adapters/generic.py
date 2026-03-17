"""Generic JSON adapter — reference implementation.

Expects input JSON to either be:
  - An Engagement object directly: {"engagement_id": ..., "findings": [...]}
  - A list of findings: [{...}, {...}]
  - A dict with a "findings" key containing a list

Field mapping is flexible — unknown fields are ignored, missing optional fields use None.
"""
from __future__ import annotations

import json
import uuid
from pathlib import Path
from typing import Any

from src.ingestion.schema import Engagement, Finding

# Maps common alternative field names → canonical Finding field names
_FIELD_ALIASES: dict[str, str] = {
    "finding_id": "id",
    "vuln_id": "id",
    "vulnerability_id": "id",
    "name": "title",
    "vulnerability": "title",
    "vuln_name": "title",
    "cvss": "severity",
    "cvss_score": "severity",
    "risk_score": "severity",
    "risk": "severity",
    "severity_rating": "severity_label",
    "risk_label": "severity_label",
    "mitre": "mitre_technique",
    "technique": "mitre_technique",
    "mitre_id": "mitre_technique",
    "step": "step_index",
    "step_number": "step_index",
    "timestamp": "timestamp_offset_s",
    "time_offset": "timestamp_offset_s",
    "offset_s": "timestamp_offset_s",
    "depends_on": "enabled_by",
    "prerequisites": "enabled_by",
    "requires": "enabled_by",
    "proof": "evidence",
    "output": "evidence",
    "raw_output": "evidence",
    "target": "host",
    "ip": "host",
    "hostname": "host",
    "detail": "ai_detail",
    "ai_description": "ai_detail",
    "remediation": "ai_remediation",
    "fix": "ai_remediation",
    "mitigation": "ai_remediation",
    "confidence": "ai_confidence",
    "ai_confidence_score": "ai_confidence",
}

_SEVERITY_LABEL_MAP: dict[str, str] = {
    "critical": "CRITICAL",
    "crit": "CRITICAL",
    "high": "HIGH",
    "medium": "MEDIUM",
    "med": "MEDIUM",
    "moderate": "MEDIUM",
    "low": "LOW",
    "info": "INFO",
    "informational": "INFO",
    "note": "INFO",
}


def _infer_severity_label(severity: float, raw_label: str | None) -> str:
    """Infer severity label from score if raw label is missing or invalid."""
    if raw_label:
        mapped = _SEVERITY_LABEL_MAP.get(raw_label.lower())
        if mapped:
            return mapped

    # CVSS threshold mapping
    if severity >= 9.0:
        return "CRITICAL"
    if severity >= 7.0:
        return "HIGH"
    if severity >= 4.0:
        return "MEDIUM"
    if severity >= 1.0:
        return "LOW"
    return "INFO"


def _normalise_finding(raw: dict[str, Any], idx: int) -> Finding:
    """Map a raw dict to a Finding, resolving aliases and inferring missing fields."""
    # Apply field aliases first
    normalised: dict[str, Any] = {}
    for key, value in raw.items():
        canonical = _FIELD_ALIASES.get(key, key)
        normalised[canonical] = value

    # Ensure id exists
    if "id" not in normalised or not normalised["id"]:
        normalised["id"] = f"finding-{idx}"

    # Ensure title exists
    if "title" not in normalised or not normalised["title"]:
        normalised["title"] = f"Finding {idx}"

    # Ensure severity is a float
    severity_raw = normalised.get("severity", 0.0)
    try:
        severity = float(severity_raw)
        severity = max(0.0, min(10.0, severity))
    except (TypeError, ValueError):
        severity = 0.0
    normalised["severity"] = severity

    # Infer severity_label
    raw_label = normalised.get("severity_label")
    normalised["severity_label"] = _infer_severity_label(severity, raw_label)

    # Ensure enabled_by is a list of strings
    enabled_by = normalised.get("enabled_by", [])
    if isinstance(enabled_by, str):
        enabled_by = [enabled_by] if enabled_by else []
    normalised["enabled_by"] = [str(x) for x in enabled_by]

    # Strip unexpected keys Pydantic would reject
    finding_fields = set(Finding.model_fields.keys())
    clean = {k: v for k, v in normalised.items() if k in finding_fields}

    return Finding(**clean)


def _extract_findings_list(data: Any) -> tuple[list[dict], dict]:
    """Extract raw finding dicts and engagement-level metadata from any supported shape."""
    if isinstance(data, list):
        return data, {}

    if isinstance(data, dict):
        # Direct engagement object
        if "findings" in data:
            meta = {k: v for k, v in data.items() if k != "findings"}
            return data["findings"], meta
        # Nested under 'results', 'vulnerabilities', 'issues', etc.
        for key in ("results", "vulnerabilities", "issues", "vulns", "items"):
            if key in data and isinstance(data[key], list):
                meta = {k: v for k, v in data.items() if k != key}
                return data[key], meta

    raise ValueError(f"Unsupported input shape: {type(data).__name__}")


class GenericAdapter:
    """Adapter for generic JSON engagement outputs."""

    FORMAT_NAME = "generic"

    def load(self, path: Path | str) -> Engagement:
        """Load a JSON file and return a normalised Engagement."""
        path = Path(path)
        with path.open("r", encoding="utf-8") as fh:
            data = json.load(fh)
        return self.parse(data)

    def parse(self, data: Any) -> Engagement:
        """Parse a dict/list into an Engagement."""
        raw_findings, meta = _extract_findings_list(data)

        findings = [
            _normalise_finding(f, idx)
            for idx, f in enumerate(raw_findings)
            if isinstance(f, dict)
        ]

        engagement_id = (
            meta.get("engagement_id")
            or meta.get("id")
            or meta.get("scan_id")
            or str(uuid.uuid4())
        )
        target_name = (
            meta.get("target_name")
            or meta.get("target")
            or meta.get("name")
        )

        return Engagement(
            engagement_id=str(engagement_id),
            target_name=target_name,
            findings=findings,
            metadata=meta,
        )

    def describe_mapping(self, data: Any) -> dict[str, Any]:
        """Return a human-readable field mapping for use in `acm discover`."""
        raw_findings, _ = _extract_findings_list(data)
        if not raw_findings:
            return {"mapped_fields": [], "unmapped_fields": [], "sample_count": 0}

        sample = raw_findings[0]
        finding_fields = set(Finding.model_fields.keys())
        mapped = []
        unmapped = []

        for key in sample:
            canonical = _FIELD_ALIASES.get(key, key)
            if canonical in finding_fields:
                mapped.append({"source_field": key, "maps_to": canonical})
            else:
                unmapped.append(key)

        return {
            "adapter": self.FORMAT_NAME,
            "sample_count": len(raw_findings),
            "mapped_fields": mapped,
            "unmapped_fields": unmapped,
        }
