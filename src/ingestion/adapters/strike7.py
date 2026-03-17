"""Strike7 benchmark engagement adapter.

Handles Strike7's benchmark run JSON output. Resilient to format variations —
missing fields always produce None, never crash.

Expected shapes (any of these will work):
  {"benchmark_run_id": ..., "agent_steps": [...], "findings": [...]}
  {"run_id": ..., "steps": [...], "vulnerabilities": [...]}
  {"benchmark_run_id": ..., "agent_steps": [{"findings": [...], ...}]}

Severity string → float mapping:
  CRITICAL=9.5, HIGH=7.5, MEDIUM=5.0, LOW=2.5, INFO=0.5
"""
from __future__ import annotations

import json
import uuid
from pathlib import Path
from typing import Any

from src.ingestion.schema import Engagement, Finding

_SEVERITY_STR_TO_FLOAT: dict[str, float] = {
    "critical": 9.5,
    "crit": 9.5,
    "high": 7.5,
    "medium": 5.0,
    "med": 5.0,
    "moderate": 5.0,
    "low": 2.5,
    "info": 0.5,
    "informational": 0.5,
    "note": 0.5,
}

_SEVERITY_FLOAT_TO_LABEL = [
    (9.0, "CRITICAL"),
    (7.0, "HIGH"),
    (4.0, "MEDIUM"),
    (1.0, "LOW"),
    (0.0, "INFO"),
]


def _label_from_score(score: float) -> str:
    for threshold, label in _SEVERITY_FLOAT_TO_LABEL:
        if score >= threshold:
            return label
    return "INFO"


def _parse_severity(raw: Any) -> tuple[float, str]:
    """Return (severity_float, severity_label) from any severity representation."""
    if raw is None:
        return 0.0, "INFO"
    if isinstance(raw, (int, float)):
        score = max(0.0, min(10.0, float(raw)))
        return score, _label_from_score(score)
    if isinstance(raw, str):
        mapped = _SEVERITY_STR_TO_FLOAT.get(raw.lower())
        if mapped is not None:
            return mapped, _label_from_score(mapped)
        # Try parsing as float string
        try:
            score = max(0.0, min(10.0, float(raw)))
            return score, _label_from_score(score)
        except ValueError:
            pass
    return 0.0, "INFO"


def _extract_findings_from_steps(steps: list[dict]) -> list[dict]:
    """Pull findings embedded inside agent step records."""
    findings = []
    for i, step in enumerate(steps):
        if not isinstance(step, dict):
            continue
        # Findings may be under various keys within a step
        for key in ("findings", "vulnerabilities", "vulns", "issues", "results"):
            raw_list = step.get(key)
            if isinstance(raw_list, list):
                for f in raw_list:
                    if isinstance(f, dict):
                        f_copy = dict(f)
                        # Inject step metadata if not already present
                        if "step_index" not in f_copy and "step" not in f_copy:
                            f_copy["_step_index"] = step.get("step_index", i + 1)
                        if "timestamp_offset_s" not in f_copy:
                            ts = step.get("timestamp_offset_s") or step.get("timestamp") or step.get("elapsed_s")
                            if ts is not None:
                                f_copy["_timestamp_offset_s"] = ts
                        findings.append(f_copy)
        # Also check if the step itself looks like a finding
        if "title" in step or "name" in step or "vulnerability" in step:
            f_copy = dict(step)
            f_copy["_step_index"] = step.get("step_index", i + 1)
            findings.append(f_copy)
    return findings


def _normalise_strike7_finding(raw: dict[str, Any], idx: int) -> Finding:
    """Map a raw Strike7 finding dict to a Finding."""
    # ID resolution
    fid = (
        raw.get("id")
        or raw.get("finding_id")
        or raw.get("vuln_id")
        or raw.get("flag_id")
        or f"s7-finding-{idx}"
    )

    # Title resolution
    title = (
        raw.get("title")
        or raw.get("name")
        or raw.get("vulnerability")
        or raw.get("vuln_name")
        or raw.get("description", "")[:80]
        or f"Finding {idx}"
    )

    # Severity
    severity_raw = (
        raw.get("severity")
        or raw.get("cvss")
        or raw.get("risk")
        or raw.get("cvss_score")
        or raw.get("risk_score")
    )
    severity, severity_label = _parse_severity(severity_raw)

    # MITRE
    mitre = (
        raw.get("mitre_technique")
        or raw.get("mitre")
        or raw.get("technique")
        or raw.get("mitre_id")
        or raw.get("attack_technique")
    )

    # Step index
    step_index = (
        raw.get("step_index")
        or raw.get("step")
        or raw.get("_step_index")
        or raw.get("step_number")
    )
    if step_index is not None:
        try:
            step_index = int(step_index)
        except (TypeError, ValueError):
            step_index = None

    # Timestamp
    ts = (
        raw.get("timestamp_offset_s")
        or raw.get("_timestamp_offset_s")
        or raw.get("time_offset")
        or raw.get("elapsed_s")
        or raw.get("timestamp")
    )
    if ts is not None:
        try:
            ts = int(ts)
        except (TypeError, ValueError):
            ts = None

    # Enabled by
    enabled_by = raw.get("enabled_by") or raw.get("depends_on") or raw.get("prerequisites") or []
    if isinstance(enabled_by, str):
        enabled_by = [enabled_by] if enabled_by else []
    enabled_by = [str(x) for x in enabled_by]

    # Evidence
    evidence = (
        raw.get("evidence")
        or raw.get("proof")
        or raw.get("output")
        or raw.get("raw_output")
        or raw.get("command_output")
        or raw.get("tool_output")
    )
    if evidence and not isinstance(evidence, str):
        evidence = json.dumps(evidence)[:2000]

    # Host
    host = (
        raw.get("host")
        or raw.get("target")
        or raw.get("ip")
        or raw.get("hostname")
        or raw.get("target_host")
    )

    return Finding(
        id=str(fid),
        title=str(title),
        severity=severity,
        severity_label=severity_label,
        mitre_technique=mitre,
        step_index=step_index,
        timestamp_offset_s=ts,
        enabled_by=enabled_by,
        evidence=str(evidence)[:4000] if evidence else None,
        host=str(host) if host else None,
        ai_detail=raw.get("ai_detail") or raw.get("detail"),
        ai_remediation=raw.get("ai_remediation") or raw.get("remediation"),
        ai_confidence=raw.get("ai_confidence") or raw.get("confidence"),
    )


class Strike7Adapter:
    """Adapter for Strike7 benchmark run JSON output."""

    FORMAT_NAME = "strike7"

    @classmethod
    def can_handle(cls, data: dict) -> bool:
        """Return True if this data looks like a Strike7 output."""
        if not isinstance(data, dict):
            return False
        return (
            "benchmark_run_id" in data
            or "agent_steps" in data
            or ("run_id" in data and "steps" in data)
            or ("benchmark_id" in data and ("flags_captured" in data or "steps" in data))
        )

    def load(self, path: Path | str) -> Engagement:
        path = Path(path)
        with path.open("r", encoding="utf-8") as fh:
            data = json.load(fh)
        return self.parse(data)

    def parse(self, data: Any) -> Engagement:
        if not isinstance(data, dict):
            raise ValueError(f"Strike7 adapter expects a dict, got {type(data).__name__}")

        # Engagement metadata
        engagement_id = (
            data.get("benchmark_run_id")
            or data.get("run_id")
            or data.get("id")
            or str(uuid.uuid4())
        )
        target_name = (
            data.get("target_name")
            or data.get("benchmark_name")
            or data.get("name")
            or data.get("target")
        )

        # Collect raw findings from all sources
        raw_findings: list[dict] = []

        # 1. Top-level findings
        for key in ("findings", "vulnerabilities", "vulns", "issues"):
            top_level = data.get(key)
            if isinstance(top_level, list):
                raw_findings.extend(f for f in top_level if isinstance(f, dict))
                break  # use first match

        # 2. Findings embedded in agent_steps or steps
        steps = data.get("agent_steps") or data.get("steps") or []
        if isinstance(steps, list) and steps:
            step_findings = _extract_findings_from_steps(steps)
            # Avoid duplicates (if top-level findings were already there)
            existing_ids = {f.get("id") for f in raw_findings if f.get("id")}
            for sf in step_findings:
                if sf.get("id") not in existing_ids:
                    raw_findings.append(sf)

        findings = [
            _normalise_strike7_finding(f, idx)
            for idx, f in enumerate(raw_findings)
        ]

        return Engagement(
            engagement_id=str(engagement_id),
            target_name=str(target_name) if target_name else None,
            findings=findings,
            metadata={k: v for k, v in data.items() if k not in ("findings", "agent_steps", "steps", "vulnerabilities")},
        )

    def describe_mapping(self, data: Any) -> dict:
        if not isinstance(data, dict):
            return {"adapter": self.FORMAT_NAME, "sample_count": 0, "mapped_fields": [], "unmapped_fields": []}

        # Gather all finding sources
        raw_findings = []
        for key in ("findings", "vulnerabilities", "vulns", "issues"):
            if isinstance(data.get(key), list):
                raw_findings = data[key]
                break
        steps = data.get("agent_steps") or data.get("steps") or []
        if not raw_findings and steps:
            raw_findings = _extract_findings_from_steps(steps)

        sample = raw_findings[0] if raw_findings else {}
        known = {
            "id", "finding_id", "vuln_id", "flag_id",
            "title", "name", "vulnerability", "vuln_name",
            "severity", "cvss", "risk", "cvss_score",
            "mitre_technique", "mitre", "technique",
            "step_index", "step",
            "timestamp_offset_s", "time_offset",
            "enabled_by", "depends_on",
            "evidence", "proof", "output",
            "host", "target", "ip",
        }
        mapped = [{"source_field": k, "maps_to": k} for k in sample if k in known]
        unmapped = [k for k in sample if k not in known]

        return {
            "adapter": self.FORMAT_NAME,
            "sample_count": len(raw_findings),
            "mapped_fields": mapped,
            "unmapped_fields": unmapped,
        }
