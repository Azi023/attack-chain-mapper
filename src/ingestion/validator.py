"""Smart input validation for attack-chain-mapper findings.

Tells users exactly what is wrong, how to fix it, and degrades
gracefully (warns, doesn't crash) when possible.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, List, Optional


@dataclass
class ValidationError:
    code: str         # e.g. "MISSING_REQUIRED_FIELD"
    field: str        # e.g. "findings[3].id"
    message: str      # human-readable
    fix_hint: str     # what the user should do


@dataclass
class ValidationWarning:
    code: str
    field: str
    message: str
    impact: str       # what quality degrades without this field


@dataclass
class ValidationResult:
    valid: bool
    errors: List[ValidationError] = field(default_factory=list)
    warnings: List[ValidationWarning] = field(default_factory=list)
    auto_fixed: List[str] = field(default_factory=list)

    def summary(self) -> str:
        """Human-readable summary suitable for CLI output."""
        lines = []
        for af in self.auto_fixed:
            lines.append(f"  ✓ Auto-fixed: {af}")
        for w in self.warnings:
            lines.append(f"  ⚠  {w.message}")
        for e in self.errors:
            lines.append(f"  ✗ {e.code}: {e.message}")
            lines.append(f"    Fix: {e.fix_hint}")
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _is_circular(finding_id: str, enabled_by_map: dict[str, list[str]], visited: set[str]) -> bool:
    """DFS to detect circular dependency from finding_id."""
    if finding_id in visited:
        return True
    visited.add(finding_id)
    for dep in enabled_by_map.get(finding_id, []):
        if _is_circular(dep, enabled_by_map, visited):
            return True
    visited.discard(finding_id)
    return False


def _detect_circular_pair(enabled_by_map: dict[str, list[str]]) -> Optional[tuple[str, str]]:
    """Return the first (a, b) pair where a enables_by b and b enables_by a."""
    for a, deps in enabled_by_map.items():
        for b in deps:
            if a in enabled_by_map.get(b, []):
                return (a, b)
    return None


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def validate(raw_data: Any) -> tuple[ValidationResult, list]:
    """Validate and auto-fix findings data.

    Args:
        raw_data: parsed JSON (dict with 'findings' key, or list of finding dicts)

    Returns:
        (ValidationResult, fixed_findings_list)
        fixed_findings is a list of dicts with auto-fixes applied.
        If there are errors, fixed_findings is whatever could be extracted.
    """
    result = ValidationResult(valid=True)
    findings: list[dict] = []

    # ── Extract findings list ────────────────────────────────────────────────
    if isinstance(raw_data, list):
        findings = raw_data
    elif isinstance(raw_data, dict):
        for key in ("findings", "vulnerabilities", "results", "issues", "vulns", "items"):
            if isinstance(raw_data.get(key), list):
                findings = raw_data[key]
                break

    # ── EMPTY_FINDINGS ───────────────────────────────────────────────────────
    if not findings:
        result.valid = False
        result.errors.append(ValidationError(
            code="EMPTY_FINDINGS",
            field="findings",
            message="No findings found in input.",
            fix_hint=(
                "Check that your file has a 'findings', 'vulnerabilities', or 'results' key "
                "with a non-empty list."
            ),
        ))
        return result, []

    # Work on a deep copy so we don't mutate caller's data
    import copy
    findings = copy.deepcopy(findings)

    # ── Per-finding auto-fixes ───────────────────────────────────────────────
    for i, f in enumerate(findings):
        if not isinstance(f, dict):
            continue
        fid = f.get("id", f"[{i}]")

        # Trim whitespace from all string fields
        for k, v in list(f.items()):
            if isinstance(v, str):
                stripped = v.strip()
                if stripped != v:
                    f[k] = stripped

        # Normalize severity_label to uppercase
        if "severity_label" in f and isinstance(f["severity_label"], str):
            f["severity_label"] = f["severity_label"].upper()

        # Remove duplicate IDs from enabled_by lists
        if "enabled_by" in f and isinstance(f["enabled_by"], list):
            seen = set()
            deduped = []
            for ref in f["enabled_by"]:
                if ref not in seen:
                    seen.add(ref)
                    deduped.append(ref)
            if len(deduped) < len(f["enabled_by"]):
                result.auto_fixed.append(
                    f"Removed duplicate enabled_by references for finding '{fid}'"
                )
                f["enabled_by"] = deduped

        # Replace None host with empty string
        if f.get("host") is None:
            f["host"] = ""

        # NULL_SEVERITY — auto-fix to 0.0 INFO
        if f.get("severity") is None:
            f["severity"] = 0.0
            f["severity_label"] = "INFO"
            result.warnings.append(ValidationWarning(
                code="NULL_SEVERITY",
                field=f"findings[{i}].severity",
                message=f"Finding '{fid}' has no severity — defaulted to 0.0 INFO.",
                impact="Finding will appear at the bottom of the severity ranking.",
            ))
            result.auto_fixed.append(f"Finding '{fid}' null severity defaulted to 0.0 INFO")

        # INVALID_SEVERITY_RANGE — clamp and warn
        sev = f.get("severity")
        if isinstance(sev, (int, float)) and not (0.0 <= float(sev) <= 10.0):
            clamped = max(0.0, min(10.0, float(sev)))
            f["severity"] = clamped
            result.warnings.append(ValidationWarning(
                code="INVALID_SEVERITY_RANGE",
                field=f"findings[{i}].severity",
                message=f"Finding '{fid}' severity {sev} out of range — clamped to {clamped}.",
                impact="Severity capped at valid CVSS range.",
            ))
            result.auto_fixed.append(f"Finding '{fid}' severity clamped to {clamped}")

        # MISSING_TITLE — auto-fix
        if not f.get("title"):
            f["title"] = f"Untitled Finding {fid}"
            result.auto_fixed.append(f"Finding '{fid}' had no title — set to 'Untitled Finding {fid}'")

    # ── DUPLICATE_IDS ────────────────────────────────────────────────────────
    id_seen: dict[str, int] = {}
    for i, f in enumerate(findings):
        if not isinstance(f, dict):
            continue
        fid = f.get("id")
        if fid is not None:
            if fid in id_seen:
                result.valid = False
                result.errors.append(ValidationError(
                    code="DUPLICATE_IDS",
                    field=f"findings[{id_seen[fid]}] and findings[{i}]",
                    message=f"Findings at index {id_seen[fid]} and {i} share id '{fid}'. IDs must be unique.",
                    fix_hint="Ensure all finding IDs are unique in your source data.",
                ))
            else:
                id_seen[fid] = i

    # ── UNKNOWN_ENABLED_BY_REF — auto-fix ────────────────────────────────────
    all_ids = set(id_seen.keys())
    for i, f in enumerate(findings):
        if not isinstance(f, dict):
            continue
        fid = f.get("id", f"[{i}]")
        eb = f.get("enabled_by", [])
        if not isinstance(eb, list):
            continue
        bad_refs = [ref for ref in eb if ref not in all_ids]
        if bad_refs:
            f["enabled_by"] = [ref for ref in eb if ref in all_ids]
            for ref in bad_refs:
                result.warnings.append(ValidationWarning(
                    code="UNKNOWN_ENABLED_BY_REF",
                    field=f"findings[{i}].enabled_by",
                    message=f"Finding '{fid}' references unknown enabled_by '{ref}' — reference removed.",
                    impact="Chain relationships may be incomplete.",
                ))
                result.auto_fixed.append(
                    f"Removed unknown enabled_by '{ref}' from finding '{fid}'"
                )

    # ── CIRCULAR_ENABLED_BY ──────────────────────────────────────────────────
    enabled_by_map = {
        f["id"]: f.get("enabled_by", [])
        for f in findings
        if isinstance(f, dict) and "id" in f
    }
    pair = _detect_circular_pair(enabled_by_map)
    if pair:
        result.valid = False
        a, b = pair
        result.errors.append(ValidationError(
            code="CIRCULAR_ENABLED_BY",
            field=f"findings[{a}].enabled_by ↔ findings[{b}].enabled_by",
            message=f"Circular dependency detected between '{a}' and '{b}'.",
            fix_hint=f"Remove one direction: either remove '{b}' from '{a}'.enabled_by or vice versa.",
        ))

    # ── Engagement-level warnings ────────────────────────────────────────────
    valid_findings = [f for f in findings if isinstance(f, dict)]
    has_enabled_by = any(
        f.get("enabled_by") for f in valid_findings
    )
    if not has_enabled_by:
        result.warnings.append(ValidationWarning(
            code="MISSING_ENABLED_BY",
            field="findings[*].enabled_by",
            message="No chain relationships found — chain inference will be applied.",
            impact="Chain structure will be approximated from severity and step order.",
        ))

    has_step_index = any(
        f.get("step_index") is not None for f in valid_findings
    )
    if not has_step_index:
        result.warnings.append(ValidationWarning(
            code="MISSING_STEP_INDEX",
            field="findings[*].step_index",
            message="Step ordering unavailable — chain inference will use severity progression only.",
            impact="Chain order may be less accurate.",
        ))

    total = len(valid_findings)
    thin_count = sum(
        1 for f in valid_findings
        if not f.get("evidence") or len(str(f.get("evidence", ""))) < 50
    )
    if total > 0 and thin_count / total > 0.6:
        result.warnings.append(ValidationWarning(
            code="THIN_EVIDENCE",
            field="findings[*].evidence",
            message=f"Most findings have thin evidence ({thin_count} of {total} < 50 chars).",
            impact="AI analysis quality will be reduced — responses will rely on MITRE technique reasoning.",
        ))

    # Mark valid only if no errors accumulated
    if result.errors:
        result.valid = False

    return result, findings
