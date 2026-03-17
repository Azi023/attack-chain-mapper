"""Format detector — auto-detects input format from JSON structure."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def _load_json(path: Path | str) -> Any:
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def detect_format(data: Any) -> str:
    """Return the best-match adapter format name for the given parsed JSON data.

    Currently supports:
    - "generic" — the catch-all for any JSON list or dict with findings
    Future adapters will be detected here by signature.
    """
    # Strike7 signature: has "benchmark_run_id" and "agent_steps"
    if isinstance(data, dict):
        if "benchmark_run_id" in data or "agent_steps" in data:
            return "strike7"

        # Burp signature: XML-converted dict with "issues" and "host"
        if "issues" in data and "host" in data:
            return "burp"

        # Generic: has "findings" or is a flat list-like dict
        if "findings" in data or any(
            k in data for k in ("results", "vulnerabilities", "issues", "vulns", "items")
        ):
            return "generic"

    if isinstance(data, list):
        # List of finding-like dicts
        if data and isinstance(data[0], dict):
            return "generic"

    return "generic"


def detect_format_from_file(path: Path | str) -> tuple[str, Any]:
    """Load JSON from path and return (format_name, parsed_data)."""
    data = _load_json(path)
    return detect_format(data), data
