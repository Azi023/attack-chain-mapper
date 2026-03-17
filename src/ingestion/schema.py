"""Finding schema — the contract. Adapters map TO this. Never modify to suit an adapter."""
from __future__ import annotations

from typing import List, Optional
from pydantic import BaseModel, field_validator


class Finding(BaseModel):
    id: str
    title: str
    severity: float                     # 0.0–10.0 CVSS-style
    severity_label: str                 # CRITICAL / HIGH / MEDIUM / LOW / INFO
    mitre_technique: Optional[str] = None   # T-number e.g. "T1557.001"
    step_index: Optional[int] = None    # which agent step produced this finding
    timestamp_offset_s: Optional[int] = None  # seconds from engagement start
    enabled_by: List[str] = []          # IDs of findings that made this possible
    evidence: Optional[str] = None      # raw evidence string
    host: Optional[str] = None          # target host/IP
    # AI-generated fields (populated async after graph is built)
    ai_detail: Optional[str] = None
    ai_remediation: Optional[str] = None
    ai_confidence: Optional[float] = None

    @field_validator("severity")
    @classmethod
    def validate_severity_range(cls, v: float) -> float:
        if not (0.0 <= v <= 10.0):
            raise ValueError(f"severity must be 0.0–10.0, got {v}")
        return v

    @field_validator("severity_label")
    @classmethod
    def validate_severity_label(cls, v: str) -> str:
        valid = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}
        upper = v.upper()
        if upper not in valid:
            raise ValueError(f"severity_label must be one of {valid}, got {v!r}")
        return upper


class Engagement(BaseModel):
    engagement_id: str
    target_name: Optional[str] = None
    findings: List[Finding]
    metadata: dict = {}
