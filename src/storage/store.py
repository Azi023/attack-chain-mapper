"""SQLite-backed store for generated attack chains.

WAL mode. Thread-safe. Matches PIL's storage pattern.
Default DB path: ~/.attack-chain-mapper/chains.db
Override with ACM_DB_PATH env var or --db-path CLI flag.
"""
from __future__ import annotations

import json
import os
import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional

from src.ingestion.schema import Engagement
from src import AttackChain


_DEFAULT_DB_DIR = Path.home() / ".attack-chain-mapper"
_DEFAULT_DB_PATH = _DEFAULT_DB_DIR / "chains.db"

_CREATE_CHAINS = """
CREATE TABLE IF NOT EXISTS chains (
    id TEXT PRIMARY KEY,
    engagement_id TEXT NOT NULL,
    target_name TEXT,
    created_at TEXT NOT NULL,
    chain_risk_score REAL,
    primary_chain_length INTEGER,
    finding_count INTEGER,
    chain_json TEXT NOT NULL,
    html_path TEXT
);
"""

_CREATE_FINDINGS = """
CREATE TABLE IF NOT EXISTS findings (
    chain_id TEXT NOT NULL,
    finding_id TEXT NOT NULL,
    title TEXT,
    severity REAL,
    severity_label TEXT,
    mitre_technique TEXT,
    in_primary_chain INTEGER,
    inferred_chain INTEGER,
    FOREIGN KEY (chain_id) REFERENCES chains(id)
);
"""

_CREATE_IDX_CHAINS = "CREATE INDEX IF NOT EXISTS idx_chains_engagement ON chains(engagement_id);"
_CREATE_IDX_FINDINGS = "CREATE INDEX IF NOT EXISTS idx_findings_chain ON findings(chain_id);"


def _resolve_db_path(db_path: Optional[str] = None) -> Path:
    if db_path:
        return Path(db_path)
    env = os.environ.get("ACM_DB_PATH")
    if env:
        return Path(env)
    return _DEFAULT_DB_PATH


class ChainStore:
    """Thread-safe SQLite store for attack chains."""

    def __init__(self, db_path: Optional[str] = None):
        self.db_path = _resolve_db_path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(self.db_path), check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL;")
        self._conn.execute("PRAGMA foreign_keys=ON;")
        self._init_schema()

    def _init_schema(self) -> None:
        cur = self._conn.cursor()
        cur.executescript(
            _CREATE_CHAINS + _CREATE_FINDINGS +
            _CREATE_IDX_CHAINS + _CREATE_IDX_FINDINGS
        )
        self._conn.commit()

    def save_chain(
        self,
        chain: AttackChain,
        engagement: Engagement,
        html_path: Optional[str] = None,
    ) -> str:
        """Save a chain. Returns chain_id (UUID).

        Upserts on same engagement_id + same calendar day — replaces the
        previous record rather than duplicating it.
        """
        today = datetime.now(tz=timezone.utc).date().isoformat()
        chain_id = str(uuid.uuid4())
        created_at = datetime.now(tz=timezone.utc).isoformat()

        # Check for an existing chain on the same engagement + same day
        cur = self._conn.cursor()
        cur.execute(
            "SELECT id FROM chains WHERE engagement_id = ? AND created_at LIKE ?",
            (engagement.engagement_id, f"{today}%"),
        )
        existing = cur.fetchone()
        if existing:
            # Delete old findings + chain row, then re-insert with new chain_id
            old_id = existing["id"]
            cur.execute("DELETE FROM findings WHERE chain_id = ?", (old_id,))
            cur.execute("DELETE FROM chains WHERE id = ?", (old_id,))

        chain_json = json.dumps(chain.to_json())
        primary_ids = {f.id for f in chain.primary_path}

        cur.execute(
            """
            INSERT INTO chains
                (id, engagement_id, target_name, created_at, chain_risk_score,
                 primary_chain_length, finding_count, chain_json, html_path)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                chain_id,
                engagement.engagement_id,
                engagement.target_name,
                created_at,
                chain.chain_risk_score,
                len(chain.primary_path),
                len(engagement.findings),
                chain_json,
                html_path,
            ),
        )

        for f in engagement.findings:
            cur.execute(
                """
                INSERT INTO findings
                    (chain_id, finding_id, title, severity, severity_label,
                     mitre_technique, in_primary_chain, inferred_chain)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    chain_id,
                    f.id,
                    f.title,
                    f.severity,
                    f.severity_label,
                    f.mitre_technique,
                    1 if f.id in primary_ids else 0,
                    1 if f.id in chain.inferred_ids else 0,
                ),
            )

        self._conn.commit()
        return chain_id

    def get_chain(self, chain_id: str) -> Optional[dict]:
        """Retrieve chain JSON by ID. Returns None if not found."""
        cur = self._conn.cursor()
        cur.execute("SELECT * FROM chains WHERE id = ?", (chain_id,))
        row = cur.fetchone()
        if row is None:
            return None
        return dict(row)

    def get_chains_for_engagement(self, engagement_id: str) -> List[dict]:
        """All chains for an engagement, newest first."""
        cur = self._conn.cursor()
        cur.execute(
            "SELECT * FROM chains WHERE engagement_id = ? ORDER BY created_at DESC",
            (engagement_id,),
        )
        return [dict(r) for r in cur.fetchall()]

    def diff_chains(self, chain_id_a: str, chain_id_b: str) -> dict:
        """Compare two chains for the same engagement.

        Returns:
            {
                "new_findings": [...],       # in B but not A
                "resolved_findings": [...],  # in A but not B
                "severity_changes": [...],   # same finding_id, different severity
                "chain_changed": bool,       # primary path differs
                "risk_score_delta": float
            }
        """
        def _get_findings(chain_id: str) -> dict[str, sqlite3.Row]:
            cur = self._conn.cursor()
            cur.execute("SELECT * FROM findings WHERE chain_id = ?", (chain_id,))
            return {r["finding_id"]: r for r in cur.fetchall()}

        findings_a = _get_findings(chain_id_a)
        findings_b = _get_findings(chain_id_b)

        ids_a = set(findings_a.keys())
        ids_b = set(findings_b.keys())

        new_findings = [
            {"finding_id": fid, "title": dict(findings_b[fid])["title"], "severity": dict(findings_b[fid])["severity"]}
            for fid in (ids_b - ids_a)
        ]
        resolved_findings = [
            {"finding_id": fid, "title": dict(findings_a[fid])["title"], "severity": dict(findings_a[fid])["severity"]}
            for fid in (ids_a - ids_b)
        ]
        severity_changes = []
        for fid in ids_a & ids_b:
            sev_a = findings_a[fid]["severity"]
            sev_b = findings_b[fid]["severity"]
            if sev_a != sev_b:
                severity_changes.append({
                    "finding_id": fid,
                    "title": findings_a[fid]["title"],
                    "severity_before": sev_a,
                    "severity_after": sev_b,
                })

        # Compare primary paths
        def _primary_path(chain_id: str) -> list[str]:
            cur = self._conn.cursor()
            cur.execute(
                "SELECT finding_id FROM findings WHERE chain_id = ? AND in_primary_chain = 1",
                (chain_id,),
            )
            return [r["finding_id"] for r in cur.fetchall()]

        path_a = set(_primary_path(chain_id_a))
        path_b = set(_primary_path(chain_id_b))
        chain_changed = path_a != path_b

        # Risk score delta
        chain_a = self.get_chain(chain_id_a) or {}
        chain_b = self.get_chain(chain_id_b) or {}
        score_a = chain_a.get("chain_risk_score") or 0.0
        score_b = chain_b.get("chain_risk_score") or 0.0

        return {
            "new_findings": new_findings,
            "resolved_findings": resolved_findings,
            "severity_changes": severity_changes,
            "chain_changed": chain_changed,
            "risk_score_delta": round(score_b - score_a, 2),
        }

    def list_engagements(self) -> List[dict]:
        """Summary list: engagement_id, target_name, chain_count, latest_date, latest_risk_score."""
        cur = self._conn.cursor()
        cur.execute(
            """
            SELECT
                engagement_id,
                target_name,
                COUNT(*) as chain_count,
                MAX(created_at) as latest_date,
                chain_risk_score as latest_risk_score
            FROM chains
            GROUP BY engagement_id
            ORDER BY latest_date DESC
            """
        )
        return [dict(r) for r in cur.fetchall()]

    def delete_chain(self, chain_id: str) -> bool:
        """Hard delete. Returns True if deleted."""
        cur = self._conn.cursor()
        cur.execute("DELETE FROM findings WHERE chain_id = ?", (chain_id,))
        cur.execute("DELETE FROM chains WHERE id = ?", (chain_id,))
        self._conn.commit()
        return cur.rowcount > 0

    def close(self) -> None:
        self._conn.close()
