"""Tests for src/storage/store.py"""
import json
import os
import tempfile
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from src.ingestion.schema import Engagement, Finding
from src.storage.store import ChainStore
from src import AttackChain


@pytest.fixture
def tmp_db(tmp_path):
    db_file = str(tmp_path / "test_chains.db")
    store = ChainStore(db_path=db_file)
    yield store
    store.close()


def _make_finding(fid: str, severity: float = 5.0, enabled_by=None) -> Finding:
    label = "CRITICAL" if severity >= 9 else ("HIGH" if severity >= 7 else ("MEDIUM" if severity >= 4 else "LOW"))
    return Finding(
        id=fid,
        title=f"Finding {fid}",
        severity=severity,
        severity_label=label,
        enabled_by=enabled_by or [],
    )


def _make_engagement(eid="eng-001", findings=None) -> Engagement:
    findings = findings or [_make_finding("f-001"), _make_finding("f-002", severity=7.5)]
    return Engagement(
        engagement_id=eid,
        target_name="test-target",
        findings=findings,
    )


def _make_chain(engagement: Engagement, primary_path=None) -> AttackChain:
    primary = primary_path or engagement.findings[:1]
    return AttackChain(
        engagement=engagement,
        primary_path=primary,
        secondary_findings=engagement.findings[1:],
        chain_risk_score=7.5,
        inferred_ids=set(),
    )


# ---------------------------------------------------------------------------
# save_chain + get_chain
# ---------------------------------------------------------------------------

class TestSaveAndGet:
    def test_save_chain_returns_uuid(self, tmp_db):
        eng = _make_engagement()
        chain = _make_chain(eng)
        chain_id = tmp_db.save_chain(chain, eng)
        assert len(chain_id) == 36  # UUID format

    def test_get_chain_returns_correct_record(self, tmp_db):
        eng = _make_engagement(eid="eng-abc")
        chain = _make_chain(eng)
        chain_id = tmp_db.save_chain(chain, eng)

        record = tmp_db.get_chain(chain_id)
        assert record is not None
        assert record["engagement_id"] == "eng-abc"
        assert record["target_name"] == "test-target"
        assert record["chain_risk_score"] == 7.5

    def test_get_chain_returns_none_for_missing_id(self, tmp_db):
        assert tmp_db.get_chain("nonexistent-id") is None

    def test_chain_json_is_valid_json(self, tmp_db):
        eng = _make_engagement()
        chain = _make_chain(eng)
        chain_id = tmp_db.save_chain(chain, eng)
        record = tmp_db.get_chain(chain_id)
        parsed = json.loads(record["chain_json"])
        assert isinstance(parsed, dict)

    def test_html_path_stored(self, tmp_db):
        eng = _make_engagement()
        chain = _make_chain(eng)
        chain_id = tmp_db.save_chain(chain, eng, html_path="/tmp/test.html")
        record = tmp_db.get_chain(chain_id)
        assert record["html_path"] == "/tmp/test.html"

    def test_findings_stored_in_findings_table(self, tmp_db):
        findings = [
            _make_finding("f-001", severity=9.5),
            _make_finding("f-002", severity=7.5, enabled_by=["f-001"]),
        ]
        eng = _make_engagement(findings=findings)
        chain = _make_chain(eng, primary_path=[findings[0]])
        chain_id = tmp_db.save_chain(chain, eng)

        cur = tmp_db._conn.cursor()
        cur.execute("SELECT * FROM findings WHERE chain_id = ?", (chain_id,))
        rows = cur.fetchall()
        assert len(rows) == 2

    def test_in_primary_chain_flag_set_correctly(self, tmp_db):
        findings = [
            _make_finding("f-001", severity=9.5),
            _make_finding("f-002", severity=7.5),
        ]
        eng = _make_engagement(findings=findings)
        chain = _make_chain(eng, primary_path=[findings[0]])
        chain_id = tmp_db.save_chain(chain, eng)

        cur = tmp_db._conn.cursor()
        cur.execute(
            "SELECT finding_id, in_primary_chain FROM findings WHERE chain_id = ?",
            (chain_id,),
        )
        rows = {r["finding_id"]: r["in_primary_chain"] for r in cur.fetchall()}
        assert rows["f-001"] == 1
        assert rows["f-002"] == 0


# ---------------------------------------------------------------------------
# Upsert (same engagement + same day)
# ---------------------------------------------------------------------------

class TestUpsert:
    def test_same_engagement_same_day_upserts(self, tmp_db):
        eng = _make_engagement(eid="eng-upsert")
        chain = _make_chain(eng)

        id1 = tmp_db.save_chain(chain, eng)
        id2 = tmp_db.save_chain(chain, eng)  # same engagement, same day

        # Only one chain record should exist
        chains = tmp_db.get_chains_for_engagement("eng-upsert")
        assert len(chains) == 1
        # The second call replaced the first
        assert chains[0]["id"] == id2


# ---------------------------------------------------------------------------
# get_chains_for_engagement
# ---------------------------------------------------------------------------

class TestGetChainsForEngagement:
    def test_returns_chains_newest_first(self, tmp_db):
        # Use two different engagement IDs to avoid upsert
        eng_a = _make_engagement(eid="eng-order-a")
        eng_b = _make_engagement(eid="eng-order-b")
        chain_a = _make_chain(eng_a)
        chain_b = _make_chain(eng_b)

        tmp_db.save_chain(chain_a, eng_a)
        tmp_db.save_chain(chain_b, eng_b)

        chains_a = tmp_db.get_chains_for_engagement("eng-order-a")
        assert len(chains_a) == 1
        assert chains_a[0]["engagement_id"] == "eng-order-a"

    def test_returns_empty_for_unknown_engagement(self, tmp_db):
        result = tmp_db.get_chains_for_engagement("does-not-exist")
        assert result == []


# ---------------------------------------------------------------------------
# diff_chains
# ---------------------------------------------------------------------------

class TestDiffChains:
    def _save_two_chains(self, store, eid_a="eng-diff-a", eid_b="eng-diff-b"):
        """Save two chains with different engagement IDs (to avoid upsert)."""
        findings_a = [_make_finding("f-001", severity=7.5), _make_finding("f-002", severity=5.0)]
        eng_a = _make_engagement(eid=eid_a, findings=findings_a)
        chain_a = _make_chain(eng_a, primary_path=[findings_a[0]])
        id_a = store.save_chain(chain_a, eng_a)

        findings_b = [_make_finding("f-001", severity=7.5), _make_finding("f-003", severity=8.5)]
        eng_b = _make_engagement(eid=eid_b, findings=findings_b)
        chain_b = _make_chain(eng_b, primary_path=[findings_b[1]])
        id_b = store.save_chain(chain_b, eng_b)

        return id_a, id_b

    def test_new_findings_identified(self, tmp_db):
        id_a, id_b = self._save_two_chains(tmp_db)
        diff = tmp_db.diff_chains(id_a, id_b)
        new_ids = [f["finding_id"] for f in diff["new_findings"]]
        assert "f-003" in new_ids

    def test_resolved_findings_identified(self, tmp_db):
        id_a, id_b = self._save_two_chains(tmp_db)
        diff = tmp_db.diff_chains(id_a, id_b)
        resolved_ids = [f["finding_id"] for f in diff["resolved_findings"]]
        assert "f-002" in resolved_ids

    def test_chain_changed_detected(self, tmp_db):
        id_a, id_b = self._save_two_chains(tmp_db)
        diff = tmp_db.diff_chains(id_a, id_b)
        assert diff["chain_changed"] is True  # f-001 vs f-003 in primary

    def test_no_change_same_chain(self, tmp_db):
        eng = _make_engagement(eid="eng-nochange")
        chain = _make_chain(eng)
        id_a = tmp_db.save_chain(chain, eng)

        # Second engagement to avoid upsert
        eng2 = _make_engagement(eid="eng-nochange2")
        chain2 = _make_chain(eng2)
        id_b = tmp_db.save_chain(chain2, eng2)

        diff = tmp_db.diff_chains(id_a, id_b)
        assert diff["new_findings"] == []
        assert diff["resolved_findings"] == []

    def test_severity_changes_detected(self, tmp_db):
        findings_a = [_make_finding("f-001", severity=5.0)]
        eng_a = _make_engagement(eid="eng-sev-a", findings=findings_a)
        id_a = tmp_db.save_chain(_make_chain(eng_a), eng_a)

        findings_b = [_make_finding("f-001", severity=8.0)]
        eng_b = _make_engagement(eid="eng-sev-b", findings=findings_b)
        id_b = tmp_db.save_chain(_make_chain(eng_b), eng_b)

        diff = tmp_db.diff_chains(id_a, id_b)
        assert len(diff["severity_changes"]) == 1
        assert diff["severity_changes"][0]["severity_before"] == 5.0
        assert diff["severity_changes"][0]["severity_after"] == 8.0

    def test_risk_score_delta_computed(self, tmp_db):
        eng_a = _make_engagement(eid="eng-risk-a")
        chain_a = AttackChain(
            engagement=eng_a, primary_path=eng_a.findings,
            secondary_findings=[], chain_risk_score=5.0, inferred_ids=set()
        )
        id_a = tmp_db.save_chain(chain_a, eng_a)

        eng_b = _make_engagement(eid="eng-risk-b")
        chain_b = AttackChain(
            engagement=eng_b, primary_path=eng_b.findings,
            secondary_findings=[], chain_risk_score=8.0, inferred_ids=set()
        )
        id_b = tmp_db.save_chain(chain_b, eng_b)

        diff = tmp_db.diff_chains(id_a, id_b)
        assert diff["risk_score_delta"] == pytest.approx(3.0, 0.01)


# ---------------------------------------------------------------------------
# list_engagements
# ---------------------------------------------------------------------------

class TestListEngagements:
    def test_list_returns_all_engagements(self, tmp_db):
        for eid in ("eng-x", "eng-y", "eng-z"):
            eng = _make_engagement(eid=eid)
            tmp_db.save_chain(_make_chain(eng), eng)

        result = tmp_db.list_engagements()
        eids = [r["engagement_id"] for r in result]
        assert "eng-x" in eids
        assert "eng-y" in eids
        assert "eng-z" in eids

    def test_list_includes_chain_count(self, tmp_db):
        eng = _make_engagement(eid="eng-count")
        tmp_db.save_chain(_make_chain(eng), eng)
        result = tmp_db.list_engagements()
        match = next((r for r in result if r["engagement_id"] == "eng-count"), None)
        assert match is not None
        assert match["chain_count"] == 1

    def test_empty_store_returns_empty_list(self, tmp_db):
        assert tmp_db.list_engagements() == []


# ---------------------------------------------------------------------------
# delete_chain
# ---------------------------------------------------------------------------

class TestDeleteChain:
    def test_delete_returns_true_when_found(self, tmp_db):
        eng = _make_engagement(eid="eng-del")
        chain = _make_chain(eng)
        chain_id = tmp_db.save_chain(chain, eng)
        assert tmp_db.delete_chain(chain_id) is True
        assert tmp_db.get_chain(chain_id) is None

    def test_delete_returns_false_for_unknown_id(self, tmp_db):
        assert tmp_db.delete_chain("nonexistent") is False
