"""Tests for src/graph/pathfinder.py and src/graph/scorer.py"""
import pytest

from src.ingestion.schema import Finding
from src.graph.builder import build_graph
from src.graph.pathfinder import find_primary_chain, find_secondary_findings
from src.graph.scorer import compute_chain_risk_score, severity_color, label_color


def make_finding(id: str, severity: float = 5.0, enabled_by=None, step_index: int = None) -> Finding:
    label = "CRITICAL" if severity >= 9 else "HIGH" if severity >= 7 else "MEDIUM" if severity >= 4 else "LOW" if severity >= 1 else "INFO"
    return Finding(
        id=id,
        title=f"Finding {id}",
        severity=severity,
        severity_label=label,
        enabled_by=enabled_by or [],
        step_index=step_index,
    )


class TestFindPrimaryChain:
    def test_empty_graph(self):
        G = build_graph([])
        chain = find_primary_chain(G)
        assert chain == []

    def test_single_node(self):
        f = make_finding("a", severity=5.0)
        G = build_graph([f])
        chain = find_primary_chain(G)
        assert len(chain) == 1
        assert chain[0].id == "a"

    def test_linear_chain_correct_order(self):
        """a → b → c should return [a, b, c]"""
        findings = [
            make_finding("a", severity=2.0),
            make_finding("b", severity=5.0, enabled_by=["a"]),
            make_finding("c", severity=9.5, enabled_by=["b"]),
        ]
        G = build_graph(findings)
        chain = find_primary_chain(G)
        assert [f.id for f in chain] == ["a", "b", "c"]

    def test_goad_chain_identification(self):
        """Replicate the GOAD engagement: primary chain is recon → ldap → smb+sysvol → ntlm-relay"""
        findings = [
            make_finding("f-recon", severity=0.0),
            make_finding("f-ldap", severity=3.1, enabled_by=["f-recon"]),
            make_finding("f-sysvol", severity=6.5, enabled_by=["f-ldap"]),
            make_finding("f-smb", severity=6.8, enabled_by=["f-ldap"]),
            make_finding("f-ntlm-relay", severity=9.8, enabled_by=["f-smb", "f-sysvol"]),
            make_finding("f-kerberoast", severity=7.2, enabled_by=["f-ldap"]),
        ]
        G = build_graph(findings)
        chain = find_primary_chain(G)
        chain_ids = [f.id for f in chain]

        # Crown jewel must be the last node
        assert chain_ids[-1] == "f-ntlm-relay"
        # Entry point must come first in the chain
        assert chain_ids[0] == "f-recon"

    def test_secondary_findings_excludes_primary_chain(self):
        findings = [
            make_finding("a", severity=2.0),
            make_finding("b", severity=5.0, enabled_by=["a"]),
            make_finding("c", severity=9.5, enabled_by=["b"]),
            make_finding("d", severity=7.0, enabled_by=["a"]),  # secondary branch
        ]
        G = build_graph(findings)
        chain = find_primary_chain(G)
        secondary = find_secondary_findings(G, chain)

        primary_ids = {f.id for f in chain}
        secondary_ids = {f.id for f in secondary}

        assert primary_ids.isdisjoint(secondary_ids)
        assert "d" in secondary_ids

    def test_kerberoast_is_secondary_in_goad(self):
        findings = [
            make_finding("f-recon", severity=0.0),
            make_finding("f-ldap", severity=3.1, enabled_by=["f-recon"]),
            make_finding("f-sysvol", severity=6.5, enabled_by=["f-ldap"]),
            make_finding("f-smb", severity=6.8, enabled_by=["f-ldap"]),
            make_finding("f-ntlm-relay", severity=9.8, enabled_by=["f-smb", "f-sysvol"]),
            make_finding("f-kerberoast", severity=7.2, enabled_by=["f-ldap"]),
        ]
        G = build_graph(findings)
        chain = find_primary_chain(G)
        secondary = find_secondary_findings(G, chain)
        secondary_ids = {f.id for f in secondary}
        assert "f-kerberoast" in secondary_ids

    def test_secondary_sorted_by_severity_desc(self):
        findings = [
            make_finding("a"),
            make_finding("b", severity=3.0, enabled_by=["a"]),
            make_finding("c", severity=7.0, enabled_by=["a"]),
            make_finding("d", severity=5.0, enabled_by=["a"]),
        ]
        G = build_graph(findings)
        chain = find_primary_chain(G)
        secondary = find_secondary_findings(G, chain)
        if len(secondary) >= 2:
            for i in range(len(secondary) - 1):
                assert secondary[i].severity >= secondary[i + 1].severity

    def test_diamond_primary_chain_covers_both_paths(self):
        """a → b, a → c, b+c → d: primary chain should include a and d"""
        findings = [
            make_finding("a", severity=1.0),
            make_finding("b", severity=5.0, enabled_by=["a"]),
            make_finding("c", severity=5.0, enabled_by=["a"]),
            make_finding("d", severity=9.0, enabled_by=["b", "c"]),
        ]
        G = build_graph(findings)
        chain = find_primary_chain(G)
        chain_ids = [f.id for f in chain]
        assert "a" in chain_ids
        assert "d" in chain_ids


class TestChainRiskScore:
    def test_empty_chain_zero_score(self):
        assert compute_chain_risk_score([]) == 0.0

    def test_single_finding_score(self):
        f = make_finding("a", severity=5.0)
        score = compute_chain_risk_score([f])
        # Single finding: step_weight = 1.0 + 0/0 = 1.0, score = 5.0 * 1.0 = 5.0
        assert score == 5.0

    def test_score_increases_with_chain_length(self):
        short_chain = [make_finding(str(i), severity=5.0) for i in range(2)]
        long_chain = [make_finding(str(i), severity=5.0) for i in range(5)]
        short_score = compute_chain_risk_score(short_chain)
        long_score = compute_chain_risk_score(long_chain)
        assert long_score > short_score

    def test_crown_jewel_weighs_more(self):
        """Last finding (crown jewel) should have a higher multiplier."""
        chain = [
            make_finding("entry", severity=5.0),
            make_finding("crown", severity=5.0),
        ]
        score = compute_chain_risk_score(chain)
        # entry: 5.0 * 1.0 = 5.0, crown: 5.0 * 2.0 = 10.0, total = 15.0
        assert score == 15.0

    def test_goad_chain_score_positive(self):
        chain = [
            make_finding("f-recon", severity=0.0),
            make_finding("f-ldap", severity=3.1),
            make_finding("f-smb", severity=6.8),
            make_finding("f-ntlm-relay", severity=9.8),
        ]
        score = compute_chain_risk_score(chain)
        assert score > 0


class TestSeverityColors:
    def test_critical_color(self):
        assert severity_color(9.5) == "#e74c3c"

    def test_high_color(self):
        assert severity_color(7.5) == "#e67e22"

    def test_medium_color(self):
        assert severity_color(5.0) == "#f39c12"

    def test_low_color(self):
        assert severity_color(2.0) == "#7f8c8d"

    def test_info_color(self):
        assert severity_color(0.0) == "#95a5a6"

    def test_label_color_critical(self):
        assert label_color("CRITICAL") == "#e74c3c"

    def test_label_color_case_insensitive(self):
        assert label_color("critical") == label_color("CRITICAL")
