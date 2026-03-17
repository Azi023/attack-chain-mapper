"""Demo runner — generates /tmp/acm_demo.html from the GOAD fixture.

Run with:
    python demo/run_demo.py

No API key needed — AI details are pre-written in the fixture.
"""
from __future__ import annotations

import sys
from pathlib import Path

# Make src importable when running directly
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.ingestion.adapters.generic import GenericAdapter
from src.graph.builder import build_graph
from src.graph.pathfinder import find_primary_chain, find_secondary_findings
from src.graph.scorer import compute_chain_risk_score
from src.renderer.html import render_to_file

FIXTURE = Path(__file__).parent / "fixtures" / "goad_sample.json"
OUTPUT = Path("/tmp/acm_demo.html")


def run():
    print("Attack Chain Mapper — Demo")
    print("=" * 40)
    print(f"Loading fixture: {FIXTURE}")

    adapter = GenericAdapter()
    engagement = adapter.load(FIXTURE)
    print(f"Findings loaded: {len(engagement.findings)}")
    print(f"Target: {engagement.target_name}")

    print("Building attack graph...")
    G = build_graph(engagement.findings)

    print("Computing primary chain...")
    primary_chain = find_primary_chain(G)
    secondary = find_secondary_findings(G, primary_chain)
    risk_score = compute_chain_risk_score(primary_chain)

    print(f"Primary chain: {len(primary_chain)} steps")
    for i, f in enumerate(primary_chain):
        arrow = "→ " if i > 0 else "  "
        print(f"  {arrow}[{f.severity_label}] {f.title}")

    print(f"\nSecondary findings: {len(secondary)}")
    for f in secondary:
        print(f"  • [{f.severity_label}] {f.title}")

    print(f"\nChain risk score: {risk_score}")

    print(f"\nRendering HTML...")
    out = render_to_file(engagement, primary_chain, secondary, risk_score, OUTPUT)
    size_kb = out.stat().st_size / 1024
    print(f"Output: {out} ({size_kb:.1f} KB)")

    if size_kb < 30:
        print("WARNING: Output HTML is smaller than expected (< 30KB)")
    else:
        print("OK: HTML output is full-size")

    print(f"\nOpen in browser: file://{out}")
    return str(out)


if __name__ == "__main__":
    run()
