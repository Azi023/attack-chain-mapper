"""CLI entry point for attack-chain-mapper.

Usage:
    python -m acm discover path/to/file.json
    python -m acm chain path/to/file.json --output chain.html
    python -m acm chain path/to/file.json --output chain.html --model claude-sonnet-4-5
    python -m acm scaffold-adapter path/to/unknown_format.json
    python -m acm list
    python -m acm history <engagement_id>
    python -m acm diff <chain_id_a> <chain_id_b>
    python -m acm serve --port 8200
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import click

from src.ingestion.detector import detect_format, detect_format_from_file, describe_field_mapping
from src.ingestion.adapters import get_adapter
from src.ingestion.validator import validate
from src.graph.builder import build_graph, get_node_finding
from src.graph.inference import infer_and_build, mark_inferred_edges
from src.graph.pathfinder import find_all_chains, find_primary_chain, find_secondary_findings
from src.graph.scorer import compute_chain_risk_score, total_engagement_risk as calc_total_risk
from src.graph.scorer import score_all_chains
from src.renderer.html import render_to_file
from src.renderer.json_export import export_graph_json


@click.group()
@click.option("--debug", is_flag=True, default=False, envvar="ACM_DEBUG",
              help="Show full tracebacks on error.")
@click.pass_context
def cli(ctx, debug: bool):
    """Attack Chain Mapper — AI-powered pentest attack chain visualizer."""
    ctx.ensure_object(dict)
    ctx.obj["debug"] = debug


@cli.command()
@click.argument("path", type=click.Path(exists=True))
@click.pass_context
def discover(ctx, path: str):
    """Detect format and print a detailed field mapping for a findings JSON file."""
    try:
        input_path = Path(path)
        format_name, data = detect_format_from_file(input_path)
        adapter_cls = get_adapter(format_name)
        adapter = adapter_cls()
        mapping = describe_field_mapping(data, format_name)

        click.echo(f"\n  File:        {input_path.name}")
        click.echo(f"  Format:      {format_name}")
        click.echo(f"  Findings:    {mapping['sample_count']}")
        click.echo(f"  Chain links: {mapping['chain_note']}\n")

        if mapping["mapped_fields"]:
            click.echo("  Field mapping:")
            for m in mapping["mapped_fields"]:
                source = f"[source: {m['source_field']}]" if m['source_field'] != m['canonical'] else ""
                click.echo(f"    {m['canonical']:<28} ✓ found  {source}")

        if mapping["missing_critical"]:
            click.echo("\n  Missing CRITICAL fields (will impair chain quality):")
            for f in mapping["missing_critical"]:
                note = "chain inference will be applied" if f == "enabled_by" else "will be auto-generated"
                click.echo(f"    {f:<28} ✗ missing — {note}")

        if mapping["missing_optional"]:
            click.echo("\n  Missing optional fields (will be null):")
            for f in mapping["missing_optional"]:
                click.echo(f"    {f:<28} — not present")

        if mapping["unmapped_source_fields"]:
            click.echo("\n  Unrecognised source fields (ignored):")
            for f in mapping["unmapped_source_fields"]:
                click.echo(f"    {f}")

        click.echo(
            f"\n  To generate a chain:\n"
            f"    python -m acm chain {path} --output chain.html\n"
        )
    except Exception as e:
        _handle_error(e, ctx.obj.get("debug", False))


@cli.command()
@click.argument("path", type=click.Path(exists=True))
@click.option("--output", "-o", required=True, help="Output HTML file path")
@click.option("--model", default="claude-sonnet-4-5", help="Anthropic model for AI details")
@click.option("--api-key", default=None, envvar="ANTHROPIC_API_KEY", help="Anthropic API key")
@click.option("--format", "format_override", default=None,
              help="Force adapter format (e.g. generic, strike7)")
@click.option("--json-output", default=None, help="Also write graph JSON to this file")
@click.option("--no-infer", is_flag=True, default=False,
              help="Disable chain inference for missing enabled_by")
@click.option("--no-ai-detect", is_flag=True, default=False,
              help="Skip AI format detection for unrecognized formats, use strict adapter matching only")
@click.option("--db-path", default=None, envvar="ACM_DB_PATH",
              help="Override SQLite DB path (default: ~/.attack-chain-mapper/chains.db)")
@click.pass_context
def chain(
    ctx,
    path: str,
    output: str,
    model: str,
    api_key: str | None,
    format_override: str | None,
    json_output: str | None,
    no_infer: bool,
    no_ai_detect: bool,
    db_path: str | None,
):
    """Generate an attack chain HTML visualization from a findings file."""
    debug = ctx.obj.get("debug", False)
    try:
        _run_chain(
            path=path,
            output=output,
            model=model,
            api_key=api_key,
            format_override=format_override,
            json_output=json_output,
            no_infer=no_infer,
            no_ai_detect=no_ai_detect,
            db_path=db_path,
        )
    except SystemExit:
        raise
    except Exception as e:
        _handle_error(e, debug)


def _run_chain(
    path: str,
    output: str,
    model: str,
    api_key: str | None,
    format_override: str | None,
    json_output: str | None,
    no_infer: bool,
    no_ai_detect: bool,
    db_path: str | None,
) -> None:
    input_path = Path(path)
    output_path = Path(output)

    click.echo(f"Loading {input_path.name}...")
    with input_path.open() as fh:
        raw_data = json.load(fh)

    format_name = format_override or detect_format(raw_data)

    # AI format detection for unrecognized formats
    findings_override = None
    if format_name == "generic" and not format_override:
        # Check whether the file actually has a known generic structure
        has_known_key = isinstance(raw_data, (list, dict)) and (
            isinstance(raw_data, list) or any(
                k in raw_data for k in ("findings", "results", "vulnerabilities", "issues", "vulns", "items")
            )
        )
        if not has_known_key:
            effective_key = api_key or os.environ.get("ANTHROPIC_API_KEY")
            if not no_ai_detect and effective_key:
                click.echo("  Format not recognized — running AI format detection...")
                from src.ingestion.detector import ai_detect_and_adapt
                findings_override, report = ai_detect_and_adapt(raw_data, api_key=effective_key)
                click.echo(f"  ✓ AI detected {report.finding_count} findings ({report.format_guess}-style)")
                if report.fields_mapped:
                    click.echo(f"  ✓ Mapped: {', '.join(report.fields_mapped)}")
                for w in report.warnings:
                    click.echo(f"  ⚠  {w}")
            else:
                msg = (
                    "  Format not recognized. Set ANTHROPIC_API_KEY or use --api-key to enable AI format detection."
                    if not no_ai_detect
                    else "  Format not recognized and --no-ai-detect is set. Use --format to specify an adapter."
                )
                click.echo(msg, err=True)
                click.echo(
                    "\n✗ Cannot process file: format unknown and AI detection unavailable.\n"
                    "  Hint: run 'acm discover' on the file to inspect the structure.\n"
                    "  Or provide ANTHROPIC_API_KEY to enable automatic AI format detection.",
                    err=True,
                )
                sys.exit(1)

    # Parse via adapter (unless AI detection already gave us findings)
    if findings_override is not None:
        from src.ingestion.schema import Engagement as Eng
        engagement = Eng(
            engagement_id=input_path.stem,
            target_name=input_path.stem,
            findings=findings_override,
        )
    else:
        adapter_cls = get_adapter(format_name)
        adapter = adapter_cls()
        engagement = adapter.parse(raw_data)

    # ── Validation ──────────────────────────────────────────────────────────
    click.echo("\nValidating input...")
    validation_input = {"findings": [f.model_dump() for f in engagement.findings]}
    vresult, fixed_findings_dicts = validate(validation_input)

    finding_count = len(fixed_findings_dicts)
    click.echo(f"  ✓ {finding_count} findings loaded")

    if vresult.auto_fixed:
        for af in vresult.auto_fixed:
            click.echo(f"  ✓ Auto-fixed: {af}")

    for w in vresult.warnings:
        click.echo(f"  ⚠  {w.message}")

    if vresult.errors:
        for e in vresult.errors:
            click.echo(f"  ✗ {e.code}: {e.message}", err=True)
            click.echo(f"    Fix: {e.fix_hint}", err=True)
        count = len(vresult.errors)
        click.echo(f"\n{count} error(s) — cannot generate chain. Fix the errors above and retry.", err=True)
        sys.exit(1)

    # Rebuild engagement from validated/fixed findings if any auto-fixes applied
    if vresult.auto_fixed or vresult.warnings:
        from src.ingestion.schema import Finding as F, Engagement as Eng
        fixed = []
        for fd in fixed_findings_dicts:
            try:
                fixed.append(F(**fd))
            except Exception:
                pass
        if fixed:
            engagement = Eng(
                engagement_id=engagement.engagement_id,
                target_name=engagement.target_name,
                findings=fixed,
                metadata=engagement.metadata,
            )

    click.echo("")

    # ── Chain inference ─────────────────────────────────────────────────────
    findings = engagement.findings
    inferred_ids: set[str] = set()
    if not no_infer:
        findings, inferred_ids = infer_and_build(findings)
        if inferred_ids:
            click.echo(f"  Chain inference applied to {len(inferred_ids)} findings")
            from src.ingestion.schema import Engagement as Eng
            engagement = Eng(
                engagement_id=engagement.engagement_id,
                target_name=engagement.target_name,
                findings=findings,
                metadata=engagement.metadata,
            )

    click.echo("Building graph...")
    G = build_graph(engagement.findings)
    if inferred_ids:
        mark_inferred_edges(G, inferred_ids)

    click.echo("Finding chains...")
    chains = find_all_chains(G)
    findings_by_id = {f.id: f for f in engagement.findings}
    chains = score_all_chains(chains, findings_by_id)

    for cr in chains:
        path_findings = [get_node_finding(G, nid) for nid in cr.primary_path if get_node_finding(G, nid)]
        click.echo(f"  {cr.label} ({cr.chain_risk_score:.2f}): {len(path_findings)} steps")
        for i, f in enumerate(path_findings):
            inferred_note = " [inferred]" if f.id in inferred_ids else ""
            arrow = "→ " if i > 0 else "  "
            click.echo(f"    {arrow}[{f.severity_label}] {f.title}{inferred_note}")

    primary_chain = []
    if chains:
        for nid in chains[0].primary_path:
            f = get_node_finding(G, nid)
            if f is not None:
                primary_chain.append(f)

    all_primary_ids: set[str] = set()
    for cr in chains:
        all_primary_ids.update(cr.primary_path)
    secondary = [f for f in engagement.findings if f.id not in all_primary_ids]
    secondary.sort(key=lambda f: f.severity, reverse=True)

    risk_score = chains[0].chain_risk_score if chains else 0.0
    eng_risk = calc_total_risk(chains)

    click.echo(f"  Secondary findings: {len(secondary)}")
    click.echo(f"  Chain risk score: {risk_score}")
    if len(chains) > 1:
        click.echo(f"  Total engagement risk: {eng_risk}")

    # ── AI enrichment ────────────────────────────────────────────────────────
    from src.ai.client import AIClient
    ai = AIClient(api_key=api_key, model=model)
    if ai.available:
        click.echo(f"\nEnriching with AI details ({model})...")
        try:
            enriched = ai.enrich_findings_sync(engagement.findings, G)
            from src.ingestion.schema import Engagement as Eng
            engagement = Eng(
                engagement_id=engagement.engagement_id,
                target_name=engagement.target_name,
                findings=enriched,
                metadata=engagement.metadata,
            )
            G = build_graph(engagement.findings)
            if inferred_ids:
                mark_inferred_edges(G, inferred_ids)
            chains = find_all_chains(G)
            findings_by_id = {f.id: f for f in engagement.findings}
            chains = score_all_chains(chains, findings_by_id)
            primary_chain = []
            if chains:
                for nid in chains[0].primary_path:
                    f = get_node_finding(G, nid)
                    if f is not None:
                        primary_chain.append(f)
            all_primary_ids = set()
            for cr in chains:
                all_primary_ids.update(cr.primary_path)
            secondary = [f for f in engagement.findings if f.id not in all_primary_ids]
            secondary.sort(key=lambda f: f.severity, reverse=True)
            risk_score = chains[0].chain_risk_score if chains else 0.0
            eng_risk = calc_total_risk(chains)
        except Exception as e:
            click.echo(f"  Warning: AI enrichment failed: {e}", err=True)
    else:
        click.echo("\n  No API key — using pre-written AI details from fixture (if present)")

    # ── Build AttackChain object ─────────────────────────────────────────────
    from src import AttackChain
    attack_chain = AttackChain(
        engagement=engagement,
        primary_path=primary_chain,
        secondary_findings=secondary,
        chain_risk_score=risk_score,
        inferred_ids=inferred_ids,
        chains=chains,
        total_engagement_risk=eng_risk,
        chain_count=len(chains),
    )

    # ── Render ───────────────────────────────────────────────────────────────
    click.echo(f"\nRendering HTML → {output_path}...")
    html_content = attack_chain.render_html()
    output_path.write_text(html_content, encoding="utf-8")
    size_kb = output_path.stat().st_size / 1024
    click.echo(f"  Written: {output_path} ({size_kb:.1f} KB)")

    if json_output:
        from src.renderer.json_export import export_to_file
        graph_data = export_graph_json(engagement, primary_chain, secondary, risk_score)
        export_to_file(graph_data, json_output)
        click.echo(f"  JSON: {json_output}")

    # ── Persist to SQLite ────────────────────────────────────────────────────
    try:
        from src.storage.store import ChainStore
        store = ChainStore(db_path=db_path)
        chain_id = store.save_chain(attack_chain, engagement, html_path=str(output_path))
        store.close()
        click.echo(f"\n  Chain saved → {chain_id[:8]} (use --chain-id {chain_id[:8]} to retrieve)")
        click.echo(f"  Run: acm list   to see all engagements")
    except Exception as e:
        click.echo(f"  Warning: could not save chain to store: {e}", err=True)

    click.echo("\nDone. Open the HTML file in any browser.")


@cli.command("list")
@click.option("--db-path", default=None, envvar="ACM_DB_PATH", help="Override DB path")
@click.pass_context
def list_engagements(ctx, db_path: str | None):
    """List all stored engagements with chain count and latest risk score."""
    debug = ctx.obj.get("debug", False)
    try:
        from src.storage.store import ChainStore
        store = ChainStore(db_path=db_path)
        engagements = store.list_engagements()
        store.close()

        if not engagements:
            click.echo("No engagements found. Run: acm chain <file.json> --output chain.html")
            return

        click.echo(f"\n  {'ENGAGEMENT ID':<36} {'TARGET':<20} {'CHAINS':>6} {'LATEST DATE':<24} {'RISK':>6}")
        click.echo("  " + "-" * 96)
        for e in engagements:
            target = (e["target_name"] or "unknown")[:19]
            date = (e["latest_date"] or "")[:19]
            score = f"{e['latest_risk_score']:.1f}" if e["latest_risk_score"] else "N/A"
            click.echo(f"  {e['engagement_id']:<36} {target:<20} {e['chain_count']:>6} {date:<24} {score:>6}")
        click.echo("")
    except Exception as e:
        _handle_error(e, debug)


@cli.command("history")
@click.argument("engagement_id")
@click.option("--db-path", default=None, envvar="ACM_DB_PATH", help="Override DB path")
@click.pass_context
def history(ctx, engagement_id: str, db_path: str | None):
    """List all chains for an engagement, newest first."""
    debug = ctx.obj.get("debug", False)
    try:
        from src.storage.store import ChainStore
        store = ChainStore(db_path=db_path)
        chains = store.get_chains_for_engagement(engagement_id)
        store.close()

        if not chains:
            click.echo(f"No chains found for engagement '{engagement_id}'.")
            return

        click.echo(f"\n  Chains for engagement: {engagement_id}")
        click.echo(f"  {'CHAIN ID':<36} {'DATE':<24} {'RISK':>6} {'PATH LEN':>8} {'FINDINGS':>8}")
        click.echo("  " + "-" * 88)
        for c in chains:
            date = (c["created_at"] or "")[:19]
            score = f"{c['chain_risk_score']:.1f}" if c["chain_risk_score"] else "N/A"
            click.echo(
                f"  {c['id']:<36} {date:<24} {score:>6} "
                f"{c['primary_chain_length']:>8} {c['finding_count']:>8}"
            )
        click.echo("")
    except Exception as e:
        _handle_error(e, debug)


@cli.command("diff")
@click.argument("chain_id_a")
@click.argument("chain_id_b")
@click.option("--db-path", default=None, envvar="ACM_DB_PATH", help="Override DB path")
@click.pass_context
def diff(ctx, chain_id_a: str, chain_id_b: str, db_path: str | None):
    """Compare two chains and print a diff summary."""
    debug = ctx.obj.get("debug", False)
    try:
        from src.storage.store import ChainStore
        store = ChainStore(db_path=db_path)

        # Allow short IDs (prefix match)
        def _resolve_id(partial: str) -> str:
            cur = store._conn.cursor()
            cur.execute("SELECT id FROM chains WHERE id LIKE ?", (f"{partial}%",))
            rows = cur.fetchall()
            if not rows:
                raise click.ClickException(f"No chain found matching '{partial}'")
            if len(rows) > 1:
                raise click.ClickException(
                    f"Multiple chains match '{partial}': {[r['id'] for r in rows]}"
                )
            return rows[0]["id"]

        full_a = _resolve_id(chain_id_a)
        full_b = _resolve_id(chain_id_b)
        result = store.diff_chains(full_a, full_b)
        store.close()

        click.echo(f"\n  Diff: {chain_id_a[:8]} → {chain_id_b[:8]}")
        click.echo(f"  Risk score delta: {result['risk_score_delta']:+.1f}")
        click.echo(f"  Primary path changed: {'yes' if result['chain_changed'] else 'no'}")

        if result["new_findings"]:
            click.echo(f"\n  New findings ({len(result['new_findings'])}):")
            for f in result["new_findings"]:
                click.echo(f"    + [{f['severity']:.1f}] {f['title']}")

        if result["resolved_findings"]:
            click.echo(f"\n  Resolved findings ({len(result['resolved_findings'])}):")
            for f in result["resolved_findings"]:
                click.echo(f"    - [{f['severity']:.1f}] {f['title']}")

        if result["severity_changes"]:
            click.echo(f"\n  Severity changes ({len(result['severity_changes'])}):")
            for f in result["severity_changes"]:
                click.echo(
                    f"    ~ {f['title']}: "
                    f"{f['severity_before']:.1f} → {f['severity_after']:.1f}"
                )

        if not any([result["new_findings"], result["resolved_findings"], result["severity_changes"]]):
            click.echo("  No finding changes detected.")
        click.echo("")
    except click.ClickException:
        raise
    except Exception as e:
        _handle_error(e, debug)


@cli.command("scaffold-adapter")
@click.argument("path", type=click.Path(exists=True))
@click.pass_context
def scaffold_adapter(ctx, path: str):
    """Print a Claude Code prompt for scaffolding a custom adapter for an unknown format."""
    try:
        input_path = Path(path)
        with input_path.open() as fh:
            data = json.load(fh)

        top_keys = list(data.keys()) if isinstance(data, dict) else ["[list]"]
        snippet = json.dumps(data, indent=2)[:3000]

        sample_finding = None
        if isinstance(data, dict):
            for key in ("findings", "results", "vulnerabilities", "issues", "vulns", "items"):
                if isinstance(data.get(key), list) and data[key]:
                    sample_finding = data[key][0]
                    break
        elif isinstance(data, list) and data:
            sample_finding = data[0]

        sample_str = json.dumps(sample_finding, indent=2) if sample_finding else "N/A"
        key_path_str = f"Top-level keys: {top_keys}"
        if sample_finding and isinstance(sample_finding, dict):
            key_path_str += f"\nFirst finding keys: {list(sample_finding.keys())}"

        prompt = f"""You are writing a Python adapter for attack-chain-mapper.

The input file is: {input_path.name}

{key_path_str}

Here is the full JSON structure (first 3000 chars):
```json
{snippet}
```

Sample finding object:
```json
{sample_str}
```

Write src/ingestion/adapters/custom.py that:
1. Has a class CustomAdapter with:
   - FORMAT_NAME = "custom"
   - can_handle(cls, data: dict) -> bool  (return True if data matches this format)
   - load(self, path) -> Engagement
   - parse(self, data) -> Engagement
   - describe_mapping(self, data) -> dict

2. Maps the source fields to List[Finding] using this LOCKED schema:
```python
class Finding(BaseModel):
    id: str
    title: str
    severity: float
    severity_label: str
    mitre_technique: Optional[str]
    step_index: Optional[int]
    timestamp_offset_s: Optional[int]
    enabled_by: List[str]
    evidence: Optional[str]
    host: Optional[str]
    ai_detail: Optional[str]
    ai_remediation: Optional[str]
    ai_confidence: Optional[float]
```

3. Severity string → float mapping: CRITICAL=9.5, HIGH=7.5, MEDIUM=5.0, LOW=2.5, INFO=0.5

4. Handles missing fields gracefully — use None, never raise on missing optional fields.

5. If enabled_by is not in the source data, leave it as [] — chain inference will be applied automatically.

Then add this registration line in src/ingestion/adapters/__init__.py:
```python
from src.ingestion.adapters.custom import CustomAdapter
ADAPTER_REGISTRY["custom"] = CustomAdapter
```

The adapter should be 60-90 lines. No external dependencies beyond pydantic and the standard library.
"""
        click.echo(prompt)
    except Exception as e:
        _handle_error(e, ctx.obj.get("debug", False))


@cli.command()
@click.option("--port", default=8200, help="Port to listen on")
@click.option("--host", default="127.0.0.1", help="Host to bind to")
@click.pass_context
def serve(ctx, port: int, host: str):
    """Start the FastAPI server."""
    try:
        import uvicorn
    except ImportError:
        click.echo("uvicorn is required: pip install uvicorn", err=True)
        sys.exit(1)
    click.echo(f"Starting attack-chain-mapper API on http://{host}:{port}")
    uvicorn.run("src.api.app:app", host=host, port=port, reload=False)


# ---------------------------------------------------------------------------
# Error handler
# ---------------------------------------------------------------------------

def _handle_error(e: Exception, debug: bool) -> None:
    click.echo(f"\n✗ Unexpected error: {e}", err=True)
    click.echo("  Run with --debug for full traceback.", err=True)
    if debug:
        raise e
    sys.exit(1)


if __name__ == "__main__":
    cli()
