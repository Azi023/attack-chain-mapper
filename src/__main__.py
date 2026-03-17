"""CLI entry point for attack-chain-mapper.

Usage:
    python -m acm discover path/to/file.json
    python -m acm chain path/to/file.json --output chain.html
    python -m acm chain path/to/file.json --output chain.html --model claude-sonnet-4-5
    python -m acm scaffold-adapter path/to/unknown_format.json
    python -m acm serve --port 8200
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import click

from src.ingestion.detector import detect_format_from_file, describe_field_mapping
from src.ingestion.adapters import get_adapter
from src.graph.builder import build_graph
from src.graph.inference import infer_and_build, mark_inferred_edges
from src.graph.pathfinder import find_primary_chain, find_secondary_findings
from src.graph.scorer import compute_chain_risk_score
from src.renderer.html import render_to_file
from src.renderer.json_export import export_graph_json


@click.group()
def cli():
    """Attack Chain Mapper — AI-powered pentest attack chain visualizer."""


@cli.command()
@click.argument("path", type=click.Path(exists=True))
def discover(path: str):
    """Detect format and print a detailed field mapping for a findings JSON file."""
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


@cli.command()
@click.argument("path", type=click.Path(exists=True))
@click.option("--output", "-o", required=True, help="Output HTML file path")
@click.option("--model", default="claude-sonnet-4-5", help="Anthropic model for AI details")
@click.option("--api-key", default=None, envvar="ANTHROPIC_API_KEY", help="Anthropic API key")
@click.option("--format", "format_override", default=None, help="Force adapter format (e.g. generic, strike7)")
@click.option("--json-output", default=None, help="Also write graph JSON to this file")
@click.option("--no-infer", is_flag=True, default=False, help="Disable chain inference for missing enabled_by")
def chain(path: str, output: str, model: str, api_key: str | None, format_override: str | None, json_output: str | None, no_infer: bool):
    """Generate an attack chain HTML visualization from a findings file."""
    input_path = Path(path)
    output_path = Path(output)

    click.echo(f"Loading {input_path.name}...")
    format_name, data = detect_format_from_file(input_path)
    if format_override:
        format_name = format_override

    adapter_cls = get_adapter(format_name)
    adapter = adapter_cls()
    engagement = adapter.parse(data)
    click.echo(f"  {len(engagement.findings)} findings loaded ({format_name} adapter)")

    # Chain inference — auto-applied when enabled_by is missing
    findings = engagement.findings
    inferred_ids: set[str] = set()
    if not no_infer:
        findings, inferred_ids = infer_and_build(findings)
        if inferred_ids:
            click.echo(f"  Chain inference applied to {len(inferred_ids)} findings (no explicit enabled_by)")
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

    click.echo("Finding primary chain...")
    primary_chain = find_primary_chain(G)
    secondary = find_secondary_findings(G, primary_chain)
    risk_score = compute_chain_risk_score(primary_chain)

    click.echo(f"  Primary chain: {len(primary_chain)} steps")
    for i, f in enumerate(primary_chain):
        inferred_note = " [inferred]" if f.id in inferred_ids else ""
        arrow = "→ " if i > 0 else "  "
        click.echo(f"    {arrow}[{f.severity_label}] {f.title}{inferred_note}")
    click.echo(f"  Secondary findings: {len(secondary)}")
    click.echo(f"  Chain risk score: {risk_score}")

    # AI enrichment
    from src.ai.client import AIClient
    ai = AIClient(api_key=api_key, model=model)
    if ai.available:
        click.echo(f"Enriching with AI details ({model})...")
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
            primary_chain = find_primary_chain(G)
            secondary = find_secondary_findings(G, primary_chain)
        except Exception as e:
            click.echo(f"  Warning: AI enrichment failed: {e}", err=True)
    else:
        click.echo("  No API key — using pre-written AI details from fixture (if present)")

    click.echo(f"Rendering HTML → {output_path}...")
    render_to_file(engagement, primary_chain, secondary, risk_score, output_path)
    size_kb = output_path.stat().st_size / 1024
    click.echo(f"  Written: {output_path} ({size_kb:.1f} KB)")

    if json_output:
        from src.renderer.json_export import export_to_file
        graph_data = export_graph_json(engagement, primary_chain, secondary, risk_score)
        export_to_file(graph_data, json_output)
        click.echo(f"  JSON: {json_output}")

    click.echo("\nDone. Open the HTML file in any browser.")


@cli.command("scaffold-adapter")
@click.argument("path", type=click.Path(exists=True))
def scaffold_adapter(path: str):
    """Print a Claude Code prompt for scaffolding a custom adapter for an unknown format."""
    input_path = Path(path)
    with input_path.open() as fh:
        data = json.load(fh)

    # Analyse structure
    top_keys = list(data.keys()) if isinstance(data, dict) else ["[list]"]
    snippet = json.dumps(data, indent=2)[:3000]

    # Find a sample finding
    sample_finding = None
    if isinstance(data, dict):
        for key in ("findings", "results", "vulnerabilities", "issues", "vulns", "items"):
            if isinstance(data.get(key), list) and data[key]:
                sample_finding = data[key][0]
                break
    elif isinstance(data, list) and data:
        sample_finding = data[0]

    sample_str = json.dumps(sample_finding, indent=2) if sample_finding else "N/A"

    # Key paths found
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
    id: str                           # required, unique
    title: str                        # required
    severity: float                   # required, 0.0-10.0 CVSS-style
    severity_label: str               # CRITICAL/HIGH/MEDIUM/LOW/INFO
    mitre_technique: Optional[str]    # e.g. "T1557.001"
    step_index: Optional[int]         # sequential step number
    timestamp_offset_s: Optional[int] # seconds from engagement start
    enabled_by: List[str]             # IDs of prerequisite findings (can be [] if unknown)
    evidence: Optional[str]           # raw evidence text
    host: Optional[str]               # target hostname/IP
    ai_detail: Optional[str]          # pre-written detail if available
    ai_remediation: Optional[str]     # pre-written remediation if available
    ai_confidence: Optional[float]    # confidence 0.0-1.0
```

3. Severity string → float mapping to use if severity is a label, not a number:
   CRITICAL=9.5, HIGH=7.5, MEDIUM=5.0, LOW=2.5, INFO=0.5

4. Handles missing fields gracefully — use None, never raise on missing optional fields.
   The only required fields are id, title, severity, severity_label.

5. If enabled_by is not in the source data, leave it as [] — chain inference will be applied automatically.

Then add this registration line in src/ingestion/adapters/__init__.py:
```python
from src.ingestion.adapters.custom import CustomAdapter
ADAPTER_REGISTRY["custom"] = CustomAdapter
```

The adapter should be 60-90 lines. No external dependencies beyond pydantic and the standard library.

IMPORTANT: The schema is locked — never change Finding fields to match the source format. Always map the source to the schema, not the other way around.
"""
    click.echo(prompt)


@cli.command()
@click.option("--port", default=8200, help="Port to listen on")
@click.option("--host", default="127.0.0.1", help="Host to bind to")
def serve(port: int, host: str):
    """Start the FastAPI server."""
    try:
        import uvicorn
    except ImportError:
        click.echo("uvicorn is required: pip install uvicorn", err=True)
        sys.exit(1)
    click.echo(f"Starting attack-chain-mapper API on http://{host}:{port}")
    uvicorn.run("src.api.app:app", host=host, port=port, reload=False)


if __name__ == "__main__":
    cli()
