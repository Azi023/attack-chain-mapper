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

from src.ingestion.detector import detect_format_from_file
from src.ingestion.adapters import get_adapter
from src.graph.builder import build_graph
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
    """Detect format and print field mapping for a findings JSON file."""
    input_path = Path(path)
    format_name, data = detect_format_from_file(input_path)
    adapter_cls = get_adapter(format_name)
    adapter = adapter_cls()
    mapping = adapter.describe_mapping(data)

    click.echo(f"\n  File:    {input_path.name}")
    click.echo(f"  Adapter: {mapping['adapter']}")
    click.echo(f"  Findings found: {mapping['sample_count']}\n")

    if mapping["mapped_fields"]:
        click.echo("  Mapped fields:")
        for m in mapping["mapped_fields"]:
            click.echo(f"    {m['source_field']:<30} → {m['maps_to']}")

    if mapping["unmapped_fields"]:
        click.echo("\n  Unmapped fields (will be ignored):")
        for f in mapping["unmapped_fields"]:
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
@click.option("--format", "format_override", default=None, help="Force adapter format (e.g. generic)")
@click.option("--json-output", default=None, help="Also write graph JSON to this file")
def chain(path: str, output: str, model: str, api_key: str | None, format_override: str | None, json_output: str | None):
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
    click.echo(f"  Loaded {len(engagement.findings)} findings ({format_name} format)")

    click.echo("Building graph...")
    G = build_graph(engagement.findings)

    click.echo("Finding primary chain...")
    primary_chain = find_primary_chain(G)
    secondary = find_secondary_findings(G, primary_chain)
    risk_score = compute_chain_risk_score(primary_chain)

    click.echo(f"  Primary chain: {len(primary_chain)} steps")
    click.echo(f"  Secondary findings: {len(secondary)}")
    click.echo(f"  Chain risk score: {risk_score}")

    # AI enrichment (only if API key is available)
    if api_key:
        click.echo(f"Enriching with AI details ({model})...")
        try:
            from src.ai.client import enrich_findings_sync
            enriched = enrich_findings_sync(engagement.findings, G, api_key=api_key, model=model)
            # Rebuild with enriched findings
            from src.ingestion.schema import Engagement
            engagement = Engagement(
                engagement_id=engagement.engagement_id,
                target_name=engagement.target_name,
                findings=enriched,
                metadata=engagement.metadata,
            )
            G = build_graph(engagement.findings)
            primary_chain = find_primary_chain(G)
            secondary = find_secondary_findings(G, primary_chain)
        except Exception as e:
            click.echo(f"  Warning: AI enrichment failed: {e}", err=True)
    else:
        click.echo("  No API key — using pre-written AI details from fixture (if present)")

    click.echo(f"Rendering HTML to {output_path}...")
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

    # Show a snippet of the data structure
    snippet = json.dumps(data, indent=2)[:2000]

    prompt = f"""You are building a custom adapter for the `attack-chain-mapper` tool.

The input file is: {input_path.name}

Here is a sample of the JSON structure (first 2000 chars):
```json
{snippet}
```

The adapter must:
1. Map the input fields to the canonical Finding schema fields
2. Be placed in `src/ingestion/adapters/<adapter_name>.py`
3. Follow the same interface as `src/ingestion/adapters/generic.py` (GenericAdapter)
4. Be 50-80 lines max
5. Be registered in `src/ingestion/adapters/__init__.py`

The canonical Finding schema is:
- id: str (unique finding identifier)
- title: str (short human title)
- severity: float (0.0-10.0 CVSS-style)
- severity_label: str (CRITICAL/HIGH/MEDIUM/LOW/INFO)
- mitre_technique: Optional[str] (e.g. "T1557.001")
- step_index: Optional[int] (sequential step number)
- timestamp_offset_s: Optional[int] (seconds from engagement start)
- enabled_by: List[str] (IDs of prerequisite findings)
- evidence: Optional[str] (raw evidence text)
- host: Optional[str] (target hostname/IP)
- ai_detail: Optional[str] (pre-written detail, if available)
- ai_remediation: Optional[str] (pre-written remediation, if available)
- ai_confidence: Optional[float] (confidence 0.0-1.0)

Write the complete adapter file and the registration line for __init__.py.
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
