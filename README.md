# attack-chain-mapper

AI-powered pentest attack chain visualizer. Takes completed engagement findings, reconstructs the actual attack path taken, and produces an interactive CISO-grade HTML visualization.

**Standalone · Open-source · Integrable as PIL F7**

---

## Quick Start

```bash
# Clone and install
git clone <repo>
cd attack-chain-mapper
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"

# Run the demo (no API key needed)
python demo/run_demo.py
# Opens /tmp/acm_demo.html
```

---

## CLI Usage

```bash
# Detect format and print field mapping
python -m acm discover path/to/engagement.json

# Generate chain (no API key — uses pre-written AI details if present)
python -m acm chain path/to/engagement.json --output chain.html

# Generate chain with AI-generated finding details
export ANTHROPIC_API_KEY=sk-ant-...
python -m acm chain path/to/engagement.json --output chain.html --model claude-sonnet-4-5

# Generate a Claude Code prompt for a custom adapter
python -m acm scaffold-adapter path/to/unknown_format.json

# Start API server
python -m acm serve --port 8200
```

---

## API Key Setup

This tool **never ships with or assumes an API key**. Users provide their own:

```bash
export ANTHROPIC_API_KEY=sk-ant-...
# or
python -m acm chain input.json --output chain.html --api-key sk-ant-...
```

If no API key is provided, the chain renders immediately using pre-written AI details from the fixture (if present) — the demo works fully without any key.

Recommended models: `claude-sonnet-4-5` (default) or `claude-sonnet-4-6`.

---

## HTML Renderer Features

The output is a single self-contained `.html` file with:

1. **Left panel** — all findings ranked by severity, colour-coded, clickable
2. **Right panel** — primary attack chain, entry point at bottom → crown jewel at top
3. **Animated flow arrows** — SVG arrows with CSS animation showing chain direction
4. **Node click** — selecting a node highlights it in both panels simultaneously
5. **Finding detail drawer** — slides in with AI analysis, MITRE link, evidence, remediation
6. **Secondary findings** — findings not in the primary chain listed below the main chain
7. **Chain risk score** — aggregate severity × step-weight score shown prominently
8. **Timeline bar** — attack progression plotted by `timestamp_offset_s`
9. **Export button** — downloads a self-contained copy of the HTML file
10. **Responsive layout** — works at 1200px and 1600px without horizontal scroll

---

## Finding Schema

Adapters map TO this schema — the schema never changes to suit an adapter:

```python
class Finding(BaseModel):
    id: str                           # unique, stable across retests
    title: str                        # short human title
    severity: float                   # 0.0–10.0 CVSS-style
    severity_label: str               # CRITICAL / HIGH / MEDIUM / LOW / INFO
    mitre_technique: Optional[str]    # e.g. "T1557.001"
    step_index: Optional[int]         # agent step number
    timestamp_offset_s: Optional[int] # seconds from engagement start
    enabled_by: List[str]             # prerequisite finding IDs
    evidence: Optional[str]           # raw evidence (redaction OK)
    host: Optional[str]               # target host/IP
    ai_detail: Optional[str]          # AI-generated finding detail
    ai_remediation: Optional[str]     # AI-generated remediation
    ai_confidence: Optional[float]    # AI confidence 0.0–1.0
```

---

## Architecture

- **Graph library**: NetworkX DAG — no custom graph implementation
- **Renderer**: Pure HTML + vanilla JS — single self-contained file, no React/Vue
- **API layer**: FastAPI — `POST /chain` returns graph JSON + rendered HTML
- **LLM**: Anthropic API (BYOK) — one async call per finding, non-blocking
- **Storage**: SQLite WAL (Phase 3)
- **Adapters**: One file per format in `src/ingestion/adapters/`, registered in `__init__.py`

---

## Running Tests

```bash
python -m pytest tests/ -q
```

---

## Adding a Custom Adapter

```bash
# Get a scaffolding prompt for your format:
python -m acm scaffold-adapter path/to/your_format.json
# Paste the output into Claude Code
```

Or follow the pattern in `src/ingestion/adapters/generic.py`.

---

## Local-First Privacy

All processing is local. No finding data leaves your machine unless you explicitly configure an Anthropic API call with `--api-key`. This is enforced at the architecture level — the tool has no telemetry, no analytics, no network calls except the optional LLM enrichment.
