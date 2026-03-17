# attack-chain-mapper

**AI-powered pentest attack chain visualizer.**

Takes completed engagement findings, reconstructs the actual attack path taken, and produces an interactive CISO-grade HTML visualization. Works with any structured findings source — including Strike7, generic JSON, and Burp-style exports.

Standalone · Open-source · Integrable as PIL F7

---

## What it produces

![Attack chain visualization showing the primary strike path from Host/port discovery through Anonymous LDAP bind, Credentials in SYSVOL, SMB signing disabled, up to Domain admin via NTLM relay. Left panel ranks all findings by severity. Right panel shows the chain bottom-to-top.](docs/assets/screenshot.png)

The output is a single self-contained HTML file you can email, open in any browser, or embed in a report. No server needed. No external dependencies.

---

## What it does

### 1. Ingests findings from any source

Drop in a JSON file from any tool. The adapter layer handles different field names, severity formats (strings or floats), nested structures, and missing fields. If your tool isn't supported yet, `acm scaffold-adapter` generates a Claude Code prompt that writes a custom adapter for you in under 5 minutes.

Supported formats:
- **Generic JSON** — any JSON with a `findings`, `results`, `vulnerabilities`, or `issues` list
- **Strike7** — benchmark run output (`benchmark_run_id`, `agent_steps`, nested findings)
- **Any other format** — use `acm scaffold-adapter` to generate a custom adapter

### 2. Builds the attack graph

Constructs a directed acyclic graph (DAG) where nodes are findings and edges represent "this finding made the next one possible." If your data includes explicit `enabled_by` relationships, those are used directly. If not — which is the real-world case for most tools — **chain inference** is applied automatically.

**Chain inference** uses:
- Step ordering (`step_index` or array position)
- Severity progression (lower severity findings are assumed to be prerequisites for higher ones)
- Host proximity (findings on the same host or subnet are more likely to be causally linked)

Inferred edges are labelled `[inferred]` in CLI output and flagged in the graph so you can distinguish them from explicit relationships.

### 3. Identifies the primary attack chain

Uses a longest-weighted-path algorithm (DP over topological sort, O(V+E)) to find the most impactful sequence of exploits — from the initial entry point to the highest-severity crown jewel. Findings not on the primary chain are listed as secondary findings.

### 4. Scores the chain

Computes a **chain risk score** = Σ(severity × step_weight), where later steps in the chain carry a higher weight (1.0→2.0 from entry to crown jewel). This gives a single number suitable for CISO-level reporting.

### 5. Generates AI finding details (optional, BYOK)

If you provide an Anthropic API key, each finding gets enriched with:
- **AI analysis** — what the vulnerability is, why it exists, what the attacker did with it
- **Remediation** — concrete, numbered, actionable steps
- **Confidence** — the model's confidence this is a true positive

All AI calls are async and non-blocking. The chain renders immediately; AI details stream in as they complete. If no API key is provided, pre-written details from the fixture are shown instead — the demo works fully with no key.

### 6. Renders an interactive HTML report

The output is a single `.html` file containing:

| Feature | Description |
|---|---|
| Left panel | All findings ranked by severity, colour-coded (critical=red → info=grey), clickable |
| Right panel | Primary attack chain, entry point at bottom → crown jewel at top |
| Animated arrows | SVG flow arrows with CSS animation showing direction of chain progression |
| Node click | Selecting any node highlights it simultaneously in both panels |
| Detail drawer | Slides in from the right: AI analysis, MITRE link, evidence, remediation, confidence bar |
| Secondary findings | Findings not in the primary chain listed below the main chain |
| Chain risk score | Aggregate score shown prominently at the top for CISO reporting |
| Timeline bar | Attack progression plotted by timestamp at the bottom of the right panel |
| Export button | Downloads a fully self-contained copy of the HTML (no server, no dependencies) |
| Responsive | Works at 1200px and 1600px without horizontal scroll |

---

## Quick start

```bash
git clone https://github.com/Azi023/attack-chain-mapper.git
cd attack-chain-mapper
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"

# Run the demo (no API key needed)
python demo/run_demo.py
# → output: /tmp/acm_demo.html — open in any browser
```

---

## CLI reference

```bash
# Detect format, show field mapping, check if chain inference will be needed
python -m acm discover path/to/engagement.json

# Generate chain HTML (no API key — uses pre-written details if present)
python -m acm chain path/to/engagement.json --output chain.html

# Generate chain with live AI analysis
export ANTHROPIC_API_KEY=sk-ant-...
python -m acm chain path/to/engagement.json --output chain.html --model claude-sonnet-4-5

# Generate a Claude Code prompt for a custom adapter (paste into Claude Code)
python -m acm scaffold-adapter path/to/unknown_format.json

# Start the FastAPI server (POST /chain)
python -m acm serve --port 8200
```

### `discover` output example

```
  File:        engagement.json
  Format:      strike7
  Findings:    12
  Chain links: ✗ missing — chain inference will be applied automatically

  Field mapping:
    id                           ✓ found
    title                        ✓ found  [source: name]
    severity                     ✓ found  [source: risk_score]
    mitre_technique              ✓ found  [source: technique]
    host                         ✓ found  [source: target]

  Missing CRITICAL fields:
    enabled_by                   ✗ missing — chain inference will be applied
```

---

## Strike7 integration

Attack-chain-mapper is designed to ingest Strike7 benchmark run output directly.

### Step 1: Discover the format

```bash
python -m acm discover path/to/strike7_run_output.json
```

This identifies the format, maps fields, and tells you whether chain inference will be applied.

### Step 2: Generate the chain

```bash
python -m acm chain path/to/strike7_run_output.json --output chain.html
```

The Strike7 adapter handles:
- Findings nested inside `agent_steps[*].findings`
- Top-level `findings` and `vulnerabilities` keys
- String severity labels (`"HIGH"`, `"CRITICAL"`) → CVSS floats (7.5, 9.5)
- Strike7-specific field names: `technique`, `proof`, `output`, `command_output`, `target`, `hostname`, `risk`, `risk_score`
- `step_index` and `timestamp_offset_s` injected from the parent `agent_step` record

### Step 3: With AI analysis

```bash
export ANTHROPIC_API_KEY=sk-ant-...
python -m acm chain path/to/strike7_run_output.json \
  --output chain.html \
  --model claude-sonnet-4-5
```

### PIL F7 integration (one-function API)

```python
from src import build_chain
from src.ingestion.adapters.strike7 import Strike7Adapter

chain = build_chain(
    engagement_data=engagement_dict,   # raw dict from Strike7 output
    adapter=Strike7Adapter(),
    api_key=None,                      # PIL controls whether AI is called
    infer_chain=True,                  # auto-infer when enabled_by is absent
)

html = chain.render_html()            # str — complete self-contained HTML
data = chain.to_json()               # dict — for PIL SQLite storage
path = chain.primary_path            # list[Finding] — the attack chain
score = chain.chain_risk_score       # float — for CISO dashboard
```

---

## Chain inference — how it works

Most real-world tool outputs don't include explicit `enabled_by` relationships between findings. Without those, there's no chain — just a list.

Chain inference solves this by heuristically linking findings based on three signals:

1. **Step ordering** — findings that come earlier in the engagement timeline are prerequisites for later ones
2. **Severity progression** — a lower-severity finding is assumed to be a prerequisite for a higher-severity one. Recon enables foothold enables escalation.
3. **Host proximity** — findings on the same host or /24 subnet are more likely to be causally linked than findings on different targets

Inferred edges are flagged in the output so you can distinguish them from explicit relationships. Explicit `enabled_by` values in the source data are always respected and never overridden.

This is what makes the tool genuinely useful on real engagement data, not just on pre-structured synthetic fixtures.

---

## API key setup

The tool **never ships with or assumes an API key**. Provide your own:

```bash
export ANTHROPIC_API_KEY=sk-ant-...
# or
python -m acm chain input.json --output chain.html --api-key sk-ant-...
```

Without a key: the chain renders immediately with pre-written details (if present in the fixture) or a placeholder message. The demo works fully with no key.

Recommended models: `claude-sonnet-4-5` (default) or `claude-sonnet-4-6`.

---

## Finding schema (locked)

Adapters map TO this schema. The schema never changes to suit an adapter.

```python
class Finding(BaseModel):
    id: str                           # unique, stable across retests
    title: str                        # short human title
    severity: float                   # 0.0–10.0 CVSS-style
    severity_label: str               # CRITICAL / HIGH / MEDIUM / LOW / INFO
    mitre_technique: Optional[str]    # e.g. "T1557.001"
    step_index: Optional[int]         # agent step number
    timestamp_offset_s: Optional[int] # seconds from engagement start
    enabled_by: List[str]             # prerequisite finding IDs ([] if unknown)
    evidence: Optional[str]           # raw evidence text
    host: Optional[str]               # target host/IP
    ai_detail: Optional[str]          # AI-generated or pre-written detail
    ai_remediation: Optional[str]     # AI-generated or pre-written remediation
    ai_confidence: Optional[float]    # confidence 0.0–1.0
```

---

## Architecture

| Component | Technology | Notes |
|---|---|---|
| Graph engine | NetworkX DAG | Longest-weighted-path for primary chain (O(V+E) DP) |
| Renderer | Pure HTML + vanilla JS | Single self-contained file, no React/Vue, can be emailed |
| API | FastAPI | `POST /chain` → JSON + HTML |
| AI enrichment | Anthropic API (BYOK) | Async, one call per finding, non-blocking |
| Adapters | Plugin pattern | One file per format, registered in `adapters/__init__.py` |
| Chain inference | Heuristic DAG | Step order + severity + host proximity |

---

## Running tests

```bash
python -m pytest tests/ -q
# 159 tests, 0 failures
```

Test coverage includes: schema validation, graph construction, cycle detection, pathfinder, chain inference, Strike7 adapter, generic adapter, format detector, and AI client.

---

## Privacy

All processing is local. No finding data leaves your machine unless you explicitly configure an Anthropic API call with `--api-key`. The HTML output contains no credentials. No telemetry, no analytics, no network calls except the optional LLM enrichment you choose to trigger.

---

## Adding a custom adapter

```bash
# Get a scaffold prompt for your tool's output format:
python -m acm scaffold-adapter path/to/your_format.json
# Paste the printed prompt into Claude Code — it writes the adapter for you
```

Or follow the pattern in `src/ingestion/adapters/generic.py`. An adapter is ~60-80 lines: a `parse()` method that maps your source fields to `Finding` objects, and a `describe_mapping()` method for `acm discover`.
