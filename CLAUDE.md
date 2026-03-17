# attack-chain-mapper — CLAUDE.md

> AI-powered pentest attack chain visualizer. Takes completed engagement findings,
> reconstructs the actual attack path taken, and produces an interactive CISO-grade
> visualization. Standalone · open-source · integrable as PIL F7.

---

## Workflow Orchestration

### 1. Plan Mode Default
- Enter plan mode for ANY non-trivial task (new feature, schema change, adapter, renderer)
- If something goes sideways mid-implementation, STOP and re-plan before continuing
- Write detailed specs before touching code — schema first, then logic, then UI
- Never start building an adapter without first running the discovery command on sample data
- For multi-file changes, list every file that will be touched BEFORE making any changes

### 2. Subagent Strategy
- Use subagents for: adapter discovery runs, synthetic data generation, render output validation
- Offload format-detection logic and LLM API calls to subagents — keep the main context clean
- For the rendering layer: one subagent builds the graph object, another validates the HTML output
- One task per subagent — never bundle ingestion + rendering + API call into a single subagent run

### 3. Self-Improvement Loop
- After ANY correction from the user: update tasks/lessons.md with the pattern
- After any adapter fails to detect a format: add the failure case to tests/fixtures/
- After any LLM API call produces a bad finding detail: improve the prompt in prompts/finding_detail.py
- Review lessons.md at the start of every new implementation block

### 4. Verification Before Done
- Never mark a task complete without actually running the output and visually verifying it
- For renderers: open the HTML in a browser-preview or dump the SVG to confirm no clipped nodes
- For adapters: run against the sample fixture AND the synthetic data, confirm field mapping is correct
- For API calls: log the raw response before parsing — never assume the shape is correct
- Ask: "Would a CISO looking at this trust it?" If no, it's not done.

### 5. Demand Elegance (Balanced)
- For non-trivial graph logic: pause and ask "is there a cleaner traversal?"
- If path detection feels hacky, it probably is — rewrite the graph builder before adding workarounds
- Skip elegance for simple things: file I/O, config loading, CLI argument parsing — just make it work
- Never over-engineer the adapter layer — it should be 50-80 lines per adapter, not 300

### 6. Autonomous Bug Fixing
- When a graph cycle causes infinite traversal: fix the cycle detection immediately, don't ask for guidance
- When the LLM API returns a non-JSON response: fix the parser, log the raw response, continue
- Zero user hand-holding needed for: import errors, missing dependencies, path issues, type errors
- Go fix failing tests without being told how

---

## Task Management

1. **Plan First**: Write the implementation plan to tasks/todo.md with checkable items before ANY code
2. **Verify Plan**: Check sample data format before building an adapter — never guess the schema
3. **Track Progress**: Mark items complete as you go — never batch-complete multiple items at once
4. **Explain Changes**: Write a one-line comment above every non-obvious function explaining WHY
5. **Document Results**: Add a "## Completed" section to tasks/todo.md after each implementation block
6. **Capture Lessons**: Update tasks/lessons.md after any correction or unexpected failure

---

## Core Principles

- **Schema First**: The finding schema is the contract. Every adapter maps TO it. Never let an adapter change the schema to suit itself.
- **Bring Your Own Key**: The package NEVER ships with or assumes an API key. Users provide their own via env var or CLI flag. Default model: `claude-sonnet-4-5`.
- **Demo Must Be Full**: The synthetic data demo must exercise ALL features end-to-end. A demo that skips the AI finding detail, or skips secondary chains, is not a demo — it's a lie.
- **Adapter Resilience**: If an adapter cannot map a field, it uses None — never crashes. Partial data produces a partial chain, not an error.
- **CISO Standard**: Every output must pass the "would a CISO trust this in a board report?" test. Vague finding details, missing severity scores, or broken arrows = not done.
- **Local Always**: All processing is local. No finding data leaves the machine unless the user explicitly configures an external LLM API call. Make this clear in every README section and every CLI help string.

---

## Architecture Decisions (locked)

- **Graph library**: NetworkX for DAG construction. No custom graph implementation.
- **Renderer**: Pure HTML + vanilla JS for the interactive widget. No React, no Vue — must work as a single self-contained HTML file that can be emailed or embedded.
- **API layer**: FastAPI, matching PIL's pattern. Single endpoint: `POST /chain` returns graph JSON + rendered HTML.
- **LLM call**: Anthropic API only, model `claude-sonnet-4-5` default. One call per finding for detail generation. Calls are async and non-blocking — chain renders without waiting for all details.
- **Storage**: SQLite, WAL mode, matching PIL's pattern. Chains are stored for reuse and diff.
- **Adapter pattern**: Each source format gets one adapter file in `src/ingestion/adapters/`. Adapters are registered in `adapters/__init__.py` — adding a new one is one file + one registration line.

---

## Project Structure

```
attack-chain-mapper/
├── CLAUDE.md                      ← you are here
├── README.md
├── pyproject.toml
├── tasks/
│   ├── todo.md                    ← always-current task list
│   └── lessons.md                 ← accumulated corrections and patterns
├── src/
│   ├── ingestion/
│   │   ├── schema.py              ← Pydantic models — the contract
│   │   ├── detector.py            ← auto-detects input format
│   │   └── adapters/
│   │       ├── __init__.py        ← adapter registry
│   │       ├── generic.py         ← generic JSON (reference implementation)
│   │       ├── strike7.py         ← Strike7 engagement format adapter
│   │       └── burp.py            ← Burp XML adapter (future)
│   ├── graph/
│   │   ├── builder.py             ← constructs NetworkX DAG from findings
│   │   ├── pathfinder.py          ← primary chain = longest weighted path
│   │   └── scorer.py             ← severity aggregation, chain risk score
│   ├── ai/
│   │   ├── client.py              ← Anthropic API wrapper (BYOK)
│   │   └── prompts/
│   │       └── finding_detail.py  ← prompt template for AI finding details
│   ├── renderer/
│   │   ├── html.py                ← interactive HTML widget (main output)
│   │   ├── json_export.py         ← machine-readable graph export
│   │   └── embed.py               ← for embedding in reports/PIL
│   └── api/
│       └── app.py                 ← FastAPI service
├── synthetic/
│   └── generator.py               ← GOAD-style synthetic engagement generator
├── demo/
│   ├── run_demo.py                ← one command, full demo, no API key needed
│   └── fixtures/
│       └── goad_sample.json       ← pre-generated synthetic engagement
├── tests/
│   ├── test_schema.py
│   ├── test_builder.py
│   ├── test_pathfinder.py
│   ├── test_adapters.py
│   └── fixtures/                  ← one JSON file per adapter, for regression
└── docs/
    ├── 01-SCHEMA.md
    ├── 02-ADAPTERS.md
    └── 03-API.md
```

---

## Finding Schema (locked — adapters map TO this, not from it)

```python
class Finding(BaseModel):
    id: str                        # unique within engagement, stable across retests
    title: str                     # short human title
    severity: float                # CVSS-style 0.0–10.0
    severity_label: str            # CRITICAL / HIGH / MEDIUM / LOW / INFO
    mitre_technique: Optional[str] # T-number e.g. "T1557.001"
    step_index: Optional[int]      # which agent step produced this finding
    timestamp_offset_s: Optional[int]  # seconds from engagement start
    enabled_by: List[str]          # list of finding IDs that made this possible
    evidence: Optional[str]        # raw evidence string (redacted is fine)
    host: Optional[str]            # target host/IP (can be redacted)
    # AI-generated fields (populated async after graph is built)
    ai_detail: Optional[str]       # AI-generated full finding detail
    ai_remediation: Optional[str]  # AI-generated remediation guidance
    ai_confidence: Optional[float] # AI's confidence this is a true positive
```

---

## LLM Integration Rules

- **User provides API key** via `ANTHROPIC_API_KEY` env var or `--api-key` CLI flag
- **Default model**: `claude-sonnet-4-5` (users can override with `--model`)
- **Recommended** in all docs and CLI help: `claude-sonnet-4-5` or `claude-sonnet-4-6` for best results
- **Demo mode**: if no API key provided, AI fields populate from fixture data — demo still works fully
- **One call per finding** — prompt includes: finding title, severity, evidence, MITRE technique, chain context (what it enabled_by, what it enabled). Output is JSON with `detail`, `remediation`, `confidence`.
- **Async, non-blocking**: chain renders immediately. AI details stream in as they complete.
- **Never retry silently** — if an API call fails, log it clearly and mark `ai_detail` as `null`. Don't pretend.

---

## Renderer Requirements (non-negotiable for v1)

The interactive HTML output MUST include ALL of the following. If any are missing, it's not v1:

1. **Left panel**: all findings ranked by severity, clickable, colour-coded by severity level
2. **Right panel**: primary attack chain, bottom-to-top (entry point at bottom, crown jewel at top)
3. **Animated flow arrows**: direction indicators showing chain progression
4. **Node click**: selecting any node highlights it in both panels simultaneously
5. **Finding detail drawer**: slides in on node click, shows AI-generated detail, MITRE link, evidence
6. **Secondary chains**: findings not in the primary chain shown as a sidebar or secondary column
7. **Chain risk score**: aggregate severity score for the full chain, shown prominently for CISO
8. **Timeline bar**: horizontal bar at bottom showing step_index and timestamp_offset_s progression
9. **Export button**: downloads the chain as a self-contained HTML file (no server needed)
10. **No API key exposed in output**: the HTML output contains NO credentials, ever

---

## Integration Guide (for HOS / Strike7 users)

### Step 1: Discover your format (run this first)
```bash
python -m acm discover path/to/your/engagement_output.json
```
This prints: detected format, field mapping, any gaps, suggested adapter.

### Step 2: Run with auto-adapter
```bash
python -m acm chain path/to/engagement.json --output chain.html
```
If auto-detection works, you're done. If not, Step 3.

### Step 3: Generate a custom adapter prompt (for Claude Code)
```bash
python -m acm scaffold-adapter path/to/engagement.json
```
This prints a ready-to-run Claude Code prompt that inspects your format and generates a custom adapter. The user pastes it into Claude Code — no one needs to know your internal schema.

### Step 4: With AI finding details
```bash
export ANTHROPIC_API_KEY=sk-ant-...
python -m acm chain path/to/engagement.json --output chain.html --model claude-sonnet-4-5
```

---

## Synthetic Data Generator Spec

`synthetic/generator.py` must generate a realistic GOAD-style AD engagement with:
- 1 crown jewel finding (CVSS 9.0+, DA compromise)
- 2–3 high severity findings that enabled it
- 3–4 medium/low findings that fed into the highs
- 1–2 info findings as entry points
- Realistic MITRE techniques, step_index, timestamp_offset_s values
- Pre-generated AI detail for each finding (so demo works without API key)
- Saved to `demo/fixtures/goad_sample.json`

---

## Development Commands

```bash
# Install
pip install -e ".[dev]"

# Run demo (no API key needed)
python demo/run_demo.py

# Run tests
python -m pytest tests/ -q

# Discover format of an existing file
python -m acm discover sample.json

# Generate a chain
python -m acm chain sample.json --output chain.html

# Generate a chain with AI details
ANTHROPIC_API_KEY=sk-ant-... python -m acm chain sample.json --output chain.html --model claude-sonnet-4-5

# Start API server
uvicorn src.api.app:app --port 8200

# Run the adapter scaffolder (generates a Claude Code prompt)
python -m acm scaffold-adapter unknown_format.json
```

---

## What "Done" Looks Like (Definition of Done per phase)

### Phase 1 — Core (done when):
- [ ] Schema defined and validated with Pydantic
- [ ] Generic JSON adapter working against 3 fixture files
- [ ] Graph builder constructs correct DAG from generic fixture
- [ ] Pathfinder identifies correct primary chain on synthetic data
- [ ] All tests green

### Phase 2 — Renderer (done when):
- [ ] HTML output opens in browser with zero JS errors
- [ ] All 10 renderer requirements above are present and working
- [ ] Demo runs end-to-end on synthetic GOAD data with no API key
- [ ] Exported HTML works when opened directly from filesystem (no server)

### Phase 3 — AI Integration (done when):
- [ ] LLM finding detail generates correctly for each node
- [ ] Demo works with API key: AI details populate within 10s of chain render
- [ ] Demo works WITHOUT API key: fixture details shown, no error, no broken UI
- [ ] Model flag works: `--model claude-sonnet-4-5` and `claude-sonnet-4-6` both work

### Phase 4 — Adapters + Integration (done when):
- [ ] Strike7 adapter works against sample benchmark run output
- [ ] `acm discover` correctly identifies Strike7 format
- [ ] `acm scaffold-adapter` generates a working Claude Code prompt for an unknown format
- [ ] FastAPI endpoint returns correct JSON + HTML
- [ ] README integration guide tested end-to-end by someone who doesn't know the codebase

### Phase 5 — Open Source Release (done when):
- [ ] README covers: install, demo, API key setup, Strike7 integration, PIL F7 integration
- [ ] synthetic data demo works on a fresh clone with zero config
- [ ] All personal references, Strike7 internals, client data removed from fixtures
- [ ] GitHub Actions CI runs tests on push
