You are building `attack-chain-mapper` — a standalone, open-source Python package that takes completed pentest engagement findings, reconstructs the actual attack chain taken by an AI agent, and renders an interactive CISO-grade visualization.

## Your role
Senior Python engineer + security tool developer. You write production-quality code with real tests, not scaffolding. You never leave TODO comments without implementations. You never build a demo that is missing features.

## Your task
Build Phase 1 (core) and Phase 2 (renderer) of attack-chain-mapper from scratch.

## Stop conditions
Only stop when ALL of the following are true:
- `python -m pytest tests/ -q` shows 0 failures
- `python demo/run_demo.py` opens a working HTML file with ZERO JS console errors
- The HTML demo shows ALL 10 renderer features listed below
- `python -m acm discover demo/fixtures/goad_sample.json` prints correct field mapping
- `python -m acm chain demo/fixtures/goad_sample.json --output /tmp/chain.html` completes successfully

## Project structure to create
```
attack-chain-mapper/
├── CLAUDE.md                    (copy from context — do not modify)
├── README.md                    (write this last)
├── pyproject.toml
├── tasks/
│   ├── todo.md
│   └── lessons.md
├── src/
│   ├── __init__.py
│   ├── __main__.py              (CLI entry point: discover, chain, scaffold-adapter)
│   ├── ingestion/
│   │   ├── __init__.py
│   │   ├── schema.py            (Pydantic v2 models)
│   │   ├── detector.py          (auto-detect format from JSON structure)
│   │   └── adapters/
│   │       ├── __init__.py      (adapter registry)
│   │       └── generic.py       (generic JSON adapter — reference implementation)
│   ├── graph/
│   │   ├── __init__.py
│   │   ├── builder.py           (NetworkX DAG from findings list)
│   │   ├── pathfinder.py        (longest weighted path = primary chain)
│   │   └── scorer.py           (chain risk score aggregation)
│   ├── ai/
│   │   ├── __init__.py
│   │   ├── client.py            (Anthropic API wrapper, BYOK, async)
│   │   └── prompts/
│   │       └── finding_detail.py
│   ├── renderer/
│   │   ├── __init__.py
│   │   ├── html.py              (full interactive HTML renderer)
│   │   └── json_export.py
│   └── api/
│       ├── __init__.py
│       └── app.py               (FastAPI)
├── synthetic/
│   └── generator.py             (GOAD-style synthetic engagement generator)
├── demo/
│   ├── run_demo.py
│   └── fixtures/
│       └── goad_sample.json     (pre-generated, AI details included)
└── tests/
    ├── test_schema.py
    ├── test_builder.py
    ├── test_pathfinder.py
    ├── test_adapters.py
    └── fixtures/
        └── generic_sample.json
```

## Finding schema (locked — implement exactly as below)

```python
from pydantic import BaseModel
from typing import Optional, List

class Finding(BaseModel):
    id: str
    title: str
    severity: float                    # 0.0–10.0
    severity_label: str                # CRITICAL / HIGH / MEDIUM / LOW / INFO
    mitre_technique: Optional[str] = None
    step_index: Optional[int] = None
    timestamp_offset_s: Optional[int] = None
    enabled_by: List[str] = []         # IDs of findings that made this possible
    evidence: Optional[str] = None
    host: Optional[str] = None
    ai_detail: Optional[str] = None
    ai_remediation: Optional[str] = None
    ai_confidence: Optional[float] = None

class Engagement(BaseModel):
    engagement_id: str
    target_name: Optional[str] = None
    findings: List[Finding]
    metadata: dict = {}
```

## Synthetic GOAD data to generate (for demo/fixtures/goad_sample.json)

Generate a realistic AD engagement with this exact chain:
1. INFO (step 1, 0s): "Host and port discovery" — T1046, entry point, enabled_by=[]
2. LOW (step 3, 720s): "Anonymous LDAP bind" — T1087.002, enabled_by=["f-recon"]
3. MEDIUM (step 6, 3300s): "Credentials in SYSVOL GPP" — T1552.006, enabled_by=["f-ldap"]
4. MEDIUM (step 9, 6480s): "SMB signing disabled on DC01" — T1557, enabled_by=["f-ldap"]
5. CRITICAL (step 14, 9240s): "Domain admin via NTLM relay" — T1557.001, enabled_by=["f-smb", "f-sysvol"]
6. HIGH (step 11, 7800s): "Kerberoastable svc_backup account" — T1558.003, enabled_by=["f-ldap"] — this is NOT in the primary chain, it's a secondary branch

Include realistic, pre-written ai_detail and ai_remediation for each finding so the demo works without an API key. Make these genuinely useful security descriptions, not placeholder text.

## HTML renderer requirements (ALL 10 must be present — non-negotiable)

1. Left panel: all findings ranked by severity, colour-coded (critical=red, high=orange, medium=amber, low=gray, info=light gray), clickable
2. Right panel: primary attack chain, bottom-to-top layout (entry point at bottom, crown jewel at top)
3. Animated SVG flow arrows between chain nodes — use CSS stroke-dashoffset animation to show flow direction upward along the chain
4. Node click: selecting any node highlights it in BOTH left panel AND right panel simultaneously
5. Finding detail drawer: slides in from the right on node click. Shows: title, severity badge, MITRE technique as a clickable link to attack.mitre.org, evidence, AI detail, AI remediation
6. Secondary findings section: findings NOT in the primary chain listed below or beside the main chain, labelled "Additional findings not in primary chain"
7. Chain risk score: prominent score at top of right panel (sum of severity × step weight), with label "Chain risk score" and a colour indicator
8. Timeline bar: horizontal bar at the bottom of the right panel, nodes plotted by timestamp_offset_s with step_index labels
9. Export button: top-right, downloads the HTML as a self-contained file (inline all CSS/JS, no external dependencies)
10. Responsive layout: works at 1200px and 1600px viewport widths without horizontal scroll

## Styling requirements
- Dark theme: background #0f1117, surface #1a1f2e, border #2a3040
- Severity colours: CRITICAL #e74c3c, HIGH #e67e22, MEDIUM #f39c12, LOW #7f8c8d, INFO #95a5a6
- Chain spine: animated gradient line connecting nodes, flowing upward
- Font: system-ui or monospace for labels, clean and legible at small sizes
- Arrows: SVG with animated stroke-dashoffset, direction clearly upward
- Node selected state: glowing border, same colour as severity

## CLI commands to implement

```bash
# Detect format and print field mapping
python -m acm discover path/to/file.json

# Generate chain, output HTML
python -m acm chain path/to/file.json --output chain.html

# Generate chain with AI details
python -m acm chain path/to/file.json --output chain.html --model claude-sonnet-4-5

# Print a Claude Code prompt for scaffolding a custom adapter
python -m acm scaffold-adapter path/to/unknown_format.json

# Start API server
python -m acm serve --port 8200
```

## Tests to write (all must pass)

- test_schema.py: valid Finding, invalid severity range, missing required fields, enabled_by references
- test_builder.py: correct DAG construction, cycle detection raises error, orphan node handling
- test_pathfinder.py: correct primary chain identified, secondary findings correctly separated
- test_adapters.py: generic adapter maps fixture to Engagement correctly, missing fields use None

## Execution rules
- Run `pip install -e ".[dev]"` after creating pyproject.toml before attempting any imports
- After creating each file, verify it parses: `python -c "import src.ingestion.schema"`
- After writing the HTML renderer, validate by opening it: write output to /tmp/chain_test.html and confirm size > 10KB
- After all files: run pytest, fix all failures before marking done
- Commit nothing — this is a local build session

## Dependencies (pyproject.toml)
```toml
[project]
name = "attack-chain-mapper"
version = "0.1.0"
dependencies = [
    "pydantic>=2.0",
    "networkx>=3.0",
    "fastapi>=0.100",
    "uvicorn>=0.20",
    "anthropic>=0.20",
    "click>=8.0",
    "jinja2>=3.0",
    "python-multipart>=0.0.6",
]

[project.optional-dependencies]
dev = ["pytest>=7.0", "httpx>=0.24", "pytest-asyncio>=0.21"]

[project.scripts]
acm = "src.__main__:cli"
```

## What "done" means
You are done when:
1. `python -m pytest tests/ -q` → 0 failures, all tests collected
2. `python demo/run_demo.py` → opens /tmp/acm_demo.html (or prints path)
3. The HTML file is > 30KB (real content, not scaffold)
4. All 10 renderer features are visually present in the HTML
5. `python -m acm discover demo/fixtures/goad_sample.json` prints a clean field mapping table
6. `python -m acm chain demo/fixtures/goad_sample.json --output /tmp/chain.html` exits 0

Do not stop early. Do not leave placeholder functions. Do not write "# TODO: implement this". If you hit an unexpected error, fix it and continue. This is a complete, working implementation session.
