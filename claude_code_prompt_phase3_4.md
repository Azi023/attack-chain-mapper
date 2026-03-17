You are continuing development of `attack-chain-mapper`. Phase 1 (core) and Phase 2 (renderer) are already complete. Now build Phase 3 (AI integration) and Phase 4 (adapters + Strike7 bridge).

## Your role
Senior Python engineer. Continue from where Phase 1+2 left off. Verify the existing code works before extending it. Fix anything broken before adding new features.

## Stop conditions
Only stop when ALL of the following are true:
- `python -m pytest tests/ -q` → 0 failures including new tests
- Demo works WITHOUT API key (shows fixture ai_detail, no errors)
- Demo works WITH API key: `ANTHROPIC_API_KEY=sk-ant-... python -m acm chain demo/fixtures/goad_sample.json --output /tmp/chain_ai.html --model claude-sonnet-4-5` — AI details appear in the detail drawer
- `python -m acm scaffold-adapter demo/fixtures/goad_sample.json` prints a usable Claude Code prompt
- `python -m acm discover demo/fixtures/goad_sample.json` correctly identifies the format

---

## Phase 3: AI Integration

### src/ai/client.py — implement fully
```python
import asyncio
import os
from anthropic import AsyncAnthropic
from src.ingestion.schema import Finding

class AIClient:
    def __init__(self, api_key: str = None, model: str = "claude-sonnet-4-5"):
        self.api_key = api_key or os.environ.get("ANTHROPIC_API_KEY")
        self.model = model
        self.client = AsyncAnthropic(api_key=self.api_key) if self.api_key else None

    @property
    def available(self) -> bool:
        return self.client is not None

    async def generate_finding_detail(self, finding: Finding, chain_context: str) -> dict:
        """
        Returns: {"detail": str, "remediation": str, "confidence": float}
        If client unavailable, returns fixture values from finding or empty strings.
        Never raises — always returns a dict.
        """
        ...
```

### src/ai/prompts/finding_detail.py — the prompt template

The prompt must instruct the model to return ONLY valid JSON with keys: `detail`, `remediation`, `confidence`.

Context to include in the prompt:
- Finding title, severity, CVSS, MITRE technique
- Evidence string (redacted)
- What findings enabled this one (chain context)
- What findings this one enabled (what it unlocked)

The prompt must:
- Instruct the model to write the detail from the perspective of a senior pentester explaining this to a CISO
- Keep detail to 3-4 sentences: what the vulnerability is, why it matters, what the attacker can do with it
- Keep remediation to 2-3 actionable sentences
- Set confidence to 0.0-1.0 based on evidence quality and CVSS

### HTML renderer update (src/renderer/html.py)
Modify the existing renderer to:
- On page load: if any finding has ai_detail populated in the JSON, show it in the detail drawer immediately
- If a finding does NOT have ai_detail, show a "Loading AI analysis..." placeholder in the drawer
- Add a data attribute `data-has-ai="true|false"` to each node for CSS styling

---

## Phase 4: Adapters + Strike7 Bridge

### src/ingestion/detector.py — implement auto-detection

Detection logic (check in order):
1. Has key "findings" with list → likely generic or Strike7
2. Has key "issues" with list → likely Burp-style
3. Has key "vulnerabilities" → another common pattern
4. Has nested "results" → scan output style

For each detected pattern, print:
```
Detected format: generic_json
Field mapping:
  id           → findings[*].id          ✓ found
  title        → findings[*].title       ✓ found  
  severity     → findings[*].severity    ✓ found
  enabled_by   → findings[*].enabled_by  ✗ missing — chain inference will be used
  step_index   → findings[*].step_index  ✗ missing — will be estimated from order
```

### Chain inference for missing fields

When `enabled_by` is not present in the source data (which is the case for most real-world formats including Strike7), implement chain inference:
- Sort findings by step_index (or array order if missing)
- Use severity as a proxy: lower severity findings are assumed to enable higher severity ones
- Build a heuristic `enabled_by` based on: findings that occurred earlier AND have lower severity AND share the same host
- Flag inferred chains clearly in the output: `"inferred": true` on the edge

This is CRITICAL — most users won't have enabled_by in their data. Chain inference is what makes the tool useful in the real world.

### src/ingestion/adapters/strike7.py — Strike7 adapter

Strike7's benchmark engagement output format (based on what is known — write the adapter to be resilient to format variations):

The adapter should handle:
- Findings from benchmark run JSON (model_benchmarks.db export style)
- Fields likely present: run_id, benchmark_id, flags_captured, steps (list), findings or vulnerabilities
- Map steps to step_index
- Extract findings from either top-level "findings" key or nested inside step records
- If severity is a string label (HIGH, MEDIUM) rather than float, convert using: CRITICAL=9.5, HIGH=7.5, MEDIUM=5.0, LOW=2.5, INFO=0.5

The adapter MUST be resilient — never crash on missing fields, always return what it can.

### python -m acm scaffold-adapter — implement fully

This command:
1. Reads the provided JSON file (any format)
2. Prints a complete, ready-to-paste Claude Code prompt that says:

```
You are writing a Python adapter for attack-chain-mapper.

The input file has this structure:
[pretty-printed first 50 lines of the file, truncated]

Key paths found:
- Top-level keys: [list]
- First list element: [structure]

Write src/ingestion/adapters/custom.py that:
1. Detects this format (returns True/False from can_handle(data: dict))
2. Maps it to List[Finding] using the schema below
3. Handles missing fields gracefully (use None, not raise)
4. Registers itself in adapters/__init__.py

[full Finding schema]

The adapter should be 50-80 lines. No external dependencies beyond what's in pyproject.toml.
```

This is how users who don't know Python generate adapters for their own tool's output.

---

## Tests to add (Phase 3+4)

### tests/test_ai_client.py
- Test that AIClient.available returns False when no API key
- Test that generate_finding_detail returns dict with correct keys when no API key
- Test that fixture ai_detail is returned when client unavailable

### tests/test_detector.py
- Test detection of generic format returns "generic_json"
- Test detection of Burp-style returns "burp_xml_like"
- Test field mapping output is correct for goad_sample.json

### tests/test_chain_inference.py
- Test that inferred chains are marked with "inferred": true
- Test that severity ordering produces a plausible chain
- Test that inference does not produce circular dependencies

---

## Integration note for HOS / future PIL F7

When PIL integrates this as F7, the call will be:

```python
from attack_chain_mapper import build_chain
from attack_chain_mapper.ingestion.adapters.strike7 import Strike7Adapter

chain = build_chain(
    engagement_data=engagement_dict,
    adapter=Strike7Adapter(),
    ai_client=None,  # PIL handles whether to call AI or not
)
# chain.primary_path → list of Finding
# chain.render_html() → str (complete HTML)
# chain.to_json() → dict (machine-readable for PIL storage)
```

PIL's F7 stores the chain JSON in SQLite and returns the HTML to Strike7's reporting pipeline. This is a one-function integration.

---

## Execution rules
- First: run `python -m pytest tests/ -q` and fix any existing failures before adding new code
- After detector.py: test it: `python -m acm discover demo/fixtures/goad_sample.json`
- After chain inference: run the full demo again and verify the inferred chain is plausible
- After scaffold-adapter: test it against the goad fixture and verify the printed prompt is copy-pasteable
- Never mark a test as xfail — either implement it or delete it

Done when all stop conditions above are met. Not before.
