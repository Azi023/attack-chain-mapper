# attack-chain-mapper Phase 1+2 Build

## Phase 1: Core ✅

- [x] pyproject.toml
- [x] src/ directory structure + __init__ files
- [x] src/ingestion/schema.py (Pydantic v2 Finding + Engagement)
- [x] src/ingestion/adapters/generic.py
- [x] src/ingestion/adapters/__init__.py (registry)
- [x] src/ingestion/detector.py
- [x] src/graph/builder.py (NetworkX DAG)
- [x] src/graph/pathfinder.py (longest weighted path)
- [x] src/graph/scorer.py (chain risk score)
- [x] src/ai/client.py (BYOK Anthropic wrapper)
- [x] src/ai/prompts/finding_detail.py
- [x] pip install -e ".[dev]" — venv at .venv/
- [x] tests/fixtures/generic_sample.json
- [x] tests/test_schema.py
- [x] tests/test_builder.py
- [x] tests/test_pathfinder.py
- [x] tests/test_adapters.py
- [x] pytest — 78 passed, 0 failed

## Phase 2: Renderer + Demo ✅

- [x] demo/fixtures/goad_sample.json (synthetic GOAD data with ai_detail pre-written)
- [x] src/renderer/html.py (all 10 features)
- [x] src/renderer/json_export.py
- [x] src/__main__.py (CLI: discover, chain, scaffold-adapter, serve)
- [x] acm/__main__.py (enables python -m acm)
- [x] src/api/app.py (FastAPI)
- [x] synthetic/generator.py
- [x] demo/run_demo.py
- [x] HTML > 30KB — 50.5 KB
- [x] python -m acm discover goad_sample.json — correct output
- [x] python -m acm chain goad_sample.json --output /tmp/chain.html — exits 0
- [x] python demo/run_demo.py — produces /tmp/acm_demo.html

## Completed

Phase 1 + Phase 2 complete as of 2026-03-17.
All 5 stop conditions green.
78 tests, 0 failures.
HTML output: 50.5 KB with all 10 renderer features.
