# attack-chain-mapper — Gap 3+4+5 + Universal Adapter

## Plan (implementation order: validator → store → enrichment → ai_detect → CLI → tests)

### Phase A: Smart Validation (Gap 5) — src/ingestion/validator.py
- [ ] Create ValidationError, ValidationWarning, ValidationResult dataclasses
- [ ] Implement EMPTY_FINDINGS check
- [ ] Implement DUPLICATE_IDS check
- [ ] Implement CIRCULAR_ENABLED_BY check
- [ ] Implement MISSING_ENABLED_BY warning
- [ ] Implement THIN_EVIDENCE warning
- [ ] Implement MISSING_STEP_INDEX warning
- [ ] Implement UNKNOWN_ENABLED_BY_REF auto-fix
- [ ] Implement NULL_SEVERITY auto-fix
- [ ] Implement MISSING_TITLE auto-fix
- [ ] Implement INVALID_SEVERITY_RANGE auto-clamp
- [ ] Implement auto-fixes: whitespace trim, uppercase severity_label, dedup enabled_by, host None→""
- [ ] summary() method for human-readable CLI output
- [ ] validate() top-level function
- [ ] Quick import test: python -c "from src.ingestion.validator import validate; print('OK')"

### Phase B: SQLite Persistence (Gap 3) — src/storage/store.py
- [ ] Create src/storage/__init__.py
- [ ] Create ChainStore class with WAL mode SQLite
- [ ] Create tables: chains, findings + indexes
- [ ] Implement save_chain() with UUID + upsert logic
- [ ] Implement get_chain()
- [ ] Implement get_chains_for_engagement()
- [ ] Implement diff_chains()
- [ ] Implement list_engagements()
- [ ] Implement delete_chain()
- [ ] Quick import test: python -c "from src.storage.store import ChainStore; print('OK')"

### Phase C: AI Enrichment Quality (Gap 4) — src/ai/prompts/finding_detail.py
- [ ] Add MITRE_DESCRIPTIONS dict (~25 common AD/web pentest techniques)
- [ ] Implement FINDING_DETAIL_PROMPT with Mode A/B/C (rich/thin/crown_jewel)
- [ ] Update build_finding_detail_prompt() to detect evidence richness + crown jewel status
- [ ] Add chain_position context building
- [ ] Add reasoning_mode to JSON output schema
- [ ] Update AIClient.generate_finding_detail() to pass full context (step_index, total_steps, etc.)
- [ ] Quick import test: python -c "from src.ai.prompts.finding_detail import FINDING_DETAIL_PROMPT; print('OK')"

### Phase D: Universal AI Adapter (Gap 1/4) — src/ingestion/detector.py
- [ ] Add FORMAT_DETECTION_PROMPT to detector.py
- [ ] Implement AdaptationReport dataclass
- [ ] Implement ai_detect_and_adapt() method on detector module
- [ ] Fallback to generic adapter on AI failure
- [ ] Quick import test

### Phase E: CLI Wiring — src/__main__.py
- [ ] Add --debug flag to CLI group
- [ ] Wrap entire chain command in top-level try/except (no tracebacks)
- [ ] Add validation step to chain command (print ✓/⚠/✗ summary)
- [ ] Auto-save chain to store after chain command
- [ ] Print "Chain saved → {id}" after save
- [ ] Add --no-ai-detect flag to chain command
- [ ] AI detect fallback for unrecognized formats
- [ ] Add `acm list` command
- [ ] Add `acm diff <chain_id_a> <chain_id_b>` command
- [ ] Add `acm history <engagement_id>` command
- [ ] Add --db-path option

### Phase F: Update build_chain() — src/__init__.py
- [ ] Add store: bool = True parameter
- [ ] Add db_path: str = None parameter
- [ ] Wire store into build_chain()

### Phase G: Tests
- [ ] tests/test_validator.py — all ValidationResult cases
- [ ] tests/test_store.py — save/get/diff/list/upsert
- [ ] tests/test_ai_detect.py — mock Claude response, fallback, no-ai-detect flag

### Phase H: Verification
- [ ] pytest tests/ -q → 0 failures
- [ ] acm chain demo/fixtures/goad_sample.json --output /tmp/t.html → exits 0, prints validation
- [ ] acm list → prints at least 1 engagement
- [ ] acm diff on two chains → prints diff
- [ ] acm chain on unrecognized JSON → AI detect message or no-key message
- [ ] Bad input (empty findings) → ✗ error, no traceback
- [ ] demo/run_demo.py → HTML > 20KB
- [ ] git commit + push

## Completed
Phase 1+2 complete (78 tests, HTML 50.5 KB). See prior entries.
