# PLAN — Function Audit: `evograph`

> Part of [PLAN.md](PLAN.md) Section 2. Generated 2026-06-06. Module: **core/evograph.py**

**Exists:** True  

## Summary

EvoGraph is a synchronous SQLite-backed cross-session attack-memory store (Q-tables, attack/tech success maps, ReACT traces, attack chains, failure lessons). 24 methods + 1 static helper. Pure local persistence — performs NO network/target actions, so no scope/RoE concern, but it has no input sanitization for the operator-controlled strings it stores. Main defects: several bare `except Exception` that silently swallow DB errors and return empty results (masking corruption), substring `LIKE %x%` matching that over-matches targets/tech, runtime DDL inside read methods, no per-call commit batching, and ~17 of 24 public methods are not covered by tests/test_evograph.py.

## Top issues

- Runtime DDL inside read/ingest methods (lines 586, 622)
- Broad except Exception swallowing DB errors in 4 methods (613, 653, 669, 720)
- Substring LIKE %x% over-matching across 5 query methods
- is_duplicate_finding ignores url param and matches wrong column (306-312)
- Unbounded table scans / no LIMIT (295, 543, 699) and unbounded q_snapshot growth (456)
- ~17/24 public methods untested

## Scope / safety notes

No scope/RoE concern from a network standpoint: this module performs ZERO network or target-directed actions — it is a pure local SQLite persistence layer. It never makes HTTP requests, never resolves/contacts hosts, and imports no networking libs. Therefore a scope/RoE check is not applicable to its operations. Caveat: it stores operator-supplied strings (target URLs, tech, reasoning, evidence) verbatim and logs the target_url at INFO (line 282) and on session end (line 292) — so target identifiers land in logs and the DB unredacted, which is an audit/data-handling note rather than a scope-enforcement gap. All SQL uses bound parameters (the few f-string-built fragments interpolate only class-constant table names or placeholder counts, not user values), so no SQL-injection scope-escape vector.

## Function-by-function table

| File:Line | Function | Purpose | Inputs | Outputs | Side effects | Status | Issues |
|---|---|---|---|---|---|---|---|
| core/evograph.py:28 | EvoGraph.__init__ | Open/create DB, set PRAGMAs, init+validate schema | db_path: Path | None | Creates parent dir, opens sqlite conn (WAL), writes schema_meta | OK | Hard-coded default DB path via module constant DEFAULT_DB_PATH (line 22); conn never closed if __init__ raises after connect; long-lived conn = mutable shared state if instance reused across threads (sqlite conn not thread-safe by default) |
| core/evograph.py:41 | EvoGraph._init_tables | Create all tables/indexes via executescript | self | None | DDL + commit | OK | schema_meta also created here AND in _init_schema_meta (duplicate DDL, harmless) |
| core/evograph.py:187 | EvoGraph._init_schema_meta | Ensure schema_meta + seed version row | self | None | DDL, INSERT, commit | OK | Redundant with _init_tables/_check_schema seeding |
| core/evograph.py:204 | EvoGraph._validate_schema | Raise if expected table missing; warn on missing cols | self | None (raises RuntimeError) | None | OK | f-string interpolates `table` into PRAGMA (line 217) — values are hard-coded class constants, not user input, so no injection in practice |
| core/evograph.py:226 | EvoGraph._check_schema | Read version, log migration intent | self | None | INSERT/commit if no version row | OK | Migration path is a no-op log only (line 238) — future-version DB only warns, does not refuse |
| core/evograph.py:247 | EvoGraph.validate_schema | Public schema check, returns bool | self | bool | None | UNTESTED | f-string PRAGMA(table) (line 253) — table from class constant, safe; not covered by tests |
| core/evograph.py:266 | EvoGraph.get_schema_version | Return stored schema version | self | int | None | OK | |
| core/evograph.py:273 | EvoGraph.start_session | Insert new session row | target_url:str, tech_stack:List[str] | int session_id | INSERT+commit | OK | logger.info logs target_url (line 282) — could log a real target/host; acceptable for audit but is target data in logs |
| core/evograph.py:285 | EvoGraph.end_session | Update session final stats | session_id, findings_count, total_reward | None | UPDATE+commit | OK | No check that session_id exists; silent no-op if id absent |
| core/evograph.py:295 | EvoGraph.get_sessions | List all sessions | self | List[Dict] | None | OK | Unbounded SELECT * (no LIMIT) — full table load can grow without bound |
| core/evograph.py:306 | EvoGraph.is_duplicate_finding | Check if finding seen before | target, vuln_type, url | bool | None | UNTESTED | `target_tech LIKE %target%` (line 309) over-matches (substring): e.g. target 'a.com' matches 'cdn-a.com'; param `url` accepted but unused; matches against target_tech column, not actual target — likely wrong column semantics |
| core/evograph.py:316 | EvoGraph.record_attack | Insert attack + upsert tech_attack_map | session_id, attack_type, target_tech:List, success, confidence, reward, reasoning | None | 2x INSERT/UPSERT+commit | OK | avg_reward recompute `(total_reward+?)/(attempts+1)` (line 343) assumes exactly one new attempt; correct only because SET uses pre-update row values — fragile/non-obvious; reasoning stored unbounded (no truncation unlike other methods) |
| core/evograph.py:349 | EvoGraph.record_reasoning_step | Insert ReACT trace step | session_id, step_num, thought, action, observation, reward | None | INSERT+commit | OK | observation truncated [:2000] but thought/action stored unbounded |
| core/evograph.py:370 | EvoGraph.get_best_attacks_for_tech | Rank attacks by success rate for tech | tech_stack:List, top_n=10 | List[Dict] | None | OK | Dynamic f-string WHERE built from param count (line 386) — values are bound params, safe |
| core/evograph.py:404 | EvoGraph.get_attack_success_rate | Overall + per-tech success stats | attack_type, tech_signature='' | Dict | None | UNTESTED | `tech_signature LIKE %x%` substring over-match (line 425); per_tech .fetchone() picks one arbitrary matching row, not aggregate |
| core/evograph.py:435 | EvoGraph.get_failed_approaches | Attacks with <5% success on tech | target_tech:List, last_n=50 | List[str] | None | UNTESTED | Dynamic WHERE from params (bound, safe); substring LIKE over-match |
| core/evograph.py:456 | EvoGraph.save_q_table | Snapshot Q-table rows | session_id, q_table:Dict | None | executemany INSERT+commit | UNTESTED | No dedup — repeated saves append duplicate snapshots, table grows unbounded; appends rather than replacing prior snapshot for same session |
| core/evograph.py:472 | EvoGraph.load_best_q_table | Load Q-table from highest-reward session | self | Dict[Tuple,Dict] | None | UNTESTED | Nested func _deep_tuple redefined per-row (line 491, minor); bare except on JSONDecodeError/TypeError falls back to comma-split (acceptable); ties on MAX(total_reward) resolved by id only |
| core/evograph.py:509 | EvoGraph.get_evolution_stats | Aggregate session/attack stats + trend | self | Dict | None | UNTESTED | Trend compares first-5 vs last-5 by id; overlaps when <10 sessions (counts same rows on both sides) giving trend≈0 — misleading |
| core/evograph.py:540 | EvoGraph.export_knowledge | Export tech map + sessions + stats | self | Dict | None | UNTESTED | sessions limited to 100 but tech_attack_map unbounded |
| core/evograph.py:562 | EvoGraph.ingest_failure_lesson | Store FailureAnalyzer lesson | lesson: dataclass/dict | None | DDL + INSERT + commit | NEEDS-FIX | DDL (CREATE TABLE/INDEX) run at call time inside method (line 586) instead of schema init; broad `except Exception` swallows all errors with only debug log (line 613) — silent data loss; non-dataclass/non-dict silently returns (line 575) |
| core/evograph.py:616 | EvoGraph.get_top_bypasses | Top bypass suggestions for attack | attack_type, n=5 | List[Dict] | DDL (CREATE TABLE) at call time | NEEDS-FIX | Runtime DDL inside read method (line 622); bare `except Exception: return []` (line 653) masks query/schema errors |
| core/evograph.py:656 | EvoGraph.get_payload_fitness_history | Payload history by hash substring | payload_hash:str | List[Dict] | None | NEEDS-FIX | `reasoning LIKE %hash%` substring match can collide; bare `except Exception: return []` (line 669) hides errors |
| core/evograph.py:672 | EvoGraph.export_attack_evolution | Build attack graph nodes/edges | self | Dict{nodes,edges} | None | NEEDS-FIX | Loads ALL attack_history rows into memory (line 699) — unbounded; broad `except Exception` swallows partial-build errors returning whatever accumulated (line 720); edges only link consecutive attacks, not true causation |
| core/evograph.py:727 | EvoGraph.record_chain_step | Insert chain step | session_id, step_num, phase, tool_name, ... | None | INSERT+commit | UNTESTED | thought/output truncated [:2000]; error_message untruncated |
| core/evograph.py:752 | EvoGraph.record_chain_finding | Insert chain finding | session_id, finding_type, severity, ... | None | INSERT+commit | UNTESTED | evidence/description truncated [:4000]; no severity validation |
| core/evograph.py:776 | EvoGraph.record_chain_decision | Insert chain decision | session_id, decision_type, from/to_state, reason | None | INSERT+commit | UNTESTED | |
| core/evograph.py:794 | EvoGraph.record_chain_failure | Insert chain failure | session_id, failure_type, ... | None | INSERT+commit | UNTESTED | error_message/root_cause/lesson untruncated |
| core/evograph.py:814 | EvoGraph.query_prior_chains | Rank prior chains for tech | target_tech:str, limit=5 | List[Dict] | None | UNTESTED | N+1 queries (per-chain steps+findings in loop, lines 837/843); `tech_stack LIKE %x%` substring over-match |
| core/evograph.py:865 | EvoGraph._normalize_tech | Normalize tech list to sorted csv string | tech_stack:List[str] | str | None | OK | |
| core/evograph.py:870 | EvoGraph.close | Close DB connection | self | None | Closes conn | OK | Does not set self.conn=None; double-close benign |
