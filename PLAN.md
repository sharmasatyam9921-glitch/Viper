# VIPER — Multi-Phase Execution Plan

_Generated 2026-06-06 from an evidence-based full-repo audit (23 agents, 105 endpoints, 11 module function-audits). **Planning only — no implementation has begun.** Approve sections individually before any code changes._

**How to read:** Sections 1–3 are the audit (what exists, with `File:Line`). Sections 4–8 are the build design. Section 9 is risk. Section 10 is the decisions I need from you. Function tables are paginated into `PLAN-audit-*.md`.

> ## ⚠️ Ground-truth reconciliation (claimed vs. actual)
>
> The brief described an architecture; reading the code shows where it differs. These are **facts to plan around**, not nitpicks:
>
> | Claimed | Actual (evidence) |
> | --- | --- |
> | ~61 core modules | **100** `.py` files in `core/` (Section 1) |
> | 5 SwarmCoordinators (incl. Report) | **4** real coordinators — `Recon/Vuln/Exploit/Post` in `core/swarm_coordinator.py`; the **Report phase is a `_NoOpCoordinator`** in `core/hack_mode.py` (PLAN-audit-hack_mode.md) |
> | 28 workers | Workers are **`WorkerSpec`-driven**, registered in `core/swarm_workers/` — see PLAN-audit-swarm_engine_workers.md for the real registry count (not 28 hand-written classes) |
> | `viper_memory.json` handlers in core | The only writer/reader is **`archive/old_agents/agentic_viper.py`** (a `Memory` class) + a one-time `migrate_from_json` in `core/viper_db.py`. The live hack pipeline does **not** maintain it — Section 5 must build this. |
> | "7-Question Gate" | **No such gate exists** in code today. Section 4 designs it. |
>
> Every section below is grounded in the actual code at File:Line.


---

## SECTION 1 — Repository Inventory

# SECTION 1 — Repository Inventory: VIPER

Root: `C:\Users\sharm\clawd\skills\hackagent`. All evidence cited as `File:Line`. Excludes `archive/`, `_quarantine/`, `node_modules/`, `natas/` per request.

---

## 1. Top-Level Tree + Key Root Modules

### Top-level directories (`core/` = 100 `.py` modules; full list below)

```
hackagent/
├── agents/          # Specialized autonomous agents (recon/vuln/exploit/chain/codefix/post)
├── ai/              # model_router (Claude CLI→LiteLLM→Ollama) + llm_analyzer
├── benchmark/       # (untracked) benchmark harness
├── core/            # 100 .py modules — brain/engine/graph/agents/swarm/tools
├── credentials/     # Platform API creds (gitignored, NOT staged)
├── dashboard/       # server.py (HTTP API :8080) + index.html (legacy SPA) + webapp/ (Next.js :3000)
├── data/            # SQLite DBs + static JSON (viper.db, evograph.db, *.csv, wappalyzer)
├── docker/          # Docker compose (GVM, scalable api+worker+redis+webapp stack)
├── docs/            # AUDIT_PLAN.md, FIXIT_PROMPT.md (untracked)
├── findings/        # Discovered-vuln markdown alerts (ALERT_*.md)
├── fitness/         # (present; not central to hunt pipeline) — UNKNOWN purpose
├── knowledge/       # Attack knowledge base
├── labs/            # Interactive practice labs
├── logs/            # Audit / recon logs
├── memory/          # Cross-session learned patterns (viper_memory.json, failures, swarm/)
├── models/          # ML experience data + Q-tables (viper_experience.json, natas_progress.json)
├── pentest/         # (present) — UNKNOWN purpose
├── programs/        # Target program definitions (targets.json gitignored)
├── recon/           # 21-module 7-phase recon pipeline
├── recon_output/    # MCP/recon scratch output
├── reports/         # Generated HTML/MD reports + PoCs (~25,957 entries)
├── scanners/        # nuclei / gvm / trufflehog wrappers
├── scope/           # scope_manager + roe_parser
├── scopes/          # Platform scope JSON (gitignored)
├── scripts/         # Helper scripts
├── state/           # Runtime state JSON + state/hunts/<id>/ audit logs + graphs/ sessions/
├── tests/           # pytest suite
├── tools/           # 14 tool modules (http_client, brute_forcer, tool_manager, audit/)
└── wordlists/       # Fuzzing wordlists
```

NOTE: directories also present but excluded/ignored or stale: underscore-prefixed vendored/scratch source trees, `clawd/`, `juice-shop/`, `juice-shop-src/`, `webapp/` (top-level, distinct from `dashboard/webapp/`), `__pycache__/`.

### Key root modules (one-line purpose, verified by reading headers)

| Module | Purpose |
|---|---|
| `viper.py` | Main CLI entry. Subcommand dispatch: `hack` → `core.hack_cli`; else argparse → `run_hunt`/`ViperCore` (`viper.py:51-57`). |
| `viper_core.py` | `ViperCore` hunt orchestrator — `full_hunt()` / `hunt()` 8-phase legacy pipeline. |
| `viper_daemon.py` | 24/7 continuous-monitoring daemon — re-scans on interval, diff-based NEW-finding alerts (`viper_daemon.py:1-18`). |
| `mcp_server.py` | MCP tool server (FastMCP, stdio transport) exposing recon/scan/exploit/report tools to Claude Code (`mcp_server.py:17-20,427-428`). |
| `advanced.py` | Hardcore LLM-attack techniques (GCG suffix, multi-turn, context poison) (`advanced.py:1-9`). |
| `viper_submit_queue.py` | Submission queue + risk-based prioritizer for findings (`viper_submit_queue.py:1-9`). |

### `core/` module list (100 files)

```
__init__ account_pool agent_bus agent_registry agent_state ai_techniques approval_gate
attack_chain attack_graph attack_orchestrator attack_patterns audit_logger auth_scanner
auto_signup auto_submit autopilot bola_scanner bounty_hunter bounty_optimizer chain_escalator
chain_of_custody chain_writer cidr_targeting cloud_agent codefix_engine codefix_tools
compliance_mapper cross_target_correlator ctf_feedback ctf_mode ctf_training evograph
exploit_db failure_analyzer finding_stream finding_validator fp_filter fuzzer graph_engine
graph_query graphql_fuzzer guardrail_hard guardrail_llm guardrails hack_cli hack_mode
hack_profile hacker_mind hackerone_submitter html_reporter hunt_phases iana_services
injection_arsenal key_rotation knowledge_base logic_modeler mitre_mapper models module_loader
narrator oauth_fuzzer orchestrator parallel_hunter phase_engine poc_generator preflight
prompt_injection_v3 race_engine rate_limiter react_engine redis_bus report_exporter
report_narrative report_quality_gate reporter roe_engine scanner scope_reasoner secret_scanner
session_manager settings_manager skill_classifier stealth swarm_coordinator swarm_engine
swarm_worker_daemon temp_account template_generator think_engine tool_registry training_mode
triage_engine triage_queries utils validator_engine viper_db viper_knowledge wave_runner
web3_auditor websocket_fuzzer
```
Plus subpackages: `core/swarm_workers/` (registry + recon/vuln/exploit/post), `core/skill_prompts/`, `core/ai_hunter/` (untracked), `core/mind_pipeline/` (untracked).

---

## 2. `dashboard/webapp/src/app` Routes (Next.js App Router)

All 15 pages confirmed present via `page.tsx` files:

```
dashboard/webapp/src/app/
├── page.tsx              # root (/)
├── layout.tsx            # shared layout (Sidebar + TopBar)
├── globals.css
├── overview/page.tsx     # /overview
├── agents/page.tsx       # /agents
├── hack/page.tsx         # /hack       (launch hunts)
├── recon/page.tsx        # /recon
├── targets/page.tsx      # /targets
├── graph/page.tsx        # /graph      (3D attack graph)
├── findings/page.tsx     # /findings
├── insights/page.tsx     # /insights   (charts)
├── reports/page.tsx      # /reports
├── terminal/page.tsx     # /terminal
├── chat/page.tsx         # /chat
├── cypherfix/page.tsx    # /cypherfix  (remediation)
├── projects/page.tsx     # /projects
└── settings/page.tsx     # /settings
```

Supporting: `src/components/layout/{Sidebar,TopBar}.tsx`, `src/components/graph/` + `src/components/ui/` + `ThemeScript.tsx` (untracked new components), `src/lib/types.ts`.

---

## 3. Entrypoints

| Entrypoint | Type / Trigger | Detail (cited) |
|---|---|---|
| `viper.py` (CLI) | `python viper.py ...` | Dispatch at `viper.py:55-57`: if `argv[1]=="hack"` → `from core.hack_cli import run_hack_cli; sys.exit(run_hack_cli(sys.argv[2:]))`. Otherwise full argparse (`viper.py:59-110`) → `run_hunt()` → `ViperCore.full_hunt()`/`hunt()` (`viper.py:523-533`). Also handles `--dashboard-only`, `--export/import`, `--train`, `--triage`, `--targets` (ParallelHunter), `--waves` (WaveRunner). |
| `core/hack_cli.run_hack_cli` | Swarm entry | `build_parser()` (`hack_cli.py:37`), builds `Profile` via `detect_profile`, then `HackMode(...).run()` via `asyncio.run(hm.run())` (`hack_cli.py:197-205`). `--resume HUNT_ID` recovers from audit log. |
| `dashboard/server.py` | **HTTP API server** | `ThreadedHTTPServer(ThreadingMixIn + HTTPServer)`, `daemon_threads=True` (`server.py:33`). Bind: `main()` reads `VIPER_PORT` or **8080** (`server.py:4879-4889`, `.serve_forever()` at 4948). `start_dashboard(port=8080)` runs it on a daemon thread (`server.py:4871-4874`). Zero-dependency; reads `viper.db`+`evograph.db`; 20+ REST endpoints + SSE + WebSocket framing + sandboxed terminal. UI redirect port = `VIPER_UI_PORT` default **3000** (`server.py:80`). |
| `dashboard/launch.py` | **Single-command launcher** (untracked) | Starts API (:8080, `VIPER_PORT`) + Next.js UI (:3000, `VIPER_UI_PORT`) together, waits `/api/health`, opens browser, tears down on Ctrl+C (`launch.py:1-31`). `--prod` / `--no-open`. Windows uses `CREATE_NEW_PROCESS_GROUP` + `taskkill /T`. |
| `viper_daemon.py` | **Scheduler / continuous daemon** | `ViperDaemon` re-scans on interval (default 6h, `--daemon [minutes]`), diff-based alerts. Loop: scan → `_interruptible_sleep(interval_hours*3600)` (`viper_daemon.py:200-202`), 5-min backoff on error (line 209). State in `state/daemon_state.json` (line 32). |
| `mcp_server.py` | **MCP server** (stdio) | `FastMCP("VIPER", json_response=True)` (`mcp_server.py:20`); 8 `@mcp.tool()` functions; default `mcp.run()` stdio transport (`mcp_server.py:427-428`). |
| `core/swarm_worker_daemon.py` | **Distributed worker daemon** (Docker) | Entry for `MODE=worker` containers — subscribes to phase queues on `core.redis_bus.get_bus()`, runs workers, scaled via `docker compose up --scale viper-worker=N` (`swarm_worker_daemon.py:1-22`). Separate from in-process hack-mode swarm. |

Schedulers: only `viper_daemon.py` (interval loop). No cron files in-repo. The deferred `CronCreate`/`scheduled-tasks` MCP tools are harness-level, not project entrypoints.

---

## 4. Persistence Surfaces

| Surface | Path | Written by |
|---|---|---|
| **Main SQLite DB** | `data/viper.db` | `AuditLogger` mirrors every hunt event into `audit_log` table (`audit_logger.py:171,183,264`); `core/viper_db.py` (findings/targets/attacks). Default DB for hack-mode audit (`hack_cli.py:98`). |
| **Evograph / Q-learning DB** | `data/evograph.db` | `EvoGraph` (`evograph.py:22,28,31`) — tables `sessions, attack_history, tech_attack_map, q_snapshots, reasoning_traces, chain_*`. `save_q_table()` snapshots Q-table per session (`evograph.py:456-470`). Read by dashboard. |
| **Per-hunt audit log** | `state/hunts/<hunt_id>/audit.jsonl` | `AuditLogger._write_jsonl` (`audit_logger.py:128,137,248`). Primary swarm-event trail (worker.dispatched/completed, finding.published, phase.*). |
| **Per-hunt summary** | `state/hunts/<id>/summary.json` | `run_hack_cli` writes `result.to_dict()` on completion (`hack_cli.py:219-228`). |
| **Other DBs** | `data/{ctf_feedback,knowledge_base,llm_observability,projects}.db` | `ctf_feedback.py`, `knowledge_base.py`, LLM observability, projects store respectively. |
| **Graph persistence** | networkx + SQLite `~/.viper/data/graph.db` (default) and `state/graphs/<id>.json` | `graph_engine.py:261-264` (NetworkxBackend); `graph_engine.populate_from_findings()/save()` called from `viper.py:568-569`. Neo4j if available, else SQLite fallback. |
| **Cross-session memory** | `memory/viper_memory.json`, `memory/failures.json`, `memory/failure_analysis.json`, `memory/viper_kb.json`, `memory/swarm/*.json` | Learned patterns / failure analysis; `viper_db.py:307-341` migrates `viper_memory.json` into DB. (Direct JSON writers are the failure_analyzer / KB modules — exact writer not line-cited here.) |
| **ML experience / Q-tables** | `models/viper_experience.json`, `models/natas_progress.json` | Experience replay + NATAS lab progress. |
| **Findings (markdown)** | `findings/ALERT_*.md` | Alert/finding dumps; `viper_daemon.py` writes to `FINDINGS_DIR` (`viper_daemon.py:31`). |
| **Reports** | `reports/` (~25,957 files) | `html_reporter.save_report()` (`hack_mode.py:412`, `viper.py:330,541`); CISO/exporter paths. |
| **Hunt-results JSON** | `data/*_hunt_results.json`, `state/*_state.json`, `state/chat_history.json`, `state/submission_tracker.json`, `state/daemon_state.json` | Various hunt drivers / daemon / dashboard chat / submission tracker. Most gitignored per `.claude/rules/git-commit.md`. |
| **Static (read-only) data** | `data/wappalyzer_technologies.json`, `data/iana_services.csv`, `data/mitre_db/` | Shipped reference data, not runtime-written. |

---

## 5. Hack-Mode Call Graph (traced, with File:Line at each hop)

```
viper.py hack <target>
  └─ viper.py:55-57   if argv[1]=="hack": run_hack_cli(argv[2:])
       │
       ▼
core/hack_cli.py :: run_hack_cli
  ├─ hack_cli.py:139  detect_profile(target, scope, explicit, go)      → Profile
  ├─ hack_cli.py:197  HackMode(target, profile, narrator, audit, scope_reasoner)
  └─ hack_cli.py:205  asyncio.run(hm.run())
       │
       ▼
core/hack_mode.py :: HackMode.run
  ├─ hack_mode.py:322  await self.bus.start()         (AgentBus)
  ├─ hack_mode.py:332  asyncio.wait_for(self._run_loop(result), timeout=profile.time_budget_s)
  └─ _run_loop  hack_mode.py:423
       ├─ :425  phases_to_run = [p for p in profile.phases if p != "report"]
       └─ for each phase → _run_phase  hack_mode.py:526
            ├─ :543  coord = self._coord_factory(phase, common)
            │         _default_coordinator  hack_mode.py:566-589 maps:
            │           recon  → ReconSwarmCoordinator
            │           vuln   → VulnSwarmCoordinator
            │           exploit→ ExploitSwarmCoordinator (approval-gated)
            │           post   → PostSwarmCoordinator    (approval-gated)
            │           else   → _NoOpCoordinator (report = no-op)
            └─ :560  await coord.handle_message(payload)
                 │
                 ▼
core/swarm_coordinator.py :: SwarmCoordinator.handle_message
  ├─ :187  manifest = self.build_manifest(target, payload)   # per-phase subclass
  │          ReconSwarmCoordinator.build_manifest :504  → get_worker_runner("recon", tech)
  │          VulnSwarmCoordinator.build_manifest  :566  → workers × discovered assets
  │          ExploitSwarmCoordinator.build_manifest :745 → vuln_type → exploit worker (gated)
  │          PostSwarmCoordinator.build_manifest   :877 → privesc/flag workers (gated)
  └─ _run_manifest  :197
       ├─ :210  engine = self._make_engine()  → SwarmEngine(max_concurrent, timeout)  (:471)
       ├─ :218-229  for spec in manifest: engine.register_runner(); engine.spawn()
       └─ :233  stats = await asyncio.wait_for(engine.run_swarm(), timeout=overall_timeout)
            │      each finding streamed to next-phase topic via bus.publish (:414-465)
            ▼
core/swarm_engine.py :: SwarmEngine.run_swarm
  └─ bounded-concurrency asyncio.gather of short-lived SwarmAgent runners
       (workers from core/swarm_workers/<phase>/<tech>.py, self-registered
        via register_worker(phase, tech, run), e.g. recon/subdomain.py:108)
```

`core/swarm_worker_daemon.py` is NOT in this in-process path — it is the **separate Docker/Redis distributed worker** that consumes phase queues from `core.redis_bus`. In-process hack mode uses `SwarmEngine` directly.

### REAL coordinator / worker counts vs claimed 5 / 28

| | Claimed | **Actual (verified)** |
|---|---|---|
| Coordinators | 5 | **4 functional** (`ReconSwarmCoordinator`, `VulnSwarmCoordinator`, `ExploitSwarmCoordinator`, `PostSwarmCoordinator`). The 5th — `ReportSwarmCoordinator` — does **not exist**; the `report` phase routes to `_NoOpCoordinator` (`hack_mode.py:425,589`). Report generation happens in `HackMode._write_report` (`hack_mode.py:387`), not a coordinator. |
| Workers | 28 | **30 registered worker techniques** (runtime count via `list_workers`): recon **9** (crtsh, dns, endpoints, github_secrets, port_scan, shodan, subdomain, wappalyzer, wayback), vuln **10** (ai_hunter, bola, cors, graphql, idor, jwt, nuclei, secrets, sqli_probe, xss_probe), exploit **6** (auth_bypass, cmdi_exploit, idor_exploit, sqli_exploit, ssti_exploit, xss_exploit), post **5** (ad_enum, flag_hunter, gtfobins, linpeas, windows_privesc). |

NOTE: vuln count is 10 only because `ai_hunter` is an **untracked** new worker (`core/swarm_workers/vuln/ai_hunter.py`, `?? ` in git status). Without it, vuln = 9 and total = 29. The CLI default `--workers` cap is **12 concurrent per swarm** (`hack_cli.py:79`), distinct from the number of distinct techniques.

---

## 6. Git Status / `dashboard/webapp` Tracking

`git status --short`: working tree has many `M` (modified, tracked) files including `dashboard/webapp/src/app/*/page.tsx`, plus `??` untracked dirs (`benchmark/`, `core/ai_hunter/`, `core/mind_pipeline/`, `dashboard/launch.py`, `dashboard/webapp/src/components/{graph,ui}/`, `tools/audit/`, several new tests).

**`dashboard/webapp` IS tracked.** `git ls-files dashboard/webapp` returns **42 tracked files** (config, source, public assets), e.g.:
```
dashboard/webapp/.claude/launch.json
dashboard/webapp/AGENTS.md  CLAUDE.md  Dockerfile  README.md
dashboard/webapp/next.config.ts  package.json  package-lock.json  postcss.config.mjs
dashboard/webapp/src/app/{agents,chat,cypherfix,...}/page.tsx
dashboard/webapp/public/*.svg
```
The webapp's 15 `page.tsx` route files are tracked but show as `M` (locally modified, uncommitted on branch `session-untracked-batch`). Newer subcomponents (`src/components/graph/`, `src/components/ui/`, `ThemeScript.tsx`) are untracked (`??`).


---

## SECTION 2 — Function-by-Function Audit

Full per-function tables are paginated into `PLAN-audit-<module>.md` (linked below). Each row: `File:Line | Function | Purpose | Inputs | Outputs | Side effects | Status | Issues`.

| Module | Exists | # top issues | Audit file |
| --- | --- | --- | --- |
| `core/hacker_mind.py` | True | 7 | [PLAN-audit-hacker_mind.md](PLAN-audit-hacker_mind.md) |
| `core/orchestrator.py` | True | 6 | [PLAN-audit-orchestrator.md](PLAN-audit-orchestrator.md) |
| `core/attack_patterns.py` | True | 3 | [PLAN-audit-attack_patterns.md](PLAN-audit-attack_patterns.md) |
| `core/ai_techniques.py` | True | 4 | [PLAN-audit-ai_techniques.md](PLAN-audit-ai_techniques.md) |
| `bounty_hunter` | True | 6 | [PLAN-audit-bounty_hunter.md](PLAN-audit-bounty_hunter.md) |
| `core/evograph.py` | True | 6 | [PLAN-audit-evograph.md](PLAN-audit-evograph.md) |
| `core/hack_mode.py — HackMode orchestrator + _NoO` | True | 6 | [PLAN-audit-hack_mode.md](PLAN-audit-hack_mode.md) |
| `core/swarm_coordinator.py (SwarmCoordinator + Wo` | True | 5 | [PLAN-audit-swarm_coordinator.md](PLAN-audit-swarm_coordinator.md) |
| `swarm_engine_workers (core/swarm_engine.py, core` | True | 7 | [PLAN-audit-swarm_engine_workers.md](PLAN-audit-swarm_engine_workers.md) |
| `hack_cli (core/hack_cli.py + core/hack_profile.p` | True | 5 | [PLAN-audit-hack_cli.md](PLAN-audit-hack_cli.md) |
| `memory/viper_memory.json + handlers: archive/old` | True | 6 | [PLAN-audit-memory.md](PLAN-audit-memory.md) |

### Cross-module critical issues (rolled up from each audit's top issues)

**`hacker_mind`**
- generate_payload (line 546-555) IDOR branch calls int(base_id) with no try/except: a non-numeric base_id (e.g. 'admin' or any string id) raises ValueError and crashes the caller. Needs guarding.
- think() (line 119) has no dispatch branch for AttackPhase.POST_EXPLOITATION or REPORTING -> reasoning/decision remain empty strings and the function returns '' silently, which a driving loop would treat as a no-op/unknown decision.
- Hypothesis/chain generation is non-idempotent: _think_enumeration/_think_exploitation call _generate_hypotheses/_find_attack_chains on every invocation and blindly .extend() the results with fresh md5 ids, so repeated think() calls accumulate duplicate hypotheses and chains unboundedly (memory growth + skewed counts).
- Phase oscillation: _think_vuln_analysis backtracks to RECON and _think_exploitation backtracks to ENUMERATION with no attempt counter or termination condition; when driven in an external loop with no confirmable hypotheses this can cycle indefinitely.
- _gen_id (line 559) uses md5(str(datetime.now()))[:8] which can produce colliding ids under rapid successive calls (same timestamp resolution), giving non-unique hypothesis ids.
- Type-hint mismatch: _identify_interesting_endpoints is annotated -> List[str] but returns List[Tuple[str,str]] (line 256 appends a tuple).
- No scope/RoE enforcement: process_response/observe ingest arbitrary urls and the stored self.scope is never consulted; the class itself is purely passive (no network actions) so this is informational, but any caller relying on it for scope safety would be wrong.

**`orchestrator`**
- invoke() (302) lacks try/finally -> agent subsystem + open chain leak if _machine.run raises.
- No per-tool timeout in _execute_tool/_execute_plan -> hung tool stalls the loop indefinitely.
- _execute_plan unbounded asyncio.gather + default executor, no concurrency cap/rate limit -> resource exhaustion / target flood.
- Scope/RoE checked only at init; execute_tool/execute_plan run LLM-chosen tool_args with no per-call scope re-check -> out-of-scope action risk.
- _DefaultApprovalGate auto-approves all phase transitions (incl. exploitation) when no real gate is injected.
- Multiple sync I/O-capable calls (guardrail.validate, graph.add_node, chain_writer.*) run inside async defs without executor offload -> event-loop blocking.

**`attack_patterns`**
- Module is effectively dead code: PATTERNS imported only by archived agent.py; all 4 accessor functions have no live callers; no tests.
- Line 249 data list contains a destructive payload string "test'); DROP TABLE users;--" — never executed here but violates non-destructive-payload rule if a consumer sends it.
- Line 160 typo 'UUID version Agentlysis' (should be 'Analysis') corrupts playbook text.

**`ai_techniques`**
- scan_endpoint (line 1135) does live network I/O with no scope check
- destructive DROP TABLE payload in _run_order_agent
- silent excepts at lines 782 and 1163
- blocking threadpool .result() unsafe in async; unguarded concurrent file writes

**`bounty_hunter`**
- Module-wide deception: docstring claims HackerOne/Bugcrowd/Intigriti API integration and imports urllib.request+ssl (L18-19) that are NEVER used — no network/API code exists; check_duplicate and submission tracking are local-only.
- Hardcoded CWD-relative default paths skills/hackagent/programs (L163) and skills/hackagent/submissions.json (L222) break when CWD != repo root.
- No error handling or atomic writes on file I/O (_load L226, _save L243, _save_program L178): malformed/concurrent JSON corrupts state, raises raw exceptions, non-atomic truncate-then-write loses data on crash, no lock -> race.
- Report formatters (L314, L341) index required finding keys directly (KeyError risk) and interpolate raw evidence/payload with NO redaction, violating the project no-PII/secrets-in-reports rule.
- Loose substring scope matching (is_in_scope L63, check_duplicate L486) is over-broad -> false in-scope / false-duplicate results.
- Contract bugs: list_targets (L560) annotated List[str] but returns str; select_target (L412) 'new'/'responsive' strategies unimplemented; _save_program drops severity_payouts/rating (lossy persistence).

**`evograph`**
- Runtime DDL inside read/ingest methods (lines 586, 622)
- Broad except Exception swallowing DB errors in 4 methods (613, 653, 669, 720)
- Substring LIKE %x% over-matching across 5 query methods
- is_duplicate_finding ignores url param and matches wrong column (306-312)
- Unbounded table scans / no LIMIT (295, 543, 699) and unbounded q_snapshot growth (456)
- ~17/24 public methods untested

**`hack_mode`**
- No scope/RoE enforcement inside HackMode: scope_reasoner defaults to None and is passed unverified into _run_phase payload (line 549). for_target() builds a BugBountyProfile (use_scope_reasoner=True) but never requires/asserts a scope_reasoner, so active recon/vuln/exploit workers can be dispatched with scope_reasoner=None — enforcement is wholly delegated downstream to workers.
- Silent except in _check_named_stop (line 522-523, `except Exception: continue`): a raising stop_condition is silently ignored, which can mask a legitimate stop (e.g. CTF flag_found), causing the hunt to keep attacking past the intended stop.
- Silent `except Exception: pass` on bus.stop() in _teardown (line 354): bus shutdown errors swallowed with no log.
- Hard-coded relative default paths in resume(): Path('state/hunts') (line 211) and Path('data/viper.db') (line 222) are cwd-dependent.
- Dead conditional at line 475: `'success' if phase_res.workers_failed == 0 else 'success'` — both branches identical, failed-phase status never surfaced to narrator.
- auto_approve_destructive (lines 576-578, 584-586): destructive exploit/post workers auto-approved when allow_destructive and approval_gate is None, bypassing human gate — risky default if a destructive profile meets a real target.

**`swarm_coordinator`**
- MISSING 5TH COORDINATOR: ReportSwarmCoordinator is claimed in core/hack_mode.py:18 docstring but does NOT exist anywhere (grep finds the name only in that one docstring line). The 'report' phase is actually served by _NoOpCoordinator (core/hack_mode.py:589/597) and reporting is done by HackMode._write_report + CLI --report. So only 4 real coordinators exist, matching the file.
- NO SCOPE/RoE ENFORCEMENT in the coordinator: SwarmCoordinator.handle_message (line 174) dispatches network workers against payload['target'] with no in-scope/RoE check. scope_reasoner is only passed through in worker payload (lines 529/594/779/909) and only a few recon workers (crtsh.py, subdomain.py) actually honor it; vuln/exploit/post enforcement is unverified. The coordinator layer itself is scope-blind.
- BOGUS STATS ON TIMEOUT: _run_manifest (lines 237-247) builds a fresh SwarmStats(spawned=N) on asyncio.TimeoutError, so workers_completed and workers_failed are reported as 0 regardless of actual progress; engine.get_findings() is still read from a cancelled engine (possible partial/lost findings, orphaned inner tasks).
- SILENT EXCEPTS: PostSwarmCoordinator._approve (lines 938-939) swallows gate exceptions with no logging (Exploit._approve logs the same case at line 834); _available_techniques (line 483) bare-excepts to [] masking import errors.
- UNBOUNDED MANIFEST: VulnSwarmCoordinator.build_manifest expands workers x assets with no cap on manifest size (only runtime concurrency is bounded), so a large discovered-asset list produces a very large WorkerSpec list (docstring itself cites 225).

**`swarm_engine_workers`**
- WORKER COUNT WRONG: project claims 28 workers; actual registered = 30 (recon 9 / vuln 10 / exploit 6 / post 5), one TECHNIQUE per module. Off by +2. Count is also fragile: _safe_import (swarm_workers/__init__.py:66) silently swallows import errors, so a broken worker file vanishes from the registry with only a warning log.
- DISPATCH BUG (swarm_worker_daemon.py:67-70): code does `runner = get_worker_runner(env.topic, technique); if runner is None: ...` but get_worker_runner (swarm_workers/__init__.py:41) RAISES KeyError instead of returning None. An unknown/unregistered technique throws an uncaught KeyError BEFORE the try block at line 76, so the job task dies silently via the done-callback path — the None-check is dead and the 'no runner' warning never fires.
- NO SCOPE / RoE / GUARDRAIL CHECK in the entire dispatch path. handle_job (daemon:56) and all 4 engine runners (swarm_engine.py:222/255/281/306) take `target` straight off the bus / agent and fire network requests (incl. SQLi SLEEP payloads) with no in-scope validation, no roe_engine, no guardrails. Violates the project's own scope.md ('cross-reference scopes before any active recon').
- SILENT EXCEPTS everywhere: engine runners use `except Exception: pass`/`continue` (swarm_engine.py:250,276,301,325) hiding network/parse errors; _run_one (131) reduces exceptions to str(e) with no logging; redis_bus list_workers (191) and close (198) swallow; _safe_import swallows import failures.
- UNBOUNDED GROWTH / BACKPRESSURE GAP: consume_phase (daemon:138) creates a task per BLPOP'd job and only bounds *execution* via semaphore, not task creation; the `active` set and pending coroutines can grow without limit if jobs arrive faster than they complete. redis consume/BLPOP and asyncio consume use `while True` with no max-attempt cap.
- MUTABLE GLOBAL STATE w/o locks: get_bus singleton `_BUS` (redis_bus.py:203) can double-init under concurrent first-callers; swarm_workers `_REGISTRY` global mutated by register_worker; engine `_finding_hashes` set is mutated concurrently by gathered _run_one tasks (swarm_engine.py:151-152) — data race on dedup.
- REDIS OPS HAVE NO TIMEOUT/RETRY/IDEMPOTENCY: _RedisBus.publish (139) and heartbeat (173) have no try/except or op timeout; findings re-published on worker retry have no idempotency key (message_id is regenerated per publish), so downstream phases can receive duplicate jobs. get_bus also opens a second throwaway client just to PING (redis_bus.py:217-220).

**`hack_cli`**
- detect_profile (hack_profile.py:286,302-305) forces allow_destructive=True AND use_scope_reasoner=False for CTF-pattern hostnames and private IPs regardless of the --go flag — a target matching the CTF regex (e.g. attacker-controlled 'ctf.victim.com') silently enables destructive exploit/post workers with no scope rails by default.
- Fail-open scope handling: when the scope file fails to load or the reasoner build raises, hack_cli (lines 166-167, 253-256) prints only a [WARN] and proceeds with scope_reasoner=None; the documented default-deny is only as strong as HackMode's handling of a None reasoner (unverified).
- Profile.should_stop (hack_profile.py:145) has a silent `except Exception: continue` that swallows errors from a faulty stop-condition; a perpetually-raising condition would never fire, leaving only max_iterations to backstop an otherwise unbounded persistence loop.
- Documented exit codes 2 (guardrail blocked) and 3 (approval denied) are never returned by run_hack_cli — guardrail/approval outcomes are not surfaced to the shell exit code, so callers/scripts cannot distinguish them.
- Minor: --report and --no-dashboard flags are parsed but never consumed in run_hack_cli; list_profiles (hack_profile.py:320) is dead code; default paths state/hunts and data/viper.db are relative (CWD-dependent).

**`memory`**
- WRITE PATH IS NON-ATOMIC + WRITE-PER-EVENT: Memory.save (agentic_viper.py:65-67) does write_text of the whole file on every remember_success/remember_failure/learn_pattern call. No tmp-file+rename, so a crash or two concurrent agent runs corrupt the file; combined with O(n) full rewrite per event this is a race + performance hazard.
- SILENT DATA-LOSS ON CORRUPT FILE: Memory._load (agentic_viper.py:54-55) uses `except Exception: pass` and silently returns an empty default skeleton, discarding all on-disk history without any log if the JSON is malformed.
- NO IDEMPOTENCY / DUP EXPLOSION: neither remember_failure (agentic_viper.py:81) nor migrate_from_json (viper_db.py:305) dedups. The live file already shows ~18 identical natas2 failure rows, and re-running migrate_from_json re-inserts every target/attack into SQLite.
- UNBOUNDED GROWTH: only successful_attacks(500)/failed_attacks(200) are trimmed; learned_patterns, target_history, techniques, and hackerone_hunts have no TTL, size cap, or rotation — they grow forever. There is no time-based TTL anywhere.
- SECRETS PERSISTED UNREDACTED: remember_success stores raw result/payload to disk; viper_memory.json on disk contains real CTF flags (HTB{...}) and recovered natas passwords in cleartext, violating the project's 'findings redacted / no credentials' rule.
- DEAD/STALE MODULE: the only writer (Memory class) lives in archive/old_agents/ and is referenced only by other archived agents; migrate_from_json is reachable only via `python core/viper_db.py` __main__. The live VIPER 5.0 pipeline neither reads nor writes this file, so it is stale legacy state.


---

## SECTION 2.1 — Scope & Safety Enforcement Audit

# VIPER Scope & Safety Enforcement Audit

Root: `C:\Users\sharm\clawd\skills\hackagent`

## (a) Authoritative scope check & fail-closed behavior

There is **no single authoritative chokepoint**. Three independent, inconsistent layers exist, each wired into a different entry path:

1. **`core/guardrail_hard.is_blocked()`** (`core/guardrail_hard.py:175`) — deterministic gov/mil/edu/int TLD + major-domain blocklist. **Fails OPEN for unknown domains** by design: returns `(False, "")` for anything not on its list (`guardrail_hard.py:211`). It is a blocklist, not an allowlist. Only invoked at **one** call site: `viper.py:283` inside `run_hunt`, gated by `if not no_guardrail`.

2. **`scope/scope_manager.ScopeManager.is_in_scope()`** (`scope_manager.py:300`) — bug-bounty scope file matcher. **Fails OPEN when no scope loaded**: `if not self.active_scope: return True, "No active scope - allowing all"` (`scope_manager.py:307-308`). When a scope *is* loaded it fails closed (out-of-scope checked first at `:311`, default-deny "not in explicit scope" at `:325-327`). `enforce_before_request()` (`:338`) raises `ScopeViolationError` — but only fires when `active_scope` is set (`viper_core.py:822`: `if self.scope_manager and self.scope_manager.active_scope`).

3. **`core/scope_reasoner.ScopeReasoner.decide()`** (`scope_reasoner.py:131`) — the only layer that is genuinely **fail-closed**: empty target → deny (`:134`), exception in `is_in_scope` → deny (`:160-166`), default-deny at end (`:196-202`). BUT when no scope manager is loaded it returns `default_when_no_scope` which defaults to `False` (deny) — correct — yet `_build_scope_reasoner` (`hack_cli.py:246`) only constructs a reasoner at all when a `--scope` file is given or the profile opts in (`hack_cli.py:160-163`). With no scope file, `scope_reasoner` stays `None` and is never consulted.

**Verdict:** The authoritative-by-design layer (ScopeReasoner) fails closed, but it is only reachable when the operator supplies a scope file. The two layers that run by default (hard guardrail, ScopeManager) **fail open** for unknown/unscoped targets. Net behavior with no scope file: **permissive**.

## (b) Are all network actions routed through a check?

**No.** Multiple network call paths bypass scope entirely.

- **Central client** `viper_core.ViperCore._request` enforces scope only `if self.scope_manager and self.scope_manager.active_scope` (`viper_core.py:822`). With no scope file loaded, every request through this method is unchecked. It also never calls `is_blocked` per-request.
- **Swarm vuln workers** use `core/swarm_workers/vuln/_http.py` `fetch()` (`_http.py:88`) → raw `urllib.request.build_opener().open()` (`_http.py:34,61`). **Zero scope/guardrail logic.** Rate-limited only.
- **AI hunter probes** `core/ai_hunter/probes.py:156-161` build their own `urllib` opener directly. **No scope check.**
- **Recon swarm workers** are the *only* workers that consult scope: `crtsh.py:40` and `subdomain.py:91` call `scope.decide(s).allowed` — but (i) only to filter *discovered subdomains*, not the seed target; (ii) only `if scope is not None` (skipped entirely when no reasoner built); (iii) `subdomain.py:88-93` wraps the filter in `try/except: pass`, so any exception **silently keeps all subdomains (fails open)**.
- **`grep` of `core/` and `agents/`** shows ~30 modules issuing `aiohttp`/`requests`/`urllib` calls (e.g. `scanner.py`, `oauth_fuzzer.py`, `race_engine.py`, `bola_scanner.py`, `web3_auditor.py`, `attack_orchestrator.py`, `agents/exploit_agent.py`, `agents/vuln_agent.py`, `recon/web_crawler.py`). Only `crtsh.py`/`subdomain.py` reference any scope primitive. The rest hit targets with no per-call scope gate.

**`viper.py hack` / daemon / dashboard path bypasses the hard guardrail completely:** `viper.py:55-57` routes `hack` straight to `run_hack_cli` and `sys.exit()`s — it never reaches `run_hunt` (`viper.py:245`) where `is_blocked` lives. `HackMode` (`core/hack_mode.py`) never calls `is_blocked`/`guardrail_hard` (grep: no matches). So the documented primary continuous-hunting mode — and the mode the dashboard spawns (`dashboard/server.py:148` builds `python viper.py hack ...`) — has **no gov/mil/edu TLD block and no major-domain block**. Scope is enforced there only if `--scope` is passed (`hack_cli.py:168-170`, `server.py:168-170`).

**Dashboard direct path:** `dashboard/server.py:3579-3603` calls `ViperCore().full_hunt(target, max_minutes=15)` with **no scope argument**, so `full_hunt`'s scope gate (`viper_core.py:940` `if scope and self.scope_manager`) is skipped and the hunt runs unscoped. `dashboard/server.py` has **zero** references to `is_blocked`/`guardrail`/`scope_manager` (grep: no matches).

## (c) What `--no-guardrail` disables, and is it dangerous?

`--no-guardrail` (`viper.py:90`) gates the lone `is_blocked` call in `run_hunt` (`viper.py:280-290`). When set, it skips the hard deterministic blocklist (gov/mil/edu/int TLDs + ~200 major/bank/cloud domains). It does **not** affect `ScopeManager` or `ScopeReasoner`.

**Dangerous, but the bigger problem is that the guardrail it disables barely runs anyway:**
- The flag only matters on the `run_hunt` (legacy `--full`) path. The `hack`/daemon/dashboard path never runs `is_blocked` regardless, so `--no-guardrail` is effectively the *default* there.
- Even when active, `is_blocked` is a blocklist that fails open for unknown domains, so disabling it mainly removes protection against accidentally scanning a well-known protected domain (e.g. `irs.gov`, `chase.com`).
- The benchmark harness hardcodes `--no-guardrail` (`benchmark/harness/runner.py:87`), which is acceptable for labs but shows the bypass is normalized.

## (d) Tool confirmation / approval gate — triggers & bypasses

`core/approval_gate.ApprovalGate`:
- **Triggers:** a tool is "dangerous" if its name is in `DANGEROUS_TOOLS` (`approval_gate.py:38-56`: nmap, naabu, nuclei, hydra, sqlmap, msfconsole, kali_shell, brute_force, etc.) or matches an arg pattern in `DANGEROUS_ARG_PATTERNS` (`:60-73`, e.g. `nuclei_scan severity=critical`, `nmap -sU`). Safe tools pass through silently (`:141-143`, `:294-296`).
- **Bypasses (by design):** `auto_approve=True` approves everything silently across `confirm_tool` (`:144-146`), `check_phase_transition` (`:233`), `check_tool_execution` (`:298`), `check_tool_confirmation` (`:364`), `ask_question` (`:427`). Daemon/dashboard hunts run detached with stdin = `DEVNULL` (`server.py:179`), so they must run in auto-approve/non-interactive mode — meaning the gate is a no-op for the dashboard-launched and daemon hunts.
- **Coverage gap:** the dangerous-tool set is keyed on *VIPER tool names*. The swarm vuln workers and `ai_hunter` probes that fire raw `urllib` requests (`_http.py`, `probes.py`) are not modeled as "tools" and never reach the gate.
- **Bug:** `check_phase_transition` (`approval_gate.py:240-242`) references `request.from_phase`/`request.to_phase`/`request.reason`, but the parameter is named `request_or_from_phase`. In interactive, non-auto-approve mode this raises `NameError` and crashes the prompt (fails closed-ish — aborts — but it is a real defect).

---

## Strengths

- **`ScopeReasoner` is correctly fail-closed**: empty target, scope-check exceptions, and unmatched targets all deny (`scope_reasoner.py:134,160-166,196-202`); decisions are cached + audit-attributed with confidence/source.
- **`ScopeManager` checks out-of-scope before in-scope** (`scope_manager.py:311` before `:320`), so explicit exclusions always win.
- **Hard guardrail is deterministic and non-LLM** (`guardrail_hard.py`): no network/LLM dependency, covers gov/mil/edu/int TLD variants + a broad major-domain/bank/cloud list, with an explicit safe-target allowlist for labs/CTF/RFC1918.
- **Wildcard/CIDR matching** is reasonable (`scope_manager.py:84-120`), and `*.example.com` correctly also matches the apex.
- **Approval gate** has both name-based and argument-pattern-based dangerous detection and a structured y/m/n flow.
- **LLM guardrail** uses a conservative default-deny on non-JSON in the scope callback (`scope_reasoner.py:387-389`).

## Weaknesses / bypasses (ranked, highest risk first)

1. **`hack`/daemon/dashboard path has no hard guardrail at all.** `viper.py:55-57` bypasses `run_hunt`; `HackMode` never calls `is_blocked`. The documented primary mode and the dashboard-spawned hunts will scan any host (incl. `.gov`/`.mil`/`chase.com`) when no `--scope` file is given.
2. **Default behavior is fail-open when unscoped.** `ScopeManager.is_in_scope` returns allow with no `active_scope` (`scope_manager.py:307-308`); `_request` skips enforcement without `active_scope` (`viper_core.py:822`). No scope file ⇒ no scope enforcement.
3. **Worker/probe network calls bypass every scope layer.** `swarm_workers/vuln/_http.py:88` and `ai_hunter/probes.py:156-161` issue raw `urllib` requests with no check. The seed target and any worker-constructed URL are never re-validated.
4. **Dashboard direct hunt is unscoped.** `dashboard/server.py:3579-3603` calls `full_hunt(target)` with no `scope=`, skipping the `:940` gate; `server.py` has no guardrail references.
5. **Recon scope filter fails open on error.** `subdomain.py:88-93` `try/except: pass` keeps all discovered subdomains if `decide()` throws; filter also skipped when `scope is None`.
6. **`--no-guardrail` disables the only hard-block call** on the `--full` path and is hardcoded in the benchmark runner (`benchmark/harness/runner.py:87`).
7. **Approval gate is a no-op for non-interactive/daemon/dashboard hunts** (auto-approve + `DEVNULL` stdin) and does not see raw-`urllib` worker traffic.
8. **Default-permit `TargetGuardrail`.** `core/guardrails.py:124-130` and `:182` both end in "default permit"; the LLM guardrail also fails open after 3 retries (`guardrail_llm.py:375-377`).
9. **`check_phase_transition` NameError** (`approval_gate.py:240-242`) crashes the interactive phase-approval prompt.

## Hardening recommendations (concrete)

1. **Single mandatory chokepoint.** Make `ViperCore._request` (and the swarm `_http.fetch`/`probes` openers) call one `enforce(target)` that runs, in order: `guardrail_hard.is_blocked` → `ScopeReasoner.decide` (constructed for *every* hunt, not just when `--scope` is present) → rate-limit. Raise/deny on any failure. Route `swarm_workers/vuln/_http.py:61` and `ai_hunter/probes.py:161` through it instead of opening sockets directly.
2. **Wire the hard guardrail into the `hack`/`HackMode` path.** Call `is_blocked(target)` (and per-discovered-host) in `hack_cli.run_hack_cli` before constructing `HackMode`, returning the existing exit code 2 ("guardrail blocked", referenced in `hack_cli.py:9`). Apply it to subprocess-spawned dashboard hunts too.
3. **Flip the default to fail-closed for public targets.** In `ScopeManager.is_in_scope`, when `active_scope is None`, deny unless the target is `guardrail_hard.is_safe_target()` (RFC1918/lab/CTF). Have the dashboard direct path pass an explicit scope or refuse to start unscoped.
4. **Remove the silent `except: pass` in `subdomain.py:88-93`** — on `decide()` error, drop the subdomain (fail closed), don't keep all.
5. **Constrain `--no-guardrail`** to only take effect when the target resolves to RFC1918/loopback or matches `is_safe_target()`; otherwise ignore it and warn. Keep it for the benchmark harness via that same safe-target check.
6. **Make approval-gate auto-approve explicit and audited.** In daemon/dashboard mode, require an explicit `--autopilot yolo`-style opt-in to set `auto_approve=True`, and log every auto-approved dangerous tool to the audit log.
7. **Fix `approval_gate.py:240-242`** to reference the normalized request object (build a `PhaseTransitionRequest` first, like `:225-228` already does, then use it).
8. **Tighten LLM fail-open:** `guardrail_llm._invoke_guardrail_llm` (`:375-377`) should fall back to the deterministic `is_blocked`/safe-target result on LLM failure, not unconditionally allow.

---

## SECTION 3 — Dashboard ↔ Backend Wiring Audit

`dashboard/server.py` exposes **105 routes** (full table: [PLAN-audit-endpoints.md](PLAN-audit-endpoints.md)). Webapp has **15 tabs**.

### Per-tab wiring

| Tab | Frontend file | Backend endpoint(s) | Data model | Wired? | Issues |
| --- | --- | --- | --- | --- | --- |
| (root redirect) | `app/page.tsx` | — | — | — (static) | Server component that just calls redirect('/overview'). No data, no states. Not a real tab — counts toward the 15 files but renders nothing.; missing loading/error/empty state |
| Agents | `app/agents/page.tsx` | `/api/agents/monitor`, `/api/react/current`, `/ws` | Reads ReACT state file, Reads agent monitor stat, none (live event stream) | ✅ | No loading vs empty distinction: while monitor is undefined the header shows 'Loading…' (line 56) but the body immediately renders the EmptyState 'No agents running' (line 84) because `monitor?.agents ?? []` is empty — so first paint shows  |
| Attack Graph | `app/graph/page.tsx` | `/api/graph/stats`, `/api/graph/query?q=<cypher>`, `/api/graph`, `/api/graph?hunt_id=<id>` | Reads data/viper.db audi | ✅ | Cypher console race: `run()` (line 38-44) sets running=true, awaits apiGet, sets result — but there is no request-cancellation/sequence guard. Rapid successive Runs (or preset-then-Run) can resolve out of order and show a stale result for t |
| Chat | `app/chat/page.tsx` | `/api/chat/history`, `/api/chat/send`, `/api/agent/approve` | Appends to in-memory _ch, Reads in-memory _chat_hi, Writes state/approval_re | ✅ | Hand-rolled polling via setInterval (lines 80-88) instead of useApi — duplicates React Query infra and won't benefit from dedup/staleTime.; Optimistic-append race: send() appends the user message locally (line 99) AND the 3s poll replaces ` |
| CypherFix | `app/cypherfix/page.tsx` | `/api/triage/findings`, `/api/codefix/run`, `/api/codefix/status?finding_id=<id>` | In-memory _codefix_jobs , Reads data/viper.db (fin, Reads state/codefix_stat | ✅ | Per-fix setInterval (lines 57-66) is never cleared on unmount — `pollingRef` tracks ids but the cleanup is only inside the interval callback on completed/failed. Navigating away mid-fix leaks the interval (keeps polling /api/codefix/status  |
| Findings | `app/findings/page.tsx` | `/api/findings?page=<n>&limit=25` | Reads data/viper.db (fin | ✅ | No loading state: header shows 'Loading…' (line 180) but the table shows the EmptyState 'No findings yet' (line 222) whenever `filtered.length===0`, including during the initial load — misleading empty-state flash.; No error state: apiGet n |
| Hunt (live swarm) | `app/hack/page.tsx` | `/api/hack/hunts?limit=50`, `/api/hack/hunt?hunt_id=<id>`, `/api/hack/start`, `/api/hack/report`, `/api/reports/<name>` | Reads audit_log in db (d, Reads audit_log table in, Reads data/viper.db (aud, Reads reports/ directory, Spawns viper hunt subpro | ✅ | NOT using the WebSocket despite being the 'real-time swarm dashboard' (header says 'Real-time', line 486) — it polls the snapshot every 1.5s (useSwarm.ts:31-42). useAuditTail hook exists in useSwarm.ts but is NOT consumed here, so the audit |
| Insights | `app/insights/page.tsx` | `/api/attacks/stats`, `/api/attacks/kill-chain`, `/api/evograph/stats`, `/api/evograph/tech-map`, `/api/sessions/list` | Reads data/evograph.db, Reads data/evograph.db (, Reads data/viper.db, Reads data/viper.db (att | ✅ | No loading state: all five queries; charts render empty frames while pending. EvoGraph stat cards are gated on `evoStats?.available` (line 73) so they simply vanish during load/when unavailable — no skeleton.; No error state: any of the 5 e |
| Overview / Dashboard | `app/overview/page.tsx` | `/api/overview`, `/api/risk-score`, `/api/findings/by-severity`, `/api/findings/timeline`, `/api/findings/by-type`, `/api/findings?limit=8`, `/api/hack/start`, `/ws` | Reads data/viper.db (fin, Reads data/viper.db: tar, Spawns viper hunt subpro, none (live event stream) | ✅ | No loading state: every useApi returns only `data`; while pending, all cards render `?? 0` and charts render empty arrays — indistinguishable from a backend that genuinely returned zeros.; No error state anywhere: apiGet swallows fetch fail |
| Projects | `app/projects/page.tsx` | `/api/projects`, `/api/sessions/list`, `/api/sessions/<id>`, `/api/scan/start` | In-memory _active_scans , Reads data/evograph.db (, Reads session store (evo, Reads state/project_sett, Writes state/project_set | ✅ | startScan POSTs /api/scan/start with EMPTY body {} (line 81) — no target specified; depends entirely on backend having a pre-configured target. If no project target is configured ('Not configured', line 109) the button still fires a no-op/e |
| Recon Pipeline | `app/recon/page.tsx` | `/api/recon/pipeline/list`, `/api/recon/pipeline/<jobId>`, `/api/recon/pipeline/start` | In-memory _recon_pipelin, Reads in-memory _recon_p | ✅ | startPipeline (lines 96-107) ignores the POST result entirely — no success/error feedback. If start fails (apiPost null), the UI shows nothing; user only learns via the 3s job-list poll eventually (or never).; No loading/error state for the |
| Reports | `app/reports/page.tsx` | `/api/reports`, `/api/hack/hunts?limit=50`, `/api/hack/report`, `/api/reports/delete`, `/Download` | Deletes a file under rep, Reads audit_log table in, Reads data/viper.db (aud, Reads files under dashbo, Reads reports/ directory, none | ✅ | generate() and del() ignore the apiPost result (lines 52-58, 60-64) — no success/error feedback; rely on refetch() to eventually reflect changes. A failed generate/delete is silent.; No loading state: 10s reports poll; EmptyState 'No report |
| Settings | `app/settings/page.tsx` | `/api/settings`, `/api/settings` | Reads SettingsManager (s, SettingsManager persists | ✅ | If GET /api/settings returns null (backend down) `loaded` stays false forever → the page is stuck on the skeleton loader (lines 114-120) with no error/retry — a hard dead-end when the API is unreachable.; Save has a real toast for success/e |
| Targets | `app/targets/page.tsx` | `/api/targets`, `/api/findings?domain=<domain>&limit=50` | Reads data/viper.db (fin, Reads data/viper.db (tar | ✅ | No loading vs empty distinction: header 'Loading…' (line 232) but grid renders EmptyState 'No targets yet' (line 243) while targets is undefined — empty-state flash on load.; No error state: backend-down indistinguishable from no targets.;  |
| Terminal | `app/terminal/page.tsx` | `/api/terminal/nlp`, `/api/terminal/execute`, `/api/terminal/connect` | Mutates in-memory _TERMI, Writes entry into in-mem, none (translation only) | ✅ | Purely command-driven; no GET/poll. Has a 'running…' indicator (loading, lines 171-176) and error lines for non-zero exit / null response (lines 56-58) and try/catch 'Request failed' (line 61) — this is the ONLY page with a genuine error pa |

### Loose cannons

**Tabs with no resolvable backend:** none — every tab resolves at least partially.

**Endpoints with no UI consumer (64 of 100 base paths)** — candidates for either a UI surface or removal:

- `GET /` — :8080 is now headless API; root returns a landing page bouncing users to the Nex
- `POST /api/agent/answer` — Same-origin enforced. Broadcasts PHASE_UPDATE WS. 400 on exception. Agent Q&A re
- `POST /api/agent/guidance` — Same-origin enforced. Broadcasts PHASE_UPDATE over WS (_ws_broadcast). 400 on ex
- `GET /api/agent/status` — No auth.
- `GET /api/agent/thinking` — No auth.
- `GET /api/agents/status` — v5 multi-agent status. Checks core.agent_bus/agent_registry importability; lists
- `GET /api/attack-graph` — Phase 9 endpoint. No auth.
- `GET /api/attack-history` — ?limit(default 200). Legacy alias.
- `GET /api/attack-stats, /api/attack_stats` — Legacy backwards-compat aliases of /api/attacks/stats.
- `GET /api/attacks/history` — ?limit(default 200). No auth.
- `GET /api/codefix/status/*` — Dynamic job_id. 404 if not found. No auth.
- `POST /api/ctf/feedback` — Same-origin enforced. Requires challenge+category else 400. Returns feedback_id 
- `GET /api/ctf/feedback/list` — ?limit (default 50). 500 on exception.
- `GET /api/ctf/ranking` — ?category, ?min_tries. 500 on exception.
- `GET /api/ctf/recommend` — ?category(default web), ?stack(csv), ?top(default 5). 500 on exception.
- `POST /api/ctf/run` — Same-origin enforced. Daemon thread runs CTF flag hunt (flag_prefix, custom_patt
- `GET /api/ctf/stats` — 500 on exception.
- `POST /api/ctf/train` — Same-origin enforced. mode in {url,github,dir}; each runs in daemon thread. Miss
- `GET /api/evograph, /api/evolution` — Legacy combined alias.
- `GET /api/evograph/graph` — No auth.
- `GET /api/evograph/sessions` — No auth.
- `POST /api/export/excel` — Same-origin enforced. Streams CSV (text/csv, Content-Disposition attachment vipe
- `GET /api/findings/*` — Dynamic numeric id (last segment). Non-numeric -> 400 'Invalid finding ID'. 404 
- `GET /api/findings/by-domain` — No auth.
- `GET /api/findings/by-severity` — No auth.
- `GET /api/findings/by-type` — No auth.
- `GET /api/findings/timeline` — No auth.
- `GET /api/graph/query` — ?q NL query. Empty q or no engine -> empty results. No auth.
- `GET /api/graph/stats` — ?hunt_id. node/edge counts + types. No auth.
- `GET /api/hack/audit` — ?hunt_id required else 400; ?since(unix-ts), ?action filter, ?limit(default 500,
- `GET /api/health` — Liveness probe {ok:true, ts}. No auth.
- `GET /api/insights/charts` — Single endpoint for all insight charts. No auth.
- `POST /api/kb/search` — Same-origin enforced. query required else 400; supports category + top_k. 500 if
- `GET /api/logs` — ?lines(default 80). No auth.
- `GET /api/react/latest` — No auth.
- `GET /api/react/traces, /api/react` — No auth.
- `POST /api/recon/pipeline/cancel` — Same-origin enforced. Best-effort cancel (no thread kill). 404 if job not found,
- `POST /api/recon/pipeline/status` — Same-origin enforced. 404 if job_id not found, 400 on exception.
- `GET /api/reports/*` — Path traversal guard: Path(filename).name only. Serves text/html or text/plain. 
- `POST /api/scan/status` — Same-origin enforced. 404 if scan_id not found, 400 on exception.
- `GET /api/scans` — Lists up to 20 recent scans sorted by started_at. No auth.
- `GET /api/security-posture` — Phase 9. No auth.
- `GET /api/session/*` — Dynamic numeric id (legacy session endpoint maps to target detail). Non-numeric 
- `GET /api/sessions` — Legacy alias. No auth.
- `GET /api/state` — No auth.
- `GET /api/status` — Aggregate system status: version, db/evograph connected flags, external tool ava
- `GET /api/stream, /api/events` — Server-Sent Events. text/event-stream keep-alive. Subscribes to event_bus, emits
- `GET /api/targets/*` — Dynamic domain (everything after /api/targets/). 404 if not found.
- `GET /api/tech-heatmap` — Phase 9. No auth.
- `POST /api/terminal/disconnect` — Same-origin enforced. Removes session_id. 400 on exception.
- `GET /api/timeline` — Alias of findings timeline. No auth.
- `GET /api/triage` — Requires graph engine else empty remediations. Returns {error} (200) on engine e
- `GET /api/v5/evolution` — Returns nodes/edges. Exceptions swallowed (empty graph). No auth.
- `GET /api/v5/failure-lessons` — Last 20 lessons + waf_stats + attack_types. Exceptions swallowed (returns defaul
- `GET /api/v5/modules` — Probes importability of 14 core modules (agent_bus, oauth_fuzzer, race_engine, e
- `GET /charts` — Legacy static page.
- `GET /chat` — Legacy static page.
- `GET /chat-v2` — Legacy static page.
- `GET /cypherfix-v2` — Legacy static page.
- `GET /graph` — Legacy v4 static HTML page. 404 if file missing.

_…list truncated; see endpoint appendix._


### 3.1 Git hygiene (dashboard currently untracked)

`dashboard/webapp/`, `dashboard/launch.py`, `benchmark/`, and several `core/` subpackages
(`core/ai_hunter/`, `core/mind_pipeline/`) are **untracked** (see Section 1 git status).

Plan:
1. Add a scoped `.gitignore` under `dashboard/webapp/` for `node_modules/`, `.next/`, `out/`,
   `*.tsbuildinfo` (verify none already staged).
2. Stage source only: `dashboard/webapp/src`, `public`, `package.json`, `package-lock.json`,
   `next.config.ts`, `tsconfig.json`, `AGENTS.md`. **Never** stage `.env*`.
3. Run the repo pre-commit checklist (secret scan, no sensitive files, `from viper_core import
   ViperCore` import check, `pytest`) before the first dashboard commit.
4. One focused commit per surface (webapp, launcher, benchmark) so history stays bisectable.

### 3.2 Contract layer (stop UI/backend drift)

Root cause of drift: `dashboard/server.py` is a hand-rolled `ThreadingHTTPServer` with **no
schema** — the 105 endpoints are an `if/elif` path chain, and the webapp hand-writes fetch
URLs in hooks. Nothing fails when they diverge.

Proposed fix (Phase 4):
- Define response shapes once as Python dataclasses/`TypedDict` in a new `dashboard/contracts.py`,
  and have each handler return one (no more ad-hoc dicts).
- Emit a machine-readable schema (a small `/api/_schema` route that dumps the contract registry,
  or a build-time JSON Schema export).
- Generate a typed TS client (`dashboard/webapp/src/lib/contracts.ts`) from that schema and route
  **all** `useApi` calls through it. CI step fails if generated client != committed client.
- Net: adding/renaming an endpoint without updating the contract breaks the build, not production.


---

## SECTION 4 — The Persistence Loop Fix

I have everything I need. The `evograph.py` already has `record_attack`, `tech_attack_map` (a tech→attack co-occurrence store), `to_graph`-style export with nodes/edges (`:673-723`), and Q-table save/load. The section can ground the EvoGraph edge-type proposal in these real primitives. Writing now.

---

# SECTION 4 — The Persistence Loop Fix

## 4.0 Executive summary

VIPER runs two disconnected hunt pipelines. The legacy `ViperCore.full_hunt` path (`viper_core.py`) calls `phase_chain_escalation → ChainEscalator`, builds an `AttackGraph`, and persists chains — so it chains, shallowly. The active swarm path (`core/hack_mode.py` + `core/swarm_coordinator.py`), which every exploit worker actually runs under, **never calls `ChainEscalator`, never instantiates `AttackGraph`, never writes to `EvoGraph`, and never re-dispatches a finding back into the swarm**. Confirmed: `core/hack_mode.py` contains zero references to `ChainEscalator`, `AttackGraph`, `EvoGraph`, `ChainWriter`, or `attack_chain`.

Chaining in the swarm path is a fixed, forward, phase-sequential fan-out (`recon → vuln → exploit → post`). An exploit worker's output is consumed only as a one-shot flat input list to the next phase's `build_manifest`. There is no feedback edge, no depth budget, no cycle guard, and no learned attack selection. Exploit findings die at the `exploit → post` boundary because deep post-exploit techniques are gated behind a `foothold: True` flag that **only 2 of 6 exploit workers set** (`cmdi_exploit.py:74`, `auth_bypass.py:108`; `sqli/xss/idor/ssti` omit it). The fix is to (a) standardize the finding schema with a *primitive type + provenance + confidence*, (b) turn findings into re-dispatchable tasks under a bounded budget, (c) record chain edges in `EvoGraph` so selection becomes learned, and (d) enforce a per-finding **7-Question Gate** that issues an explicit verdict so "DO NOT STOP" becomes *bounded* exploration that converges instead of looping.

---

## 4.1 Where findings live today (the real data path)

**Schema is split three ways.** The canonical `Finding` dataclass (`core/models.py:66-86`) is **never used by the swarm path**. Swarm workers emit ad-hoc `dict`s with divergent keys — e.g. `xss_exploit.py:42-51` emits `{type, vuln_type, exploited, ...}`. A third taxonomy, the 26-value `FindingType` enum (`core/chain_writer.py:26-54`), is used only by the legacy graph writer.

**Creation:** inside each worker's `run()` (`core/swarm_workers/exploit/*`). Note the documented worker contract in `core/swarm_workers/exploit/__init__.py:10-12` *already* declares `foothold` (default `False`) — the schema exists; most workers just don't populate it.

**Transport (telemetry, not work):** findings are published to the bus via `_publish_finding` (`core/swarm_coordinator.py:414-465`) on topics `vuln/exploit/post/report`. **Nobody subscribes** — `AgentBus.subscribe` is never called by `HackMode` or any coordinator, so `_dispatch_loop` (`agent_bus.py:152-173`) delivers to zero consumers. The bus is a dashboard side-channel.

**Consumption (the only real handoff):** `HackMode._run_phase` (`core/hack_mode.py:557-558`) sets `payload["findings"] = list(self._state.get("findings", []))` for every non-recon phase. `_state["findings"]` is the flat accumulation of all findings from all prior phases this run (`hack_mode.py:469-471`). `build_manifest` reads `context["findings"]` (`swarm_coordinator.py:748` exploit, `:880` post). Findings therefore move **forward only, once per phase, as an undifferentiated flat list** — no edges, no parent/child, no graph.

---

## 4.2 Ranked root cause of the chaining stall

| # | Root cause | Evidence | Severity |
|---|-----------|----------|----------|
| 1 | **No re-dispatch / no graph traversal.** Phase order is a hardcoded list (`hack_mode.py:425,455`), not graph-driven. A finding can only be re-fed flat to the next fixed phase; it cannot spawn a new, deeper task. `AttackGraph` traversal primitives (`get_attack_chain` `attack_graph.py:239`, `shortest_path` `:261`, `build_from_hunt` `:519`) are never instantiated in the swarm path. | grep: `AttackGraph` only in `viper_core.py`/`dashboard`/`graph_engine` | **PRIMARY** |
| 2 | **`foothold` gate kills exploit→post for 4/6 types.** `PostSwarmCoordinator.build_manifest` picks `_FOOTHOLD_TECHNIQUES` only if `any(f.get("foothold"))` (`swarm_coordinator.py:881-884`); else `_DEFAULT_TECHNIQUES = ["flag_hunter"]` (`:862`). Only `cmdi`/`auth_bypass` set `foothold:True`. Confirmed critical SQLi/SSTI/IDOR/XSS yield only `flag_hunter` — no privesc, no lateral. | `swarm_coordinator.py:862,881-884`; worker grep above | **PRIMARY** |
| 3 | **`ChainEscalator` is dead code for the swarm.** Its 11 rule-based chains (CORS+CSRF→ATO, LFI+log→RCE, …) run only via `phase_chain_escalation` (`hunt_phases.py`), called only from `viper_core.py:1049`. Two low findings that should combine into a critical never do. | grep: zero refs in `hack_mode.py`/`swarm_coordinator.py` | **PRIMARY** |
| 4 | **Flat-list semantics + publish-time dedup.** `_state["findings"]` carries every prior finding forward with no relationship metadata, so by `post` the coordinator sees recon+vuln+exploit mixed with no edges. `FindingDedup` (`swarm_coordinator.py:104-114`) is applied at *publish* (the consumer-less bus), so it gates telemetry, not the work feed — masking the stall. | `hack_mode.py:558`; `swarm_coordinator.py:420` | CONTRIBUTING |
| 5 | **Timeouts truncate breadth.** Per-worker 60s (`swarm_engine.py:140`), per-phase `time_budget_s*0.9/phase_count` (`hack_mode.py:533`). Drops in-flight workers, not already-returned findings. | — | SECONDARY |
| 6 | **Bus backpressure.** `maxsize` drop on full (`agent_bus.py:119-122`); but bus is non-load-bearing, so this only loses telemetry. | — | RULED OUT |

**Net:** depth is structurally fixed at 4 phases. There is **no chain-depth counter, no `max_depth`, no cycle detection, no learned selection** in the swarm path.

---

## 4.3 Fix design

### 4.3.1 Unified finding schema (primitive type + provenance + confidence)

Extend the swarm-dict contract in `core/swarm_workers/exploit/__init__.py` and back it with the canonical `Finding` in `core/models.py`. Every worker must emit:

```python
{
  # identity (dedup + graph node key)
  "id": "<uuid>",
  "vuln_type": "sqli",            # canonical class, NOT "sqli_exploited:id"
  "target": "https://host",
  "endpoint": "/search",
  "parameter": "q",
  "payload": "...",

  # PRIMITIVE TYPE — what capability this finding grants the chain.
  # Drives re-dispatch. Maps to core/models.py:Phase + chain_writer.FindingType.
  "primitive": "INJECTION",       # READ_FILE | RCE | AUTH_BYPASS | SSRF |
                                  # CREDENTIAL | INFO_DISCLOSURE | FOOTHOLD | NONE
  "foothold": False,             # True iff primitive in {RCE, AUTH_BYPASS, CREDENTIAL}

  # PROVENANCE — the chain edge, currently absent everywhere.
  "source_phase": "exploit",
  "source_technique": "sqli_exploit",
  "parent_id": "<finding id this was derived from>",   # None for roots
  "chain_depth": 2,              # parent.chain_depth + 1

  # CONFIDENCE — gates verdicts (4.4) and EvoGraph reward.
  "confidence": 0.0,             # 0.0–1.0; 1.0 = behaviorally verified
  "exploited": True,
  "evidence": "...",
}
```

Adding `primitive`, `parent_id`, `chain_depth`, and a real `confidence` is the minimum to make findings chainable. Collapsing `vuln_type` to the canonical class (not `sqli_exploited:{param}`) lets `FindingDedup` (`swarm_coordinator.py:104-114`), `ChainEscalator` matching, and `AttackGraph` nodes key consistently. **Immediate one-liner win:** set `foothold:True`/`primitive` on `sqli/xss/idor/ssti_exploit` so `PostSwarmCoordinator` (`:881`) escalates past `flag_hunter`.

### 4.3.2 EvoGraph edge types for chaining

`core/evograph.py` already has the storage primitives: `record_attack(session_id, attack_type, target_tech, success, confidence, reward, reasoning)` (`:316`), the `tech_attack_map` upsert with `avg_reward` (`:335-345`), Q-table save/load (`:456`, `:472`), and a nodes/edges export built from session co-occurrence (`:673-723`). Today none of this is called by the swarm. Wire it in and add a typed **chain-edge table** so edges are causal, not merely co-occurring:

```
CREATE TABLE chain_edges (
  src_primitive TEXT,   -- e.g. INJECTION
  dst_primitive TEXT,   -- e.g. READ_FILE
  edge_type    TEXT,    -- ENABLES | ESCALATES | REQUIRES | PIVOTS_TO
  tech_signature TEXT,  -- reuse _normalize_tech() (:327)
  attempts INT, successes INT, avg_reward REAL,
  PRIMARY KEY (src_primitive, dst_primitive, edge_type, tech_signature)
);
```

Edge semantics: `ENABLES` (SSRF→internal scan), `ESCALATES` (LFI+log→RCE — the existing `ChainEscalator` rules become edge seeds), `REQUIRES` (privesc REQUIRES foothold), `PIVOTS_TO` (credential→lateral). On each finding-derived-from-finding event, `record_attack` + upsert the edge with its reward. Selection then queries best-reward outgoing edges for a node's `primitive` filtered by `tech_signature` — replacing the static profile technique list (`hack_mode.py:546`) with **learned** dispatch.

### 4.3.3 Worker dispatch: feed new findings back as tasks

Add the missing feedback edge to `SwarmEngine.run_swarm` (currently one-shot `asyncio.gather`, `swarm_engine.py:167-182`). After each phase, a **re-dispatch pass** converts qualifying findings into new `WorkerSpec`s instead of only forwarding them flat:

1. For each finding with `verdict == CHAIN-REQUIRED` (4.4) and `chain_depth < max_depth`:
2. Query EvoGraph outgoing `chain_edges` for `finding.primitive` (4.3.2), ranked by `avg_reward`.
3. For each candidate edge not in the visited-set, emit a child `WorkerSpec` with `parent_id = finding.id`, `chain_depth = finding.chain_depth + 1`, populating the long-unused `SwarmAgent.parent_id` field (`swarm_engine.py:44`).
4. Re-feed only that finding (not the whole flat list) plus its ancestry, so the child worker has provenance, not noise.

Cap fan-out per finding by `max_children` (breadth) and total by `max_concurrent` (existing semaphore, `swarm_engine.py:169`).

### 4.3.4 Depth / breadth budgets + cycle detection

Today: breadth is bounded (`max_concurrent` 12/16, manifest size); **depth is unbounded-by-absence** — fixed at 4 phases with no counter. Add explicit budgets to `HackProfile`:

```python
max_chain_depth   = 4    # BugBounty; CTF 6, Lab 1. Hard cap on chain_depth.
max_children      = 3    # fan-out per finding (breadth of re-dispatch)
chain_node_budget = 64   # total chain nodes per run (global breadth cap)
```

**Cycle detection** (entirely absent in the swarm path today): maintain a per-run `visited: Set[chain_key]` where `chain_key = (vuln_type, target, endpoint, parameter, primitive)`. A finding is re-dispatched only if its `chain_key` is unseen. This reuses the visited-set discipline already present in `AttackGraph.get_attack_chain` (`attack_graph.py:246-249`) but applies it to the live work feed. Re-feeding the entire flat `_state["findings"]` every iteration (`hack_mode.py:558`) is the current cycle source; the visited-set + per-finding (not whole-list) re-dispatch eliminates it.

### 4.3.5 Termination that is NOT a wall-clock timeout

Today the only real stop is the global `asyncio.wait_for(time_budget_s)` (`hack_mode.py:332-335`) plus `max_iterations`. Replace "stop when the clock runs out" with **stop when the frontier is exhausted of productive work**:

- **Frontier-empty:** no finding has verdict `CHAIN-REQUIRED` with an unvisited, positive-reward outgoing edge. (Primary convergence condition.)
- **Budget-exhausted:** `chain_node_budget` reached or all live chains hit `max_chain_depth`.
- **No-progress:** N consecutive re-dispatch passes produce zero `PASS`/`CHAIN-REQUIRED` verdicts (reward plateau) — bounds reward-chasing.

Wall-clock remains only as a backstop, not the design's stopping logic.

---

## 4.4 Bounded "DO NOT STOP": the 7-Question Gate

"DO NOT STOP" must mean *exhaust the productive frontier*, not *loop forever*. Every finding passes a **7-Question Gate** that emits exactly one verdict before it can enter the frontier. The gate is what makes the loop converge.

**The 7 questions (each yes/no, evaluated per finding):**
1. **Reproducible?** Behaviorally re-verified (`finding_validator` style), `confidence ≥ 0.5`?
2. **In scope?** Passes `roe_engine`/scope check?
3. **Novel?** `chain_key` not in `visited` (4.3.4)?
4. **Primitive grants capability?** `primitive != NONE`?
5. **Reachable next step?** EvoGraph has an unvisited outgoing edge with `avg_reward > 0`?
6. **Depth budget left?** `chain_depth < max_chain_depth`?
7. **Breadth budget left?** `chain_node_budget` not exhausted?

**Verdict mapping:**
- **KILL** — Q1 or Q2 = no. Unreproducible or out-of-scope. Drop, never re-present.
- **DOWNGRADE** — Q1 yes but Q4 = no (no capability). Record for the report; do **not** re-dispatch. (This is where most current "stalls" should legitimately land — they're terminal leaves, not bugs.)
- **PASS** — Q1–Q4 yes but Q5 = no (capability, but no learned next step). Terminal-but-valuable: persist + report, no re-dispatch.
- **CHAIN-REQUIRED** — Q1–Q7 all yes. The *only* verdict that re-enters the frontier and spawns children (4.3.3).

Because only `CHAIN-REQUIRED` re-dispatches, and Q3/Q6/Q7 are monotonically tightening (visited grows, depth/budget shrink), the frontier is guaranteed to drain → **frontier-empty termination (4.3.5) is reachable without the clock**.

### 4.4.1 State machine

```
                ┌─────────────────────────────────────────────┐
                │            HUNT LOOP (per finding)           │
                └─────────────────────────────────────────────┘
  finding ──► [7-QUESTION GATE]
                  │
      ┌───────────┼───────────┬──────────────────┐
   Q1/Q2=no    Q4=no       Q5=no            Q1–Q7=yes
      │           │           │                  │
    KILL      DOWNGRADE      PASS         CHAIN-REQUIRED
      │           │           │                  │
    drop     report-only  report-only      mark visited;
              (leaf)        (leaf)         EvoGraph.record_attack(+reward);
                                           emit ≤max_children child WorkerSpecs
                                            (parent_id, chain_depth+1) ──┐
                                                                         │
                                                            re-dispatch into swarm
                                                                         │
                                                                         ▼
                                                                  back to GATE
```

```python
def hunt_loop(roots, profile, evo, bus_findings):
    frontier = deque(roots)
    visited  = set()
    nodes    = 0
    no_progress = 0

    while frontier:
        # --- TERMINATION (not wall-clock) ---
        if nodes >= profile.chain_node_budget: break          # budget-exhausted
        if no_progress >= profile.no_progress_limit: break    # reward plateau

        f = frontier.popleft()
        verdict = seven_question_gate(f, visited, evo, profile)

        if verdict in ("KILL", "DOWNGRADE", "PASS"):
            persist_leaf(f, verdict)                           # report only
            if verdict in ("KILL",): no_progress += 1
            continue

        # CHAIN-REQUIRED
        visited.add(f.chain_key); nodes += 1; no_progress = 0
        evo.record_attack(f.session_id, f.vuln_type, f.tech, success=True,
                          confidence=f.confidence, reward=reward_of(f))   # evograph.py:316
        children = 0
        for edge in evo.best_edges(f.primitive, f.tech):       # 4.3.2, ranked by avg_reward
            if children >= profile.max_children: break
            if edge.dst_key in visited: continue               # cycle guard
            child = make_worker_spec(parent=f, primitive=edge.dst_primitive,
                                     depth=f.chain_depth + 1)
            if child.chain_depth <= profile.max_chain_depth:
                frontier.append(dispatch(child))               # feedback edge (4.3.3)
                children += 1
    # frontier empty  ==>  frontier-exhausted termination (the convergence goal)
```

---

## 4.5 Implementation checklist (wiring, in dependency order)

1. **Schema (4.3.1):** add `primitive`, `parent_id`, `chain_depth`, real `confidence` to the `core/swarm_workers/exploit/__init__.py` contract; set `foothold`/`primitive` on `sqli/xss/idor/ssti_exploit`. *(Unblocks fix #2 immediately.)*
2. **EvoGraph wiring (4.3.2):** instantiate `EvoGraph` in `HackMode`; call `record_attack` (`evograph.py:316`) on each verdict; add `chain_edges` table seeded from `ChainEscalator`'s 11 rules.
3. **Gate (4.4):** implement `seven_question_gate` returning `KILL/DOWNGRADE/PASS/CHAIN-REQUIRED`.
4. **Feedback loop (4.3.3):** extend `SwarmEngine.run_swarm` (`swarm_engine.py:167`) to re-dispatch `CHAIN-REQUIRED` children, populating `SwarmAgent.parent_id` (`:44`).
5. **Budgets + cycle guard (4.3.4):** add `max_chain_depth/max_children/chain_node_budget` to `HackProfile`; add per-run `visited` set.
6. **Termination (4.3.5):** replace clock-primary stop in `_run_loop` with frontier-empty / budget / no-progress; keep `time_budget_s` as backstop only.

---

**Out-of-section note (resolved):** a stale comment in `core/chain_writer.py` referenced a third-party tool name, which `.claude/rules/git-commit.md §7` forbids. It has been rewritten generically.

---

Relevant files (all absolute):
- `C:\Users\sharm\clawd\skills\hackagent\core\models.py` (`Finding` `:66-86`, `Phase` `:56-63`, `Target.should_try_attack` `:122`)
- `C:\Users\sharm\clawd\skills\hackagent\core\hack_mode.py` (flat work feed `:557-558`, `:469-471`; phase list `:425,455`; budgets `:332-335,533`)
- `C:\Users\sharm\clawd\skills\hackagent\core\swarm_coordinator.py` (`_publish_finding` `:414-465`; `FindingDedup` `:104-114`; foothold gate `:862,881-884`)
- `C:\Users\sharm\clawd\skills\hackagent\core\swarm_workers\exploit\__init__.py` (`foothold` contract `:10-12`) and `sqli/xss/idor/ssti/cmdi/auth_bypass`
- `C:\Users\sharm\clawd\skills\hackagent\core\evograph.py` (`record_attack` `:316`, `tech_attack_map` upsert `:335-345`, Q-table `:456,472`, edge export `:673-723`)
- `C:\Users\sharm\clawd\skills\hackagent\core\attack_graph.py` (`get_attack_chain` `:239`, `shortest_path` `:261`, `build_from_hunt` `:519`)
- `C:\Users\sharm\clawd\skills\hackagent\core\attack_chain.py` (`AttackChain` `:28`, `AttackChainEngine` `:419`)
- `C:\Users\sharm\clawd\skills\hackagent\core\chain_writer.py` (`FindingType` `:26-54`; rule-violating comments `:48-49`)

---

## SECTION 5 — Self-Improvement Loop (Bounded)

I now have the real API surface. Writing SECTION 5 grounded in these exact methods, tables, and the `viper_memory.json` shape.

---

# SECTION 5 — Self-Improvement Loop (Bounded)

> **Status today:** VIPER's learning substrate is split across two stores — `memory/viper_memory.json` (flat JSON, written only by the archived `archive/old_agents/agentic_viper.py:Memory` class) and `core/evograph.py` (live SQLite `data/evograph.db`). Neither is wired into the live swarm path, both persist raw CTF flags / recovered passwords in cleartext, and `viper_memory.json` is non-atomic, write-per-event, and partly unbounded. This section defines the **bounded, sanitized, gated** self-improvement loop that replaces both, and the exact file that owns each step.

The design rule for this entire section: **VIPER learns *generalizable tactics*, never *raw target data from prior engagements*.** A pattern derived on engagement A may influence VIPER's behavior on engagement B only after it has been stripped of all target identifiers, validated, and proven in a lab. Anything that cannot be generalized without leaking a prior target is discarded, not stored.

---

## 5.1 What gets written after each run

After every hunt teardown, exactly **four** record classes are written. Each is derived from the run's findings *post-redaction*. Raw target data (hostnames, IPs, URLs, parameter values, response bodies, flags, credentials, evidence blobs) from one engagement is **never** carried into the cross-engagement store.

| Record class | Purpose | Owning file | Backing table / key |
|---|---|---|---|
| Finding patterns | Generalizable "what worked" tactic | `core/evograph.py` | `tech_attack_map`, `attack_history` |
| FP signatures | "This looked like a bug but wasn't" | `core/finding_validator.py` → `core/evograph.py` | `fp_signatures` (new) |
| Target fingerprints | Tech-stack class, **not identity** | `core/evograph.py` | `tech_attack_map.tech_signature` |
| Payload efficacy stats | Which payload family beats which defense | `core/evograph.py` | `payload_efficacy` (new) + `get_top_bypasses` |

### 5.1.1 Redaction gate (runs BEFORE anything is written)

Owned by `core/secret_scanner.py:SecretScanner.scan_text()` (already present, 40+ regex + Shannon entropy) plus a new `core/learning_sanitizer.py`. Every candidate record passes through `sanitize(record) -> record | None`:

1. **Drop target identity.** Hostname, IP, full URL, subdomain, port, `Host` header, and any value matching the engagement's scope file are replaced with the structural token `<TARGET>` / `<HOST>` / `<PATH>`. The concrete host is **never** stored cross-engagement.
2. **Drop secrets.** Run `SecretScanner.scan_text()` over `result`, `payload`, `evidence`, `poc_request`. Any hit (API key, JWT, password, `HTB{...}` / CTF flag regex `r'[A-Z0-9_]{2,}\{[^}]+\}'`, AWS keys, cookies) → replace the matched span with `<REDACTED:type>`. If a flag/credential is the *entire* result, the record is **dropped**, not stored.
3. **Drop PII.** Email, phone, SSN-shaped, name patterns → `<PII>`.
4. **Generalize the payload.** Store the **payload family + mutation class**, not the literal string. `' OR SLEEP(3)--` → `{family: "sqli.time_based", mutation: "comment_terminated", db_hint: "mysql"}`. The literal is discarded after the family is derived.
5. **Reject on residue.** If after steps 1–4 any token still matches the scope file of *any* prior engagement, the record is rejected and counted in `sanitizer.rejected_residue` (audited). Fail-closed: a sanitizer exception → drop the record, never store the raw form.

> This directly fixes the audited defect "SECRETS PERSISTED UNREDACTED" — `viper_memory.json` currently holds live `HTB{...}` flags and recovered `natas` passwords in cleartext. Under this design those records are dropped at step 2 before write.

### 5.1.2 Finding patterns — schema

Written by `core/evograph.py:record_attack()` (exists, line 316) and `update_tech_attack` (new wrapper around `tech_attack_map`). **No target identity.**

```json
{
  "tech_signature": "php+apache+mysql",          // sorted, lowercased tech class — NOT a hostname
  "attack_type": "sqli.time_based",
  "outcome": "confirmed | failed | fp",
  "confidence": 0.0,                              // 0..1 from finding_validator
  "reward": 0.0,                                  // Q-learning reward, bounded [-1, 1]
  "mutation_class": "comment_terminated",
  "engagement_id_hash": "sha256(engagement_id)[:12]",  // opaque, non-reversible — for dedup only
  "schema_version": 2,
  "timestamp": "ISO-8601"
}
```

### 5.1.3 FP signatures — schema

Owned by `core/finding_validator.py` (the 37 vuln-type behavioral FP filter), persisted to a new `evograph.fp_signatures` table. Captures *why* a finding was a false positive so the next run can pre-suppress it.

```json
{
  "vuln_type": "cors",
  "fp_reason": "reflected_origin_no_credentials",   // controlled vocabulary, see 5.1.7
  "behavioral_signature": "acao_reflects_but_acac_false",
  "tech_signature": "nginx",
  "validator_rule_id": "cors.r07",
  "hits": 1,                                         // incremented, not appended (idempotent)
  "schema_version": 2,
  "last_seen": "ISO-8601"
}
```

### 5.1.4 Target fingerprints — schema (tech **class**, never identity)

This is the one record most prone to leaking target data, so it is the most constrained. A "target fingerprint" is a **bucketed tech-stack class string**, identical to `tech_attack_map.tech_signature`. It stores *"PHP+Apache sites with WAF X tend to be vulnerable to Y"* — a statistical prior — and contains **zero** resolvable identity.

```json
{
  "tech_signature": "php+apache+cloudflare",
  "waf_class": "cloudflare",                  // class only, never a rule-set fingerprint tied to one site
  "observed_count": 12,                       // how many DISTINCT engagements (by hash) contributed
  "attack_success_rates": { "ssti": 0.4, "sqli": 0.1 },
  "schema_version": 2
}
```
**Hard rule:** a fingerprint is only retained once `observed_count >= 3` distinct engagements (k-anonymity-style floor). A signature seen on a single engagement is held in a quarantine buffer and **not** promoted into the shared store until two more independent engagements corroborate it — this prevents a single target's identity from being reconstructed from a unique tech string.

### 5.1.5 Payload efficacy stats — schema

Owned by `core/evograph.py:get_top_bypasses()` (exists, line 616) + a new `payload_efficacy` table fed by the fuzzer/WAF-bypass path. Tracks which **payload family + encoding mutation** beat which **defense class** — never the literal payload that hit a specific endpoint.

```json
{
  "payload_family": "xss.svg_onload",
  "mutation": "double_url_encode",
  "defense_class": "modsecurity_crs",
  "attempts": 20,
  "successes": 7,
  "fitness": 0.35,                            // successes/attempts, bounded
  "payload_hash": "sha256(family+mutation)[:16]",  // links to get_payload_fitness_history
  "schema_version": 2
}
```

### 5.1.6 What is explicitly NOT written

The following are **never** persisted to the cross-engagement store (enforced by the sanitizer's reject list and a unit test in `tests/test_learning_sanitizer.py`):

- Raw target hostnames, IPs, URLs, subdomains, ports.
- Response bodies, screenshots, evidence blobs, `poc_request` strings.
- Recovered credentials, session tokens, cookies, API keys, JWTs.
- CTF flags (`HTB{...}`, `flag{...}`, natas passwords) — currently leaking in `viper_memory.json`.
- Any value that appears in *any* engagement's scope file.
- Per-engagement `findings_raw` / `submissions` business data (these stay in the per-hunt audit log + HTML report under `state/hunts/`, scoped to one engagement and never cross-pollinated).

> **Per-engagement vs cross-engagement boundary:** raw run data lives only in the *per-engagement* audit log (`AuditLogger.for_hunt`, `state/hunts/<id>/`) and the generated HTML report — both already engagement-scoped and never read by the learning loop. Only the four sanitized record classes above cross the boundary into `data/evograph.db`.

### 5.1.7 Controlled vocabularies

`fp_reason`, `attack_type`, `payload_family`, `defense_class`, `waf_class` are **closed enums** defined in `core/learning_vocab.py`. Free-text is rejected at write time. This (a) prevents unbounded cardinality growth, (b) makes the substring-`LIKE %x%` over-matching defect in `evograph.py` moot by switching its queries to exact enum equality, and (c) stops operator-supplied raw strings from smuggling target data through a "reasoning" field.

---

## 5.2 Retention policy: TTL, max size, rotation, anti-poisoning

Owned by `core/evograph.py` (new `prune()` + `rotate()` methods) and a daily maintenance task in `viper_daemon.py`. Replaces the current state where `viper_memory.json` has **no TTL, no rotation, and unbounded `learned_patterns`/`target_history`/`techniques`/`hackerone_hunts`**.

### 5.2.1 TTL

| Record class | TTL | Decay |
|---|---|---|
| Finding patterns (`attack_history`) | 180 days | reward multiplied by `0.5^(age_days/90)` before use |
| FP signatures | 365 days | none (FPs stay valid long) |
| Target fingerprints | 90 days OR until `observed_count` re-corroborated | `observed_count` decays −1 per 30 idle days |
| Payload efficacy | 120 days | `fitness` decayed by recency-weighted EWMA |

`prune()` runs on `EvoGraph.__init__` (cheap, indexed `WHERE timestamp < cutoff`) and nightly. Aggregate rows (`tech_attack_map`, `payload_efficacy`) are **never** deleted by TTL — only their *raw* contributing `attack_history` rows are; the aggregate counters are recomputed from survivors so long-term priors survive while raw per-event rows expire.

### 5.2.2 Max size & rotation

- **Hard row caps** (replacing the current 500/200 in-memory slice): `attack_history` ≤ 50,000 rows, `reasoning_traces` ≤ 20,000, `q_snapshots` ≤ 10,000 (fixes the audited "unbounded `q_snapshot` growth"). On overflow, **lowest-reward / oldest** rows are evicted first (`DELETE ... ORDER BY reward ASC, timestamp ASC LIMIT n`).
- **DB size cap:** 256 MB. On breach, `rotate()` archives the current `evograph.db` to `data/evograph_archive/evograph-<date>.db` (gzip), recreates a fresh DB, and **re-seeds only the aggregate tables** (`tech_attack_map`, `fp_signatures`, `payload_efficacy`) — i.e. learned priors survive rotation, raw history does not.
- **Atomic writes:** all JSON-side writes (if `viper_memory.json` is retained for compat) move to tmp-file + `os.replace`, fixing the audited non-atomic write-per-event corruption hazard. SQLite already uses WAL (`evograph.py:33`), so the JSON path is the only one needing this fix.

### 5.2.3 Anti-poisoning

Because patterns from one run alter behavior on the next, a corrupted/adversarial run could poison the store (e.g. a honeypot target that "confirms" everything to make VIPER waste budget, or to bias it toward a destructive technique). Mitigations, owned by `core/evograph.py:record_attack()` validators + `core/learning_sanitizer.py`:

1. **Bounded rewards.** Reward clamped to `[-1.0, 1.0]` at write. Rejects the audited "similarity heuristic can exceed 1.0" class of bug.
2. **Corroboration floor (k-anonymity).** No pattern influences technique selection until corroborated by `>= 3` distinct engagements (`engagement_id_hash` count). Single-source patterns sit in quarantine and are non-authoritative.
3. **Provenance + quarantine.** Every record stores `engagement_id_hash` and a `trust` field (`unverified | lab_passed | promoted`). Only `lab_passed`+ records influence live attack selection. A run flagged anomalous (FP rate > 0.9, or 100% success — both honeypot tells, cf. the Whatnot hunt's recorded `fp_rate: 0.95`) is written with `trust=unverified` and `weight=0`.
4. **Schema-version + signature.** Each record carries `schema_version`; on load, `evograph._validate_schema()` (exists, line 204) rejects mismatches instead of silently swallowing (fixes the audited "broad `except Exception` swallowing DB errors" — these now log + quarantine rather than return empty).
5. **No raw-string influence.** Because selection keys are closed enums (5.1.7), an attacker cannot inject a free-text technique name that smuggles a payload or target.
6. **Outlier rejection.** A pattern whose success rate deviates > 3σ from the rolling mean for its `tech_signature` is quarantined for manual review rather than auto-promoted.

---

## 5.3 Pattern-ingestion lifecycle: source → validation → LAB test → promotion

A learned pattern is allowed to influence VIPER's **live attack selection** (and, at the top tier, be written into `core/attack_patterns.py`) only after passing every gate below. The pipeline is one-directional; a pattern cannot skip a stage.

```
[1] SOURCE            [2] SANITIZE+VALIDATE      [3] QUARANTINE        [4] LAB TEST           [5] PROMOTION
hunt teardown   ->   learning_sanitizer.py  ->  evograph.db        -> labs/ regression  ->  core/attack_patterns.py
(per-engagement)     finding_validator.py       (trust=unverified)    runner (trust=        (trust=promoted,
                     secret_scanner.py                                 lab_passed)            human-approved)
```

### Stage 1 — Source
- **Owner:** `core/hack_mode.py` teardown → new `core/learning_recorder.py`.
- **Input:** the per-engagement finding list + audit events.
- **Action:** emit raw candidate records. Nothing is shared yet; this is engagement-local.

### Stage 2 — Sanitize + Validate
- **Owner:** `core/learning_sanitizer.py` (redaction, §5.1.1) → `core/finding_validator.py` (behavioral confirmation).
- **Gate:** record must (a) survive sanitization with zero residue, (b) be re-confirmed by `finding_validator` (not just "the worker said exploited=true"), (c) map to a closed-vocab `attack_type`. Failures are routed to **FP signatures** instead of finding patterns.
- **Writes:** `trust=unverified` rows into `evograph.db`. **Cannot yet influence live selection.**

### Stage 3 — Quarantine
- **Owner:** `core/evograph.py`.
- **Gate:** record accrues corroboration (`observed_count >= 3` distinct engagements) and stays within outlier bounds (§5.2.3). Quarantined records have `weight=0` in `get_best_attacks_for_tech()` so they do not steer hunts.

### Stage 4 — LAB test (mandatory, automated)
- **Owner:** `labs/` regression harness driven by a new `tests/test_pattern_promotion.py` + `benchmark/harness/runner.py` (already runs against safe targets with `is_safe_target()` enforcement).
- **Gate:** the candidate pattern's payload family is fired **only against `labs/` and RFC1918/CTF safe targets** (Juice Shop, DVWA, local containers). Promotion requires:
  - reproduced on ≥ 2 distinct lab targets of the matching `tech_signature`,
  - **zero** destructive side-effects (read-only assertion; any write/DROP/DoS signal → permanent reject),
  - measured success rate ≥ 0.6 and FP rate ≤ 0.1 in the lab,
  - passes the authorized-use gate (§5.4).
- On pass → `trust=lab_passed`; the pattern now influences live selection via `evograph.get_best_attacks_for_tech` / `load_best_q_table`.
- **No pattern is ever lab-tested against a real/external target.** The harness hard-fails if the lab target resolves outside `guardrail_hard.is_safe_target()`.

### Stage 5 — Promotion into `core/attack_patterns.py`
- **Owner:** `core/attack_patterns.py` is **append-only and human-gated.** A `lab_passed` pattern that has additionally proven itself across ≥ 5 engagements and ≥ 3 lab targets generates a **proposed `AttackPattern` dataclass diff** (via `core/pattern_promoter.py`), written to `state/pattern_proposals/`. It is **not** auto-merged.
- **Gate criteria for the human reviewer / approval gate:**
  1. `trust=lab_passed`, corroboration ≥ 5 engagements.
  2. Sanitizer attests **zero** target identity / secret residue in the generated `payloads`, `attack_steps`, `real_world_examples` fields.
  3. No destructive payload in the `payloads` list (the §5.4 gate must pass; this also fixes the audited `DROP TABLE` string sitting in `attack_patterns.py:249`).
  4. Reviewer approves via `core/approval_gate.py` (`check_tool_confirmation`-style flow) — **never** auto-approved, even in daemon/CTF mode.
- Only after explicit approval does the new `AttackPattern` enter `PATTERNS`. The proposal records the approving identity + timestamp in the audit log.

> **Why a human gate at Stage 5:** `core/attack_patterns.py` is the curated, canonical playbook. Auto-writing to it from machine-learned data would let a poisoned/honeypot run permanently bias the core methodology. Stages 1–4 are automated and bounded; Stage 5 is deliberately the one manual choke point.

---

## 5.4 Hard authorized-use gate (blocks weaponization learning)

A **fail-closed, deterministic, non-LLM** gate that runs at three points: (a) Stage-2 ingestion, (b) Stage-4 lab test, (c) Stage-5 promotion. Owned by a new `core/learning_authz_gate.py`. It refuses to learn, store, lab-test, or promote any pattern whose intent is offensive capability *beyond authorized vulnerability assessment*. This is independent of, and in addition to, the scope/RoE guardrails.

### 5.4.1 Blocked capability classes (hard deny — pattern dropped, audited, never stored)

| Class | What is blocked | Detection |
|---|---|---|
| **Malware authoring** | Patterns that build/encode droppers, ransomware, wipers, downloaders, packers, polymorphic stubs | keyword/AST signatures: `encrypt_files`, `ransom`, `dropper`, `shellcode_loader`, payload that writes+executes a second-stage binary |
| **Post-exploit persistence** | Backdoor install, cron/systemd/registry/run-key persistence, SSH-key implant, scheduled-task implant, web-shell upload | technique tags `persistence.*`, `webshell.*`, `implant.*`; any payload writing to autostart locations |
| **C2 / beaconing** | Establishing command-and-control, reverse shells intended as persistent channels, beacon stagers, DNS/HTTP C2 tunnels | tags `c2.*`, `beacon.*`, `reverse_shell.persistent`; outbound-callback payloads |
| **Evasion / anti-forensics** | AV/EDR bypass, log deletion, anti-forensics, timestomping, sandbox-detection-for-evasion | tags `evasion.av_bypass`, `antiforensics.*`, `log_clearing`; the existing WAF-bypass *for vuln-confirmation* is explicitly allow-listed and distinguished from EDR/AV evasion |
| **Destructive payloads** | `DROP TABLE`, `rm -rf`, `DELETE FROM`, fork bombs, mass-delete, DoS amplifiers | regex + AST over payload family; also blocks the literal `"test'); DROP TABLE users;--"` currently in `attack_patterns.py:249` and `ai_techniques.py:699` |

### 5.4.2 Gate logic (fail-closed)

```
authz_check(pattern) -> ALLOW | DENY:
  1. classify(pattern.attack_type, pattern.payload_family, pattern.mutation) via closed-vocab map
  2. if class in BLOCKED_CLASSES        -> DENY  (drop, audit reason=blocked_capability)
  3. if payload matches DESTRUCTIVE_RE  -> DENY  (drop, audit)
  4. if intent ∈ {persistence, c2, evasion, malware}  -> DENY
  5. if classification fails / ambiguous -> DENY    (default-deny; never learn the unknown)
  6. else                                -> ALLOW   (read-only vuln-assessment tactic only)
```

- **Default-deny on ambiguity** (step 5): unlike the audited scope guardrails that fail *open* for unknown domains, this gate fails *closed* for unknown capability — an unclassifiable pattern is never learned.
- **Distinguishes assessment vs weaponization.** Confirming a vuln read-only (e.g. time-based SQLi probe, reflected-XSS marker, SSRF to a benign canary) is **ALLOW**. Turning that same primitive into a persistent web-shell, a C2 channel, a credential-exfil loop, or a destructive action is **DENY**. The discriminator is the *post-confirmation action*, encoded in the technique's closed-vocab tag.
- **Scope of effect:** a DENY here means VIPER will not *store, generalize, lab-test, or promote* that capability — it does not retroactively change what a worker did on a single authorized engagement, but it guarantees the behavior is never amplified into VIPER's cross-engagement playbook.
- **Audited + non-bypassable.** Every DENY is written to the audit log with the capability class. The gate has **no `auto_approve` path** and is not affected by `--no-guardrail`, `allow_destructive`, or CTF/Lab profile flags — those affect *one engagement's* live actions, never the learning loop. (This closes the audited risk that `detect_profile` forces `allow_destructive=True` for CTF/private-IP targets: even in that mode, persistence/C2/malware/evasion tactics are never learned or promoted.)

### 5.4.3 File ownership summary

| Step | Owning file(s) |
|---|---|
| Emit raw candidates | `core/hack_mode.py` → `core/learning_recorder.py` |
| Redact target data / secrets / flags | `core/learning_sanitizer.py` + `core/secret_scanner.py` |
| Behavioral re-validation / FP routing | `core/finding_validator.py` |
| Closed vocab enforcement | `core/learning_vocab.py` |
| Store + TTL + rotation + anti-poison | `core/evograph.py` (`record_attack`, `prune`, `rotate`, `_validate_schema`) |
| Authorized-use gate (malware/persistence/C2/evasion/destructive) | `core/learning_authz_gate.py` |
| Lab test harness | `labs/` + `benchmark/harness/runner.py` + `tests/test_pattern_promotion.py` |
| Promotion proposal → human approval | `core/pattern_promoter.py` → `core/approval_gate.py` → `core/attack_patterns.py` |
| Nightly maintenance (prune/rotate) | `viper_daemon.py` |
| Legacy store to deprecate | `memory/viper_memory.json` + `archive/old_agents/agentic_viper.py:Memory` |

---

### Migration note
`memory/viper_memory.json` and its archived `Memory` writer are **deprecated** by this design. Its on-disk records currently violate §5.1.6 (cleartext `HTB{...}` flags, natas passwords) and §5.2 (no TTL, unbounded growth, non-atomic writes). Migration: run the sanitizer over the existing file once, drop every record failing redaction (expected: all flag/password rows dropped), map survivors to the §5.1 schemas, write them into `evograph.db` at `trust=unverified`, then archive the JSON file out of the live tree. `core/viper_db.py:migrate_from_json` must add the missing dedup + sanitize pass before it is allowed to run against this file.

---

**Files referenced (absolute paths):**
- `C:\Users\sharm\clawd\skills\hackagent\memory\viper_memory.json` (legacy store, to deprecate)
- `C:\Users\sharm\clawd\skills\hackagent\core\evograph.py` (live SQLite store; real methods: `record_attack` L316, `is_duplicate_finding` L306, `get_best_attacks_for_tech` L370, `get_top_bypasses` L616, `get_payload_fitness_history` L656, `get_failed_approaches` L435, `load_best_q_table` L472, `_validate_schema` L204)
- `C:\Users\sharm\clawd\skills\hackagent\core\attack_patterns.py` (promotion target; destructive payload at L249 to remove)
- `C:\Users\sharm\clawd\skills\hackagent\core\secret_scanner.py` (`scan_text` L497 — redaction primitive)
- `C:\Users\sharm\clawd\skills\hackagent\core\finding_validator.py` (FP validation)
- New files proposed: `core/learning_sanitizer.py`, `core/learning_recorder.py`, `core/learning_vocab.py`, `core/learning_authz_gate.py`, `core/pattern_promoter.py`

---

## SECTION 6 — Internal Lab for Safe Method Testing

Section 6 written to `C:\Users\sharm\clawd\skills\hackagent\docs\PLAN_section6.md` (the orchestrator can splice it into PLAN.md; no PLAN.md existed yet, so I did not overwrite anything).

Below is the section verbatim.

---

## SECTION 6 — Internal Lab for Safe Method Testing

### 6.0 Purpose & relationship to what already exists

VIPER already has two of the three pieces this section needs, and we build **on** them rather than around them:

- **`benchmark/`** — a working scoring harness. `benchmark/harness/targets.py` (`TargetManager`) brings docker / docker-compose / external targets up, health-polls them, tears them down. `benchmark/harness/runner.py` (`ViperRunner`) runs a real `viper.py` subprocess per challenge in isolation. `benchmark/harness/scorer.py` (`score()`) grades the run in `flag` or `vuln_class` mode against a `Challenge` spec. `benchmark/run_benchmark.py` loads a suite (e.g. `benchmark/suite/local.json`) and writes a JSON+MD scorecard.
- **`labs/`** — practice content: `labs/lab_manager.py` (`LabManager` already knows Juice Shop / DVWA / Metasploitable), `labs/interactive_lab.py`, walkthroughs, `labs/ctf_challenges/`.

What Section 6 adds: (1) an always-on, network-isolated docker-compose vuln stack (6.1); (2) a lab-runner that scores a *new attack pattern's* TP/FP/TTFF and promotes only past a threshold, reusing `harness/scorer.py` as oracle (6.2); (3) shadow mode (6.3); (4) hard network-isolation enforcement (6.4). New code lives under `benchmark/lab/` + `benchmark/suite/lab.json`; `targets.py`, `runner.py`, `scorer.py`, `models.py` are imported as-is.

### 6.1 The isolated vulnerable-app stack (docker-compose)

A single compose file (`benchmark/lab/docker-compose.lab.yml`) stands up five vulnerable targets (DVWA, Juice Shop, WebGoat, a vulnerable REST+GraphQL API via VAmPI/DVGA, and a SAML/OAuth/OIDC playground via dex + oauth2-proxy) on **one private bridge with `internal: true`** — Docker creates no NAT / default gateway, so **no egress**. No service publishes `ports:`, so the apps are unreachable from the host / VIPER's normal hunting interface. The only bridge-in is a `runner` container (the test driver, `cap_add: NET_ADMIN`, `VIPER_LAB_MODE=1`). Service hostnames (`dvwa.lab`, `juiceshop.lab`, …) resolve only inside `labnet` via Docker DNS. Companion suite `benchmark/suite/lab.json` uses the existing `Challenge` schema with `target.type:"external"` pointing at the in-network hostnames (full YAML + JSONC in the file).

### 6.2 The lab-runner: score a new attack pattern, promote only if it beats threshold

`benchmark/lab/lab_runner.py` answers "is *this new pattern* a net improvement" by running the lab suite twice — pattern off (baseline) vs on (candidate) — and diffing. It **reuses the existing harness as oracle** (imports `harness.runner.ViperRunner`, `harness.scorer.score`, `harness.targets.TargetManager`, `harness.models`). Ground truth = `expect.vuln_types` per challenge, plus **negative/control challenges** (`expect.vuln_types: []`) so FP-rate is measurable. Metrics: **TP-rate**, **FP-rate**, **TTFF** (time-to-first-finding), and **ΔTP/ΔFP** vs baseline. Promotion gate (tunable): `tp_rate≥0.60 AND fp_rate≤0.10 AND ΔTP≥0.05 AND ΔFP≤0.02 AND ttff not >1.5× baseline`. Patterns are `core/skill_prompts/<name>.py` modules and/or EvoGraph heuristics, toggled via forwarded `--enable-pattern`/`--disable-pattern` viper flags. Decisions persist to `benchmark/lab/pattern_registry.json` with tier `candidate → shadow → trusted`; **a pattern can never reach verdicts without a lab scorecard that beat the gate.**

### 6.3 Shadow mode

A `tier:"shadow"` pattern runs inside ordinary hunts on authorized targets but is fully quarantined: findings are tagged `shadow=True`, routed via `core/audit_logger.py` to `findings/shadow/<target>/<ts>.jsonl`, and **excluded** from `finding_validator.py` verdicts, reports (`report_narrative.py`/`html_reporter.py`), notifications (`finding_stream.py`), and production EvoGraph rewards. Shadow patterns are observe-only — they re-evaluate traffic trusted patterns already generated, adding **zero** extra requests (no scope/rate-limit impact). `benchmark/lab/shadow_promote.py` (nightly) graduates `shadow → trusted` once a stricter live gate clears (`fp_rate≤0.05` over `≥30` observations). Pipeline: `candidate ──(lab gate)──► shadow ──(live gate)──► trusted`.

### 6.4 Network-isolation enforcement (the hard guarantees)

Two invariants enforced **technically**:

- **(I1) Lab unreachable from normal hunting** — `labnet` is `internal:true` + `enable_ip_masquerade:false` (no NAT/gateway) and no app publishes `ports:`, so the host has no route to `172.31.0.0/24`; `*.lab` names resolve only inside the bridge.
- **(I2) Hunting interface can't reach arbitrary internet during a lab run** — three layers: (1) **runtime mode flag** `VIPER_LAB_MODE=1` collapses `tools/http_client.py`'s allowlist to labnet+RFC1918, refusing public hosts before a socket opens (same chokepoint as `guardrails.py`); (2) **kernel egress firewall** `egress_lockdown.sh` sets `iptables -P OUTPUT DROP` + allow lo/labnet/embedded-DNS only (runs via `NET_ADMIN`), so even an app-layer bypass is dropped by the kernel; (3) **fail-closed precondition** — `lab_runner.py` aborts before touching VIPER unless `VIPER_LAB_MODE=1` is set *and* a probe to a public host (e.g. `1.1.1.1`) fails. The flag flips the process between regimes; iptables + the probe are the backstops.

### 6.5 / 6.6

The file also includes the end-to-end operator workflow (compose up → `lab_runner.py --pattern … --promote-on-pass` → shadow during real hunts → `shadow_promote.py` → compose down) and a table of the 8 new files introduced versus the 11 existing files reused unchanged (`benchmark/harness/{targets,runner,scorer,models}.py`, `benchmark/run_benchmark.py`, `labs/lab_manager.py`, `core/skill_prompts/__init__.py`, `core/evograph.py`, `core/audit_logger.py`, `core/finding_validator.py`, `tools/http_client.py`).

---

## SECTION 7 — Truly Agentic Architecture

I have enough grounding. The existing tasks are unrelated to this writing task, so I'll ignore them. I now have a precise picture of what exists. Writing SECTION 7.

---

# SECTION 7 — Truly Agentic Architecture

VIPER today has *fragments* of agency scattered across `react_engine.py`, `think_engine.py`, `hacker_mind.py`, `orchestrator.py`, and `agent_state.py` — but they do not compose into a closed agentic loop, and the swarm path that actually runs (`hack_mode.py` → `swarm_coordinator.py`) bypasses them entirely. This section defines six properties an agent must satisfy, gives a *checkable* definition of each, maps it to the existing file(s), and specifies the minimal refactor to close the gap. Each property is grounded in code that already exists; the work is wiring and consolidation, not green-field.

The guiding constraint: **one typed tool layer (`core/tool_registry.py`) becomes the only path to the network, and the agentic loop's state (beliefs, goals, reflections) becomes a real object instead of an LLM prompt string.**

---

## 7.1 Goal decomposition — `target → sub-goals → tasks → tool calls`

**Checkable definition.** Given a target and an objective, the agent produces a *persisted tree*: one `Objective` → N `SubGoal`s → M `Task`s → K typed `tool_call`s, where every leaf tool call is traceable up to its parent objective, and completion of children rolls up to parents. Testable: `assert objective.subgoals[0].tasks[0].tool_calls[0].parent_task_id == task.id` and `assert objective.progress() == completed_tasks / total_tasks`.

**What exists.**
- `core/agent_state.py` — `ConversationObjective` (`:305`) and `ObjectiveManager` (`:651`, with `set_target`/`add_finding`/`to_dict`/`from_dict`) give the *top* of the tree. `TodoList`/`TodoItem` (`:76`, `:48`) give a flat *task* layer the LLM maintains (`from_llm_response` `:130`, `mark_completed_by_tool` `:158`, `to_prompt_string` `:126`).
- `core/think_engine.py` — the system prompt already asks the LLM for `updated_todo_list` and `tool_plan.steps[]` (`think_engine.py:72-83`), i.e. the LLM *already emits* a one-level decomposition each turn.
- `core/hacker_mind.py` — `_generate_hypotheses` (`:261`) and `_find_attack_chains` (`:350`) are an in-memory, non-LLM decomposition into typed `Hypothesis`/`AttackChain` objects.

**The gap.** The tree is **only two levels and only one of them is durable**. `ObjectiveManager` holds objectives; `TodoList` holds a *flat* task list with no link back to a sub-goal or forward to specific `tool_call` records. The `tool_plan` the LLM returns is consumed transiently (executed and discarded) — there is no `Task.tool_calls` edge. `hacker_mind`'s decomposition is unreachable dead code (per the audit: instantiated only in `archive/`). So nothing persists `objective → subgoal → task → tool_call` as a single inspectable structure.

**Minimal refactor.**
1. Add two dataclasses to `core/agent_state.py` beside the existing ones: `SubGoal{id, objective_id, description, status, tasks: List[TodoItem]}` and extend `TodoItem` with `subgoal_id` and `tool_call_ids: List[str]`.
2. Give `ObjectiveManager` a `decompose(objective, beliefs) -> List[SubGoal]` that calls the LLM **once** at objective start (reuse `think_engine`'s prompt machinery) and falls back to `hacker_mind._generate_hypotheses` when the LLM is unavailable — finally giving that dead code a live caller.
3. When `react_engine.reason_and_act` (`:138`) executes an action, stamp the resulting tool-call record id onto the active `TodoItem.tool_call_ids`. This is a ~5-line change at the existing execute site (`react_engine.py:306`).

Net: no new subsystem — `ObjectiveManager` + `TodoList` already exist; we add one middle node (`SubGoal`) and two parent/child id fields.

---

## 7.2 World model — beliefs about the target, updated per observation

**Checkable definition.** A single mutable `WorldModel` object holds the agent's *current beliefs* (open ports, technologies, endpoints, auth state, confirmed/suspected vulns, WAF presence) with a confidence per belief, and exposes `update(observation)` that is idempotent (replaying the same observation does not duplicate or inflate confidence) and monotonically improves the model. Testable: `wm.update(obs); snapshot = wm.snapshot(); wm.update(obs); assert wm.snapshot() == snapshot`.

**What exists (scattered, no single home).**
- `core/agent_state.py` — `TargetInfo` (`:228`) is *already a belief store*: `ports`, `services`, `technologies`, `vulnerabilities`, `credentials`, `sessions`, with a deduplicating `merge_from` (`:239`). This is the natural skeleton of the world model and is already idempotent via dedup.
- `core/hacker_mind.py` — `observe` (`:388`) and `process_response` (`:407`) ingest HTTP observations and categorize them; `get_status` (`:563`) emits a belief snapshot. But these are pure functions over per-instance state that nothing live calls.
- `core/evograph.py` — cross-*session* memory (Q-tables, success maps). This is the *long-term* belief store; the world model is the *per-hunt* belief store. They are complementary, not duplicates.

**The gap.** There is no single object that *is* the belief state and gets updated on every observation. `TargetInfo` is populated ad hoc by the legacy `full_hunt` path; the swarm path keeps findings in a flat `self._state["findings"]` list (`hack_mode.py:469`) with **no model** — which is exactly why Section 4's chaining stall happens (no beliefs → no planning over beliefs). `hacker_mind` has the update methods but no live owner.

**Proposed home.** Create `core/world_model.py` with a `WorldModel` dataclass that **wraps `TargetInfo`** (reuse, don't replace) and adds:
- `beliefs: Dict[str, Belief]` where `Belief{key, value, confidence, source, observed_at}`;
- `update(observation: Observation)` — delegates structural merges to `TargetInfo.merge_from` and confidence updates to a simple Bayesian-ish `max(existing, new)` rule (idempotent by construction);
- `to_prompt_section()` — replaces the free-text `target_info` blob currently interpolated into `think_engine`'s prompt (`think_engine.py:46`) with a structured, confidence-annotated view;
- backed at hunt-end by `evograph` for cross-session carryover.

`WorldModel.update` should be fed by **the tool layer** (7.5): every tool result returns an `Observation`, the loop calls `world_model.update(obs)`. This makes "updated per observation" a structural guarantee, not a convention. `hacker_mind.observe`/`process_response` become the *implementation* of `update` for HTTP observations (giving them a live caller).

---

## 7.3 Planning — choose the next sub-goal given beliefs + budget

**Checkable definition.** A `Planner.next(world_model, objective_tree, budget) -> Decision` that selects the highest-value *unblocked* sub-goal/task given current beliefs and remaining budget (time, iterations, per-phase), and never selects a task whose preconditions are unmet by the world model. Testable: with a belief "no open web port", the planner must not return a web-exploit task; with `budget.remaining_s < min_task_cost`, it must return `Decision(action="complete")`.

**What exists.**
- `core/think_engine.py` — *is* the planner today: it builds the prompt from phase/tools/trace/beliefs and returns an `LLMDecision` with `action ∈ {use_tool, plan_tools, transition_phase, complete, ask_user}` (`think_engine.py:69`). Deep-think triggers (first iter, phase change, failure streak) are a crude meta-planner.
- `core/react_engine.py` — `_think` (`:400`) / `_llm_think` (`:436`) drive it; `_check_deep_think_trigger` (`:565`) and `_check_failure_loop` (`:614`) are heuristic re-planning signals.
- `core/phase_engine.py` — `should_auto_advance` (`:269`) and `can_use_tool` (`:124`) constrain *which* plans are legal in the current phase.
- `core/evograph.py` — `recommend`/best-Q (per audit) is a **learned** planner input that the swarm path never consults.
- Budget primitives already exist: `hack_profile.get_phase_budget`, `max_iterations`, per-worker timeout (Section 4).

**The gap.** Planning is (a) **single-step and beliefs-blind** — `think_engine` plans the next *tool*, not the next *sub-goal*, and it reasons over a free-text `target_info` string rather than a structured world model; (b) **not budget-aware in the decision** — budget is enforced *externally* as a timeout that truncates work (`hack_mode.py:533`), not *internally* as an input that makes the planner choose cheaper/higher-value actions; (c) **ignores learned rewards** — the swarm picks techniques from a static profile list (`hack_mode.py:546`), never from `evograph`.

**Minimal refactor.**
1. Extract a thin `core/planner.py` `Planner` that takes `(WorldModel, ObjectiveManager, Budget)` and **delegates the actual reasoning to the existing `think_engine`**, but (i) injects `world_model.to_prompt_section()` instead of the free-text blob, (ii) injects `budget.summary()` into the prompt so the LLM plans against remaining budget, and (iii) filters candidate tasks through `phase_engine.can_use_tool` *before* asking the LLM, so illegal actions are never proposed.
2. Bias technique selection with `evograph` best-Q as a prior in the prompt (one extra context section) — closes the "static list vs learned rewards" gap noted in Section 4.
3. Precondition check: before returning a `use_tool` decision, assert the tool's required beliefs exist in the world model (e.g. an SQLi exploit task requires a belief `param_reflects_input`); if unmet, return the discovery sub-goal that produces that belief instead. This is the structural fix for "exploit workers stall instead of chaining" — planning now walks beliefs forward.

---

## 7.4 Reflection — post-phase: what was learned / wasted / next time

**Checkable definition.** After each phase (or iteration), the agent produces a structured `Reflection{learned: [...], wasted: [...], next_time: [...]}`, persists it, and feeds it into the *next* planning round so behavior measurably changes. Testable: a phase that produced zero findings but spent N tool calls yields a `Reflection` whose `wasted` lists those calls, and the next plan demotes the wasted techniques.

**What exists.**
- `core/think_engine.py` — the decision schema already has `output_analysis{interpretation, actionable_findings, recommended_next_steps}` (`:84-88`) and a `need_deep_think` self-flag (`:90`). This is *per-step* reflection, present but discarded after prompt assembly.
- `core/react_engine.py` — `_assess` (`:545`) writes a `final_assessment`; `_check_failure_loop` (`:614`) detects wasted repetition; `ReACTTrace` (`:40`) captures rewards per step (`total_reward`).
- `core/evograph.py` — `record_reasoning_step` (already called at `react_engine.py:337`) and the failure-lesson store are the **durable reflection sink** that exists but is only half-used.

**The gap.** Reflection is **per-step and ephemeral**, never aggregated into a phase-level "what did this phase accomplish vs cost" summary, and the swarm path (`hack_mode.py`) has a *dead* status line (`'success' if workers_failed == 0 else 'success'` — both branches identical, per the audit) where a real phase reflection should be. Lessons are recorded to `evograph` but the planner never reads them back within the same hunt.

**Minimal refactor.**
1. Add `Reflector.reflect(phase, trace, world_model_delta, budget_spent) -> Reflection` to `core/react_engine.py` (it already owns the trace and the failure-loop detector — reuse both). `learned` = beliefs added this phase; `wasted` = actions with reward ≤ 0 from `_check_failure_loop`; `next_time` = the LLM's `recommended_next_steps` already in `output_analysis`.
2. Persist via the existing `evograph` failure-lesson API and surface the `Reflection` to the narrator at the spot where `hack_mode.py` currently emits its dead-branch status (fix that line in the same edit).
3. Feed the last `Reflection` into the next `Planner.next` call as a prompt section. This closes the loop: reflection → next plan, which is the difference between a ReACT *loop* and a true *agent*.

---

## 7.5 Tool use — a single typed tool layer with scope + rate-limit + timeout + audit

**Checkable definition.** **Every** HTTP / DNS / subprocess action in the codebase passes through exactly one chokepoint, `core/tool_registry.ToolRegistry.execute()`, which, in order: (1) validates scope/RoE, (2) applies rate limiting, (3) enforces a per-tool timeout, (4) writes an audit-log record, then runs the handler. Testable by *grep*: zero direct `aiohttp`/`requests`/`urllib`/`subprocess` calls outside the handlers registered in the registry; and a registry call to an out-of-scope target raises before any socket opens.

**What exists.**
- `core/tool_registry.py` — already a clean typed registry: `ToolDefinition{name, tool_type, handler, is_dangerous, requires_approval, phases_allowed, timeout}` (`:27`), `register` (`:70`), `get_for_phase` (`:98`), `execute` (`:119`) with stats. It is **the right shape** — it just isn't the *mandatory* path.
- `core/roe_engine.py` — `enforce(tool, target, args, phase)` (`:268`) is the ready-made scope+tool+time+phase gate.
- `core/approval_gate.py` — `confirm_tool` (`:128`), name/arg dangerous detection (`DANGEROUS_TOOLS` `:52`, `DANGEROUS_ARG_PATTERNS` `:60`).
- Rate limiting / timeout primitives exist (`rate_limiter.py`, per-tool `timeout` field already on `ToolDefinition`).

**The gap — this is the single most important refactor.** `ToolRegistry.execute` (`:119`) **does none of the four steps** — it just calls `td.handler(**kwargs)` with stats. Scope and RoE live *elsewhere* and are bypassed by every real network path. From the safety audit, the live bypasses are concrete and must be closed:
- `core/swarm_workers/vuln/_http.py:88` (`fetch()` → raw `urllib`) — **no scope, no registry**.
- `core/ai_hunter/probes.py:156-161` — builds its own `urllib` opener — **no scope, no registry**.
- The 4 built-in engine runners in `core/swarm_engine.py` (sqli/xss/dir/subdomain, per audit `:222/255/281/306`) — raw `aiohttp` GETs with attack payloads — **no scope, no registry**.
- `viper_core._request` enforces scope only `if active_scope` (`viper_core.py:822`) — **fail-open when unscoped**.
- `react_engine` enforces RoE inline (`:258`) but then calls an injected `execute_fn` (`:306`) that is *not* the registry — so even the "good" path doesn't funnel through one typed layer.

**Minimal refactor (the keystone of Section 7).**
1. Make `ToolRegistry.execute` the chokepoint. Insert, before `td.handler(**kwargs)` (`tool_registry.py:127`), in order:
   - `roe_engine.enforce(name, target, args, phase)` → raise `ScopeViolationError` on deny (reuse the existing function verbatim);
   - **hard guardrail** `guardrail_hard.is_blocked(target)` (the audit shows `hack`/swarm path never calls it — wire it here so *all* paths get it);
   - `rate_limiter.acquire(host)`;
   - `approval_gate.confirm_tool(...)` when `td.requires_approval`;
   - wrap the handler in `asyncio.wait_for(..., td.timeout)` (the `timeout` field already exists, unused at `:127`);
   - emit one `audit_logger` record (start + result) regardless of outcome.
2. **Register the bypass paths as handlers.** Convert `_http.fetch`, `ai_hunter/probes`, and the 4 `swarm_engine` runners into registered tools (`ToolType.RECON`/`SCAN`/`EXPLOIT`) and replace their direct socket calls with `registry.execute(...)`. After this, the grep test in the checkable definition passes.
3. Point `react_engine`'s `execute_fn` and the swarm workers at `registry.execute` so there is exactly one execution path. RoE is then enforced *inside* the tool layer, so we can **delete** the now-redundant inline RoE block at `react_engine.py:258` (single source of truth).

This single change also fixes Sections (a)/(b) of the safety audit: with the registry as the only door, "fail-open when unscoped" becomes impossible because `is_blocked` + `roe_engine.enforce` run on **every** call, not just when a scope file is loaded.

---

## 7.6 Human-in-the-loop checkpoints via `core/approval_gate.py`

**Checkable definition.** Three classes of action always reach `core/approval_gate.py` before executing: (1) scope confirmation at hunt start, (2) **any write/modify/state-changing action on the target** (POST/PUT/DELETE, file upload, exploit, brute force, post-exploit), (3) report submission to an external platform. In non-interactive mode the gate must *fail closed by default* and only auto-approve when an explicit, audited opt-in is set. Testable: a registered tool with `is_dangerous=True` cannot execute in daemon mode unless `autopilot` was explicitly enabled, and every auto-approval writes an audit record.

**What exists.**
- `core/approval_gate.py` — full machinery: `confirm_tool` (`:128`), `check_phase_transition` (`:207`), `check_tool_execution` (`:281`), `check_tool_confirmation` (`:353`), `ask_question` (`:417`); dangerous detection by name (`:52`) and by argument pattern (`:60`). Structured y/m/n flow.
- `core/agent_state.py` — `ToolConfirmationRequest` (`:285`) and `PhaseTransitionRequest` (`:267`) are the typed payloads the gate consumes.
- `core/tool_registry.py` — `ToolDefinition.requires_approval` / `is_dangerous` (`:35`) already mark which tools need a checkpoint, and `get_dangerous()` (`:103`) enumerates them.

**The gap (from the safety audit).**
- The gate is a **no-op for daemon/dashboard hunts**: `auto_approve=True` silently approves everything across all methods, and detached hunts run `stdin=DEVNULL`, so the gate never prompts. This is *fail-open by default*, the opposite of the checkable definition.
- **Coverage gap:** the dangerous set is keyed on *VIPER tool names*; the raw-`urllib` worker/probe traffic isn't modeled as a tool, so write/modify actions those paths perform never reach the gate.
- **Bug:** `check_phase_transition` (`approval_gate.py:240-242`) references `request.from_phase` but the parameter is `request_or_from_phase` → `NameError` in interactive mode.

**Minimal refactor.**
1. Because 7.5 makes `ToolRegistry.execute` the only execution path and already calls `confirm_tool` when `requires_approval`, the coverage gap closes *for free* once the bypass paths are registered — the write/modify workers become tools and inherit the checkpoint.
2. Mark all state-changing tools `is_dangerous=True` at registration (POST/PUT/DELETE HTTP verbs, `file_upload`, every `exploit/*` and `post/*` worker, submission tools). Map "any write/modify on target" to an HTTP-method check in `DANGEROUS_ARG_PATTERNS` (`approval_gate.py:60`) so verb-based detection is automatic.
3. Flip the default: `auto_approve` must require an explicit `--autopilot yolo`-style flag (per the safety audit recommendation), and every auto-approval emits an audit record. Daemon mode without that flag → fail closed (skip the dangerous tool, log, continue).
4. Fix the `check_phase_transition` `NameError` by normalizing to a `PhaseTransitionRequest` first (the function already does this at `:225-228` for the other branch — reuse it).
5. Add the two missing first-class checkpoints as explicit gate calls: scope confirmation in `hack_cli.run_hack_cli` *before* constructing `HackMode` (currently absent — the audit shows `hack` mode never calls the hard guardrail), and report-submission confirmation in the submission path.

---

## 7.7 Where we are vs the target, and the minimal path

**Today's reality.** `react_engine` + `think_engine` + `agent_state` already implement a *single-step, LLM-driven ReACT loop with inline RoE and a flat todo list*. `hacker_mind` implements a *richer cognitive decomposition + world-update model that is dead code*. `tool_registry`, `approval_gate`, `phase_engine`, `roe_engine` are *correct, typed, well-shaped components that are not on the critical path* — the swarm pipeline (`hack_mode`/`swarm_coordinator`/swarm workers) that actually runs reaches almost none of them, which is why Section 4's chaining stalls and the safety audit's bypasses exist. We have all the *parts* of an agent and none of the *loop*.

**The gap in one sentence.** VIPER reasons (think_engine), but does not maintain durable beliefs, does not plan over those beliefs, does not reflect across phases, and does not funnel actions through one guarded tool layer — so its "agency" is a per-step prompt, not a goal-directed loop.

**Minimal refactor to close it (ordered, each builds on the last):**

1. **Tool layer first (7.5).** Make `ToolRegistry.execute` the mandatory chokepoint (scope → guardrail → rate-limit → approval → timeout → audit) and register the three bypass paths (`_http`, `probes`, `swarm_engine` runners). *This one change closes most of the safety audit and gives every later step a clean observation/action boundary.* Highest value, ~self-contained.
2. **World model (7.2).** Add `core/world_model.py` wrapping `TargetInfo`, fed by tool-layer `Observation`s; route `hacker_mind.observe`/`process_response` into it (resurrecting that code).
3. **Goal tree (7.1).** Add `SubGoal` between `ObjectiveManager` and `TodoList`; have `ObjectiveManager.decompose` fall back to `hacker_mind._generate_hypotheses`.
4. **Planner (7.3) + Reflector (7.4).** Wrap `think_engine` in a thin `Planner` that consumes the world model + budget + last reflection + `evograph` priors; add `Reflector.reflect` using the trace and failure-loop detector already in `react_engine`; feed reflection back into planning. Fix the dead status branch in `hack_mode.py` here.
5. **Checkpoints (7.6).** Flip `approval_gate` to fail-closed-by-default, mark write/modify tools dangerous, fix the `check_phase_transition` `NameError`, and add the scope-confirm and submission checkpoints.

No new frameworks, no LangGraph — every step reuses an existing module and mostly adds *edges* (id links, a chokepoint, a feedback line) rather than new subsystems. The largest single lift is step 1 (registering the bypass paths); the rest is wiring code that already exists into a loop it was clearly designed for but never connected to.

---

**Files touched by this section (all existing unless marked NEW):** `core/tool_registry.py`, `core/roe_engine.py`, `core/approval_gate.py`, `core/phase_engine.py`, `core/react_engine.py`, `core/think_engine.py`, `core/agent_state.py`, `core/hacker_mind.py`, `core/evograph.py`, `core/hack_mode.py`, `core/swarm_engine.py`, `core/swarm_workers/vuln/_http.py`, `core/ai_hunter/probes.py`, `core/guardrail_hard.py`, `core/hack_cli.py`, plus **NEW** `core/world_model.py` and **NEW** `core/planner.py`.

---

## SECTION 8 — Phased Build Order

I have what I need: the benchmark harness (`benchmark/run_benchmark.py` solve-rate scorecard, `benchmark/_selftest/run_selftest.py` deterministic 2/4 harness check), the scorer modes (flag / vuln_class), and the test suite names. Here is SECTION 8.

---

# SECTION 8 — Phased Build Order

Five phases, gated. No phase starts until the prior phase's exit criteria are green. Phase-1 fixes are drawn from the audit; the highest-severity theme across the audit is **scope/RoE is enforced only at init or fully delegated downstream** (`orchestrator.py`, `hack_mode.py`, `swarm_coordinator.py`, `swarm_engine`/daemon all dispatch network workers with no per-action scope check), so Phase 1 lands the typed scope-check layer that Phases 2–5 build on.

---

## Phase 1 — Foundations (audit fixes, scope-check hardening, typed tool layer)

**Goal:** make every target-affecting call pass through one typed, scope-checked seam; fix the crash/silent-fail/data-loss bugs the audit found. No new features.

**Phase-1 fix list (from audit top issues):**

| # | Module | Fix |
|---|--------|-----|
| F1 | `core/swarm_engine.py` + `swarm_worker_daemon.py` + engine runners | Insert a mandatory `scope/RoE/guardrail` gate in the dispatch path: `handle_job` (daemon:56) and all 4 engine runners (222/255/281/306) must reject any target not validated against `scopes/current_scope.json` before any aiohttp call. **Default-deny.** |
| F2 | `core/orchestrator.py` | Add per-call scope/RoE/phase re-check inside `_execute_tool` (427) and `_run_one` — not just at `_initialize`. |
| F3 | `core/hack_mode.py` | Refuse to dispatch active phases when `profile.use_scope_reasoner=True` and `scope_reasoner is None` (line 549); stop passing `None` through unverified. |
| F4 | `core/swarm_coordinator.py` | Add explicit RoE/scope assertion in `handle_message` (174) before `build_manifest`; cap `VulnSwarmCoordinator.build_manifest` (workers×assets) to a max manifest size. |
| F5 | `core/hack_profile.py` | `detect_profile` (286/302–305) must not force `allow_destructive=True`+`use_scope_reasoner=False` for CTF-regex hostnames / private IPs without an explicit `--go`/local-flag confirmation. |
| F6 | `core/hack_cli.py` + `hack_mode.py` | Make scope-load/reasoner-build failure **fail-closed** (currently `[WARN]` + `scope_reasoner=None`, lines 166–167/253–256). |
| F7 | `core/hacker_mind.py` | Guard `generate_payload` IDOR `int(base_id)` (546–555) with try/except; add `think()` dispatch for `POST_EXPLOITATION`/`REPORTING`; replace `md5(datetime.now())` `_gen_id` (559) with a collision-free id (uuid4/counter). |
| F8 | `core/hack_mode.py`, `swarm_coordinator.py`, `swarm_engine.py`, `evograph.py` | Replace silent `except: pass`/`continue` with logged handlers: `_check_named_stop` (522), `bus.stop()` (354), `Post._approve` (938), engine runners (250/276/301/325), EvoGraph (613/653/669/720). |
| F9 | `core/ai_techniques.py` | Gate `scan_endpoint` (1135) and `run_parallel_attack` (616) behind scope/RoE; remove destructive `DROP TABLE` payloads (here + `attack_patterns.py:249`). |
| F10 | `core/swarm_worker_daemon.py` | Fix dispatch bug: `get_worker_runner` (workers/__init__:41) raises `KeyError` but daemon (67–70) expects `None` — make the registry return `None` or catch `KeyError`; correct the **30 (not 28)** worker count. |
| F11 | `core/bounty_hunter.py` | Atomic writes (tmp+rename) + error handling on `_load`/`_save`/`_save_program`; redact evidence/payload in report formatters (314/341); fix `list_targets` return type; absolute/config-driven paths. |
| F12 | `core/hack_mode.py`, `hack_cli.py`, `bounty_hunter.py`, `swarm_engine` | Replace cwd-relative defaults (`state/hunts`, `data/viper.db`, `skills/hackagent/...`) with resolved/config paths. |
| F13 | Memory (`viper_memory.json`) | Redact secrets/flags/passwords before persist; atomic write; add idempotency/dedup; log-on-corrupt instead of silent skeleton reset. (Legacy/archived path — fix or formally retire.) |

- **Entry criteria:** Audit accepted; current `tests/` suite green on `main`; this fix list frozen.
- **Exit criteria:** All F1–F13 landed. No target-affecting call path reaches the network without passing the typed scope seam (verified by grep + the new guard tests). Zero new silent `except: pass` in touched files. `python -c "from viper_core import ViperCore"` OK.
- **Test plan:**
  - `pytest tests/test_guardrails.py tests/test_roe_engine.py tests/test_scope_reasoner.py -q` — scope seam.
  - `pytest tests/test_swarm_workers_*.py tests/test_swarm_coordinator.py -q` — workers reject out-of-scope targets (add a negative-path test: out-of-scope target → zero network calls, raises/blocks).
  - `pytest tests/test_hack_cli.py tests/test_hack_profile.py tests/test_hack_mode.py -q` — fail-closed scope, `detect_profile` no longer auto-enables destructive.
  - `pytest tests/test_evograph.py -q` — logged DB errors.
  - Full `pytest tests/ -q` must stay green.
- **Rollback:** Each fix is an isolated commit behind the existing seam; revert per-commit. The scope gate ships **fail-closed**, so a reverted gate blocks rather than floods. Tag `phase1-baseline` before starting.

---

## Phase 2 — HackMode orchestrator + coordinators wired end-to-end

**Goal:** one `viper.py hack <target>` drives HackMode → 4 real coordinators (Recon→Vuln→Exploit→Post) → swarm engine, with the Phase-1 scope seam enforced at every hop. Resolve the phantom 5th coordinator.

- **Entry criteria:** Phase 1 exit green. Scope seam (F1–F4) merged and exercised.
- **Exit criteria:**
  - HackMode dispatches all 4 coordinators end-to-end against a local lab target; findings flow phase→phase over the bus.
  - **`ReportSwarmCoordinator` resolved:** either implemented as a real coordinator or the false claim removed from `hack_mode.py:18` docstring and `_NoOpCoordinator`/`_write_report` documented as the report path.
  - Per-tool timeout, concurrency cap, and per-host rate limit enforced in `_execute_plan`/engine (closes orchestrator audit issues: no timeout, unbounded `gather`, no throttle).
  - Timeout path reports **real** completed/failed stats (fix `_run_manifest` 237–247 bogus 0/0).
  - `_DefaultApprovalGate` no longer auto-approves exploitation transitions silently; Exploit/Post gated.
- **Test plan:**
  - `pytest tests/test_hack_mode.py tests/test_swarm_coordinator.py tests/test_state_machine.py tests/test_approval_gate.py -q`.
  - `pytest tests/test_hack_phase5.py -q` (resume/rate-limit/per-phase budget/dedup already covered there).
  - New integration test: HackMode against `tests/vuln_server.py` → asserts a recon finding chains into a vuln-phase job, and asserts the engine never exceeds the concurrency cap / per-host rate.
- **Rollback:** Coordinators are pluggable per phase via the manifest; revert to `_NoOpCoordinator` for any phase that regresses without breaking the loop. Tag `phase2-e2e`.

---

## Phase 3 — Persistence loop + finding chaining + evograph

**Goal:** cross-session memory and finding chaining work for real: findings persist, dedup, feed the next phase, and update EvoGraph Q-tables. **This is the first phase tied to the benchmark harness** (solve rate must not regress).

- **Entry criteria:** Phase 2 exit green. EvoGraph audit fixes (F8) in.
- **Exit criteria:**
  - Persistence loop (phases × iterations) drives EvoGraph: success/failure maps, ReACT traces, attack chains, failure lessons all write and read back.
  - `is_duplicate_finding` fixed (matches the right column, honors `url`, audit 306–312); no unbounded table scans (LIMIT added, 295/543/699); no runtime DDL in read paths (586/622).
  - FindingDedup is idempotent across iterations — repeated `think()`/re-publish does not accumulate dup hypotheses/findings (closes `hacker_mind` non-idempotency + swarm dup-job issues).
  - `migrate_from_json` dedups on re-run.
- **Test plan (benchmark-tied):**
  - `pytest tests/test_evograph.py -q` — extend to cover the ~17 untested public methods.
  - `python benchmark/_selftest/run_selftest.py` — **must exit 0** (deterministic 2/4 solved, rate 50.0%); proves persistence loop doesn't break the harness contract.
  - `python benchmark/run_benchmark.py --suite suite/local.json --time 10` — record solve rate; **Phase-3 gate: solve rate ≥ Phase-2 baseline** (chaining must not lower it). Compare the `scorecard_*.json` solve_rate_pct against the pre-Phase-3 card.
  - `pytest tests/test_chain_writer.py tests/test_finding_validator.py -q`.
- **Rollback:** EvoGraph is a side-store; gate writes behind a `persist_enabled` flag — disabling it reverts to in-memory-only chaining without touching the loop. DB schema changes ship as additive migrations (no destructive `ALTER`). Snapshot `data/viper.db` and tag `phase3-memory` before enabling.

---

## Phase 4 — Dashboard wired to every backend surface + typed API contract

**Goal:** dashboard reads every backend surface (hunts, findings, swarm/phase events, EvoGraph, reports) over one typed API contract — no mock data, no untyped endpoints.

- **Entry criteria:** Phase 3 exit green. Backend emits swarm/phase/audit events on the bus (Phase 2) and findings/chains persist (Phase 3).
- **Exit criteria:**
  - Every dashboard page (overview, agents, graph, hack, recon, insights, targets, terminal, cypherfix, chat) is backed by a real endpoint; `lib/types.ts` matches server response shapes (typed contract, both ends).
  - SSE/stream surfaces live hunt + swarm phase progress.
  - `dashboard/launch.py` brings up UI + API together; no endpoint returns stub/placeholder data.
  - Terminal allowlist + scope rules from Phase 1 enforced on any target-directed dashboard action.
- **Test plan:**
  - `pytest tests/test_dashboard_hack_api.py -q` — extend to cover each new endpoint's response schema against `lib/types.ts`.
  - Contract test: for every endpoint, assert the JSON shape matches the TS type (schema snapshot test).
  - Manual smoke via `python dashboard/launch.py`: launch a hunt from `/hack`, confirm findings/phase events render live, confirm graph reads EvoGraph.
- **Rollback:** Frontend and API version independently; the typed contract is versioned, so a regressed endpoint reverts to its prior version while the page falls back to last-good. Dashboard is read-mostly — reverting it cannot corrupt hunt state. Tag `phase4-dashboard`.

---

## Phase 5 — Lab + self-improvement + agentic planning layer

**Goal:** closed-loop self-improvement — VIPER runs the lab/benchmark, learns from outcomes (EvoGraph + failure lessons), and an agentic planning layer adjusts strategy. **Measured directly by the benchmark harness.**

- **Entry criteria:** Phases 1–4 exit green. EvoGraph persistence + chaining proven (Phase 3); benchmark solve rate recorded as the improvement baseline.
- **Exit criteria:**
  - Lab targets run end-to-end under HackMode with destructive workers gated to lab/CTF only (Phase-1 F5 honored — no destructive default on real-target regex).
  - Self-improvement loop: failure lessons + Q-table updates measurably change subsequent planning (planner consults EvoGraph before phase dispatch).
  - Agentic planning layer chooses phase/worker order from learned signal, not a fixed manifest.
  - **No scope/safety regression** — all Phase-1 guards still enforced under the planner's dynamic choices.
- **Test plan (benchmark + tests harness-tied):**
  - `python benchmark/_selftest/run_selftest.py` — exit 0 (harness still honored end-to-end).
  - `python benchmark/run_benchmark.py --suite suite/xbow/...` (flag mode) and `--suite suite/local.json` (vuln_class mode) — **Phase-5 gate: solve rate strictly ≥ Phase-3 baseline**, ideally improving across repeated runs as EvoGraph learns. Diff successive `scorecard_*.json` solve_rate_pct.
  - `pytest tests/test_hack_phase5.py tests/test_mind_pipeline.py tests/test_ai_hunter.py tests/test_ai_hunter_generator.py -q` — planning + AI-hunter layer.
  - Determinism guard: run the same suite twice with learning **off** → identical solve rate (proves the planner, not noise, drives any gain).
  - Full `pytest tests/ -q` green; safety negative-path tests from Phase 1 still pass under dynamic planning.
- **Rollback:** Planner is advisory behind a `use_agentic_planner` flag — disabling it falls back to the Phase-2 fixed manifest order with all Phase-1 safety intact. EvoGraph learning input is read-only to the planner, so a bad plan can't corrupt memory. If a benchmark run regresses solve rate, disable the flag and re-baseline. Tag `phase5-selfimprove`.

---

**Cross-phase invariants (hold at every exit gate):** (1) `pytest tests/ -q` green; (2) no new silent `except: pass` on target/DB/bus paths; (3) every target-affecting call passes the Phase-1 scope seam — verified by the swarm/coordinator negative-path tests; (4) `benchmark/_selftest/run_selftest.py` exits 0 from Phase 3 onward; (5) benchmark solve rate is non-decreasing Phase 3 → 5.

---

## SECTION 9 — Risk Register

Confirmed. The dashboard has CORS/same-origin checks and binds to 127.0.0.1, but there is **no authentication** (no token, password, or session) on any endpoint — including the sandboxed terminal and SSH proxy. Any local process, or anyone who gets the bind exposed (e.g. `0.0.0.0` / Docker port-publish), reaches all 30+ endpoints unauthenticated. Notably `_enforce_same_origin_post` returns `True` for any request with no Origin/Referer (line 3130), so non-browser clients (curl) bypass it entirely.

Now I have everything needed.

| # | Risk | Category | Likelihood | Impact | Mitigation |
|---|------|----------|------------|--------|------------|
| 1 | **Scope-check bypass on active actions** — scope/RoE is validated only once at `core/orchestrator.py:_initialize` (L363-372) against the primary target; `_execute_tool` (L427) and `_execute_plan` (L506) run LLM-supplied `tool_args` (arbitrary hosts/URLs) with no per-call re-check. `swarm_coordinator.handle_message` (L174) and `swarm_worker_daemon.handle_job` (L56) take `target` straight off the bus and probe it with zero `roe_engine`/`guardrails`/`in_scope` calls. | safety | High | Critical | Add a mandatory per-call scope+RoE+phase assertion inside `orchestrator._execute_tool`/`_run_one` and at `swarm_coordinator.handle_message` before `build_manifest`; route every `target`/`tool_args` host through `core/roe_engine.py` + `core/guardrails.py` (hard blocklist) on every dispatch, not just init. Re-validate discovered subdomains in `hack_mode._run_phase` (L558) before forwarding as next-phase targets. |
| 2 | **Agent performs an unauthorized action** — `_DefaultApprovalGate` in `core/orchestrator.py` auto-approves all phase transitions incl. exploitation when no real gate is injected; `hack_mode.py` (L576-586) auto-approves destructive exploit/post workers when `allow_destructive and approval_gate is None`; `detect_profile` (`hack_profile.py:286,302-305`) forces `allow_destructive=True, use_scope_reasoner=False` for any CTF-regex hostname or private IP regardless of `--go`. | safety | Med | Critical | Make the approval gate fail-closed: replace `_DefaultApprovalGate` auto-approve with deny-by-default; require an explicit non-None `approval_gate` in `HackMode` whenever `allow_destructive` is set; gate `detect_profile`'s destructive/no-scope CTF+private-IP path behind an explicit operator flag and never key it off attacker-controllable hostname regex (`ctf.victim.com` currently qualifies). |
| 3 | **Dashboard auth bypass — :8080 is NOT authenticated at all.** `dashboard/server.py` `DashboardHandler` (L3053) has no token/password/session on any of 30+ endpoints, the sandboxed terminal, or the SSH proxy. Only CORS + a same-origin POST check exist, and `_enforce_same_origin_post` (L3122-3130) returns `True` for any request lacking Origin/Referer (curl/non-browser bypass). Exposure via `0.0.0.0` bind or Docker port-publish gives unauthenticated RCE-adjacent terminal access. | safety | High | Critical | Add a real auth layer to `DashboardHandler` (bearer token / session cookie from a generated secret, checked in `do_GET`/`do_POST` before routing); remove the fail-open `return True` for missing-Origin POSTs (L3130); keep the 127.0.0.1 bind enforced and refuse to start on a non-loopback bind without auth; require auth specifically on the terminal/SSH-proxy and tool-import endpoints. |
| 4 | **Lab escape / uncontrolled egress** — the swarm dispatch path (`swarm_engine.py` runners L222/255/281/306, `swarm_worker_daemon.handle_job` L56) fires live aiohttp requests (incl. `' AND SLEEP(3)` time-based SQLi) at any `target` off the bus with no scope gate and **no per-host rate limit** (only a global concurrency semaphore) and **no identifying User-Agent** (violates `recon.md` 2.3); `ai_techniques.MLInfrastructureExploitsV2.scan_endpoint` (L1135) does a raw `urllib` GET to any caller-supplied URL. | safety | Med | High | Enforce egress allowlisting via `core/roe_engine.py`/`scope_manager` at the engine boundary (`swarm_engine.spawn` L107 and each runner); add per-target throttling through `core/rate_limiter.py` in the worker path; set the mandated identifying User-Agent on all aiohttp sessions and on `scan_endpoint`; in containerized runs restrict worker egress with a network policy/allowlist. |
| 5 | **Runaway worker fan-out / resource exhaustion** — `orchestrator._execute_plan` (L506) uses unbounded `asyncio.gather` with the default executor and no concurrency cap or rate limit; `VulnSwarmCoordinator.build_manifest` expands workers×assets with no manifest-size cap (docstring cites 225); `swarm_worker_daemon.consume_phase` (L138) creates a task per BLPOP'd job bounding only execution, so the pending-task set grows unbounded under load; redis/asyncio consume loops are `while True` with no max-attempt cap. | ops | High | High | Cap concurrency in `_execute_plan` with a bounded semaphore + offload to a sized executor; add a hard `max_manifest_size` cap in `build_manifest` and reject/queue beyond it; bound in-flight tasks in `consume_phase` with a backpressure semaphore on task *creation*, not just execution; integrate `core/rate_limiter.py` token bucket into the wave runner. |
| 6 | **Memory poisoning from a bad ingest** — `memory/viper_memory.json` writer `Memory.save` (`archive/old_agents/agentic_viper.py:65-67`) is non-atomic full-file `write_text` per event with no tmp+rename and no lock (concurrent runs corrupt it); `_load` (L54-55) uses `except Exception: pass` and silently returns an empty skeleton, discarding all history on a single malformed byte; neither `remember_failure` nor `viper_db.migrate_from_json` (L305) dedups, so re-ingest multiplies rows (live file already has ~18 dup natas2 rows). `evograph.py` stores operator strings verbatim with no sanitization and over-matches via substring `LIKE %x%`. | safety | Med | High | Make memory writes atomic (tmp-file + `os.replace`) with a file lock in the writer; replace silent `except: pass` in `_load` with logged validation + backup-on-corrupt rather than silent discard; add idempotency keys/dedup in `remember_failure` and `migrate_from_json`; validate/normalize ingested fields and replace substring `LIKE %x%` in `evograph.py` query methods with exact/anchored matching to prevent cross-target contamination. (Note: this writer is archived/legacy — confirm it is not re-enabled in the live path.) |
| 7 | **Secret leakage in logs & persisted state** — `viper_memory.json` stores raw `result`/`payload` and on disk contains real CTF flags (`HTB{...}`) and recovered natas passwords in cleartext (violates "findings redacted" rule); `evograph.py` logs `target_url` at INFO (L282, L292) unredacted; `bounty_hunter.py` report formatters (L314, L341) interpolate raw evidence/payload with **no redaction** into generated reports. | safety | Med | High | Apply `core/secret_scanner.py` (40+ regex + entropy) redaction before any disk write in `Memory.save` and before report interpolation in `bounty_hunter.py` formatters; scrub/parameterize the `target_url` INFO logs in `evograph.py`; enforce the `audit_logger`/report path through a redaction filter; verify the git-commit secret-scan rule (`.claude/rules/git-commit.md`) blocks committing these state files. |
| 8 | **Secret leakage via dashboard terminal env exposure** — `dashboard/server.py` terminal blocklist (L2769-2771) is an *additive* denylist that has already missed creds (`HACKERONE_API_TOKEN`, `NUCLEI_API_KEY`, `TELEGRAM_BOT_TOKEN`, `DISCORD_WEBHOOK_URL`, `GMAIL_APP_PASSWORD`, `SMTP_PASSWORD`); any new env var added to `.env` leaks until manually added to the list, and the terminal itself is unauthenticated (see #3). | safety | Med | High | Replace the env-var *denylist* in `dashboard/server.py` with an allowlist (or run the terminal in a scrubbed environment with no secret env vars passed through); strip all `.env`-sourced vars from the terminal subprocess env by default; combine with dashboard auth from #3 so the terminal is not reachable unauthenticated. |
| 9 | **Dependency / supply-chain compromise** — large external toolchain (`nuclei`, `httpx`, `subfinder`, `katana`, `naabu`, `gau`, `ffuf` Go binaries + `arjun`/`paramspider` pip) auto-detected and executed via `tools/tool_manager.py`; `swarm_workers/__init__.py` `_safe_import` (L66) silently swallows import errors so a tampered/broken worker module vanishes from the registry with only a warning. A poisoned dependency or binary runs with full network egress. | tech | Med | High | Pin and hash-verify external binaries/pip deps (lockfile + checksums) in `tools/tool_manager.py` before execution; make `_safe_import` failures loud (error-level + registry-count assertion) so a missing/tampered worker is detected, not silently dropped; isolate tool execution in the container with least privilege and a fixed PATH. |
| 10 | **Hung tool / no timeout stalls the loop** — `orchestrator._execute_tool`/`_execute_plan` have no per-tool timeout, so one hung tool stalls the ReACT loop indefinitely; multiple sync I/O-capable calls (`guardrail.validate`, `graph.add_node`, `chain_writer.*`) run inside async defs without executor offload, blocking the event loop; Redis ops (`_RedisBus.publish` L139, heartbeat L173) have no op timeout. | ops | High | Med | Wrap each tool call in `asyncio.wait_for` with a per-tool timeout in `orchestrator`; offload sync `guardrail`/`graph`/`chain_writer` calls via `run_in_executor`; add op timeouts + try/except around `redis_bus` publish/heartbeat. |
| 11 | **Dispatch crash kills jobs silently** — `swarm_worker_daemon.py:67-70` calls `get_worker_runner()` expecting `None` on miss, but `swarm_workers/__init__.py:41` *raises* `KeyError`, so an unknown technique throws an uncaught exception before the `try` block (L76), killing the job task silently via the done-callback; the "no runner" warning is dead code. | tech | High | Med | Either make `get_worker_runner` return `None` on miss (matching the caller contract) or wrap the call in try/except in the daemon and log+skip; restore the intended "no runner" warning path so unknown techniques are observable, not silent. |
| 12 | **Non-idempotent reasoning → unbounded memory growth & phase oscillation** — `hacker_mind._think_*` calls `_generate_hypotheses`/`_find_attack_chains` on every `think()` and blindly `.extend()`s fresh md5-id results, accumulating duplicate hypotheses/chains unboundedly; `_think_vuln_analysis`/`_think_exploitation` backtrack phases with no attempt counter, cycling indefinitely when no hypothesis confirms. (Module currently dead but exported.) | tech | Low | Med | Dedup hypotheses/chains by content-hash before `.extend()`; add an attempt counter + termination condition to the phase-backtrack logic; add a `think()` handler for `POST_EXPLOITATION`/`REPORTING` (currently returns `''` silently, L119). Confirm the module stays unreached or fix before re-enabling. |
| 13 | **Crash on non-numeric/edge input** — `hacker_mind.generate_payload` IDOR branch (L546-555) does `int(base_id)` with no guard and `ValueError`-crashes on a string id like `'admin'`; `bounty_hunter.py` report formatters (L314/L341) index required finding keys directly (KeyError risk) and `_load`/`_save` (L226/L243) have zero error handling and non-atomic writes that corrupt `submissions.json` under concurrent access. | tech | Med | Med | Guard `int(base_id)` with try/except in `generate_payload`; use `.get()` with defaults in `bounty_hunter` formatters; add error handling + atomic tmp+rename + a lock to `bounty_hunter._load`/`_save`/`_save_program`. |
| 14 | **Silent excepts mask failures across the stack** — broad `except Exception` swallow errors with no logging in `swarm_engine.py` runners (L250/276/301/325), `_run_one` (L131), `PostSwarmCoordinator._approve` (L938-939), `_available_techniques` (L483), `evograph.py` (L613/653/669/720), `hack_mode._check_named_stop` (L522 — can mask a legit CTF `flag_found` stop, attacking past intended halt), and `ai_techniques.py` (L782/1163). Corruption and stop-condition failures pass unnoticed. | ops | High | Med | Replace bare `except Exception: pass/continue` with logged, typed handling across these modules; specifically make `_check_named_stop` and `Profile.should_stop` (`hack_profile.py:145`) log and fail-safe so a raising stop-condition halts rather than continues; surface failed-phase status (fix the dead `'success' if … else 'success'` branch at `hack_mode.py:475`). |
| 15 | **Destructive payloads embedded in data could be sent** — `attack_patterns.py:249` and `ai_techniques._run_order_agent` (L699) contain a literal `"test'); DROP TABLE users;--"` SQL payload, and `attack_patterns.py` holds live cloud-metadata SSRF URLs (`169.254.169.254`); inert in these modules but a violation of the non-destructive rule if any consumer transmits them (`ai_techniques.run_parallel_attack` L616 runs a caller `test_fn` over these payloads with no non-destructive gate). | safety | Low | Med | Remove the `DROP TABLE` strings from `attack_patterns.py:249` and `ai_techniques.py:699`; add a non-destructive payload filter (the project's payload-mutator/`payload_mutator.py` policy) at every send boundary, including `run_parallel_attack`; gate metadata-SSRF payloads behind explicit authorization. |

---

## SECTION 10 — Unknowns and Questions for You

I have the style now: numbered, dense, technical, decision-oriented prose with rationale. Now I'll synthesize the raw unknowns into a deduped, deliverable SECTION 10. The raw list collapses into recurring themes: dead-code/orphaned-consumer wiring, scope-enforcement gaps, blocking I/O in async loop, the 5th (Report) coordinator, redis vs in-proc bus, test coverage gaps, schema/migration, concurrency/thread-safety, destructive payload policy, frontend↔backend contract instability, and a few specific bugs.

Here is the section:

## Section 10 — Unknowns and Questions

These are open decision points surfaced by the audit. Each is a question the operator can answer in one pass. Most have a recommended default that lets work proceed; a few (marked **BLOCKER**) gate other phases and should be answered first. Group A is architecture/build-vs-cut, Group B is scope/safety policy, Group C is runtime correctness, Group D is contracts/coverage.

### A. Architecture & build-vs-cut

1. **Build the 5th coordinator (ReportSwarmCoordinator) or keep the no-op?**
   `hack_mode.py` docstring (lines 17–18) names a Phase-3 `ReportSwarmCoordinator`, but the report phase resolves to `_NoOpCoordinator`. Matters because the hunt currently produces no report artifact from the swarm path; downstream (`report_narrative`, `html_reporter`) is reachable only via the legacy `ViperCore` path.
   *Recommended default:* **Build a thin ReportSwarmCoordinator** that consumes persisted findings and invokes the existing `report_narrative`/`html_reporter` — do not invent a new report engine. If deferred, delete the docstring reference so it stops reading as implemented.

2. **Redis bus vs in-process AgentBus — which is the supported production transport?** (**BLOCKER for re-dispatch design**)
   Two parallel buses exist (`agent_bus.py` in-proc, `redis_bus.py` BLPOP work-feed). The in-proc coordinators never call `subscribe`, so a single-process hunt has **no finding re-dispatch path** to downstream phases; a Redis deployment via `swarm_worker_daemon.py` *might*. Matters because "does a finding in phase N trigger phase N+1?" has opposite answers depending on transport, and the audit could not confirm the Redis daemon re-dispatches vs. runs one phase.
   *Recommended default:* **Declare in-process AgentBus the default/supported path for single-host**, fix re-dispatch there, and treat Redis as an opt-in scale-out that must mirror the same re-dispatch contract. Document which `viper.py hack` / daemon / dashboard launchers wire which bus.

3. **Is `HackerMind` (`core/hacker_mind.py`) live, reserved, or dead?**
   Exported from `core/__init__.py` and named in CLAUDE.md, but the only instantiation is in `archive/old_entry_points/agent.py`; no live module constructs it, and no test references it. Same pattern affects the `PATTERNS` table (only archived importer) and the `scan_endpoint`/`run_parallel_attack`/`scan_all` API surface.
   *Recommended default:* **Decide per-symbol: wire into the live hunt path or move to `archive/` and drop the re-export.** Do not leave reachable-but-unexercised API in `core/__init__.py`. If reserved for planned wiring, add a `# RESERVED:` marker plus a tracking item so it is not mistaken for dead code.

4. **Should EvoGraph's Q-table/`tech_attack_map` bias swarm technique selection at runtime?**
   The swarm currently picks techniques from a **static profile list**; no confirmed late-binding `EvoGraph.recommend()` call exists in the swarm path, so the "self-learning" claim is not realized for swarm hunts.
   *Recommended default:* **Wire a single `EvoGraph.recommend()` consult at coordinator technique-selection time** (best-effort, fail-open to the static list). If out of scope now, downgrade the CLAUDE.md self-learning claim to "ViperCore path only."

5. **Reconcile the two graph stores and the two `webapp/` trees.**
   `graph_engine.py` writes `~/.viper/data/graph.db` while `viper.py` also writes `state/graphs/<id>.json`; unclear if both are always written or backend-dependent. Separately, a top-level `webapp/` exists alongside `dashboard/webapp/` with unverified role.
   *Recommended default:* **Pick one graph store as canonical** (SQLite `graph.db`), treat the JSON dump as an export-only artifact, and document it. **Confirm top-level `webapp/` is stale and remove it** unless it has a distinct owner.

6. **Are `migrate_from_json` (`core/viper_db.py`) and `SCHEMA_VERSION=2` migration operational or manual-only?**
   The only `migrate_from_json` caller is `python core/viper_db.py`; no scheduler/cron reference found. No v1→v2 migration logic exists (line 238 only logs), so v1 DBs are never structurally migrated. The `viper_memory.json` session_count (96 on disk) cannot be reconciled with the +1-per-construction logic, suggesting hand-editing.
   *Recommended default:* **Treat migration as manual-only and document it**, OR add real v1→v2 migration if any v1 DB exists in the field. Don't ship a `SCHEMA_VERSION` bump with no migration body.

7. **Purpose of undocumented top-level dirs `fitness/` and `pentest/`?**
   Not part of the documented hunt pipeline; role unverified.
   *Recommended default:* **Document or archive.** If neither imported nor referenced by a live entry point, move to `archive/`.

### B. Scope, safety & RoE policy

8. **Where is the authoritative scope/RoE gate — per-request, per-job, or upstream publisher?** (**BLOCKER for the scope-leak finding**)
   Scope enforcement is diffuse: only `ExploitAgent` receives a guardrail (line 258); recon/vuln/chain agents may rely on their own gates; only recon workers (`crtsh.py`, `subdomain.py`) confirmed to consume `scope_reasoner`; `SwarmCoordinator.handle_message` (line 174) checks only target presence, not `scope_reasoner`; and the bus publisher (`bus.publish('recon'/'vuln'/...)`) may or may not validate before jobs land. Static tracing suggests `viper.py hack <gov-domain>` could send traffic with no central gate.
   *Recommended default:* **Add one mandatory choke-point in the HTTP layer** (`tools/http_client.py` `_request`) that validates every outbound host against the active `scope_reasoner`, so worker-constructed URLs cannot bypass per-agent gates. Per-agent checks become defense-in-depth, not the sole line.

9. **Does `scope_reasoner=None` mean default-deny or fail-open?** (**BLOCKER, ties to #8**)
   `HackMode._build_scope_reasoner` docstring claims strict default-deny, but the audit could not confirm whether `None` is treated as "no scope = allow all" downstream. This is the difference between safe-by-default and a silent allow-all.
   *Recommended default:* **`None` → default-deny.** Add an explicit assertion at coordinator entry that refuses to dispatch active-phase work when `scope_reasoner is None`. Add a test for the None path.

10. **Remove the destructive `DROP TABLE` example payload?**
    A `DROP TABLE` example payload conflicts with the repo's non-destructive-payload rule (`.claude/rules/scope.md` §2.1, `recon.md` §2.4).
    *Recommended default:* **Replace with a non-destructive proof payload** (boolean/time-based or a benign `SELECT`). Keeping a destructive literal in shipped code is a policy violation even if "documentation only."

11. **Fix the `/api/terminal/connect` vs `/api/terminal/execute` SSRF inconsistency?**
    `execute`'s `!connect` enforces an RFC1918 restriction; `/api/terminal/connect` appears to lack it — a possible SSRF gap, pending confirmation that `_sandboxed_execute` re-validates the session target before proxying.
    *Recommended default:* **Apply the same RFC1918/scope validation at both entry points** and re-validate at proxy time. Treat as a security fix, not a follow-up.

### C. Runtime correctness & concurrency

12. **Does any synchronous I/O block the async event loop in the hunt path?**
    Unconfirmed whether `guardrail.validate()` (line 364) does network/LLM I/O, whether `chain_writer.add_step/add_decision/start_chain/end_chain` do synchronous SQLite I/O, and whether `think_engine.think()` does blocking work. Each, if synchronous on the loop, stalls all concurrent workers.
    *Recommended default:* **Audit these three call sites; wrap any blocking call in `asyncio.to_thread`** (or make them async). Prioritize `chain_writer` (almost certainly SQLite) and `guardrail.validate` (likely LLM).

13. **What is the concurrency/thread-safety contract for shared stateful singletons?**
    Open across `EvoGraph` (sqlite conn not thread-safe by default; 18 callers, single-threaded usage unconfirmed), `CollectiveMemoryV2` (reasoned-only under the 2-worker executor), `FindingDedup` (single instance shared across phases — sequential now, but workers may call concurrently), and non-atomic `_save` of `submissions.json`/`programs.json` (real race iff a concurrent writer like the daemon/dashboard exists).
    *Recommended default:* **Declare these single-writer by design and enforce it** — one owning task per resource, or add a lock/atomic-write (`tmp + os.replace`). Confirm no daemon/dashboard writes `submissions.json` concurrently; if it does, add file locking.

14. **Reconcile the `get_worker_runner` KeyError-vs-None contract.**
    `__init__.py:43-46` raises `KeyError` for an unregistered technique while the daemon (line 67) does a None-check — a mismatch with no test exercising an unregistered technique through `handle_job`.
    *Recommended default:* **Pick None-returns-on-miss** (caller-friendly) and update both sites + add a test. A `KeyError` escaping into `handle_job` likely crashes the worker loop.

15. **Confirm the redis-py async teardown API matches the installed (unpinned) version.**
    `redis_bus.py` (lines 196, 219) calls `close()`, which may be deprecated in favor of `aclose()` depending on redis-py version, and redis-py is unpinned.
    *Recommended default:* **Pin redis-py** in requirements and use the version-correct teardown (`aclose()` on redis-py ≥4.2). Unpinned async teardown is a latent break.

16. **Is `f.get('advance', True)` defaulting to True (daemon line 116) intended?**
    If workers omit `'advance'`, every non-error finding re-publishes to the next phase, risking kill-chain amplification. Intent unconfirmed without a worker/coordinator contract.
    *Recommended default:* **Default to `False` (explicit opt-in to advance)** and document `advance` in the worker→coordinator contract. Fail-closed is safer for a re-dispatch trigger.

17. **Is `rate_limit_s` per-worker or between spawns?**
    Code (lines 319–320) applies it per-worker; comments (lines 318, 143) say "between worker spawns" — a doc/behavior mismatch.
    *Recommended default:* **Make it between-spawns to match the documented intent and the RoE rate-limit rules**, or update the comments if per-worker is intentional. Pick one and align code+docs.

18. **Does `HackResult` need an explicit guardrail-blocked / approval-denied status for CLI exit codes?**
    `hack_cli.py` maps `timed_out → exit 5`, but `HackResult` exposes no field distinguishing guardrail-block (exit 2) or approval-denied (exit 3); also unverified whether per-run `asyncio.wait_for` reliably sets `timed_out` vs. raising.
    *Recommended default:* **Add `stop_category` (timeout / guardrail / approval / budget / completed) to `HackResult`** and map to exit codes; catch `TimeoutError` from `wait_for` and set `timed_out` explicitly. Also remove the parsed-but-unused `--report`/`--no-dashboard` args or wire them.

19. **Confirm the `_DefaultApprovalGate` auto-approve risk is dormant.**
    If callers always pass a real `approval_gate` and `enable_agents=True` in production, the auto-approve default never fires; this was not grep-confirmed.
    *Recommended default:* **Make `_DefaultApprovalGate` deny-by-default (or require an explicit `--yes`/unattended flag)** so a missing gate can never silently auto-approve dangerous tools. Verify production callers in the same pass.

20. **Fix the latent `generate_payload` KeyError on brace-containing templates.**
    `category='delimiter'` is not a supported branch and brace/JSON templates raise `KeyError` via `str.format`; risk is latent because the `'random'` pool currently excludes delimiter templates.
    *Recommended default:* **Escape literal braces / use a non-`format` substitution** and either support or explicitly reject `category='delimiter'`. Cheap fix that removes a crash class.

### D. Contracts, counts & test coverage

21. **Stabilize and document the frontend↔backend API contract.** (**BLOCKER for the webapp-truth phase**)
    Every page defensively dual-unwraps shapes (`[]` vs `{findings:[]}`, `{project}` vs `ProjectInfo`, `success_rate` 0–1 vs 0–100), implying the contract is unstable/undocumented. `lib/api.ts` `apiGet/apiPost` collapse 404/network errors to `null`, so missing endpoints (`/api/health`, `/api/react/current`, `/api/agents/monitor`, `/api/terminal/*`, `/api/chat/*`, `/api/codefix/*`, `/api/recon/pipeline/*`) silently render empty/loading forever. No page surfaces `isLoading`/`isError` because pages destructure `data` alone.
    *Recommended default:* **Write one canonical contract doc per endpoint, return a single shape, and stop the catch-all-to-null in the client** — surface `isError` so missing endpoints are visible. Until then, confirm which of the listed endpoints actually exist on `server.py`.

22. **Verify the WebSocket message-`type` contract against the emitter.**
    The Live activity stream assumes `type` values (`finding`/`phase_start`/`phase_done`/`worker_start`/`worker_done`/`log`/`hunt_start`/`hunt_done`) from `ActivityStream.tsx:41-45`, unverified against the Python `/ws` emitter. A name mismatch shows nothing, silently.
    *Recommended default:* **Define the `type` enum in one shared place and assert the Python emitter uses it** (a tiny contract test). Ties into AUDIT_PLAN Phase 6.

23. **Verify the inferred SQLite schemas against canonical DDL.**
    `submissions.json`/`programs.json` schema is inferred from `_load`/`_save` only (lossy `_save_program` backward-compat unconfirmed); `data/viper.db` `audit_log` columns are inferred from `_hack_*` helpers, not the `CREATE TABLE` in `core/audit_logger.py`; plugin stores (`CTFFeedbackStore`, `KnowledgeBase`, `FailureAnalyzer`, `SettingsManager`) use unread external backends.
    *Recommended default:* **Treat the `CREATE TABLE` statements as canonical, generate the doc from them**, and add a schema-round-trip test for `submissions`/`programs` to catch lossy saves.

24. **Run the verifications the audit asserted but did not execute.**
    Several claims are inspection-only and need a runtime check: realized `get_all_attacks` count vs. the documented "147+"; the live registered-worker count (should be 30, but `_safe_import` swallows import failures so it could be fewer if `ai_hunter`/`nuclei` raise on import); whether `idor_exploit.py`/`xss_exploit.py`/`ssti_exploit.py` ever set `exploited:True` without a foothold on an alternate code path.
    *Recommended default:* **Add three tiny runtime assertions** (count payloads, assert 30 workers import, grep+open the three exploit modules end-to-end). Fold into AUDIT_PLAN Phase 3.5.

25. **Close the test-coverage gaps for modules the audit found untested.**
    No tests located for: `hacker_mind`, `bounty_hunter` (`check_duplicate`/`estimate_bounty` — possibly dead-code if uncalled), `viper_memory.json`/`Memory` class, `hack_mode.py` (esp. the `resume()` event-replay / `prior_findings` carry-forward path). Status is inferred UNTESTED, not test-discovered.
    *Recommended default:* **Add at least a smoke test per module before relying on it; for any confirmed-uncalled method, decide dead-code-removal vs. wire-up** (resolves the `bounty_hunter` pipeline-membership question from the CLAUDE.md diagram).

---

**How to use this section:** answer the four **BLOCKER** items first (#2, #8, #9, #21) — they determine the swarm re-dispatch design, the scope-safety model, and the webapp-truth phase. The remaining items can be resolved inline during the fix loop (AUDIT_PLAN Phase 9), each as a one-commit decision.
