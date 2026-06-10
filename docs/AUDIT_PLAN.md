# VIPER Full-Stack Audit & Fix Plan

**Goal.** Verify every claim in `CLAUDE.md` is implemented, every module is
reachable, every tool wrapper actually shells out and parses output, every
pipeline produces findings end-to-end, and every webapp page reflects real
backend data.

**Scope.** 274 Python modules · 17 pentest tool wrappers · 14 Next.js pages
· ~30 `/api/*` endpoints · 4-phase swarm worker registry · 18 skill prompts ·
7-phase recon pipeline · `ai_hunter` + `mind_pipeline` (new).

**Non-goals.** New features. Architectural rewrites. Performance tuning beyond
"fix anything that hangs or crashes."

**Method.** Run each phase top-to-bottom. Each phase has (a) a discovery step
that produces a checklist, (b) a fix loop that processes the checklist. Never
move to the next phase until the previous one is clean.

---

## Phase 0 — Snapshot (15 min)

Before touching anything, capture the baseline so regressions are obvious.

```bash
# Tests
python -m pytest tests/ -q --tb=line | tee findings/baseline-tests.txt

# Wiring
python -m tools.audit.wiring_audit --json findings/baseline-wiring.json

# Backend smoke
curl -sS http://127.0.0.1:8080/api/status > findings/baseline-status.json
curl -sS http://127.0.0.1:8080/api/overview > findings/baseline-overview.json

# Webapp build
(cd dashboard/webapp && npm run build) | tee findings/baseline-build.txt
```

Commit the `findings/baseline-*` files. The audit succeeds when these
baselines either stay stable or improve.

---

## Phase 1 — Capability vs. reality (1 hr)

Compare every claim in `CLAUDE.md` and module docstrings to actual code.

**Output:** `findings/capability-matrix.csv` — one row per CLAUDE.md claim:

| claim | file | imported_by | last_modified | works_smoke | notes |
|---|---|---|---|---|---|
| `core/finding_validator.py — 37 vuln-type behavioral FP filter` | `core/finding_validator.py` | `viper_core.py` (ModuleLoader) | … | yes | … |
| `recon/wappalyzer.py — 3,920 tech fingerprints` | … | … | … | yes (count file) | … |

**Method.**
1. `grep -oE '(core|recon|ai|tools|scanners|agents)/[a-z_]+\.py' CLAUDE.md`
   → every claimed file path.
2. For each path: `Read` the file, take first 30 lines, confirm
   the docstring/class matches the claim.
3. For each path: run wiring_audit to confirm a real caller exists.
4. For each path: write a one-line smoke test that imports + instantiates
   the primary class without side-effects. Record pass/fail.

**Done when.** Every CLAUDE.md claim has a row, every row's `works_smoke=yes`
or has a tracked follow-up.

---

## Phase 2 — Static safety (1 hr)

Catch broken implementations before they ship.

### Python

```bash
# Type errors — install if missing
pip install --quiet pyright
pyright --outputjson core ai recon scanners tools scope agents \
  > findings/pyright.json

# Lint
pip install --quiet ruff
ruff check core ai recon scanners tools scope agents \
  > findings/ruff.txt

# Anti-patterns we care about specifically
grep -rn --include='*.py' -E \
  'bare except|except: |mutable default|shell=True|pickle\.loads\(|yaml\.load\([^,]*\)(?!.*SafeLoader)|eval\(|exec\(' \
  core ai recon scanners tools | tee findings/python-smells.txt
```

### TypeScript

```bash
(cd dashboard/webapp && npx tsc --noEmit 2>&1) | tee findings/tsc.txt
(cd dashboard/webapp && npx eslint 'src/**/*.{ts,tsx}' 2>&1) | tee findings/eslint.txt
```

**Done when.** `pyright` reports < 50 errors (target zero for new code;
inherited legacy can be tracked), `ruff` clean on new code, `tsc` reports 0,
`eslint` reports 0 errors (warnings OK).

---

## Phase 3 — Per-module functional verification (3 hr)

The static audit is necessary but not sufficient. **Every module must be
poked at runtime.** This is the longest phase but the highest signal.

For each of the 274 modules, run the appropriate verifier:

### 3.1 Tool wrappers (`tools/`, `scanners/`, `recon/*_scanner.py`)

For each tool wrapper, write a verifier that:
1. Imports the module.
2. Instantiates the wrapper class.
3. Confirms the binary is found via `tool_manager.get_path(...)` or the
   module's own resolver.
4. Calls the wrapper against a *known-safe* target (`demo.testfire.net`,
   `127.0.0.1`, or `example.com`) with the shortest possible flags.
5. Asserts the output is parsed into ≥1 finding-shaped dict (or `[]` if
   the target genuinely has nothing to find).

**Module checklist (concrete list, build into `tests/integration/tools/`)**:
- `tools/http_client.py` — HackerHTTPClient: GET with rate limiter
- `tools/brute_forcer.py` — BruteForcer: SSH dry-run (no real attempt)
- `tools/metasploit.py` — MetasploitClient: `version` command only
- `tools/google_dork.py` — GoogleDork: skip if no SerpAPI key
- `tools/web_search.py` — WebSearch: skip if no key
- `tools/payload_mutator.py` — generate 1 SQLi payload, assert shape
- `tools/nmap_scanner.py`, `masscan_scanner.py`, `sqlmap_scanner.py` — skip if binary missing
- `scanners/nuclei_scanner.py` — already verified
- `scanners/gvm_scanner.py`, `trufflehog_scanner.py` — skip if binary missing
- `recon/recon_engine.py`, `surface_mapper.py`, `web_crawler.py`,
  `resource_enum.py`, `security_checks.py`, `wappalyzer.py`,
  `shodan_enricher.py`, `urlscan_enricher.py`, `whois_lookup.py`,
  `cve_lookup.py`, `mitre_enricher.py`, `mitre_offline.py`,
  `github_hunt.py`, `arjun_discovery.py`, `paramspider_discovery.py`,
  `kiterunner_discovery.py`, `ffuf_fuzzer.py` — verify each

### 3.2 Core engines (`core/`)

- `core/react_engine.py` — single-step reason+act, mock the LLM
- `core/think_engine.py` — one Deep Think pass, mock the LLM
- `core/orchestrator.py` — init→think→execute→respond cycle
- `core/hacker_mind.py` — observe→hypothesize on synthetic input
- `core/wave_runner.py` — parallel-wave dispatch
- `core/phase_engine.py` — state transitions on synthetic input
- `core/skill_classifier.py` — classify "SQLi blind boolean" → expected category
- `core/agent_bus.py` + `core/redis_bus.py` — pub/sub round-trip
- `core/agent_state.py` — TodoList/ObjectiveManager basic ops
- `core/agent_registry.py` — register/health-check/route
- `core/approval_gate.py` — gate accept + reject
- `core/roe_engine.py` — scope/time/tool/phase pass + reject
- `core/graph_engine.py` + `core/graph_query.py` — write a Finding node, query it back
- `core/chain_writer.py` — write+read a chain
- `core/evograph.py` — write Q-table row, read back
- `core/finding_validator.py` — one example per 5 vuln types, assert
- `core/guardrails.py` + `core/guardrail_hard.py` + `core/guardrail_llm.py` —
  allowlist hit / blocklist hit / private range / unknown
- `core/stealth.py` — 4 levels return distinct fingerprints
- `core/compliance_mapper.py` — map CWE-89 → OWASP A03, PCI 6.5.1
- `core/mitre_mapper.py` — CWE-89 → CAPEC → ATT&CK
- `core/rate_limiter.py` — burst, sustained, gaussian
- `core/notifier.py` — dry-run dispatch to Discord/Telegram/email
- `core/codefix_engine.py` + `core/codefix_tools.py` — 11 nav tools each
- `core/report_narrative.py` — generate 6-section report from fixture
- `core/html_reporter.py` — render fixture → HTML
- `core/iana_services.py` — lookup port 80 → http
- `core/fuzzer.py` — generate 100 mutations
- `core/graphql_fuzzer.py` — introspect a real GraphQL endpoint (mock)
- `core/oauth_fuzzer.py` — 7 suites against a mock OAuth server
- `core/websocket_fuzzer.py` — mock WS server, send each suite
- `core/race_engine.py` — last-byte-sync against local echo server
- `core/logic_modeler.py` — synthetic checkout flow → step-skip
- `core/scanner.py` — fuzz one parameter with rate limit
- `core/secret_scanner.py` — 40+ patterns each match a known token
- `core/failure_analyzer.py` — feed 3 failed attacks, expect 1 lesson
- `core/cross_target_correlator.py` — 2 targets, 1 common CVE
- `core/chain_of_custody.py` — SHA-256 a fixture, verify HMAC
- `core/finding_stream.py` — emit + observe one event
- `core/poc_generator.py` — generate Python PoC for SQLi
- `core/skill_prompts/*.py` — each get_skill_prompt() call returns
  non-empty for its category

### 3.3 Agents (`agents/`)

- `agents/recon_agent.py`, `vuln_agent.py`, `exploit_agent.py`,
  `chain_agent.py`, `codefix_agent.py`, `post_exploit.py` —
  each takes a fixture goal and produces ≥1 expected event

### 3.4 AI section (`ai/`)

- `ai/model_router.py` — `is_available` returns true, `complete()` round-trips
  with a 5s mocked LLM (assert text non-empty + token usage tracked)
- `ai/llm_analyzer.py` — single analysis call
- `ai/observability.py` — record a generation, query stats

### 3.5 New code (audit extra carefully)

- `core/ai_hunter/*` — already has 62 tests; re-run them
- `core/mind_pipeline/*` — already has tests; re-run + add integration
- `core/swarm_workers/vuln/ai_hunter.py` — registered worker
- `core/swarm_workers/recon/*` — each registered, each emits findings
- `core/swarm_workers/vuln/*` — each registered, each emits findings

**Output.** `findings/per-module-verifier.csv` with status per module.

**Done when.** Every module has either a passing verifier or a documented
"not_applicable" reason.

---

## Phase 4 — Pipeline integration (1 hr)

End-to-end on real (authorized) targets.

### 4.1 Recon pipeline (7 phases)

```bash
python -m recon.run_pipeline_cli demo.testfire.net \
    --osint-sources whois,shodan \
    --output findings/pipeline-demo.json
```

Assert each phase ran (`phases_done` length = 7, no `error`).

### 4.2 Swarm hunt

```bash
python viper.py hack https://demo.testfire.net --profile bugbounty --time 2
```

Assert:
- `state/hunts/.../audit.jsonl` exists
- Has events for each phase (`worker.started`, `worker.completed`, `finding.persisted`)
- `summary.json` has `findings > 0`

### 4.3 Dashboard flow

With backend running on :8080, dev server on :3000:

```bash
# 1) Hunt-launch via API
curl -X POST http://localhost:3000/api/hack/start \
    -d '{"target":"https://demo.testfire.net","profile":"quick"}' \
    -H 'Content-Type: application/json'
# expect {ok:true, pid:N, command_preview:"..."}

# 2) Wait 90s, then overview should reflect new findings
sleep 90
curl http://localhost:3000/api/overview | jq '.findings'
# expect > baseline

# 3) Chat send
curl -X POST http://localhost:3000/api/chat/send \
    -d '{"message":"what is XSS"}' -H 'Content-Type: application/json'
# expect response within 30s with substantive text

# 4) Recon pipeline
curl -X POST http://localhost:3000/api/recon/pipeline/start \
    -d '{"target":"example.com","osint_sources":["urlscan"]}' \
    -H 'Content-Type: application/json'
# expect job_id, then /api/recon/pipeline/list shows it
```

### 4.4 AI Hunter

```bash
python -m core.ai_hunter http://localhost:11434/api/generate \
    --template '{"model":"llama3.1:8b","prompt":"{prompt}","stream":false}' \
    --response-path 'response' --only prompt_injection --timeout 60 \
    --output findings/ai-hunter-self-test.json
# expect ≥1 finding against raw Ollama (no system prompt)
```

**Done when.** All four flows produce expected artifacts.

---

## Phase 5 — Frontend ↔ backend contract (45 min)

For each `/api/*` endpoint the webapp calls, confirm:

1. The endpoint exists (HTTP 200 on baseline data).
2. The response shape matches what the consuming page expects.
3. Field renames/wrappers documented in code, not silently mismatched.

Script:

```bash
python tools/audit/api_contract_audit.py \
    --frontend-src dashboard/webapp/src \
    --backend dashboard/server.py \
    --report findings/api-contract.md
```

(Build this script as part of the audit — it should walk `apiGet/apiPost`
call sites, capture the TS generic, then `curl` the endpoint and diff the
shape. Known offenders to verify cleanly: `/api/projects`, `/api/findings`,
`/api/triage/findings`, `/api/sessions/list`, `/api/reports`,
`/api/findings/timeline`, `/api/attacks/kill-chain`, `/api/chat/history`.)

**Done when.** Every endpoint the webapp calls has a documented contract.

---

## Phase 6 — WebSocket (15 min)

The webapp's `useWebSocket` subscribes to `ws://:8080/ws` but the backend
may not implement it. Either:
- Add a minimal `/ws` handler that broadcasts every audit event, OR
- Document that REST polling is the only transport and gate the TopBar
  "Offline" indicator on a different signal.

Audit:
```bash
grep -nE "/ws|websocket|ws_handler" dashboard/server.py
```

**Done when.** Either WS works end-to-end or the TopBar's "Offline" lights
up only when REST is unreachable, not when WS isn't supported.

---

## Phase 7 — Documentation truth (30 min)

`CLAUDE.md` claims must match reality.

```bash
# Module counts
echo "claimed:    85+ in core/"
ls core/*.py | wc -l   # actual

echo "claimed:    21 in recon/"
ls recon/*.py | wc -l

echo "claimed:    14 in tools/"
ls tools/*.py | wc -l

echo "claimed:    4 in scanners/"
ls scanners/*.py | wc -l

# Tool counts in CLAUDE.md vs. ToolManager
grep -oE '`[a-z_]+`' CLAUDE.md | sort -u | wc -l
```

For each mismatch, either update CLAUDE.md or add the missing module/feature.

**Done when.** Running counts/claims in CLAUDE.md match the filesystem.

---

## Phase 8 — Performance smoke (20 min)

Not deep optimization, just rule out pathological cases.

| Operation | Budget | Actual | Action if exceeded |
|---|---|---|---|
| `/api/overview` | <100ms | | profile sqlite queries |
| `/api/findings?limit=25` | <200ms | | add index, reduce JOINs |
| `/api/chat/send` (Claude CLI) | <30s | | already capped — confirm |
| `/api/hack/start` | <1s | | move subprocess.Popen off main thread |
| 1-min hunt `demo.testfire.net` | ≥3 findings | 6 | passes baseline |
| Webapp build | <30s | ~5s | passes |

```bash
for ep in overview findings risk-score targets agents/monitor; do
  echo -n "/api/$ep: "
  curl -sS -o /dev/null -w '%{time_total}s\n' "http://127.0.0.1:8080/api/$ep"
done
```

**Done when.** No endpoint exceeds budget by >2x.

---

## Phase 9 — Fix loop (variable time)

For every issue surfaced by phases 1-8:

1. Smallest correct fix. No drive-by refactors.
2. Add or update the relevant test.
3. Re-run the verifier from the phase that surfaced the issue.
4. If a fix takes more than 30 minutes, file it as a follow-up instead.

**Commit pattern**: one commit per issue, message format:
```
fix(<module>): <one-line problem> 

Why: <one sentence>
Test: <how to verify>
```

---

## Phase 10 — Final pass (30 min)

Re-run the Phase 0 baseline + every verifier. Compare against the saved
baselines. Diff the test count, finding count, build size.

Then:

```bash
python -m pytest tests/ --tb=short -q
python -m tools.audit.wiring_audit
(cd dashboard/webapp && npm run build)
python viper.py hack https://demo.testfire.net --profile bugbounty --time 2
```

**Done when.** All four green, finding count ≥ baseline, no new wiring
orphans, no broken imports.

---

## Continuation strategy

Audits go stale. Schedule:
- **Daily**: `pytest tests/ -q` (existing CI)
- **Weekly**: `wiring_audit` + `pyright` + `tsc`
- **Per-PR**: `/security-review` skill on the diff
- **Quarterly**: Re-run Phases 3-4 (per-module + integration)
