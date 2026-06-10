# PLAN — Function Audit: `swarm_engine_workers`

> Part of [PLAN.md](PLAN.md) Section 2. Generated 2026-06-06. Module: **swarm_engine_workers (core/swarm_engine.py, core/swarm_worker_daemon.py, core/redis_bus.py)**

**Exists:** True  

## Summary

Three-file distributed swarm subsystem. swarm_engine.py = in-process bounded-concurrency engine (SwarmEngine) + 4 built-in async HTTP probe runners. swarm_worker_daemon.py = MODE=worker container entrypoint: subscribes to phase queues, dispatches each job to a registered worker, streams findings downstream. redis_bus.py = dual-backend bus (in-proc asyncio fallback / Redis lists+pubsub) with auto-fallback. WORKER SPEC COUNT: project claims 28; actual = 30 registered worker techniques (recon=9, vuln=10, exploit=6, post=5), one per module via TECHNIQUE constant + register_worker(). The 28 claim is WRONG by 2 (undercount). The vuln dir has 12 .py files but 3 are non-worker helpers (__init__.py, _http.py, _rate_limit.py). KEY DEFECT: daemon line 67-70 calls get_worker_runner() expecting None for a miss, but the registry's get_worker_runner (swarm_workers/__init__.py:41) RAISES KeyError — so an unknown technique throws an uncaught exception before the try block, killing the job task silently. CRITICAL SAFETY: no scope/RoE/guardrail check anywhere in the worker dispatch path or in the engine runners — targets are taken raw off the bus and probed.

## Top issues

- WORKER COUNT WRONG: project claims 28 workers; actual registered = 30 (recon 9 / vuln 10 / exploit 6 / post 5), one TECHNIQUE per module. Off by +2. Count is also fragile: _safe_import (swarm_workers/__init__.py:66) silently swallows import errors, so a broken worker file vanishes from the registry with only a warning log.
- DISPATCH BUG (swarm_worker_daemon.py:67-70): code does `runner = get_worker_runner(env.topic, technique); if runner is None: ...` but get_worker_runner (swarm_workers/__init__.py:41) RAISES KeyError instead of returning None. An unknown/unregistered technique throws an uncaught KeyError BEFORE the try block at line 76, so the job task dies silently via the done-callback path — the None-check is dead and the 'no runner' warning never fires.
- NO SCOPE / RoE / GUARDRAIL CHECK in the entire dispatch path. handle_job (daemon:56) and all 4 engine runners (swarm_engine.py:222/255/281/306) take `target` straight off the bus / agent and fire network requests (incl. SQLi SLEEP payloads) with no in-scope validation, no roe_engine, no guardrails. Violates the project's own scope.md ('cross-reference scopes before any active recon').
- SILENT EXCEPTS everywhere: engine runners use `except Exception: pass`/`continue` (swarm_engine.py:250,276,301,325) hiding network/parse errors; _run_one (131) reduces exceptions to str(e) with no logging; redis_bus list_workers (191) and close (198) swallow; _safe_import swallows import failures.
- UNBOUNDED GROWTH / BACKPRESSURE GAP: consume_phase (daemon:138) creates a task per BLPOP'd job and only bounds *execution* via semaphore, not task creation; the `active` set and pending coroutines can grow without limit if jobs arrive faster than they complete. redis consume/BLPOP and asyncio consume use `while True` with no max-attempt cap.
- MUTABLE GLOBAL STATE w/o locks: get_bus singleton `_BUS` (redis_bus.py:203) can double-init under concurrent first-callers; swarm_workers `_REGISTRY` global mutated by register_worker; engine `_finding_hashes` set is mutated concurrently by gathered _run_one tasks (swarm_engine.py:151-152) — data race on dedup.
- REDIS OPS HAVE NO TIMEOUT/RETRY/IDEMPOTENCY: _RedisBus.publish (139) and heartbeat (173) have no try/except or op timeout; findings re-published on worker retry have no idempotency key (message_id is regenerated per publish), so downstream phases can receive duplicate jobs. get_bus also opens a second throwaway client just to PING (redis_bus.py:217-220).

## Scope / safety notes

YES — this module performs network/target actions with NO scope or RoE check at any point. (1) swarm_worker_daemon.handle_job (line 56) pulls `target` directly from the bus envelope and immediately invokes a worker runner that makes live requests to that target — zero call to roe_engine / guardrails / scope_manager / in_scope before execution (grep for scope|roe|guardrail|in_scope in the daemon returns NO matches). (2) The 4 built-in engine runners (swarm_engine.py:222 sqli, 255 xss, 281 dir, 306 subdomain) all open aiohttp sessions and GET agent.target with attack payloads (incl. `' AND SLEEP(3)` time-based SQLi) without any authorization/scope gate. SwarmEngine.spawn (107) also accepts any target string unchecked. This contradicts the project's mandatory .claude/rules/scope.md and recon.md, which require cross-referencing scopes/current_scope.json before ANY active recon/scan. Scope enforcement, if any, must live entirely upstream (whoever publishes to the bus); nothing in these three files prevents an out-of-scope target from being attacked. Additionally there is no per-host rate limiting in this path (the engine bounds total concurrency via a semaphore but applies no per-target throttle), and the custom identifying User-Agent required by recon.md 2.3 is not set on any aiohttp session.

## Function-by-function table

| File:Line | Function | Purpose | Inputs | Outputs | Side effects | Status | Issues |
|---|---|---|---|---|---|---|---|
| swarm_engine.py:53 | SwarmAgent.duration_ms | Compute run duration in ms | self | int | none | OK | |
| swarm_engine.py:58 | SwarmAgent.to_dict | Serialize agent (enum→str) | self | dict | none | OK | |
| swarm_engine.py:89 | SwarmEngine.__init__ | Init engine config + state | max_concurrent, dedup, timeout | None | sets instance state | OK | |
| swarm_engine.py:103 | SwarmEngine.register_runner | Map technique→runner fn | technique, runner | None | mutates self.runners | OK | |
| swarm_engine.py:107 | SwarmEngine.spawn | Create one pending agent | objective,target,technique,payload... | SwarmAgent | mutates self.agents, _stats | OK | No scope/RoE check on target before agent created |
| swarm_engine.py:127 | SwarmEngine.spawn_many | Bulk spawn from spec dicts | specs:list[dict] | list[SwarmAgent] | via spawn() | OK | Unvalidated **s kwargs → TypeError on bad spec; no scope check |
| swarm_engine.py:131 | SwarmEngine._run_one | Execute one agent w/ sem+timeout+dedup | agent | SwarmAgent | mutates agent,_stats,_finding_hashes | NEEDS-FIX | except Exception→str(e) swallows traceback (no log); dedup mutates shared _finding_hashes set with no lock — race across gathered tasks (151-152); no retry |
| swarm_engine.py:167 | SwarmEngine.run_swarm | Run all pending w/ bounded concurrency | self | SwarmStats | sets _sem,_start_time; gather | NEEDS-FIX | gather has no return_exceptions; _sem created per-call (not safe for concurrent run_swarm); no overall wall-clock cap |
| swarm_engine.py:184 | SwarmEngine.get_findings | Aggregate/filter findings | only_validated,min_confidence | list[dict] | none | OK | |
| swarm_engine.py:196 | SwarmEngine._finding_hash | SHA256 dedup key | finding:dict | str | none | OK | |
| swarm_engine.py:200 | SwarmEngine.stats | Stats snapshot dict | self | dict | none | OK | Reads _stats before run_swarm → zeros (minor) |
| swarm_engine.py:206 | SwarmEngine.export_telemetry | Full state dump | self | dict | none | OK | |
| swarm_engine.py:222 | runner_param_sqli_probe | Time-based SQLi probe of 1 param | agent | list[dict] | network GET to target | NEEDS-FIX | except Exception: pass (250-251) silent; NO scope/RoE — sends SLEEP payloads to arbitrary target; time-based check flaky (no baseline → FP); hard-coded payloads/10s timeout |
| swarm_engine.py:255 | runner_param_xss_probe | Reflected-XSS canary probe | agent | list[dict] | network GET | NEEDS-FIX | except Exception: pass silent (276-277); no scope check; no retry |
| swarm_engine.py:281 | runner_directory_probe | Probe one dir path | agent | list[dict] | network GET | NEEDS-FIX | except Exception: pass silent (301); no scope check; status 200 auto validated=True w/o content check |
| swarm_engine.py:306 | runner_subdomain_probe | HTTP-liveness probe of subdomain | agent | list[dict] | network GET https/http | NEEDS-FIX | except Exception: continue silent (325); no scope check; confidence hard-coded 1.0 |
| swarm_engine.py:334 | demo (__main__) | Local demo harness | none | None | prints; hits example.com | DEAD-CODE | Demo only; not imported anywhere |
| swarm_worker_daemon.py:46 | next_phase | Map phase→next in PHASE_ORDER | current:str | str|None | none | OK | |
| swarm_worker_daemon.py:56 | handle_job | Dispatch 1 bus job to worker, stream findings | env, worker_id | None | runs worker (network), publishes to bus | NEEDS-FIX | BUG: get_worker_runner RAISES KeyError but code checks `if runner is None` (67-70) — unknown technique throws uncaught before try block, killing task silently; NO scope/RoE before running worker on env.target; f.get('advance',True) default True floods next phase |
| swarm_worker_daemon.py:125 | heartbeat_loop | Periodic worker heartbeat | worker_id,phases,stop | None | bus.heartbeat writes | NEEDS-FIX | except Exception→logger.debug only (silent at default INFO); hard-coded 10s interval |
| swarm_worker_daemon.py:138 | consume_phase | Consume queue, spawn bounded job tasks | phase,worker_id,concurrency,stop | None | creates tasks, drains on stop | NEEDS-FIX | sem bounds execution but create_task is unbounded between BLPOPs — `active` set + pending tasks grow without limit under load; stop checked only after job already pulled |
| swarm_worker_daemon.py:163 | main | CLI/daemon entrypoint, wire tasks+signals | argv | int | signal handlers, bus, tasks | OK | Broad except on signal setup intentional cross-platform |
| redis_bus.py:71 | Envelope.to_json | Serialize envelope→JSON bytes | self | bytes | none | OK | default=str silently coerces non-JSON types |
| redis_bus.py:74 | Envelope.from_json | Deserialize JSON→Envelope | data:bytes/str | Envelope | none | OK | cls(**d) → TypeError on unknown keys |
| redis_bus.py:87 | _AsyncioBus.__init__ | Init in-proc queues | self | None | logs | OK | |
| redis_bus.py:91 | _AsyncioBus._q | Lazy-get topic queue | topic | asyncio.Queue | mutates _queues | OK | |
| redis_bus.py:96 | _AsyncioBus.publish | Put envelope on in-proc queue | topic,payload,priority,hunt_id | message_id | enqueues | OK | priority ignored (plain FIFO Queue) |
| redis_bus.py:104 | _AsyncioBus.consume | Async-iter queue forever | topic | AsyncIterator[Envelope] | dequeues | OK | while True unbounded (intended) |
| redis_bus.py:110 | _AsyncioBus.heartbeat | No-op heartbeat | worker_id,payload | None | none | OK | |
| redis_bus.py:114 | _AsyncioBus.close | No-op close | self | None | none | OK | |
| redis_bus.py:123 | _RedisBus.__init__ | Init redis async client | redis_url | None | opens client | NEEDS-FIX | from_url sync-constructed, conn lazy; no auth/TLS handling beyond URL |
| redis_bus.py:135 | _RedisBus._queue_key | Build queue key | topic | str | none | OK | |
| redis_bus.py:139 | _RedisBus.publish | LPUSH/RPUSH + pubsub fanout | topic,payload,priority,hunt_id | message_id | 2 redis writes | NEEDS-FIX | No try/except — redis error propagates to caller unguarded; no op timeout/retry; no idempotency (message_id regenerated per publish) |
| redis_bus.py:154 | _RedisBus.consume | BLPOP loop yielding envelopes | topic | AsyncIterator[Envelope] | redis reads | NEEDS-FIX | while True unbounded; yield inside try → consumer exception mislabeled 'bad envelope' & swallowed; BLPOP error → sleep 1 retry forever (no max) |
| redis_bus.py:173 | _RedisBus.heartbeat | SET key w/ 30s TTL | worker_id,payload | None | redis SET ex=30 | NEEDS-FIX | No try/except — redis failure propagates (caught upstream in heartbeat_loop) |
| redis_bus.py:179 | _RedisBus.list_workers | KEYS scan of live workers | self | list[dict] | redis KEYS+GET | NEEDS-FIX | KEYS is O(N) blocking on large keyspaces (use SCAN); except Exception: pass (191) silent; UNTESTED |
| redis_bus.py:194 | _RedisBus.close | Close client | self | None | closes conn | OK | except Exception: pass acceptable on close |
| redis_bus.py:206 | get_bus | Singleton bus selector + redis ping fallback | none | bus instance | sets global _BUS, pings redis | NEEDS-FIX | Mutable global _BUS, no lock → double-init race; opens a 2nd throwaway client just to PING (217-220); nested broad excepts mask misconfig (always falls back to asyncio) |
| swarm_workers/__init__.py:34 | register_worker | Register (phase,technique)→runner | phase,technique,runner | None | mutates global _REGISTRY | NEEDS-FIX | Mutable global, no lock; silently overwrites existing technique |
| swarm_workers/__init__.py:41 | get_worker_runner | Look up runner | phase,technique | runner | none | NEEDS-FIX | RAISES KeyError on miss, but daemon caller expects None — contract mismatch → uncaught exception in handle_job |
| swarm_workers/__init__.py:49 | list_workers | Sorted techniques for phase | phase | list[str] | none | OK | |
| swarm_workers/__init__.py:54 | list_all_phases | List phase names | none | list[str] | none | OK | |
| swarm_workers/__init__.py:58 | clear_phase | Wipe a phase registry | phase | None | mutates _REGISTRY | OK | Test helper |
| swarm_workers/__init__.py:66 | _safe_import | Import phase module, swallow errors | modname | None | imports (side-effect registration) | NEEDS-FIX | except Exception swallows ALL import errors → broken worker file silently disappears from registry (count drifts, no error surfaced) |
