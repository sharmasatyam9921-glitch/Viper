# PLAN — Function Audit: `swarm_coordinator`

> Part of [PLAN.md](PLAN.md) Section 2. Generated 2026-06-06. Module: **core/swarm_coordinator.py (SwarmCoordinator + WorkerSpec + CoordinatorResult + FindingDedup + Recon/Vuln/Exploit/Post coordinators)**

**Exists:** True  

## Summary

939-line module defining the swarm-coordinator layer: a base SwarmCoordinator that subscribes to a phase, builds a worker manifest, dispatches via SwarmEngine with bounded concurrency + per-worker/overall timeouts, streams findings to the next-phase bus topic, and emits swarm/phase/audit events. Four concrete coordinators exist (Recon->vuln, Vuln->exploit, Exploit->post, Post->report); Exploit/Post are approval-gated. A FIFTH "ReportSwarmCoordinator" is claimed in the hack_mode.py module docstring (core/hack_mode.py:18) but DOES NOT EXIST anywhere in the repo - grep finds it only in that one docstring line. The "report" phase falls through to _NoOpCoordinator (core/hack_mode.py:589, 597) and reporting is actually done by HackMode._write_report / the CLI --report flag, not a coordinator. The module is structurally sound and well-tested (tests/test_swarm_coordinator.py covers all 4 concrete coordinators + base), but has real defects: (1) timed-out runs report bogus 0 completed/0 failed stats; (2) NO scope/RoE check is performed by the coordinator itself before dispatching network workers - scope_reasoner is merely passed through in payload and only some recon workers honor it; (3) get_findings() read after a cancelled run_swarm may lose/duplicate partial findings and orphan engine tasks; (4) PHASE='abstract' base and _available_techniques swallow all exceptions.

## Top issues

- MISSING 5TH COORDINATOR: ReportSwarmCoordinator is claimed in core/hack_mode.py:18 docstring but does NOT exist anywhere (grep finds the name only in that one docstring line). The 'report' phase is actually served by _NoOpCoordinator (core/hack_mode.py:589/597) and reporting is done by HackMode._write_report + CLI --report. So only 4 real coordinators exist, matching the file.
- NO SCOPE/RoE ENFORCEMENT in the coordinator: SwarmCoordinator.handle_message (line 174) dispatches network workers against payload['target'] with no in-scope/RoE check. scope_reasoner is only passed through in worker payload (lines 529/594/779/909) and only a few recon workers (crtsh.py, subdomain.py) actually honor it; vuln/exploit/post enforcement is unverified. The coordinator layer itself is scope-blind.
- BOGUS STATS ON TIMEOUT: _run_manifest (lines 237-247) builds a fresh SwarmStats(spawned=N) on asyncio.TimeoutError, so workers_completed and workers_failed are reported as 0 regardless of actual progress; engine.get_findings() is still read from a cancelled engine (possible partial/lost findings, orphaned inner tasks).
- SILENT EXCEPTS: PostSwarmCoordinator._approve (lines 938-939) swallows gate exceptions with no logging (Exploit._approve logs the same case at line 834); _available_techniques (line 483) bare-excepts to [] masking import errors.
- UNBOUNDED MANIFEST: VulnSwarmCoordinator.build_manifest expands workers x assets with no cap on manifest size (only runtime concurrency is bounded), so a large discovered-asset list produces a very large WorkerSpec list (docstring itself cites 225).

## Scope / safety notes

YES - this module initiates network/target actions WITHOUT any scope or RoE check in the coordinator itself. SwarmCoordinator.handle_message (line 174) only checks that target is non-empty, then build_manifest + _run_manifest spawn workers that probe the target (recon discovery, vuln scanning, exploit, post-exploit) with no in-scope/exclusion/RoE validation at the coordinator boundary. Scope is delegated entirely downstream: scope_reasoner is passed through in worker payloads (lines 529, 594, 779, 909), but only some recon workers (crtsh.py:38, subdomain.py:68/88) were confirmed to actually filter on it; vuln/exploit/post enforcement is unverified (see unknowns). Exploit and Post phases ARE gated by approval_gate (fail-closed in Exploit._approve, silent-closed in Post._approve), which provides a human/destructive-action gate but is NOT a scope check. Net: a caller that passes an out-of-scope target to handle_message will have workers dispatched against it unless a downstream worker independently rejects it. Recommend an explicit RoE/scope assertion in handle_message before build_manifest.

## Function-by-function table

| File:Line | Function | Purpose | Inputs | Outputs | Side effects | Status | Issues |
|---|---|---|---|---|---|---|---|
| core/swarm_coordinator.py:53 | WorkerSpec.__post_init__ | Validate technique non-empty | self | None | raises ValueError | OK | |
| core/swarm_coordinator.py:71 | CoordinatorResult.findings_count (property) | len(findings) | self | int | none | OK | |
| core/swarm_coordinator.py:92 | FindingDedup.__init__ | Init seen-hash set | self | None | sets self._seen | OK | mutable per-instance state shared across coords (intended); not async-safe if concurrently mutated |
| core/swarm_coordinator.py:95 | FindingDedup.is_new | Cross-coord dedup check | finding dict | bool | mutates self._seen | OK | _seen grows unbounded for long hunts (no eviction/cap) |
| core/swarm_coordinator.py:104 | FindingDedup._key (static) | SHA1 fingerprint target/type/param/payload | finding dict | str | none | OK | SHA1 weak hash, but only a dedup key (acceptable) |
| core/swarm_coordinator.py:116 | FindingDedup.reset | Clear seen set | self | None | clears self._seen | OK | |
| core/swarm_coordinator.py:135 | SwarmCoordinator.__init__ | Wire bus/audit/limits, gen coordinator_id | bus, audit_logger, limits, dedup | None | sets instance attrs | OK | |
| core/swarm_coordinator.py:162 | SwarmCoordinator.build_manifest | Abstract hook | target, context | NotImplementedError | none | OK | abstract - raises by design |
| core/swarm_coordinator.py:174 | SwarmCoordinator.handle_message | Public entrypoint: validate target, build+run manifest | payload dict | CoordinatorResult | publishes phase.skipped event | NEEDS-FIX | No scope/RoE check on target before dispatch - relies entirely on downstream workers |
| core/swarm_coordinator.py:197 | SwarmCoordinator._run_manifest | Spawn workers, run swarm w/ overall timeout, build result | target, manifest, context | CoordinatorResult | registers/spawns agents, publishes phase.started/completed | NEEDS-FIX | On TimeoutError builds fresh SwarmStats(spawned=N) -> reports completed=0/failed=0 (wrong); wait_for cancels run_swarm but inner engine tasks may orphan; get_findings() on cancelled engine may be partial |
| core/swarm_coordinator.py:269 | SwarmCoordinator._ensure_dedup_key (static) | Inject vuln_type for recon findings so engine dedup works | finding dict | dict | mutates finding in place | OK | mutates caller's finding dict (side effect on input) |
| core/swarm_coordinator.py:288 | SwarmCoordinator._wrap_runner | Wrap runner: events+audit+streaming+rate-limit; returns inner coroutine wrapped | spec, target, engine_findings, context | AgentRunner | - | OK | |
| core/swarm_coordinator.py:297 | _wrap_runner.wrapped (nested) | Run one worker, emit events, stream findings, re-raise for stats | agent | list[dict] | publishes swarm events, audit, mutates engine_findings | OK | broad except Exception at 332 intentional (logged + reraised, not silent); rate_limit_s sleep applies per-worker not between spawns (mislabeled comment) |
| core/swarm_coordinator.py:383 | SwarmCoordinator._publish_phase_event | Publish phase+swarm lifecycle event + audit | action, target, payload | None | 2x bus.publish + audit.event | OK | |
| core/swarm_coordinator.py:405 | SwarmCoordinator._publish_swarm_event | Publish dashboard swarm event | event, payload | None | bus.publish | OK | |
| core/swarm_coordinator.py:414 | SwarmCoordinator._publish_finding | Cross-coord dedup then stream finding to OUTPUT_TOPIC+swarm+audit | finding, target, technique | None | bus.publish (x1-2), audit.event | OK | **finding spread last (line 439) lets a finding's own target/source_phase override coordinator-set keys |
| core/swarm_coordinator.py:471 | SwarmCoordinator._make_engine | Factory: new SwarmEngine per run | self | SwarmEngine | none | OK | |
| core/swarm_coordinator.py:477 | SwarmCoordinator._available_techniques | List workers for PHASE | self | list[str] | imports swarm_workers | NEEDS-FIX | bare except Exception: return [] (line 483) silently hides import/lookup errors -> empty manifest masks bugs |
| core/swarm_coordinator.py:500 | ReconSwarmCoordinator.__init__ | Store default_techniques | default_techniques, **kw | None | sets attr | OK | |
| core/swarm_coordinator.py:504 | ReconSwarmCoordinator.build_manifest | Build recon worker specs | target, context | list[WorkerSpec] | imports get_worker_runner | OK | unknown-technique KeyError swallowed w/ warning (intended) |
| core/swarm_coordinator.py:562 | VulnSwarmCoordinator.__init__ | Store default_techniques | default_techniques, **kw | None | sets attr | OK | |
| core/swarm_coordinator.py:566 | VulnSwarmCoordinator.build_manifest | Expand workers x assets | target, context | list[WorkerSpec] | lazy import | NEEDS-FIX | workers x assets unbounded (docstring admits 225 slots); bounded only by max_concurrent at runtime, not manifest size - large asset lists explode spawn count |
| core/swarm_coordinator.py:601 | VulnSwarmCoordinator._make_asset_runner | Rebind agent.target to asset_url for run | base_runner, asset_url | AgentRunner | - | OK | mutates shared agent.target (restored in finally; race if agent reused concurrently) |
| core/swarm_coordinator.py:605 | _make_asset_runner.runner (nested) | Swap agent.target, run, restore | agent | list[dict] | mutates agent.target | OK | |
| core/swarm_coordinator.py:617 | VulnSwarmCoordinator._collect_assets | Resolve asset URLs from context | target, context | list[str] | none | OK | |
| core/swarm_coordinator.py:642 | VulnSwarmCoordinator._coerce_url (static) | Bare host -> https URL | asset, default | str | none | OK | defaults bare host to https only (may miss http-only assets) |
| core/swarm_coordinator.py:654 | VulnSwarmCoordinator._asset_to_url | Recon finding -> probable URL | finding dict | Optional[str] | none | OK | open_port non-HTTP ports dropped (intentional) |
| core/swarm_coordinator.py:734 | ExploitSwarmCoordinator.__init__ | Store approval_gate + auto_approve | approval_gate, auto_approve_destructive, **kw | None | sets attrs | OK | |
| core/swarm_coordinator.py:745 | ExploitSwarmCoordinator.build_manifest | Map vuln findings -> gated exploit specs | target, context | list[WorkerSpec] | lazy import | OK | |
| core/swarm_coordinator.py:784 | ExploitSwarmCoordinator._exploit_for_finding | type/vuln_type -> exploit technique | finding dict | Optional[str] | none | OK | |
| core/swarm_coordinator.py:796 | ExploitSwarmCoordinator._gated_runner | Wrap runner behind approval gate | base_runner, finding, target_url | AgentRunner | - | OK | |
| core/swarm_coordinator.py:800 | _gated_runner.gated (nested) | Approve-or-skip, rebind target | agent | list[dict] | mutates agent.target | OK | |
| core/swarm_coordinator.py:817 | ExploitSwarmCoordinator._approve | Call approval_gate.confirm_tool, fail-closed | technique, finding, target_url | bool | awaits gate | OK | broad except (line 833) intentional fail-closed + logged; logs finding title in rationale (low PII risk) |
| core/swarm_coordinator.py:866 | PostSwarmCoordinator.__init__ | Store approval_gate + auto_approve | approval_gate, auto_approve_destructive, **kw | None | sets attrs | OK | |
| core/swarm_coordinator.py:877 | PostSwarmCoordinator.build_manifest | Pick foothold/default post techniques, gate all but flag_hunter | target, context | list[WorkerSpec] | lazy import | OK | |
| core/swarm_coordinator.py:914 | PostSwarmCoordinator._gated_runner | Wrap post runner behind gate | base_runner, technique | AgentRunner | - | OK | |
| core/swarm_coordinator.py:915 | _gated_runner.gated (nested) | Approve-or-skip post worker | agent | list[dict] | awaits gate | OK | |
| core/swarm_coordinator.py:927 | PostSwarmCoordinator._approve | Approval check, fail-closed | technique, target | bool | awaits gate | NEEDS-FIX | bare except Exception: return False (lines 938-939) with NO logging - silent swallow, unlike Exploit._approve which logs |
| core/hack_mode.py:18 | (docstring) ReportSwarmCoordinator | Claimed 5th coordinator "writes reports/*" | - | - | - | DEAD-CODE | Referenced ONLY in this docstring; class never defined/imported anywhere. The 5th coordinator does not exist |
| core/hack_mode.py:589,597 | _NoOpCoordinator | Actual fallback for "report" phase | phase, **kw | empty manifest | logs | OK | this is what really handles "report" - proves no ReportSwarmCoordinator |
