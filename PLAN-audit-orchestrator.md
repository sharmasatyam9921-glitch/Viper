# PLAN — Function Audit: `orchestrator`

> Part of [PLAN.md](PLAN.md) Section 2. Generated 2026-06-06. Module: **core/orchestrator.py**

**Exists:** True  

## Summary

Pure-Python async state machine (no LangGraph) that drives VIPER's ReACT loop: initialize -> think -> execute_tool/execute_plan/await_approval -> generate_response. 818 lines, two classes (StateMachine, ViperOrchestrator) plus _DefaultApprovalGate and 3 module helpers. Scope/guardrail enforcement happens ONCE at initialize; individual tool executions (execute_tool, execute_plan) run whatever is in tool_registry with NO per-call scope/RoE/phase re-check and NO per-tool timeout. Error handling is generally non-silent (errors are logged + recorded to state), but several broad except Exception blocks swallow chain_writer/graph failures. No retries, no idempotency keys, no rate limiting in this module (delegated elsewhere). Mutable agent state (_agents) set via setattr without being declared in __init__.

## Top issues

- invoke() (302) lacks try/finally -> agent subsystem + open chain leak if _machine.run raises.
- No per-tool timeout in _execute_tool/_execute_plan -> hung tool stalls the loop indefinitely.
- _execute_plan unbounded asyncio.gather + default executor, no concurrency cap/rate limit -> resource exhaustion / target flood.
- Scope/RoE checked only at init; execute_tool/execute_plan run LLM-chosen tool_args with no per-call scope re-check -> out-of-scope action risk.
- _DefaultApprovalGate auto-approves all phase transitions (incl. exploitation) when no real gate is injected.
- Multiple sync I/O-capable calls (guardrail.validate, graph.add_node, chain_writer.*) run inside async defs without executor offload -> event-loop blocking.

## Scope / safety notes

This module performs target-affecting actions WITHOUT a per-action scope/RoE check. The only guardrail/scope gate is in _initialize (line 363-372) and validates ONLY the initial primary target via self.guardrail.validate(target). After that, _execute_tool (427) and _execute_plan (506) invoke whatever callables are in tool_registry with whatever tool_args the LLM/think_engine supplies (which may include arbitrary hosts/URLs/parameters) and there is NO re-validation against scope, exclusion lists, phase, or RoE before execution. invoke() (302) also seeds the recon agent with the target (line 324) before any scope confirmation beyond init. There is no rate limiting, no per-tool timeout, and no concurrency cap in _execute_plan, so a model-chosen wave can flood a target. Net: scope safety depends entirely on (a) the injected guardrail at init and (b) tool_registry callables / think_engine enforcing scope themselves — none of which is guaranteed by this module. This violates the project's per-action scope-enforcement intent (.claude/rules/scope.md, CLAUDE.md roe_engine usage). Recommend per-call scope/RoE/phase checks inside _execute_tool and _run_one.

## Function-by-function table

| File:Line | Function | Purpose | Inputs | Outputs | Side effects | Status | Issues |
|---|---|---|---|---|---|---|---|
| orchestrator.py:46 | StateMachine.__init__ | Init empty node/edge registries | self | None | Sets instance dicts | OK | |
| orchestrator.py:52 | StateMachine.add_node | Register async node fn | name, fn | None | Mutates _nodes | OK | No dup-name guard (silent overwrite) |
| orchestrator.py:56 | StateMachine.add_edge | Add unconditional edge | src, dst | None | Mutates _edges | OK | |
| orchestrator.py:60 | StateMachine.add_conditional_edge | Add conditional edge w/ mapping | src, condition_fn, mapping | None | Mutates _conditional_edges | OK | Overwrites prior cond edge for src silently |
| orchestrator.py:69 | StateMachine.set_entry | Set entry node name | name | None | Sets _entry | OK | No validation node exists |
| orchestrator.py:73 | StateMachine.run | Execute machine until END | state dict | state dict | Mutates state in place; logs | OK | max_steps derived from state max_iterations (bounded, good); broad `except Exception` (99) is intentional-recovery (records error, reroutes) not silent; mutates caller's state dict |
| orchestrator.py:115 | StateMachine._route | Pick next node | current, state | str node name | Logs | OK | Cond-fn failure (122) routes to END silently-ish (logged); unconditional edge picks only first edge [0], extra edges ignored |
| orchestrator.py:144 | ViperOrchestrator.__init__ | Wire deps + build machine | graph_engine, model_router, approval_gate, chain_writer, think_engine, tool_registry, guardrail, enable_agents | None | Builds machine; sets attrs | OK | _agents attr not initialized here (set later in _start_agents via implicit attr) -> AttributeError risk if _stop_agents path hit oddly (guarded by getattr at 277, but agent_bus set w/o _agents) |
| orchestrator.py:190 | ViperOrchestrator._build_machine | Construct StateMachine graph | self | StateMachine | None | OK | |
| orchestrator.py:237 | ViperOrchestrator._start_agents | Start multi-agent subsystem | self | None | Instantiates agents/bus/registry; sets self._agents; logs | NEEDS-FIX | check_interval/30.0 hard-coded; broad except (268) disables agents on any failure (acceptable degrade but masks root cause); no scope/RoE passed to recon/vuln/chain agents (only exploit gets guardrail) |
| orchestrator.py:272 | ViperOrchestrator._stop_agents | Stop agents/bus/registry | self | None | Stops tasks; logs | OK | broad except (282) swallows shutdown errors (logged) |
| orchestrator.py:285 | ViperOrchestrator.publish_to_agents | Publish msg to agent bus | topic, payload, priority | message id str | Awaits bus.publish | OK | Returns "" silently if no bus (caller can't distinguish) |
| orchestrator.py:302 | ViperOrchestrator.invoke | Public entry: run hunt | target, objective, **kwargs | response dict | Starts/stops agents; chain start/end; runs machine; timing | NEEDS-FIX | NO scope/RoE check here before seeding recon agent (324) or running; relies solely on _initialize guardrail; chain_writer.start_chain/end_chain called sync in async def (blocking if I/O) (332,345); no try/finally so _stop_agents/end_chain skipped if machine.run raises (resource leak) |
| orchestrator.py:357 | ViperOrchestrator._initialize | Validate target, seed state | state | updates dict | Guardrail validate; graph.add_node; logs | NEEDS-FIX | guardrail.validate called sync in async (357) — blocks loop if LLM/network guardrail; graph.add_node sync in async (388) wrapped in broad except->debug (silent-ish); only scope gate in module |
| orchestrator.py:399 | ViperOrchestrator._think | Delegate to ThinkEngine | state | updates dict | Mutates state[current_iteration] | OK | Mutates state directly (402) then returns partial — double-write; bounded by max_iterations |
| orchestrator.py:427 | ViperOrchestrator._execute_tool | Run one tool from decision | state | updates dict | Runs tool; chain add_step; appends trace; logs | NEEDS-FIX | NO per-tool timeout (445/447) — a hung tool stalls forever; NO scope/RoE/phase re-check before exec; NO retry; chain_writer.add_step sync in async (469); sync tool runs in default executor (unbounded thread pool); output truncated 10k (ok) |
| orchestrator.py:506 | ViperOrchestrator._execute_plan | Parallel wave of tools | state | updates dict | gather() tools; chain add_step; trace; | NEEDS-FIX | NO per-tool/wave timeout; NO scope/RoE/phase re-check; NO concurrency cap (unbounded asyncio.gather + executor threads) — DoS-amplification / resource risk; chain_writer.add_step sync in async (549) |
| orchestrator.py:515 | _execute_plan._run_one (nested) | Run single tool in wave | step_def | result dict | Runs tool | NEEDS-FIX | broad except (534) returns failure dict (non-silent, ok) but no timeout; lambda closure over loop var args is fine (per-call); no scope check |
| orchestrator.py:582 | ViperOrchestrator._await_approval | Request phase-transition approval | state | updates dict | await approval.request_approval | OK | Defaults to_phase 'exploitation' if unset (589) — could escalate phase on malformed decision |
| orchestrator.py:606 | ViperOrchestrator._process_approval | Apply approval decision | state | updates dict | chain add_decision; builds phase_history | OK | chain_writer.add_decision sync in async (622); on approve, new_phase falls back to current if to_phase unset |
| orchestrator.py:643 | ViperOrchestrator._generate_response | Mark task complete | state | updates dict | Mutates state[task_complete] | OK | Trivial; mutates state then returns same key |
| orchestrator.py:652 | ViperOrchestrator._route_after_init | Route post-init | state | str | None | OK | |
| orchestrator.py:657 | ViperOrchestrator._route_after_think | Route by decision.action | state | str | Logs unknown action | OK | ask_user -> 'think' (loop risk mitigated by max_iterations) |
| orchestrator.py:679 | ViperOrchestrator._route_after_approval | Route post-approval | state | str | None | OK | |
| orchestrator.py:688 | ViperOrchestrator._build_response | Assemble final response | state, elapsed_s | response dict | None | OK | Treats every successful tool output as a "finding" (no validation/FP filter here) — misleading findings list |
| orchestrator.py:734 | _DefaultApprovalGate.request_approval | Auto-approve transitions | request | {approved:True} | Logs | NEEDS-FIX | Auto-approves ALL phase transitions (incl. to exploitation) when no real gate injected — bypasses human approval control if misconfigured |
| orchestrator.py:746 | _create_initial_state | Build initial state dict | user_id, project_id, session_id, objective, max_iterations | state dict | None | OK | datetime.now called at default-arg-eval time? No—inside body, fine |
| orchestrator.py:807 | _classify_target | Heuristic target type | target | str type | None | OK | `import re` inside fn (minor); IPv6 not handled (returns domain/hostname) |
