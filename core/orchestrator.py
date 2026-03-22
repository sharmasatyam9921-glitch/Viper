#!/usr/bin/env python3
"""
VIPER 4.0 Orchestrator — Pure-Python State Machine.

Zero-dependency async state machine inspired by open-source pentesting frameworks.
Nodes: initialize → think → execute_tool / execute_plan / await_approval → generate_response.

No LangGraph. No LangChain. No Pydantic (uses dataclasses from agent_state).
"""

import asyncio
import json
import logging
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Callable, Coroutine, Dict, List, Optional, Tuple

logger = logging.getLogger("viper.orchestrator")


# ═══════════════════════════════════════════════════════════════════════
# PURE-PYTHON STATE MACHINE
# ═══════════════════════════════════════════════════════════════════════

class StateMachine:
    """
    Pure-Python async state machine replacing LangGraph.

    Nodes are async callables that receive state and return partial updates.
    Edges are either unconditional (src→dst) or conditional (src→fn→mapping→dst).
    Execution proceeds until a node routes to "END".
    """

    def __init__(self):
        self._nodes: Dict[str, Callable] = {}
        self._edges: Dict[str, List[Tuple[Optional[Callable], str]]] = {}
        self._conditional_edges: Dict[str, Tuple[Callable, Dict[str, str]]] = {}
        self._entry: Optional[str] = None

    def add_node(self, name: str, fn: Callable[..., Coroutine]):
        """Register an async node function."""
        self._nodes[name] = fn

    def add_edge(self, src: str, dst: str):
        """Add unconditional edge: src always routes to dst."""
        self._edges.setdefault(src, []).append((None, dst))

    def add_conditional_edge(
        self,
        src: str,
        condition_fn: Callable[[dict], str],
        mapping: Dict[str, str],
    ):
        """Add conditional edge: condition_fn(state) returns a key in mapping."""
        self._conditional_edges[src] = (condition_fn, mapping)

    def set_entry(self, name: str):
        """Set the entry node."""
        self._entry = name

    async def run(self, state: dict) -> dict:
        """Execute the state machine until END is reached."""
        if not self._entry:
            raise RuntimeError("No entry node set")

        current = self._entry
        max_steps = state.get("max_iterations", 30) * 3 + 20  # safety ceiling
        steps = 0

        while current != "END":
            steps += 1
            if steps > max_steps:
                logger.error(f"State machine exceeded {max_steps} steps — forcing END")
                state["task_complete"] = True
                state["completion_reason"] = "max_steps_exceeded"
                break

            if current not in self._nodes:
                raise RuntimeError(f"Unknown node: {current}")

            # Execute node
            node_fn = self._nodes[current]
            try:
                state_update = await node_fn(state)
                if state_update:
                    state.update(state_update)
            except Exception as exc:
                logger.error(f"Node '{current}' raised {type(exc).__name__}: {exc}")
                state.setdefault("errors", []).append({
                    "node": current,
                    "error": str(exc),
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                })
                # Route to generate_response on unhandled error
                current = "generate_response" if "generate_response" in self._nodes else "END"
                continue

            # Route to next node
            current = self._route(current, state)

        return state

    def _route(self, current: str, state: dict) -> str:
        """Determine the next node from current."""
        # Conditional edges take priority
        if current in self._conditional_edges:
            cond_fn, mapping = self._conditional_edges[current]
            try:
                key = cond_fn(state)
            except Exception as exc:
                logger.error(f"Condition fn for '{current}' failed: {exc}")
                return "END"
            target = mapping.get(key)
            if target is None:
                logger.error(f"Condition returned '{key}' but no mapping for it from '{current}'")
                return "END"
            return target

        # Unconditional edges
        if current in self._edges and self._edges[current]:
            return self._edges[current][0][1]

        # No edge defined — end
        logger.warning(f"No outgoing edge from '{current}', ending")
        return "END"


# ═══════════════════════════════════════════════════════════════════════
# VIPER ORCHESTRATOR
# ═══════════════════════════════════════════════════════════════════════

class ViperOrchestrator:
    """
    Main VIPER 4.0 orchestrator — drives the ReACT loop via StateMachine.

    Nodes:
        initialize       → validate target, set up state
        think            → LLM reasoning via ThinkEngine
        execute_tool     → run a single tool
        execute_plan     → run a wave of tools in parallel
        await_approval   → gate phase transitions
        process_approval → apply approval decision
        generate_response→ build final output

    All node methods are async and return partial state dicts.
    """

    def __init__(
        self,
        graph_engine=None,
        model_router=None,
        approval_gate=None,
        chain_writer=None,
        think_engine=None,
        tool_registry: Optional[Dict[str, Callable]] = None,
        guardrail=None,
    ):
        self.graph = graph_engine
        self.router = model_router
        self.approval = approval_gate or _DefaultApprovalGate()
        self.chain_writer = chain_writer
        self.think_engine = think_engine
        self.tool_registry = tool_registry or {}
        self.guardrail = guardrail
        self._machine = self._build_machine()

    # ------------------------------------------------------------------
    # Machine construction
    # ------------------------------------------------------------------

    def _build_machine(self) -> StateMachine:
        m = StateMachine()

        m.add_node("initialize", self._initialize)
        m.add_node("think", self._think)
        m.add_node("execute_tool", self._execute_tool)
        m.add_node("execute_plan", self._execute_plan)
        m.add_node("await_approval", self._await_approval)
        m.add_node("process_approval", self._process_approval)
        m.add_node("generate_response", self._generate_response)

        m.set_entry("initialize")

        m.add_conditional_edge("initialize", self._route_after_init, {
            "think": "think",
            "generate_response": "generate_response",
        })

        m.add_conditional_edge("think", self._route_after_think, {
            "execute_tool": "execute_tool",
            "execute_plan": "execute_plan",
            "await_approval": "await_approval",
            "generate_response": "generate_response",
            "think": "think",
        })

        m.add_edge("execute_tool", "think")
        m.add_edge("execute_plan", "think")
        m.add_edge("await_approval", "process_approval")

        m.add_conditional_edge("process_approval", self._route_after_approval, {
            "think": "think",
            "generate_response": "generate_response",
        })

        m.add_edge("generate_response", "END")

        return m

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def invoke(self, target: str, objective: str, **kwargs) -> dict:
        """
        Run VIPER against *target* with the given *objective*.

        Returns a response dict with keys:
            answer, findings, execution_trace, stats, errors
        """
        state = _create_initial_state(
            user_id=kwargs.get("user_id", "viper"),
            project_id=kwargs.get("project_id", "default"),
            session_id=kwargs.get("session_id", ""),
            objective=objective,
            max_iterations=kwargs.get("max_iterations", 30),
        )
        state["target"] = target

        # Start chain tracking
        if self.chain_writer:
            chain_id = self.chain_writer.start_chain(target)
            state["chain_id"] = chain_id

        t0 = time.monotonic()

        # Run
        final_state = await self._machine.run(state)

        elapsed = time.monotonic() - t0

        # End chain
        if self.chain_writer and "chain_id" in final_state:
            status = "completed" if final_state.get("task_complete") else "interrupted"
            self.chain_writer.end_chain(final_state["chain_id"], status=status)

        return self._build_response(final_state, elapsed)

    # ------------------------------------------------------------------
    # Node: initialize
    # ------------------------------------------------------------------

    async def _initialize(self, state: dict) -> dict:
        """Validate target and prepare initial state."""
        target = state.get("target", "")
        updates: dict = {}

        # Guardrail check
        if self.guardrail:
            allowed, reason = self.guardrail.validate(target)
            if not allowed:
                logger.warning(f"Target blocked by guardrail: {reason}")
                updates["_guardrail_blocked"] = True
                updates["completion_reason"] = f"Target blocked: {reason}"
                updates["task_complete"] = True
                return updates

        updates["_guardrail_blocked"] = False

        # Populate target_info stub
        updates["target_info"] = {
            "primary_target": target,
            "target_type": _classify_target(target),
            "ports": [],
            "services": [],
            "technologies": [],
            "vulnerabilities": [],
            "credentials": [],
        }

        # Graph: register target node
        if self.graph:
            try:
                self.graph.add_node("Target", name=target, url=target)
            except Exception as exc:
                logger.debug(f"Graph add_node failed: {exc}")

        logger.info(f"Initialized hunt: {target}")
        return updates

    # ------------------------------------------------------------------
    # Node: think
    # ------------------------------------------------------------------

    async def _think(self, state: dict) -> dict:
        """Delegate reasoning to ThinkEngine and return state updates."""
        iteration = state.get("current_iteration", 0) + 1
        state["current_iteration"] = iteration

        if iteration > state.get("max_iterations", 30):
            return {
                "task_complete": True,
                "completion_reason": "max_iterations_reached",
                "current_iteration": iteration,
            }

        if self.think_engine:
            result = await self.think_engine.think(state)
            result["current_iteration"] = iteration
            return result

        # No think engine — immediate completion
        return {
            "task_complete": True,
            "completion_reason": "no_think_engine",
            "current_iteration": iteration,
        }

    # ------------------------------------------------------------------
    # Node: execute_tool
    # ------------------------------------------------------------------

    async def _execute_tool(self, state: dict) -> dict:
        """Execute a single tool from the LLM decision."""
        decision = state.get("_decision", {})
        tool_name = decision.get("tool_name")
        tool_args = decision.get("tool_args") or {}

        if not tool_name:
            return {"_tool_result": {"error": "No tool specified", "success": False}}

        tool_fn = self.tool_registry.get(tool_name)
        if not tool_fn:
            msg = f"Unknown tool: {tool_name}"
            logger.warning(msg)
            return {"_tool_result": {"error": msg, "success": False, "tool_name": tool_name}}

        t0 = time.monotonic()
        try:
            if asyncio.iscoroutinefunction(tool_fn):
                output = await tool_fn(**tool_args)
            else:
                output = await asyncio.get_event_loop().run_in_executor(None, lambda: tool_fn(**tool_args))
            success = True
            error = None
        except Exception as exc:
            output = str(exc)
            success = False
            error = str(exc)
            logger.error(f"Tool {tool_name} failed: {exc}")

        duration_ms = (time.monotonic() - t0) * 1000

        result = {
            "tool_name": tool_name,
            "tool_args": tool_args,
            "output": str(output)[:10000] if output else "",
            "success": success,
            "error": error,
            "duration_ms": duration_ms,
        }

        # Record in chain
        if self.chain_writer and "chain_id" in state:
            self.chain_writer.add_step(
                chain_id=state["chain_id"],
                tool=tool_name,
                input_data=json.dumps(tool_args, default=str)[:5000],
                output_data=result["output"][:5000],
                phase=state.get("current_phase", "informational"),
                thought=decision.get("thought", ""),
                success=success,
                duration_ms=duration_ms,
            )

        # Append to execution trace
        step = {
            "step_id": f"step-{uuid.uuid4().hex[:8]}",
            "iteration": state.get("current_iteration", 0),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "phase": state.get("current_phase", "informational"),
            "thought": decision.get("thought", ""),
            "reasoning": decision.get("reasoning", ""),
            "tool_name": tool_name,
            "tool_args": tool_args,
            "tool_output": result["output"][:5000],
            "success": success,
            "error_message": error,
        }
        trace = list(state.get("execution_trace", []))
        trace.append(step)

        return {
            "_tool_result": result,
            "execution_trace": trace,
        }

    # ------------------------------------------------------------------
    # Node: execute_plan (Wave Runner — parallel tool execution)
    # ------------------------------------------------------------------

    async def _execute_plan(self, state: dict) -> dict:
        """Execute a wave of tools in parallel."""
        decision = state.get("_decision", {})
        plan = decision.get("tool_plan", {})
        steps = plan.get("steps", []) if isinstance(plan, dict) else []

        if not steps:
            return {"_tool_result": {"error": "Empty plan", "success": False}}

        async def _run_one(step_def: dict) -> dict:
            name = step_def.get("tool_name", "")
            args = step_def.get("tool_args", {})
            fn = self.tool_registry.get(name)
            if not fn:
                return {"tool_name": name, "output": f"Unknown tool: {name}", "success": False}
            t0 = time.monotonic()
            try:
                if asyncio.iscoroutinefunction(fn):
                    out = await fn(**args)
                else:
                    out = await asyncio.get_event_loop().run_in_executor(None, lambda: fn(**args))
                return {
                    "tool_name": name,
                    "tool_args": args,
                    "output": str(out)[:10000] if out else "",
                    "success": True,
                    "duration_ms": (time.monotonic() - t0) * 1000,
                }
            except Exception as exc:
                return {
                    "tool_name": name,
                    "tool_args": args,
                    "output": str(exc),
                    "success": False,
                    "duration_ms": (time.monotonic() - t0) * 1000,
                }

        results = await asyncio.gather(*[_run_one(s) for s in steps], return_exceptions=False)

        # Record each in chain + trace
        trace = list(state.get("execution_trace", []))
        for res in results:
            if self.chain_writer and "chain_id" in state:
                self.chain_writer.add_step(
                    chain_id=state["chain_id"],
                    tool=res["tool_name"],
                    input_data=json.dumps(res.get("tool_args", {}), default=str)[:5000],
                    output_data=res.get("output", "")[:5000],
                    phase=state.get("current_phase", "informational"),
                    thought=plan.get("plan_rationale", ""),
                    success=res.get("success", False),
                    duration_ms=res.get("duration_ms", 0),
                )
            trace.append({
                "step_id": f"step-{uuid.uuid4().hex[:8]}",
                "iteration": state.get("current_iteration", 0),
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "phase": state.get("current_phase", "informational"),
                "thought": plan.get("plan_rationale", ""),
                "reasoning": f"Wave plan: {res['tool_name']}",
                "tool_name": res["tool_name"],
                "tool_args": res.get("tool_args", {}),
                "tool_output": res.get("output", "")[:5000],
                "success": res.get("success", False),
                "error_message": None if res.get("success") else res.get("output", ""),
            })

        return {
            "_tool_result": {"plan_results": results, "success": any(r["success"] for r in results)},
            "execution_trace": trace,
        }

    # ------------------------------------------------------------------
    # Node: await_approval
    # ------------------------------------------------------------------

    async def _await_approval(self, state: dict) -> dict:
        """Request approval for a phase transition."""
        decision = state.get("_decision", {})
        transition = decision.get("phase_transition", {})

        request = {
            "from_phase": state.get("current_phase", "informational"),
            "to_phase": transition.get("to_phase", "exploitation"),
            "reason": transition.get("reason", "Phase transition requested"),
            "planned_actions": transition.get("planned_actions", []),
            "risks": transition.get("risks", []),
        }

        result = await self.approval.request_approval(request)

        return {
            "awaiting_user_approval": False,
            "_approval_result": result,
        }

    # ------------------------------------------------------------------
    # Node: process_approval
    # ------------------------------------------------------------------

    async def _process_approval(self, state: dict) -> dict:
        """Apply the approval decision."""
        result = state.get("_approval_result", {})
        approved = result.get("approved", False)
        decision = state.get("_decision", {})
        transition = decision.get("phase_transition", {})

        if approved:
            new_phase = transition.get("to_phase", state.get("current_phase"))
            phase_history = list(state.get("phase_history", []))
            phase_history.append({
                "phase": new_phase,
                "entered_at": datetime.now(timezone.utc).isoformat(),
            })

            if self.chain_writer and "chain_id" in state:
                self.chain_writer.add_decision(
                    chain_id=state["chain_id"],
                    decision=f"Phase transition to {new_phase}",
                    reasoning=transition.get("reason", ""),
                )

            return {
                "current_phase": new_phase,
                "phase_history": phase_history,
                "_abort_transition": False,
            }
        else:
            return {
                "_abort_transition": True,
                "completion_reason": result.get("reason", "Phase transition denied"),
            }

    # ------------------------------------------------------------------
    # Node: generate_response
    # ------------------------------------------------------------------

    async def _generate_response(self, state: dict) -> dict:
        """Build the final response from execution trace."""
        state["task_complete"] = True
        return {"task_complete": True}

    # ------------------------------------------------------------------
    # Routing functions
    # ------------------------------------------------------------------

    def _route_after_init(self, state: dict) -> str:
        if state.get("_guardrail_blocked"):
            return "generate_response"
        return "think"

    def _route_after_think(self, state: dict) -> str:
        if state.get("task_complete"):
            return "generate_response"

        decision = state.get("_decision", {})
        action = decision.get("action", "complete")

        if action == "use_tool":
            return "execute_tool"
        if action == "plan_tools":
            return "execute_plan"
        if action == "transition_phase":
            return "await_approval"
        if action == "complete":
            return "generate_response"
        if action == "ask_user":
            # For now, treat ask_user as think-again (no interactive UI in CLI)
            return "think"

        logger.warning(f"Unknown action '{action}', routing to generate_response")
        return "generate_response"

    def _route_after_approval(self, state: dict) -> str:
        if state.get("_abort_transition"):
            return "generate_response"
        return "think"

    # ------------------------------------------------------------------
    # Response builder
    # ------------------------------------------------------------------

    def _build_response(self, state: dict, elapsed_s: float = 0) -> dict:
        """Extract a clean response dict from final state."""
        trace = state.get("execution_trace", [])

        # Collect findings from trace
        findings = []
        for step in trace:
            if step.get("success") and step.get("tool_output"):
                findings.append({
                    "tool": step.get("tool_name"),
                    "phase": step.get("phase"),
                    "output_preview": step["tool_output"][:500],
                })

        # Count stats
        total_tools = len(trace)
        successful = sum(1 for s in trace if s.get("success"))
        failed = total_tools - successful
        phases_visited = list({s.get("phase") for s in trace if s.get("phase")})

        return {
            "target": state.get("target", ""),
            "objective": state.get("original_objective", ""),
            "answer": state.get("completion_reason", "Hunt completed"),
            "findings": findings,
            "execution_trace": trace,
            "errors": state.get("errors", []),
            "stats": {
                "iterations": state.get("current_iteration", 0),
                "total_tools_run": total_tools,
                "successful": successful,
                "failed": failed,
                "phases_visited": phases_visited,
                "elapsed_seconds": round(elapsed_s, 2),
            },
            "target_info": state.get("target_info", {}),
        }


# ═══════════════════════════════════════════════════════════════════════
# DEFAULT APPROVAL GATE (auto-approve)
# ═══════════════════════════════════════════════════════════════════════

class _DefaultApprovalGate:
    """Auto-approving gate used when no custom approval_gate is provided."""

    async def request_approval(self, request: dict) -> dict:
        logger.info(
            f"Auto-approving phase transition: "
            f"{request.get('from_phase')} → {request.get('to_phase')}"
        )
        return {"approved": True, "reason": "auto"}


# ═══════════════════════════════════════════════════════════════════════
# HELPER FUNCTIONS
# ═══════════════════════════════════════════════════════════════════════

def _create_initial_state(
    user_id: str = "viper",
    project_id: str = "default",
    session_id: str = "",
    objective: str = "",
    max_iterations: int = 30,
) -> dict:
    """Create the initial state dict (replaces LangGraph AgentState TypedDict)."""
    sid = session_id or f"session-{uuid.uuid4().hex[:12]}"
    return {
        # Core
        "messages": [],
        "current_iteration": 0,
        "max_iterations": max_iterations,
        "task_complete": False,
        "completion_reason": None,

        # Phase
        "current_phase": "informational",
        "phase_history": [{"phase": "informational", "entered_at": datetime.now(timezone.utc).isoformat()}],
        "phase_transition_pending": None,

        # Attack path
        "attack_path_type": "general-unclassified",

        # Execution
        "execution_trace": [],

        # Todo
        "todo_list": [],

        # Objectives
        "original_objective": objective,
        "conversation_objectives": [{"content": objective, "created_at": datetime.now(timezone.utc).isoformat()}],
        "current_objective_index": 0,
        "objective_history": [],

        # Target
        "target": "",
        "target_info": {},

        # Session
        "user_id": user_id,
        "project_id": project_id,
        "session_id": sid,

        # Approval
        "awaiting_user_approval": False,
        "user_approval_response": None,

        # Internal routing flags
        "_decision": None,
        "_tool_result": None,
        "_guardrail_blocked": False,
        "_abort_transition": False,

        # Errors
        "errors": [],
    }


def _classify_target(target: str) -> str:
    """Quick heuristic to classify a target string."""
    import re
    target = target.strip()
    if re.match(r'^\d{1,3}(\.\d{1,3}){3}$', target):
        return "ip"
    if target.startswith(("http://", "https://")):
        return "url"
    if "." in target:
        return "domain"
    return "hostname"
