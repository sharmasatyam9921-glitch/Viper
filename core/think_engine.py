#!/usr/bin/env python3
"""
VIPER 4.0 Think Engine — ReACT reasoning core.

Powers the "think" node in the orchestrator state machine.
No LangGraph/LangChain/Pydantic dependencies.

Reasoning flow:
  1. Check Deep Think triggers (first iteration, phase change, failure streak, self-request)
  2. Build system prompt with full context (phase, tools, trace, target, todo, deep-think)
  3. Call LLM via ModelRouter (or fall back to ViperBrain Q-learning)
  4. Parse LLMDecision from JSON response
  5. Return state updates for the orchestrator
"""

import json
import logging
import re
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("viper.think_engine")


# ═══════════════════════════════════════════════════════════════════════
# SYSTEM PROMPT TEMPLATE
# ═══════════════════════════════════════════════════════════════════════

REACT_SYSTEM_PROMPT = """\
You are VIPER, an elite autonomous penetration testing agent using the ReACT framework.
You reason step-by-step, choose precise actions, and adapt based on observations.

═══ CURRENT STATE ═══
Phase: {current_phase}
Iteration: {iteration}/{max_iterations}
Attack Path: {attack_path_type}
Target: {target}

═══ PHASE DEFINITIONS ═══
{phase_definitions}

═══ OBJECTIVE ═══
{objective}

═══ TARGET INTELLIGENCE ═══
{target_info}

═══ AVAILABLE TOOLS ═══
{available_tools}

═══ EXECUTION HISTORY (last {trace_window} steps) ═══
{chain_context}

═══ FAILURES ═══
{failure_summary}

═══ TODO LIST ═══
{todo_list}
{deep_think_section}
{pending_output_section}
═══ INSTRUCTIONS ═══
Think carefully about the current state, then output a JSON decision.

Your response MUST be valid JSON matching this schema:
{{
  "thought": "Your analysis of the current situation",
  "reasoning": "Why you chose this specific action",
  "action": "use_tool" | "plan_tools" | "transition_phase" | "complete" | "ask_user",
  "tool_name": "name_of_tool (when action=use_tool)",
  "tool_args": {{}},
  "tool_plan": {{
    "steps": [{{"tool_name": "...", "tool_args": {{}}, "rationale": "..."}}],
    "plan_rationale": "why parallel"
  }},
  "phase_transition": {{
    "to_phase": "exploitation",
    "reason": "...",
    "planned_actions": [],
    "risks": []
  }},
  "completion_reason": "why task is done (when action=complete)",
  "updated_todo_list": [{{"description": "...", "status": "pending|in_progress|completed", "priority": "high|medium|low"}}],
  "output_analysis": {{
    "interpretation": "what the last output tells us",
    "actionable_findings": [],
    "recommended_next_steps": [],
    "chain_findings": [{{"finding_type": "...", "severity": "...", "title": "...", "evidence": "..."}}]
  }},
  "need_deep_think": false
}}

Only include fields relevant to your chosen action. Omit null/empty fields.
Output ONLY the JSON — no markdown, no commentary.\
"""

DEEP_THINK_PROMPT = """\
You are performing a DEEP THINK strategic analysis for VIPER.
Reason carefully about the attack so far and produce a structured plan.

Trigger: {trigger_reason}

Target: {target}
Phase: {current_phase}
Iteration: {iteration}/{max_iterations}
Objective: {objective}

═══ ATTACK SURFACE MAP ═══
{attack_surface}

═══ AVAILABLE TOOLS & THEIR OUTPUTS ═══
{tool_status}

═══ EXECUTION HISTORY ═══
{execution_summary}

═══ FAILURES ═══
{failure_summary}

═══ HYPOTHESES IN PLAY ═══
{active_hypotheses}

Produce a COMPREHENSIVE strategic analysis as JSON:
{{
  "situation_assessment": "What we know, what we've tried, where we stand",
  "key_observations": ["observation1", "observation2"],
  "hypotheses": [
    {{"hypothesis": "What might be vulnerable and why", "test_method": "How to test it", "priority": 1}}
  ],
  "recommended_plan": [
    {{"step": 1, "action": "specific action", "tool": "tool_name", "reasoning": "why this step"}}
  ],
  "alternative_approaches": ["fallback1", "fallback2"],
  "risk_assessment": "What could go wrong and mitigations",
  "attack_vectors_identified": ["vector1", "vector2"],
  "recommended_approach": "Chosen strategy and rationale",
  "priority_order": ["step1", "step2", "step3"]
}}\
"""

PHASE_DEFINITIONS = {
    "informational": (
        "RECON/INFORMATIONAL — Gather intelligence: subdomain enum, port scanning, "
        "technology fingerprinting, directory brute-force, certificate analysis. "
        "No exploitation. Build the attack surface map."
    ),
    "exploitation": (
        "EXPLOITATION — Active attack: inject payloads (SQLi, XSS, SSTI, CMDi, SSRF), "
        "test auth bypasses, exploit CVEs, brute-force credentials. "
        "Use findings from recon to target specific weaknesses."
    ),
    "post_exploitation": (
        "POST-EXPLOITATION — Escalate: pivot, exfiltrate, establish persistence, "
        "lateral movement. Only if exploitation succeeded."
    ),
}


# ═══════════════════════════════════════════════════════════════════════
# THINK ENGINE
# ═══════════════════════════════════════════════════════════════════════

class ThinkEngine:
    """
    Core reasoning engine for VIPER's think node.

    Calls the LLM to decide the next action, or falls back to Q-learning.
    """

    def __init__(
        self,
        model_router=None,
        brain=None,
        evograph=None,
        tool_descriptions: Optional[Dict[str, str]] = None,
    ):
        """
        Args:
            model_router: ai/model_router.py ModelRouter instance for LLM calls.
            brain: viper_brain.py ViperBrain for Q-learning fallback.
            evograph: core/evograph.py EvoGraph for cross-session memory.
            tool_descriptions: {tool_name: description} for prompt building.
        """
        self.router = model_router
        self.brain = brain
        self.evograph = evograph
        self.tool_descriptions = tool_descriptions or {}
        self._consecutive_failures = 0
        self._last_deep_think: Optional[str] = None
        self._last_deep_think_structured: Optional[dict] = None

    # ------------------------------------------------------------------
    # Main entry point
    # ------------------------------------------------------------------

    async def think(self, state: dict) -> dict:
        """
        Core reasoning step. Returns partial state updates including _decision.

        Flow:
          1. Check Deep Think trigger conditions
          2. Build system prompt with full context
          3. Call LLM (or fall back to brain)
          4. Parse LLMDecision
          5. Update execution trace
          6. Return state updates
        """
        # 1. Deep Think check
        should_dt, dt_reason = self._should_deep_think(state)
        if should_dt:
            dt_result = await self.deep_think(state, dt_reason)
            self._last_deep_think = dt_result

        # 2. Build prompt
        system_prompt = self._build_system_prompt(state)

        # 3. LLM call
        decision = await self._llm_think(system_prompt, state)

        if decision is None:
            # Fallback to Q-learning
            decision = self._fallback_think(state)

        # Track failure streak
        if decision.get("action") == "complete" or decision.get("_fallback"):
            pass  # Don't count completions
        else:
            last_result = state.get("_tool_result", {})
            if isinstance(last_result, dict) and not last_result.get("success", True):
                self._consecutive_failures += 1
            else:
                self._consecutive_failures = 0

        # Clear deep think if it was consumed
        if should_dt:
            self._last_deep_think = None

        # 5/6. Return state updates
        updates = {"_decision": decision}

        if decision.get("action") == "complete":
            updates["task_complete"] = True
            updates["completion_reason"] = decision.get("completion_reason", "LLM decided complete")

        if decision.get("action") == "transition_phase":
            updates["phase_transition_pending"] = decision.get("phase_transition")

        # Todo list updates
        if decision.get("updated_todo_list"):
            updates["todo_list"] = decision["updated_todo_list"]

        return updates

    # ------------------------------------------------------------------
    # Deep Think
    # ------------------------------------------------------------------

    async def deep_think(self, state: dict, trigger_reason: str = "manual") -> dict:
        """
        Structured strategic analysis. Returns parsed DeepThinkResult dict.

        Pauses normal ReACT flow and builds a comprehensive analysis prompt with:
          - Current state summary (what we know, what we've tried)
          - Available tools and their outputs so far
          - Attack surface map
          - Hypotheses to test

        Returns structured dict with:
          situation_assessment, key_observations, hypotheses,
          recommended_plan, alternative_approaches, risk_assessment,
          attack_vectors_identified, recommended_approach, priority_order

        Also stores result as self._last_deep_think_structured for wave planning.

        Triggers:
          - First iteration
          - Phase transition
          - 3+ consecutive failures
          - LLM self-request (need_deep_think=True)
          - ReACT engine reward < -3 after 3 steps
        """
        logger.info(f"Deep Think triggered: {trigger_reason}")

        # Build execution summary
        trace = state.get("execution_trace", [])
        exec_lines = []
        for step in trace[-15:]:
            status = "OK" if step.get("success") else "FAIL"
            exec_lines.append(
                f"  [{status}] {step.get('tool_name', 'think')} → "
                f"{(step.get('tool_output') or '')[:200]}"
            )
        execution_summary = "\n".join(exec_lines) or "  (no steps yet)"

        # Failure summary
        failures = [s for s in trace if not s.get("success")]
        failure_lines = [f"  - {f.get('tool_name')}: {f.get('error_message', 'unknown')}" for f in failures[-5:]]
        failure_summary = "\n".join(failure_lines) or "  (none)"

        # Attack surface map from target_info
        ti = state.get("target_info", {})
        surface_lines = []
        for key in ("primary_target", "ports", "services", "technologies",
                     "vulnerabilities", "credentials", "endpoints", "subdomains"):
            val = ti.get(key)
            if val:
                surface_lines.append(f"  {key}: {val}")
        attack_surface = "\n".join(surface_lines) or "  (not yet mapped)"

        # Tool status — which tools have been used and what they returned
        tool_usage: Dict[str, List[str]] = {}
        for step in trace:
            tn = step.get("tool_name", "unknown")
            status = "OK" if step.get("success") else "FAIL"
            summary = (step.get("tool_output") or "")[:100]
            tool_usage.setdefault(tn, []).append(f"[{status}] {summary}")
        tool_lines = []
        for tn, usages in tool_usage.items():
            tool_lines.append(f"  {tn}: used {len(usages)}x")
            for u in usages[-2:]:  # last 2 usages
                tool_lines.append(f"    {u}")
        # Also list available but unused tools
        if self.tool_descriptions:
            used_names = set(tool_usage.keys())
            for tn, desc in self.tool_descriptions.items():
                if tn not in used_names:
                    tool_lines.append(f"  {tn}: (unused) — {desc}")
        tool_status = "\n".join(tool_lines) or "  (no tools used yet)"

        # Active hypotheses from previous deep think or todo list
        todos = state.get("todo_list", [])
        hyp_lines = []
        for t in todos:
            if isinstance(t, dict):
                hyp_lines.append(f"  [{t.get('status', 'pending')}] {t.get('description', '')}")
        active_hypotheses = "\n".join(hyp_lines) or "  (none)"

        prompt = DEEP_THINK_PROMPT.format(
            trigger_reason=trigger_reason,
            target=state.get("target", ""),
            current_phase=state.get("current_phase", "informational"),
            iteration=state.get("current_iteration", 0),
            max_iterations=state.get("max_iterations", 30),
            objective=state.get("original_objective", ""),
            execution_summary=execution_summary,
            failure_summary=failure_summary,
            attack_surface=attack_surface,
            tool_status=tool_status,
            active_hypotheses=active_hypotheses,
        )

        result = None
        if self.router:
            try:
                response = await self.router.complete(
                    prompt=prompt,
                    system="You are a strategic penetration testing advisor. Output JSON only.",
                    max_tokens=2000,
                    temperature=0.4,
                    json_mode=True,
                )
                if response:
                    result = _parse_deep_think_result(response.text)
            except Exception as exc:
                logger.warning(f"Deep Think LLM call failed: {exc}")

        # Fallback: simple structured result
        if result is None:
            result = {
                "situation_assessment": f"At iteration {state.get('current_iteration', 0)}, {len(trace)} steps completed.",
                "key_observations": [
                    f"{len(trace)} steps executed",
                    f"{len(failures)} failures encountered",
                ],
                "hypotheses": [
                    {"hypothesis": "Continue with available tools", "test_method": "Systematic enumeration", "priority": 1}
                ],
                "recommended_plan": [
                    {"step": 1, "action": "Enumerate endpoints", "tool": "auto", "reasoning": "Build attack surface"},
                    {"step": 2, "action": "Test for common vulns", "tool": "auto", "reasoning": "Low-hanging fruit"},
                    {"step": 3, "action": "Escalate if findings exist", "tool": "auto", "reasoning": "Deepen access"},
                ],
                "alternative_approaches": ["Try different attack vectors", "Change phase"],
                "risk_assessment": "Rate limiting and detection are primary risks. Throttle requests.",
                "attack_vectors_identified": ["Continue with available tools"],
                "recommended_approach": "Proceed methodically through available attack surface",
                "priority_order": ["Enumerate endpoints", "Test for common vulns", "Escalate if findings exist"],
            }

        # Store structured result for wave planning and ReACT integration
        self._last_deep_think_structured = result

        # Also store as formatted string for prompt injection (backward compat)
        self._last_deep_think = _format_deep_think_for_prompt(result)

        logger.info(f"Deep Think complete: {len(result.get('hypotheses', []))} hypotheses, "
                     f"{len(result.get('recommended_plan', []))} plan steps")

        return result

    # ------------------------------------------------------------------
    # Prompt building
    # ------------------------------------------------------------------

    def _build_system_prompt(self, state: dict) -> str:
        """Build the full system prompt with all context sections."""
        # Phase definitions
        current_phase = state.get("current_phase", "informational")
        phase_defs = "\n".join(
            f"  {'→ ' if k == current_phase else '  '}{k.upper()}: {v}"
            for k, v in PHASE_DEFINITIONS.items()
        )

        # Available tools
        if self.tool_descriptions:
            tool_lines = "\n".join(
                f"  - {name}: {desc}" for name, desc in self.tool_descriptions.items()
            )
        else:
            tool_lines = "  (no tools registered — use action='complete' to finish)"

        # Execution trace (last N steps)
        trace = state.get("execution_trace", [])
        trace_window = min(10, len(trace))
        recent = trace[-trace_window:] if trace else []
        chain_lines = []
        for step in recent:
            status = "OK" if step.get("success") else "FAIL"
            output_preview = (step.get("tool_output") or "")[:300]
            chain_lines.append(
                f"  [{step.get('iteration', '?')}] {step.get('tool_name', '?')} "
                f"[{status}]: {output_preview}"
            )
        chain_context = "\n".join(chain_lines) or "  (no steps yet)"

        # Failure summary
        failures = [s for s in trace if not s.get("success")]
        if failures:
            fail_lines = [
                f"  - iter {f.get('iteration')}: {f.get('tool_name')} — {f.get('error_message', 'failed')}"
                for f in failures[-5:]
            ]
            failure_summary = f"{len(failures)} total failures (last 5):\n" + "\n".join(fail_lines)
        else:
            failure_summary = "  (none)"

        # Todo list
        todos = state.get("todo_list", [])
        if todos:
            todo_lines = []
            for t in todos:
                if isinstance(t, dict):
                    status = t.get("status", "pending")
                    desc = t.get("description", "")
                    prio = t.get("priority", "medium")
                    todo_lines.append(f"  [{status}] ({prio}) {desc}")
            todo_text = "\n".join(todo_lines) or "  (empty)"
        else:
            todo_text = "  (empty)"

        # Target info
        ti = state.get("target_info", {})
        if isinstance(ti, dict) and ti:
            ti_lines = []
            for key in ("primary_target", "target_type", "ports", "services", "technologies", "vulnerabilities"):
                val = ti.get(key)
                if val:
                    ti_lines.append(f"  {key}: {val}")
            target_info_text = "\n".join(ti_lines) or "  (minimal)"
        else:
            target_info_text = "  (no intel yet)"

        # Deep Think section
        if self._last_deep_think:
            deep_think_section = f"\n═══ DEEP THINK ANALYSIS ═══\n{self._last_deep_think}\n"
        else:
            deep_think_section = ""

        # Pending output analysis
        last_result = state.get("_tool_result")
        if isinstance(last_result, dict) and last_result.get("output"):
            output_preview = last_result["output"][:2000]
            pending_output_section = (
                f"\n═══ PENDING OUTPUT (analyze this) ═══\n"
                f"Tool: {last_result.get('tool_name', '?')}\n"
                f"Success: {last_result.get('success', '?')}\n"
                f"Output:\n{output_preview}\n"
            )
        else:
            pending_output_section = ""

        return REACT_SYSTEM_PROMPT.format(
            current_phase=current_phase,
            iteration=state.get("current_iteration", 0),
            max_iterations=state.get("max_iterations", 30),
            attack_path_type=state.get("attack_path_type", "general-unclassified"),
            target=state.get("target", ""),
            phase_definitions=phase_defs,
            objective=state.get("original_objective", ""),
            target_info=target_info_text,
            available_tools=tool_lines,
            trace_window=trace_window,
            chain_context=chain_context,
            failure_summary=failure_summary,
            todo_list=todo_text,
            deep_think_section=deep_think_section,
            pending_output_section=pending_output_section,
        )

    # ------------------------------------------------------------------
    # Deep Think trigger check
    # ------------------------------------------------------------------

    def _should_deep_think(self, state: dict) -> Tuple[bool, str]:
        """Check if Deep Think should trigger. Returns (should, reason)."""
        iteration = state.get("current_iteration", 0)

        # First iteration
        if iteration <= 1:
            return True, "first_iteration"

        # Phase just changed
        history = state.get("phase_history", [])
        if len(history) > 1:
            last_entry = history[-1]
            # If phase changed this iteration, trigger
            if last_entry.get("entered_at"):
                return True, "phase_transition"

        # 3+ consecutive failures
        if self._consecutive_failures >= 3:
            return True, f"failure_streak ({self._consecutive_failures} consecutive)"

        # LLM self-request
        prev_decision = state.get("_decision", {})
        if isinstance(prev_decision, dict) and prev_decision.get("need_deep_think"):
            return True, "llm_self_request"

        return False, ""

    # ------------------------------------------------------------------
    # LLM reasoning call
    # ------------------------------------------------------------------

    async def _llm_think(self, system_prompt: str, state: dict) -> Optional[dict]:
        """Call LLM and parse response as LLMDecision dict."""
        if not self.router:
            return None

        # Build user message from context
        user_msg = f"Decide the next action for iteration {state.get('current_iteration', 0)}."

        try:
            response = await self.router.complete(
                prompt=user_msg,
                system=system_prompt,
                max_tokens=2048,
                temperature=0.3,
                json_mode=True,
            )
        except Exception as exc:
            logger.error(f"LLM call failed: {exc}")
            return None

        if not response:
            return None

        # Parse JSON robustly
        return _parse_llm_decision(response.text)

    # ------------------------------------------------------------------
    # Q-learning fallback
    # ------------------------------------------------------------------

    def _fallback_think(self, state: dict) -> dict:
        """Q-learning fallback when LLM is unavailable."""
        if self.brain:
            try:
                target = state.get("target", "")
                phase = state.get("current_phase", "informational")
                tech_stack = state.get("target_info", {}).get("technologies", [])

                # Get best action from brain
                brain_state = f"{phase}:{','.join(tech_stack[:3])}" if tech_stack else phase
                action = self.brain.choose_action(brain_state)

                return {
                    "thought": f"Q-learning fallback: state={brain_state}",
                    "reasoning": f"LLM unavailable. Brain selected {action} based on Q-values.",
                    "action": "use_tool",
                    "tool_name": str(action),
                    "tool_args": {"target": target},
                    "_fallback": True,
                }
            except Exception as exc:
                logger.warning(f"Brain fallback failed: {exc}")

        # Last resort: complete
        return {
            "thought": "No LLM and no brain available",
            "reasoning": "Cannot reason without LLM or Q-learning — completing",
            "action": "complete",
            "completion_reason": "No reasoning engine available",
            "_fallback": True,
        }


# ═══════════════════════════════════════════════════════════════════════
# JSON PARSING (robust — handles markdown fences, partial JSON)
# ═══════════════════════════════════════════════════════════════════════

def _parse_llm_decision(text: str) -> Optional[dict]:
    """
    Parse an LLMDecision from potentially messy LLM output.

    Handles:
      - Clean JSON
      - JSON inside ```json ... ``` fences
      - JSON inside ``` ... ``` fences
      - Leading/trailing prose around JSON
      - Trailing commas (common LLM mistake)
    """
    if not text or not text.strip():
        return None

    text = text.strip()

    # Strip markdown code fences
    fence_match = re.search(r'```(?:json)?\s*\n?(.*?)\n?\s*```', text, re.DOTALL)
    if fence_match:
        text = fence_match.group(1).strip()

    # Try direct parse
    result = _try_json_parse(text)
    if result:
        return _validate_decision(result)

    # Try to extract JSON object from surrounding text
    brace_match = re.search(r'\{.*\}', text, re.DOTALL)
    if brace_match:
        result = _try_json_parse(brace_match.group())
        if result:
            return _validate_decision(result)

    logger.warning(f"Failed to parse LLM decision from: {text[:200]}")
    return None


def _try_json_parse(text: str) -> Optional[dict]:
    """Attempt JSON parse with trailing comma cleanup."""
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass

    # Remove trailing commas before } and ]
    cleaned = re.sub(r',\s*([}\]])', r'\1', text)
    try:
        return json.loads(cleaned)
    except json.JSONDecodeError:
        return None


def _validate_decision(data: dict) -> dict:
    """Ensure the parsed dict has the minimum required fields."""
    if not isinstance(data, dict):
        return None

    # Ensure action is valid
    valid_actions = {"use_tool", "plan_tools", "transition_phase", "complete", "ask_user", "deep_think"}
    action = data.get("action", "")
    if action not in valid_actions:
        # Try to infer action
        if data.get("tool_name"):
            data["action"] = "use_tool"
        elif data.get("tool_plan"):
            data["action"] = "plan_tools"
        elif data.get("phase_transition"):
            data["action"] = "transition_phase"
        elif data.get("completion_reason"):
            data["action"] = "complete"
        else:
            data["action"] = "complete"
            data["completion_reason"] = "Could not determine action"

    # Defaults
    data.setdefault("thought", "")
    data.setdefault("reasoning", "")

    return data


# ═══════════════════════════════════════════════════════════════════════
# DEEP THINK PARSING & FORMATTING
# ═══════════════════════════════════════════════════════════════════════

_DEEP_THINK_DEFAULTS = {
    "situation_assessment": "",
    "key_observations": [],
    "hypotheses": [],
    "recommended_plan": [],
    "alternative_approaches": [],
    "risk_assessment": "",
    "attack_vectors_identified": [],
    "recommended_approach": "",
    "priority_order": [],
}


def _parse_deep_think_result(text: str) -> Optional[dict]:
    """
    Parse a Deep Think JSON result from LLM output.

    Handles markdown fences, trailing commas, surrounding prose.
    Returns normalized dict with all expected keys, or None on failure.
    """
    if not text or not text.strip():
        return None

    text = text.strip()

    # Strip markdown code fences
    fence_match = re.search(r'```(?:json)?\s*\n?(.*?)\n?\s*```', text, re.DOTALL)
    if fence_match:
        text = fence_match.group(1).strip()

    parsed = _try_json_parse(text)
    if not parsed:
        # Try to extract JSON object from surrounding text
        brace_match = re.search(r'\{.*\}', text, re.DOTALL)
        if brace_match:
            parsed = _try_json_parse(brace_match.group())

    if not parsed or not isinstance(parsed, dict):
        logger.warning(f"Failed to parse Deep Think result from: {text[:200]}")
        return None

    # Normalize: ensure all expected keys exist
    for key, default in _DEEP_THINK_DEFAULTS.items():
        parsed.setdefault(key, default)

    # Normalize hypotheses to have required fields
    normalized_hyps = []
    for i, h in enumerate(parsed.get("hypotheses", [])):
        if isinstance(h, str):
            h = {"hypothesis": h, "test_method": "", "priority": i + 1}
        elif isinstance(h, dict):
            h.setdefault("hypothesis", "")
            h.setdefault("test_method", "")
            h.setdefault("priority", i + 1)
        normalized_hyps.append(h)
    parsed["hypotheses"] = normalized_hyps

    # Normalize plan steps
    normalized_plan = []
    for i, s in enumerate(parsed.get("recommended_plan", [])):
        if isinstance(s, str):
            s = {"step": i + 1, "action": s, "tool": "auto", "reasoning": ""}
        elif isinstance(s, dict):
            s.setdefault("step", i + 1)
            s.setdefault("action", "")
            s.setdefault("tool", "auto")
            s.setdefault("reasoning", "")
        normalized_plan.append(s)
    parsed["recommended_plan"] = normalized_plan

    return parsed


def _format_deep_think_for_prompt(result: dict) -> str:
    """
    Format a structured Deep Think result dict into a readable string
    for injection into the system prompt.
    """
    lines = []

    if result.get("situation_assessment"):
        lines.append(f"**Situation:** {result['situation_assessment']}")

    if result.get("key_observations"):
        obs = ", ".join(str(o) for o in result["key_observations"][:5])
        lines.append(f"**Observations:** {obs}")

    if result.get("hypotheses"):
        hyp_strs = []
        for h in result["hypotheses"][:5]:
            if isinstance(h, dict):
                hyp_strs.append(f"P{h.get('priority', '?')}: {h.get('hypothesis', '')}")
            else:
                hyp_strs.append(str(h))
        lines.append(f"**Hypotheses:** {'; '.join(hyp_strs)}")

    if result.get("recommended_plan"):
        plan_strs = []
        for s in result["recommended_plan"][:6]:
            if isinstance(s, dict):
                plan_strs.append(f"{s.get('step', '?')}. {s.get('action', '')}")
            else:
                plan_strs.append(str(s))
        lines.append(f"**Plan:** {' -> '.join(plan_strs)}")

    if result.get("attack_vectors_identified"):
        lines.append(f"**Attack Vectors:** {', '.join(str(v) for v in result['attack_vectors_identified'])}")

    if result.get("recommended_approach"):
        lines.append(f"**Approach:** {result['recommended_approach']}")

    if result.get("priority_order"):
        lines.append(f"**Priority:** {' -> '.join(str(p) for p in result['priority_order'])}")

    if result.get("alternative_approaches"):
        lines.append(f"**Alternatives:** {', '.join(str(a) for a in result['alternative_approaches'][:3])}")

    if result.get("risk_assessment"):
        lines.append(f"**Risks:** {result['risk_assessment']}")

    return "\n\n".join(lines)


def deep_think_to_prioritized_actions(result: dict) -> List[dict]:
    """
    Convert a Deep Think result into a list of prioritized action dicts
    suitable for feeding back into the ReACT loop or WaveRunner.

    Each action dict has: tool, action, reasoning, priority, source.
    """
    actions = []

    # Primary: from recommended_plan
    for step in result.get("recommended_plan", []):
        if isinstance(step, dict) and step.get("action"):
            actions.append({
                "tool": step.get("tool", "auto"),
                "action": step.get("action", ""),
                "reasoning": step.get("reasoning", ""),
                "priority": step.get("step", len(actions) + 1),
                "source": "deep_think_plan",
            })

    # Secondary: from hypotheses (as test actions)
    for hyp in result.get("hypotheses", []):
        if isinstance(hyp, dict) and hyp.get("test_method"):
            actions.append({
                "tool": "auto",
                "action": hyp.get("test_method", ""),
                "reasoning": f"Testing hypothesis: {hyp.get('hypothesis', '')}",
                "priority": hyp.get("priority", 99) + len(result.get("recommended_plan", [])),
                "source": "deep_think_hypothesis",
            })

    # Sort by priority
    actions.sort(key=lambda a: a.get("priority", 99))

    return actions
