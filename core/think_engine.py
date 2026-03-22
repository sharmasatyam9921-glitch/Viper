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

Execution summary:
{execution_summary}

Failures so far:
{failure_summary}

Provide your analysis as JSON:
{{
  "situation_assessment": "Current state summary",
  "attack_vectors_identified": ["vector1", "vector2"],
  "recommended_approach": "Chosen approach and rationale",
  "priority_order": ["step1", "step2", "step3"],
  "risks_and_mitigations": "Potential risks and how to handle them"
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

    async def deep_think(self, state: dict, trigger_reason: str) -> str:
        """
        Structured strategic analysis. Returns formatted DeepThinkResult string.

        Triggers:
          - First iteration
          - Phase transition
          - 3+ consecutive failures
          - LLM self-request (need_deep_think=True)
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

        prompt = DEEP_THINK_PROMPT.format(
            trigger_reason=trigger_reason,
            target=state.get("target", ""),
            current_phase=state.get("current_phase", "informational"),
            iteration=state.get("current_iteration", 0),
            max_iterations=state.get("max_iterations", 30),
            objective=state.get("original_objective", ""),
            execution_summary=execution_summary,
            failure_summary=failure_summary,
        )

        if self.router:
            try:
                response = await self.router.complete(
                    prompt=prompt,
                    system="You are a strategic penetration testing advisor. Output JSON only.",
                    max_tokens=1500,
                    temperature=0.4,
                    json_mode=True,
                )
                if response:
                    return response.text
            except Exception as exc:
                logger.warning(f"Deep Think LLM call failed: {exc}")

        # Fallback: simple text summary
        return json.dumps({
            "situation_assessment": f"At iteration {state.get('current_iteration', 0)}, {len(trace)} steps completed.",
            "attack_vectors_identified": ["Continue with available tools"],
            "recommended_approach": "Proceed methodically through available attack surface",
            "priority_order": ["Enumerate endpoints", "Test for common vulns", "Escalate if findings exist"],
            "risks_and_mitigations": "Rate limiting and detection are primary risks. Throttle requests.",
        })

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
    valid_actions = {"use_tool", "plan_tools", "transition_phase", "complete", "ask_user"}
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
