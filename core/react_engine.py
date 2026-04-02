#!/usr/bin/env python3
"""
VIPER ReACT Engine - Reasoning + Action Loop

Implements the ReACT (Reasoning and Acting) pattern for autonomous security testing.
Each attack decision follows: Thought -> Action -> Observation -> repeat.

When an LLM is available, the Thought step uses it to reason about context.
Falls back to ViperBrain's Q-learning when LLM is unavailable or rate-limited.
"""

import json
import logging
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Callable, Dict, List, Optional

from core.agent_state import TodoList, ObjectiveManager
from core.phase_engine import is_tool_allowed_in_phase
from core.roe_engine import RoEEngine
from core.think_engine import ThinkEngine, deep_think_to_prioritized_actions

logger = logging.getLogger("viper.react")


@dataclass
class ReACTStep:
    """A single Thought-Action-Observation step."""
    step_num: int
    thought: str
    action: str
    action_input: Dict[str, Any]
    observation: str
    reward: float = 0.0
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    llm_used: bool = False


@dataclass
class ReACTTrace:
    """Complete reasoning trace for a target."""
    target: str
    steps: List[ReACTStep] = field(default_factory=list)
    final_assessment: str = ""
    total_reward: float = 0.0
    started_at: str = field(default_factory=lambda: datetime.now().isoformat())
    ended_at: str = ""

    def add_step(self, step: ReACTStep):
        self.steps.append(step)
        self.total_reward += step.reward

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target": self.target,
            "steps": [
                {
                    "step": s.step_num,
                    "thought": s.thought,
                    "action": s.action,
                    "observation": s.observation[:500],
                    "reward": s.reward,
                    "llm_used": s.llm_used,
                }
                for s in self.steps
            ],
            "final_assessment": self.final_assessment,
            "total_reward": self.total_reward,
            "started_at": self.started_at,
            "ended_at": self.ended_at,
            "num_steps": len(self.steps),
        }


REACT_SYSTEM_PROMPT = (
    "You are an expert penetration tester using the ReACT framework. "
    "You reason step-by-step about web application security.\n\n"
    "Given the current context about a target, reason about:\n"
    "1. What have we observed so far?\n"
    "2. What hypotheses can we form?\n"
    "3. What action should we take next and why?\n\n"
    "Output valid JSON only:\n"
    '{"thought": "your reasoning", "action": "attack_type", "rationale": "why this action"}'
)


class ReACTEngine:
    """
    ReACT reasoning loop for autonomous security testing.

    Wraps ViperBrain with an LLM-powered reasoning layer.
    Each step: Think (LLM reasons about context) -> Act (execute attack)
    -> Observe (analyze result) -> repeat.

    Args:
        brain: ViperBrain instance for Q-learning fallback and attack execution.
        model_router: ModelRouter for LLM calls (optional).
        max_steps: Maximum reasoning steps per target.
        verbose: Print reasoning trace to stdout.
    """

    def __init__(
        self,
        brain: Any,
        model_router: Optional[Any] = None,
        max_steps: int = 15,
        verbose: bool = True,
        think_engine: Optional[ThinkEngine] = None,
        roe_engine: Optional[RoEEngine] = None,
    ):
        self.brain = brain
        self.router = model_router
        self.max_steps = max_steps
        self.verbose = verbose
        self._traces: List[ReACTTrace] = []
        self.evograph = None  # Set externally by ViperCore
        self._evograph_session_id = None  # Set per hunt
        # LLM-managed todo list
        self.todo_list = TodoList()
        # G1: Multi-objective manager
        self.objective_manager = ObjectiveManager()
        # Deep Think integration
        self.think_engine = think_engine
        self._deep_think_actions: List[Dict] = []  # Prioritized actions from deep think
        self._deep_think_triggered_at: Optional[int] = None  # Step number of last trigger
        # F5: Rules of Engagement enforcement
        self.roe_engine = roe_engine or RoEEngine()

    def log(self, msg: str, level: str = "INFO"):
        if self.verbose:
            ts = datetime.now().strftime("%H:%M:%S")
            print(f"[{ts}] [ReACT] [{level}] {msg}")

    async def reason_and_act(
        self,
        target: str,
        context: Dict[str, Any],
        execute_fn: Callable,
    ) -> ReACTTrace:
        """
        Run the full ReACT loop on a target.

        Args:
            target: Target URL.
            context: Initial context dict (technologies, page_content, etc.).
            execute_fn: Async callable(url, attack_type, context) -> (reward, new_context, finding).

        Returns:
            ReACTTrace with the full reasoning history.
        """
        trace = ReACTTrace(target=target)
        current_context = dict(context)
        findings: List[Dict] = []
        tried_attacks: List[str] = []

        self.log(f"Starting ReACT loop for {target} (max {self.max_steps} steps)")

        for step_num in range(1, self.max_steps + 1):
            # ── DEEP THINK TRIGGER CHECK ──────────────────────────────
            deep_think_fired = False
            if self.think_engine:
                should_dt, dt_reason = self._check_deep_think_trigger(
                    trace, step_num, current_context, tried_attacks
                )
                if should_dt:
                    deep_think_fired = True
                    self.log(f"Step {step_num} | DEEP THINK triggered: {dt_reason}", "STRATEGY")
                    dt_state = {
                        "target": target,
                        "current_phase": current_context.get("phase", "informational"),
                        "current_iteration": step_num,
                        "max_iterations": self.max_steps,
                        "original_objective": f"Security test {target}",
                        "execution_trace": [
                            {
                                "tool_name": s.action,
                                "success": s.reward > 0,
                                "tool_output": s.observation[:300],
                                "error_message": "" if s.reward > 0 else "negative reward",
                                "iteration": s.step_num,
                            }
                            for s in trace.steps
                        ],
                        "target_info": current_context,
                        "todo_list": [],
                    }
                    try:
                        dt_result = await self.think_engine.deep_think(dt_state, dt_reason)
                        self._deep_think_actions = deep_think_to_prioritized_actions(dt_result)
                        self._deep_think_triggered_at = step_num
                        self.log(
                            f"Step {step_num} | Deep Think produced "
                            f"{len(self._deep_think_actions)} prioritized actions",
                            "STRATEGY",
                        )
                    except Exception as exc:
                        self.log(f"Step {step_num} | Deep Think failed: {exc}", "WARN")

            # ── THOUGHT: Reason about what to do next ─────────────────
            # If deep think produced prioritized actions, consume the next one
            if self._deep_think_actions:
                dt_action = self._deep_think_actions.pop(0)
                thought = (
                    f"[Deep Think plan] {dt_action.get('reasoning', '')} "
                    f"(source: {dt_action.get('source', 'plan')})"
                )
                action = dt_action.get("action", dt_action.get("tool", ""))
                # Try to match to a known attack pattern
                matched = self._fuzzy_match_attack(action) if action else None
                if matched:
                    action = matched
                    used_llm = True
                else:
                    # Fall through to normal think if deep think action not recognized
                    thought, action, used_llm = await self._think(
                        target=target,
                        context=current_context,
                        findings=findings,
                        tried_attacks=tried_attacks,
                        step_num=step_num,
                    )
                used_llm = True  # Deep think counts as LLM reasoning
            else:
                thought, action, used_llm = await self._think(
                    target=target,
                    context=current_context,
                    findings=findings,
                    tried_attacks=tried_attacks,
                    step_num=step_num,
                )

            # ── Check if LLM explicitly requested deep_think action ───
            if action == "deep_think" and self.think_engine:
                self.log(f"Step {step_num} | LLM explicitly requested deep_think", "STRATEGY")
                # Don't execute as an attack — trigger deep think on next iteration
                step = ReACTStep(
                    step_num=step_num,
                    thought=thought,
                    action="deep_think",
                    action_input={"target": target},
                    observation="Deep think will be invoked at next step.",
                    reward=0.0,
                    llm_used=used_llm,
                )
                trace.add_step(step)
                # Force deep think on next iteration
                self._deep_think_triggered_at = None  # Reset so trigger check fires
                continue

            self.log(f"Step {step_num} | Thought: {thought[:100]}...")
            self.log(f"Step {step_num} | Action: {action}")

            # ── F5: RoE enforcement before execution ──────────────────
            roe_ok, roe_reason = self.roe_engine.enforce(
                tool=action,
                target=target,
                args=current_context,
                phase=current_context.get("phase"),
            )
            if not roe_ok:
                self.log(f"Step {step_num} | RoE BLOCKED: {roe_reason}", "BLOCK")
                step = ReACTStep(
                    step_num=step_num,
                    thought=thought,
                    action=action,
                    action_input={"target": target},
                    observation=f"BLOCKED by Rules of Engagement: {roe_reason}",
                    reward=-0.5,
                    llm_used=used_llm,
                )
                trace.add_step(step)
                tried_attacks.append(action)
                continue

            # ── Phase-aware tool enforcement ───────────────────────────
            current_phase = current_context.get("phase", "RECON").upper()
            phase_ok, phase_reason = is_tool_allowed_in_phase(action, current_phase)
            if not phase_ok:
                self.log(f"Step {step_num} | PHASE BLOCKED: {phase_reason}", "BLOCK")
                step = ReACTStep(
                    step_num=step_num,
                    thought=thought,
                    action=action,
                    action_input={"target": target},
                    observation=f"BLOCKED by phase enforcement: {phase_reason}",
                    reward=-0.3,
                    llm_used=used_llm,
                )
                trace.add_step(step)
                tried_attacks.append(action)
                continue

            tried_attacks.append(action)

            # ACTION: Execute the chosen attack
            reward, new_context, finding = await execute_fn(target, action, current_context)

            # OBSERVATION: Analyze what happened
            observation = self._observe(action, reward, finding, new_context)
            self.log(f"Step {step_num} | Observation: {observation[:100]}...")

            step = ReACTStep(
                step_num=step_num,
                thought=thought,
                action=action,
                action_input={"target": target, "context_keys": list(current_context.keys())},
                observation=observation,
                reward=reward,
                llm_used=used_llm,
            )
            trace.add_step(step)

            # Auto-complete todo items matching the executed action
            if reward > 0:
                self.todo_list.mark_completed_by_tool(action)

            # EvoGraph: record reasoning step
            if self.evograph and self._evograph_session_id:
                try:
                    self.evograph.record_reasoning_step(
                        self._evograph_session_id, step_num,
                        thought, action, observation, reward,
                    )
                except Exception:
                    pass

            if finding:
                findings.append(finding)
                self.log(f"Step {step_num} | FINDING: {finding.get('type', 'unknown')}")

            # Update brain Q-values
            self.brain.update(current_context, action, reward, new_context)
            current_context = new_context

            # Early termination: high access achieved
            if current_context.get("access_level", 0) >= 3:
                self.log(f"Target compromised at step {step_num}")
                break

            # Early termination: diminishing returns
            if step_num >= 3 and trace.total_reward <= -5:
                # Before stopping, try deep think one more time if available
                if self.think_engine and not deep_think_fired:
                    self.log("Diminishing returns — attempting deep think before stopping")
                    # Will trigger on next iteration via _check_deep_think_trigger
                    continue
                self.log("Diminishing returns, stopping early")
                break

        # Final assessment
        trace.final_assessment = self._assess(trace, findings)
        trace.ended_at = datetime.now().isoformat()
        self._traces.append(trace)

        self.log(f"Completed: {len(trace.steps)} steps, reward={trace.total_reward:.1f}, "
                 f"findings={len(findings)}")

        # ── G1: Multi-objective management ────────────────────────────
        # Complete current objective and check for next
        current_obj = self.objective_manager.get_current()
        if current_obj:
            current_obj.findings_count = len(findings)
            summary = (
                f"{len(findings)} findings in {len(trace.steps)} steps, "
                f"reward={trace.total_reward:.1f}"
            )
            if trace.total_reward <= -5 and not findings:
                self.objective_manager.fail_current(summary)
            else:
                self.objective_manager.complete_current(summary)

            # Auto-advance to next objective if available
            if self.objective_manager.has_pending():
                next_obj = self.objective_manager.advance()
                if next_obj:
                    self.log(f"Advancing to next objective: {next_obj.content[:80]}")

        return trace

    async def _think(
        self,
        target: str,
        context: Dict[str, Any],
        findings: List[Dict],
        tried_attacks: List[str],
        step_num: int,
    ) -> tuple:
        """
        Generate a thought and choose an action.

        Returns:
            (thought_text, action_name, used_llm)
        """
        # Try LLM reasoning first
        if self.router and self.router.is_available:
            thought, action = await self._llm_think(
                target, context, findings, tried_attacks, step_num
            )
            if thought and action:
                # Validate action exists in brain's patterns
                if action in self.brain.attack_patterns:
                    return thought, action, True
                # Try fuzzy match
                matched = self._fuzzy_match_attack(action)
                if matched:
                    return thought, matched, True

        # Fallback: Q-learning via ViperBrain
        action = self.brain.choose_attack(context)
        thought = (
            f"[Q-learning fallback] Selected '{action}' based on Q-values and "
            f"pattern success rates. Tried so far: {tried_attacks[-5:]}."
        )
        return thought, action, False

    async def _llm_think(
        self,
        target: str,
        context: Dict[str, Any],
        findings: List[Dict],
        tried_attacks: List[str],
        step_num: int,
    ) -> tuple:
        """Use LLM to reason about the next step."""
        available_attacks = list(self.brain.attack_patterns.keys())

        # Include todo list context for LLM awareness
        todo_context = self.todo_list.to_prompt_string()

        # G1: Include objective history context
        objective_history = self.objective_manager.get_history_prompt()

        # Build objective history section
        obj_section = f"\n{objective_history}\n\n" if objective_history else "\n"

        prompt = (
            f"Target: {target}\n"
            f"Step: {step_num}/{self.max_steps}\n"
            f"Technologies detected: {context.get('technologies', [])}\n"
            f"Has input forms: {context.get('has_input', False)}\n"
            f"Has login: {context.get('has_login', False)}\n"
            f"Current access level: {context.get('access_level', 0)}/5\n"
            f"Vulnerabilities found: {context.get('vulns_found', [])}\n"
            f"Attacks tried: {tried_attacks[-10:]}\n"
            f"Findings: {json.dumps(findings[-5:], default=str)[:800]}\n"
            f"Available attacks: {available_attacks}\n\n"
            f"{todo_context}\n"
            f"{obj_section}"
            "Reason about what to try next. Pick ONE action from the available attacks list.\n"
            "You may also return an 'updated_todo_list' array of "
            '{"id": "...", "description": "...", "status": "pending|in_progress|completed|blocked", '
            '"priority": "high|medium|low"} to update the task tracker.'
        )

        # F5: Inject RoE rules into the system prompt so the LLM is aware
        system_prompt = REACT_SYSTEM_PROMPT
        roe_section = self.roe_engine.to_prompt_section()
        if roe_section:
            system_prompt = system_prompt + "\n\n" + roe_section

        try:
            response = await self.router.complete_for_task(
                task="reasoning",
                prompt=prompt,
                system=system_prompt,
                max_tokens=512,
                json_mode=True,
            )
            if response:
                data = response.extract_json_object()
                if data:
                    # Sync todo list from LLM response if present
                    if "updated_todo_list" in data and isinstance(data["updated_todo_list"], list):
                        self.todo_list.from_llm_response(data["updated_todo_list"])
                    return (
                        data.get("thought", ""),
                        data.get("action", "").lower().replace("-", "_").replace(" ", "_"),
                    )
                # Parse as plain text fallback
                return response.text[:200], self._extract_action_from_text(response.text, available_attacks)
        except Exception as e:
            logger.warning(f"LLM think failed: {e}")

        return None, None

    def _extract_action_from_text(self, text: str, available: List[str]) -> Optional[str]:
        """Try to find an attack name in free-form LLM text."""
        text_lower = text.lower()
        for attack in available:
            if attack.lower() in text_lower:
                return attack
        return None

    def _fuzzy_match_attack(self, action: str) -> Optional[str]:
        """Fuzzy-match an LLM-suggested action to known attack patterns."""
        action_lower = action.lower().replace("-", "_").replace(" ", "_")
        for name in self.brain.attack_patterns:
            if action_lower in name.lower() or name.lower() in action_lower:
                return name
        return None

    def _observe(
        self, action: str, reward: float, finding: Optional[Dict], context: Dict
    ) -> str:
        """Build an observation string from action results."""
        parts = [f"Action '{action}' completed with reward={reward:.1f}."]
        if finding:
            parts.append(f"FINDING: {finding.get('type', 'unknown')} vulnerability detected.")
            if "evidence" in finding:
                parts.append(f"Evidence: {str(finding['evidence'])[:200]}")
        else:
            parts.append("No new vulnerability found in this step.")

        access = context.get("access_level", 0)
        if access > 0:
            parts.append(f"Current access level: {access}/5.")

        vulns = context.get("vulns_found", [])
        if vulns:
            parts.append(f"Known vulns: {vulns[-5:]}.")

        return " ".join(parts)

    def _assess(self, trace: ReACTTrace, findings: List[Dict]) -> str:
        """Generate a final assessment of the ReACT run."""
        if not findings:
            return (
                f"No vulnerabilities confirmed in {len(trace.steps)} steps. "
                f"Total reward: {trace.total_reward:.1f}. "
                "Target may be well-hardened or requires different approach."
            )

        finding_types = [f.get("type", "unknown") for f in findings]
        max_access = max(
            (s.action_input.get("context", {}).get("access_level", 0) for s in trace.steps),
            default=0,
        )
        return (
            f"Found {len(findings)} potential vulnerabilities: {finding_types}. "
            f"Highest access level reached: {max_access}. "
            f"Total reward: {trace.total_reward:.1f} over {len(trace.steps)} steps."
        )

    def _check_deep_think_trigger(
        self,
        trace: ReACTTrace,
        step_num: int,
        context: Dict[str, Any],
        tried_attacks: List[str],
    ) -> tuple:
        """
        Check if Deep Think should trigger during the ReACT loop.

        Returns (should_trigger: bool, reason: str).

        Triggers:
          1. reward < -3 after 3+ steps (cumulative negative)
          2. 3+ consecutive negative reward steps
          3. First step (initial strategy)
          4. Cooldown: won't re-trigger within 3 steps of last trigger
        """
        # Cooldown check: don't trigger again within 3 steps
        if self._deep_think_triggered_at is not None:
            if step_num - self._deep_think_triggered_at < 3:
                return False, ""

        # Don't trigger if we still have queued deep think actions
        if self._deep_think_actions:
            return False, ""

        # Trigger 1: First step — establish initial strategy
        if step_num == 1:
            return True, "first_step"

        # Trigger 2: Cumulative reward < -3 after 3+ steps
        if step_num >= 3 and trace.total_reward < -3:
            return True, f"low_cumulative_reward ({trace.total_reward:.1f} after {step_num} steps)"

        # Trigger 3: 3+ consecutive negative rewards
        if len(trace.steps) >= 3:
            last_3 = trace.steps[-3:]
            if all(s.reward < 0 for s in last_3):
                return True, f"3_consecutive_failures (rewards: {[s.reward for s in last_3]})"

        # Trigger 4: Going in circles (same action repeated 3+ times)
        if len(tried_attacks) >= 3:
            last_3_attacks = tried_attacks[-3:]
            if len(set(last_3_attacks)) == 1:
                return True, f"action_repetition ('{last_3_attacks[0]}' repeated 3x)"

        return False, ""

    def add_objective(self, objective: str) -> None:
        """Queue a new objective for multi-objective execution (G1)."""
        self.objective_manager.add(objective)

    async def run_all_objectives(
        self,
        target: str,
        context: Dict[str, Any],
        execute_fn: Callable,
    ) -> List[ReACTTrace]:
        """
        Run ReACT loops for all queued objectives sequentially (G1).

        Each objective gets its own ReACT loop. Context carries over between
        objectives so that findings from earlier objectives inform later ones.

        Returns:
            List of ReACTTrace, one per objective.
        """
        traces = []
        current_context = dict(context)

        while True:
            obj = self.objective_manager.get_current()
            if obj is None or obj.status != "active":
                if not self.objective_manager.has_pending():
                    break
                next_obj = self.objective_manager.advance()
                if next_obj is None:
                    break
                obj = next_obj

            self.log(f"Starting objective: {obj.content[:80]}")
            trace = await self.reason_and_act(target, current_context, execute_fn)
            traces.append(trace)

            # Carry forward context enrichment from this trace
            if trace.steps:
                last_step = trace.steps[-1]
                if last_step.action_input and "context_keys" in last_step.action_input:
                    # The context was updated during the loop
                    pass

        return traces

    @property
    def traces(self) -> List[ReACTTrace]:
        """Get all reasoning traces from this session."""
        return self._traces

    def get_trace_summary(self) -> List[Dict]:
        """Get summary of all traces."""
        return [t.to_dict() for t in self._traces]
