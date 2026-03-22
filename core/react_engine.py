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
    ):
        self.brain = brain
        self.router = model_router
        self.max_steps = max_steps
        self.verbose = verbose
        self._traces: List[ReACTTrace] = []
        self.evograph = None  # Set externally by ViperCore
        self._evograph_session_id = None  # Set per hunt

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
            # THOUGHT: Reason about what to do next
            thought, action, used_llm = await self._think(
                target=target,
                context=current_context,
                findings=findings,
                tried_attacks=tried_attacks,
                step_num=step_num,
            )

            self.log(f"Step {step_num} | Thought: {thought[:100]}...")
            self.log(f"Step {step_num} | Action: {action}")

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
                self.log("Diminishing returns, stopping early")
                break

        # Final assessment
        trace.final_assessment = self._assess(trace, findings)
        trace.ended_at = datetime.now().isoformat()
        self._traces.append(trace)

        self.log(f"Completed: {len(trace.steps)} steps, reward={trace.total_reward:.1f}, "
                 f"findings={len(findings)}")

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
            "Reason about what to try next. Pick ONE action from the available attacks list."
        )

        try:
            response = await self.router.complete_for_task(
                task="reasoning",
                prompt=prompt,
                system=REACT_SYSTEM_PROMPT,
                max_tokens=512,
                json_mode=True,
            )
            if response:
                data = response.extract_json_object()
                if data:
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

    @property
    def traces(self) -> List[ReACTTrace]:
        """Get all reasoning traces from this session."""
        return self._traces

    def get_trace_summary(self) -> List[Dict]:
        """Get summary of all traces."""
        return [t.to_dict() for t in self._traces]
