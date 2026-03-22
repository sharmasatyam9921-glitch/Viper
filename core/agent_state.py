"""
VIPER 4.0 Agent State — Pure Python state machine inspired by open-source pentesting frameworks.
No LangGraph/LangChain dependency. Uses only stdlib.
"""

from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime, timezone
from typing import Any, Optional
import uuid
import json


# ── Enums ──────────────────────────────────────────────────────────────────

class Phase(str, Enum):
    INFORMATIONAL = "informational"
    EXPLOITATION = "exploitation"
    POST_EXPLOITATION = "post_exploitation"


class ActionType(str, Enum):
    USE_TOOL = "use_tool"
    PLAN_TOOLS = "plan_tools"
    TRANSITION_PHASE = "transition_phase"
    COMPLETE = "complete"
    ASK_USER = "ask_user"


class TodoStatus(str, Enum):
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    BLOCKED = "blocked"


class Priority(str, Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


# ── Core Dataclasses ──────────────────────────────────────────────────────

@dataclass
class TodoItem:
    id: str = field(default_factory=lambda: uuid.uuid4().hex[:8])
    description: str = ""
    status: TodoStatus = TodoStatus.PENDING
    priority: Priority = Priority.MEDIUM
    notes: str = ""
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    completed_at: Optional[str] = None

    def complete(self, notes: str = ""):
        self.status = TodoStatus.COMPLETED
        self.completed_at = datetime.now(timezone.utc).isoformat()
        if notes:
            self.notes = f"{self.notes}; {notes}" if self.notes else notes

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "description": self.description,
            "status": self.status.value,
            "priority": self.priority.value,
            "notes": self.notes,
            "created_at": self.created_at,
            "completed_at": self.completed_at,
        }


@dataclass
class ExecutionStep:
    step_id: str = field(default_factory=lambda: uuid.uuid4().hex[:8])
    iteration: int = 0
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    phase: str = Phase.INFORMATIONAL.value
    thought: str = ""
    reasoning: str = ""
    tool_name: Optional[str] = None
    tool_args: Optional[dict] = None
    tool_output: Optional[str] = None
    output_analysis: Optional[str] = None
    success: Optional[bool] = None
    error_message: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "step_id": self.step_id,
            "iteration": self.iteration,
            "timestamp": self.timestamp,
            "phase": self.phase,
            "thought": self.thought,
            "reasoning": self.reasoning,
            "tool_name": self.tool_name,
            "tool_args": self.tool_args,
            "tool_output": self.tool_output[:500] if self.tool_output and len(self.tool_output) > 500 else self.tool_output,
            "output_analysis": self.output_analysis,
            "success": self.success,
            "error_message": self.error_message,
        }


@dataclass
class TargetInfo:
    primary_target: str = ""
    target_type: str = "web"  # web, network, api, mobile
    ports: list = field(default_factory=list)
    services: dict = field(default_factory=dict)  # port -> service info
    technologies: list = field(default_factory=list)
    vulnerabilities: list = field(default_factory=list)
    credentials: list = field(default_factory=list)
    sessions: list = field(default_factory=list)

    def merge_from(self, other: "TargetInfo"):
        """Merge discovered info from another TargetInfo, deduplicating."""
        if other.primary_target and not self.primary_target:
            self.primary_target = other.primary_target
        if other.target_type != "web":
            self.target_type = other.target_type
        # Lists: deduplicate
        for attr in ("ports", "technologies", "vulnerabilities", "credentials", "sessions"):
            existing = getattr(self, attr)
            for item in getattr(other, attr):
                if item not in existing:
                    existing.append(item)
        # Dict: merge
        self.services.update(other.services)

    def to_dict(self) -> dict:
        return {
            "primary_target": self.primary_target,
            "target_type": self.target_type,
            "ports": self.ports,
            "services": self.services,
            "technologies": self.technologies,
            "vulnerabilities": self.vulnerabilities,
            "credentials": self.credentials,
            "sessions": self.sessions,
        }


@dataclass
class PhaseTransitionRequest:
    from_phase: str = Phase.INFORMATIONAL.value
    to_phase: str = Phase.EXPLOITATION.value
    reason: str = ""
    planned_actions: list = field(default_factory=list)
    risks: list = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "from_phase": self.from_phase,
            "to_phase": self.to_phase,
            "reason": self.reason,
            "planned_actions": self.planned_actions,
            "risks": self.risks,
        }


@dataclass
class ToolConfirmationRequest:
    confirmation_id: str = field(default_factory=lambda: uuid.uuid4().hex[:8])
    mode: str = "single"  # single, batch
    tools: list = field(default_factory=list)  # list of {tool_name, tool_args}
    reasoning: str = ""
    phase: str = Phase.INFORMATIONAL.value
    iteration: int = 0

    def to_dict(self) -> dict:
        return {
            "confirmation_id": self.confirmation_id,
            "mode": self.mode,
            "tools": self.tools,
            "reasoning": self.reasoning,
            "phase": self.phase,
            "iteration": self.iteration,
        }


@dataclass
class ConversationObjective:
    objective_id: str = field(default_factory=lambda: uuid.uuid4().hex[:8])
    content: str = ""
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    completed_at: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "objective_id": self.objective_id,
            "content": self.content,
            "created_at": self.created_at,
            "completed_at": self.completed_at,
        }


@dataclass
class ToolPlanStep:
    tool_name: str = ""
    tool_args: dict = field(default_factory=dict)
    rationale: str = ""
    tool_output: Optional[str] = None
    success: Optional[bool] = None
    error_message: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "tool_name": self.tool_name,
            "tool_args": self.tool_args,
            "rationale": self.rationale,
            "tool_output": self.tool_output[:300] if self.tool_output and len(self.tool_output) > 300 else self.tool_output,
            "success": self.success,
            "error_message": self.error_message,
        }


@dataclass
class ToolPlan:
    steps: list = field(default_factory=list)  # list of ToolPlanStep
    plan_rationale: str = ""

    def to_dict(self) -> dict:
        return {
            "steps": [s.to_dict() if hasattr(s, "to_dict") else s for s in self.steps],
            "plan_rationale": self.plan_rationale,
        }


@dataclass
class LLMDecision:
    thought: str = ""
    reasoning: str = ""
    action: ActionType = ActionType.USE_TOOL
    tool_name: Optional[str] = None
    tool_args: Optional[dict] = None
    phase_transition: Optional[PhaseTransitionRequest] = None
    completion_reason: Optional[str] = None
    tool_plan: Optional[ToolPlan] = None
    need_deep_think: bool = False
    updated_todo_list: Optional[list] = None  # list of TodoItem

    def to_dict(self) -> dict:
        return {
            "thought": self.thought,
            "reasoning": self.reasoning,
            "action": self.action.value,
            "tool_name": self.tool_name,
            "tool_args": self.tool_args,
            "phase_transition": self.phase_transition.to_dict() if self.phase_transition else None,
            "completion_reason": self.completion_reason,
            "tool_plan": self.tool_plan.to_dict() if self.tool_plan else None,
            "need_deep_think": self.need_deep_think,
            "updated_todo_list": [t.to_dict() if hasattr(t, "to_dict") else t for t in (self.updated_todo_list or [])],
        }


@dataclass
class DeepThinkResult:
    situation_assessment: str = ""
    attack_vectors_identified: list = field(default_factory=list)
    recommended_approach: str = ""
    priority_order: list = field(default_factory=list)
    risks_and_mitigations: list = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "situation_assessment": self.situation_assessment,
            "attack_vectors_identified": self.attack_vectors_identified,
            "recommended_approach": self.recommended_approach,
            "priority_order": self.priority_order,
            "risks_and_mitigations": self.risks_and_mitigations,
        }


@dataclass
class InvokeResponse:
    answer: str = ""
    tool_used: Optional[str] = None
    tool_output: Optional[str] = None
    error: Optional[str] = None
    current_phase: str = Phase.INFORMATIONAL.value
    iteration_count: int = 0
    task_complete: bool = False
    todo_list: list = field(default_factory=list)
    execution_trace_summary: str = ""
    awaiting_approval: Optional[PhaseTransitionRequest] = None
    awaiting_question: Optional[str] = None
    awaiting_tool_confirmation: Optional[ToolConfirmationRequest] = None

    def to_dict(self) -> dict:
        return {
            "answer": self.answer,
            "tool_used": self.tool_used,
            "tool_output": self.tool_output,
            "error": self.error,
            "current_phase": self.current_phase,
            "iteration_count": self.iteration_count,
            "task_complete": self.task_complete,
            "todo_list": [t.to_dict() if hasattr(t, "to_dict") else t for t in self.todo_list],
            "execution_trace_summary": self.execution_trace_summary,
            "awaiting_approval": self.awaiting_approval.to_dict() if self.awaiting_approval else None,
            "awaiting_question": self.awaiting_question,
            "awaiting_tool_confirmation": self.awaiting_tool_confirmation.to_dict() if self.awaiting_tool_confirmation else None,
        }


# ── AgentState factory ────────────────────────────────────────────────────

def create_initial_state(
    user_id: str,
    project_id: str,
    session_id: str,
    objective: str,
    max_iterations: int = 30,
) -> dict:
    """Create the initial agent state dict."""
    now = datetime.now(timezone.utc).isoformat()
    return {
        # Identity
        "user_id": user_id,
        "project_id": project_id,
        "session_id": session_id,

        # Messages (chat history for LLM context)
        "messages": [],

        # Iteration control
        "current_iteration": 0,
        "max_iterations": max_iterations,
        "task_complete": False,

        # Phase management
        "current_phase": Phase.INFORMATIONAL.value,
        "phase_history": [],  # list of {phase, entered_at, exited_at}
        "attack_path_type": "",  # e.g. "web_app", "network", "api"

        # Execution trace
        "execution_trace": [],  # list of ExecutionStep dicts

        # Todo list
        "todo_list": [],  # list of TodoItem dicts

        # Target intelligence
        "target_info": TargetInfo().to_dict(),

        # Deep think
        "deep_think_result": None,  # DeepThinkResult dict or None

        # Chain-of-thought context (accumulated across iterations)
        "chain_findings": [],      # key discoveries
        "chain_failures": [],      # what didn't work and why
        "chain_decisions": [],     # reasoning for major decisions

        # Current objective
        "objective": ConversationObjective(content=objective).to_dict(),

        # Approval flow (phase transitions)
        "awaiting_approval": False,
        "pending_phase_transition": None,  # PhaseTransitionRequest dict
        "approval_response": None,  # "approve" | "modify" | "abort"
        "approval_modification": None,  # user modification text

        # Question flow (ask user)
        "awaiting_question": False,
        "pending_question": None,
        "question_context": None,
        "question_answer": None,

        # Tool confirmation flow
        "awaiting_tool_confirmation": False,
        "pending_tool_confirmation": None,  # ToolConfirmationRequest dict
        "tool_confirmation_response": None,

        # Tool plan execution
        "current_tool_plan": None,  # ToolPlan dict
        "tool_plan_index": 0,

        # Metadata
        "created_at": now,
        "updated_at": now,
        "last_error": None,
    }


# ── Helper / formatter functions ──────────────────────────────────────────

class AgentPhase(str, Enum):
    """Compatibility alias for phase names used by Phase 2 modules."""
    IDLE = 'idle'
    RECON = 'recon'
    EXPLOIT = 'exploit'
    POST_EXPLOIT = 'post_exploit'
    REPORT = 'report'


class AgentState:
    """Convenience wrapper around the dict-based state for Phase 2 callers."""

    def __init__(self):
        self.phase = 'idle'
        self.target = None
        self.findings = []
        self.attacks_tried = []
        self.technologies = []
        self.access_level = 0
        self.objectives = []
        self.deep_think_results = []

    def set_target(self, target):
        self.target = target

    def add_finding(self, finding):
        self.findings.append(finding)

    def to_dict(self):
        return {
            'phase': self.phase,
            'target': self.target,
            'findings': self.findings,
            'attacks_tried': self.attacks_tried,
            'technologies': self.technologies,
            'access_level': self.access_level,
        }

    @classmethod
    def from_dict(cls, data):
        state = cls()
        for k, v in data.items():
            if hasattr(state, k):
                setattr(state, k, v)
        return state


def format_todo_list(todo_list: list) -> str:
    """Format todo list for LLM context injection."""
    if not todo_list:
        return "No tasks in todo list."

    lines = ["## Current Todo List"]
    status_icons = {
        "pending": "[ ]",
        "in_progress": "[~]",
        "completed": "[x]",
        "blocked": "[!]",
    }
    priority_tags = {
        "high": "HIGH",
        "medium": "MED",
        "low": "LOW",
    }

    for item in todo_list:
        # Support both dicts and TodoItem objects
        if hasattr(item, "status"):
            st, pr, desc, notes = item.status.value, item.priority.value, item.description, item.notes
        else:
            st, pr, desc, notes = item.get("status", "pending"), item.get("priority", "medium"), item.get("description", ""), item.get("notes", "")

        icon = status_icons.get(st, "[ ]")
        tag = priority_tags.get(pr, "MED")
        line = f"  {icon} [{tag}] {desc}"
        if notes:
            line += f"  -- {notes}"
        lines.append(line)

    # Summary counts
    statuses = [i.get("status", "pending") if isinstance(i, dict) else i.status.value for i in todo_list]
    pending = statuses.count("pending") + statuses.count("in_progress")
    done = statuses.count("completed")
    blocked = statuses.count("blocked")
    lines.append(f"\n  Progress: {done}/{len(todo_list)} done, {pending} remaining, {blocked} blocked")
    return "\n".join(lines)


def format_execution_trace(trace: list, last_n: int = 10) -> str:
    """Format recent execution steps for LLM context."""
    if not trace:
        return "No execution history yet."

    recent = trace[-last_n:]
    lines = [f"## Execution Trace (last {len(recent)} of {len(trace)} steps)"]

    for step in recent:
        if isinstance(step, dict):
            it = step.get("iteration", "?")
            phase = step.get("phase", "?")
            tool = step.get("tool_name", "think")
            success = step.get("success")
            thought = step.get("thought", "")
            analysis = step.get("output_analysis", "")
            error = step.get("error_message", "")
        else:
            it, phase, tool = step.iteration, step.phase, step.tool_name or "think"
            success, thought, analysis, error = step.success, step.thought, step.output_analysis, step.error_message

        status = "OK" if success else ("FAIL" if success is False else "---")
        line = f"  [{it}] {phase}/{tool} -> {status}"
        if thought:
            line += f"\n        Thought: {thought[:120]}"
        if analysis:
            line += f"\n        Analysis: {analysis[:120]}"
        if error:
            line += f"\n        Error: {error[:120]}"
        lines.append(line)

    return "\n".join(lines)


def format_chain_context(
    findings: list,
    failures: list,
    decisions: list,
    trace: list,
    recent_count: int = 5,
) -> str:
    """Format chain-of-thought context for the LLM to maintain coherence."""
    sections = []

    if findings:
        recent_findings = findings[-recent_count:]
        sections.append("### Key Findings\n" + "\n".join(f"  - {f}" for f in recent_findings))

    if failures:
        recent_failures = failures[-recent_count:]
        sections.append("### What Didn't Work\n" + "\n".join(f"  - {f}" for f in recent_failures))

    if decisions:
        recent_decisions = decisions[-recent_count:]
        sections.append("### Decisions Made\n" + "\n".join(f"  - {d}" for d in recent_decisions))

    if trace:
        sections.append(format_execution_trace(trace, last_n=recent_count))

    if not sections:
        return "No chain context accumulated yet."

    return "## Chain Context\n\n" + "\n\n".join(sections)
