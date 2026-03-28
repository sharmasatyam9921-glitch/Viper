"""
VIPER 4.0 Agent State — Pure Python state machine inspired by open-source pentesting frameworks.
No LangGraph/LangChain dependency. Uses only stdlib.
"""

from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime, timezone
from typing import Any, List, Optional
import uuid
import json
import logging

logger = logging.getLogger("viper.state")


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


class TodoList:
    """
    LLM-managed todo list for tracking attack plan progress.

    The LLM proposes tasks, marks them in-progress, and completes them.
    The engine auto-completes items when a matching tool action succeeds.
    """

    def __init__(self):
        self.items: List[TodoItem] = []

    def add(self, description: str, priority: int = 0, tool_hint: str = "") -> TodoItem:
        """Add a new todo item. priority: 0=highest."""
        pri_map = {0: Priority.HIGH, 1: Priority.MEDIUM}
        item = TodoItem(
            description=description,
            priority=pri_map.get(priority, Priority.LOW),
            notes=f"tool_hint:{tool_hint}" if tool_hint else "",
        )
        self.items.append(item)
        logger.debug("TodoList: added '%s' (id=%s, priority=%s)", description, item.id, item.priority.value)
        return item

    def update_status(self, item_id: str, status: str) -> None:
        """Update the status of an item by ID."""
        for item in self.items:
            if item.id == item_id:
                try:
                    item.status = TodoStatus(status)
                except ValueError:
                    item.status = TodoStatus.PENDING
                if status == "completed":
                    item.completed_at = datetime.now(timezone.utc).isoformat()
                logger.debug("TodoList: %s -> %s", item_id, status)
                return
        logger.debug("TodoList: item %s not found", item_id)

    def get_pending(self) -> List[TodoItem]:
        """Return all pending or in-progress items, sorted by priority."""
        priority_order = {Priority.HIGH: 0, Priority.MEDIUM: 1, Priority.LOW: 2}
        return sorted(
            [i for i in self.items if i.status in (TodoStatus.PENDING, TodoStatus.IN_PROGRESS)],
            key=lambda i: priority_order.get(i.priority, 9),
        )

    def get_next(self) -> Optional[TodoItem]:
        """Return the highest-priority pending item, or None."""
        pending = self.get_pending()
        return pending[0] if pending else None

    def to_prompt_string(self) -> str:
        """Format todo list for LLM context injection."""
        return format_todo_list([i.to_dict() for i in self.items])

    def from_llm_response(self, items: List[dict]) -> None:
        """
        Sync the todo list from LLM's updated_todo_list response.
        New items (no matching id) are added; existing items get status updated.
        """
        existing_ids = {i.id for i in self.items}
        for raw in items:
            item_id = raw.get("id")
            status = raw.get("status", "pending")
            if item_id and item_id in existing_ids:
                self.update_status(item_id, status)
            else:
                # New item from LLM
                pri_str = raw.get("priority", "medium")
                try:
                    pri = Priority(pri_str)
                except ValueError:
                    pri = Priority.MEDIUM
                new_item = TodoItem(
                    id=item_id or uuid.uuid4().hex[:8],
                    description=raw.get("description", ""),
                    status=TodoStatus(status) if status in [s.value for s in TodoStatus] else TodoStatus.PENDING,
                    priority=pri,
                    notes=raw.get("notes", ""),
                )
                self.items.append(new_item)
                logger.debug("TodoList: LLM added new item '%s' (id=%s)", new_item.description, new_item.id)

    def mark_completed_by_tool(self, tool_name: str) -> None:
        """Auto-complete items whose tool_hint matches the executed tool."""
        for item in self.items:
            if item.status in (TodoStatus.PENDING, TodoStatus.IN_PROGRESS):
                hint = ""
                if item.notes and "tool_hint:" in item.notes:
                    hint = item.notes.split("tool_hint:", 1)[1].split(";")[0].strip()
                if hint and hint.lower() in tool_name.lower():
                    item.complete(notes=f"auto-completed by {tool_name}")
                    logger.debug("TodoList: auto-completed '%s' via tool %s", item.description, tool_name)

    def to_list_of_dicts(self) -> List[dict]:
        """Serialize all items to list of dicts for state persistence."""
        return [i.to_dict() for i in self.items]

    def load_from_dicts(self, items: List[dict]) -> None:
        """Restore items from state dicts."""
        self.items = []
        for d in items:
            try:
                status = TodoStatus(d.get("status", "pending"))
            except ValueError:
                status = TodoStatus.PENDING
            try:
                priority = Priority(d.get("priority", "medium"))
            except ValueError:
                priority = Priority.MEDIUM
            self.items.append(TodoItem(
                id=d.get("id", uuid.uuid4().hex[:8]),
                description=d.get("description", ""),
                status=status,
                priority=priority,
                notes=d.get("notes", ""),
                created_at=d.get("created_at", datetime.now(timezone.utc).isoformat()),
                completed_at=d.get("completed_at"),
            ))


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
    status: str = "active"  # active, completed, failed
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    completed_at: Optional[str] = None
    findings_count: int = 0
    execution_trace_summary: str = ""

    def to_dict(self) -> dict:
        return {
            "objective_id": self.objective_id,
            "content": self.content,
            "status": self.status,
            "created_at": self.created_at,
            "completed_at": self.completed_at,
            "findings_count": self.findings_count,
            "execution_trace_summary": self.execution_trace_summary,
        }


class ObjectiveManager:
    """
    Manages multiple objectives within a single conversation session.

    Supports sequential objective execution: when one objective completes,
    the manager advances to the next pending objective. The LLM receives
    context about completed objectives to maintain coherence.
    """

    def __init__(self):
        self.objectives: List[ConversationObjective] = []
        self.current_index: int = -1

    def add(self, objective: str) -> ConversationObjective:
        """Add a new objective to the queue. Auto-advances if none is current."""
        obj = ConversationObjective(content=objective)
        self.objectives.append(obj)
        logger.info("ObjectiveManager: added objective '%s' (id=%s)", objective[:60], obj.objective_id)
        if self.current_index == -1:
            self.current_index = len(self.objectives) - 1
            logger.debug("ObjectiveManager: auto-advanced to index %d", self.current_index)
        return obj

    def complete_current(self, summary: str) -> None:
        """Mark the current objective as completed with a summary."""
        obj = self.get_current()
        if obj is None:
            logger.warning("ObjectiveManager: no current objective to complete")
            return
        obj.status = "completed"
        obj.completed_at = datetime.now(timezone.utc).isoformat()
        obj.execution_trace_summary = summary
        logger.info("ObjectiveManager: completed objective '%s' (id=%s)", obj.content[:60], obj.objective_id)

    def fail_current(self, reason: str) -> None:
        """Mark the current objective as failed."""
        obj = self.get_current()
        if obj is None:
            return
        obj.status = "failed"
        obj.completed_at = datetime.now(timezone.utc).isoformat()
        obj.execution_trace_summary = reason
        logger.info("ObjectiveManager: failed objective '%s': %s", obj.content[:60], reason)

    def get_current(self) -> Optional[ConversationObjective]:
        """Return the current active objective, or None."""
        if 0 <= self.current_index < len(self.objectives):
            return self.objectives[self.current_index]
        return None

    def has_pending(self) -> bool:
        """Return True if there are objectives that haven't started yet."""
        for i, obj in enumerate(self.objectives):
            if i > self.current_index and obj.status == "active":
                return True
        # Also true if current is completed/failed and there's a next one
        current = self.get_current()
        if current and current.status in ("completed", "failed"):
            for obj in self.objectives[self.current_index + 1:]:
                if obj.status == "active":
                    return True
        return False

    def advance(self) -> Optional[ConversationObjective]:
        """Advance to the next pending objective. Returns it, or None if no more."""
        start = self.current_index + 1
        for i in range(start, len(self.objectives)):
            if self.objectives[i].status == "active":
                self.current_index = i
                logger.info("ObjectiveManager: advanced to objective %d '%s'",
                            i, self.objectives[i].content[:60])
                return self.objectives[i]
        logger.debug("ObjectiveManager: no more pending objectives")
        return None

    def get_history_prompt(self) -> str:
        """Build an LLM context string summarizing completed/failed objectives."""
        completed = [o for o in self.objectives if o.status in ("completed", "failed")]
        if not completed:
            return ""

        lines = ["## Previous Objectives"]
        for i, obj in enumerate(completed, 1):
            status_tag = "COMPLETED" if obj.status == "completed" else "FAILED"
            lines.append(f"  {i}. [{status_tag}] {obj.content}")
            if obj.execution_trace_summary:
                lines.append(f"     Summary: {obj.execution_trace_summary}")
            if obj.findings_count > 0:
                lines.append(f"     Findings: {obj.findings_count}")
        return "\n".join(lines)

    def increment_findings(self) -> None:
        """Increment findings_count on the current objective."""
        obj = self.get_current()
        if obj:
            obj.findings_count += 1

    def to_list_of_dicts(self) -> List[dict]:
        """Serialize all objectives for state persistence."""
        return [o.to_dict() for o in self.objectives]

    def load_from_dicts(self, items: List[dict], current_index: int = -1) -> None:
        """Restore objectives from state dicts."""
        self.objectives = []
        for d in items:
            self.objectives.append(ConversationObjective(
                objective_id=d.get("objective_id", uuid.uuid4().hex[:8]),
                content=d.get("content", ""),
                status=d.get("status", "active"),
                created_at=d.get("created_at", datetime.now(timezone.utc).isoformat()),
                completed_at=d.get("completed_at"),
                findings_count=d.get("findings_count", 0),
                execution_trace_summary=d.get("execution_trace_summary", ""),
            ))
        self.current_index = current_index


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

        # Current objective (legacy single-objective field)
        "objective": ConversationObjective(content=objective).to_dict(),

        # Multi-objective support (G1)
        "conversation_objectives": [ConversationObjective(content=objective).to_dict()],
        "current_objective_index": 0,
        "objective_history_prompt": "",

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
