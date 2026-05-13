"""HackMode — the top-level orchestrator behind `python viper.py hack <target>`.

Architecture (matches the approved plan):

  HackMode (observer)
    │
    ├─ AgentBus              ← shared findings channel (one queue per topic)
    ├─ AgentRegistry         ← worker heartbeats (transient mode)
    ├─ AuditLogger           ← every step persisted to JSONL + SQLite
    ├─ ScopeReasoner         ← aggressive within scope, hard-stop at edge
    ├─ Narrator              ← plain-English terminal output
    │
    └─ Coordinators (per phase):
         ReconSwarmCoordinator   → publishes onto "vuln"
         VulnSwarmCoordinator    → publishes onto "exploit"   [Phase 2]
         ExploitSwarmCoordinator → publishes onto "post"      [Phase 3]
         PostSwarmCoordinator    → publishes onto "report"    [Phase 3]
         ReportSwarmCoordinator  → writes reports/*           [Phase 3]

For Phase 1 acceptance we wire only ReconSwarmCoordinator. The
persistence loop and additional coordinators are stubbed so subsequent
phases can plug them in without rewriting the orchestrator.
"""

from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Awaitable, Callable, Optional

from .agent_bus import AgentBus, Priority
from .audit_logger import AuditLogger
from .hack_profile import Profile, detect_profile
from .narrator import Narrator
from .scope_reasoner import ScopeReasoner
from .swarm_coordinator import (
    CoordinatorResult,
    ReconSwarmCoordinator,
    SwarmCoordinator,
)

logger = logging.getLogger("viper.hack_mode")


# ---------------------------------------------------------------------------
# Result type
# ---------------------------------------------------------------------------


@dataclass
class HackResult:
    target: str
    profile: str
    hunt_id: str
    audit_path: Path
    phase_results: dict[str, CoordinatorResult] = field(default_factory=dict)
    findings: list[dict] = field(default_factory=list)
    iterations: int = 0
    elapsed_s: float = 0.0
    stop_reason: str = ""
    timed_out: bool = False

    @property
    def findings_count(self) -> int:
        return len(self.findings)

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "profile": self.profile,
            "hunt_id": self.hunt_id,
            "audit_path": str(self.audit_path),
            "iterations": self.iterations,
            "elapsed_s": self.elapsed_s,
            "stop_reason": self.stop_reason,
            "timed_out": self.timed_out,
            "findings_count": self.findings_count,
            "phase_results": {
                phase: {
                    "workers_dispatched": r.workers_dispatched,
                    "workers_completed": r.workers_completed,
                    "workers_failed": r.workers_failed,
                    "findings_count": r.findings_count,
                    "duration_s": r.duration_s,
                }
                for phase, r in self.phase_results.items()
            },
        }


# ---------------------------------------------------------------------------
# HackMode
# ---------------------------------------------------------------------------


class HackMode:
    """One hack run. Build with `HackMode.for_target(...)`, then `await run()`."""

    def __init__(
        self,
        *,
        target: str,
        profile: Profile,
        narrator: Narrator,
        audit: AuditLogger,
        scope_reasoner: Optional[ScopeReasoner] = None,
        bus_queue_size: int = 10_000,
        coordinator_factory: Optional[
            Callable[[str, dict], SwarmCoordinator]
        ] = None,
    ) -> None:
        """
        coordinator_factory: optional override for tests. Takes
        (phase_name, common_kw) and returns a SwarmCoordinator. Default
        wires the built-in coordinators per phase.
        """
        self.target = target
        self.profile = profile
        self.narrator = narrator
        self.audit = audit
        self.scope_reasoner = scope_reasoner
        self.bus = AgentBus(max_queue_size=bus_queue_size)
        self._coord_factory = coordinator_factory or self._default_coordinator
        self._started = False
        self._stopped = False
        # State carried into stop_conditions
        self._state: dict[str, Any] = {
            "iteration": 0,
            "findings": [],
            "findings_per_iteration": [],
        }

    # ------------------------------------------------------------------
    # Constructor helpers
    # ------------------------------------------------------------------

    @classmethod
    def for_target(
        cls,
        target: str,
        *,
        profile: Optional[Profile] = None,
        scope_file: Optional[str] = None,
        explicit_profile: Optional[str] = None,
        go: bool = False,
        narrator: Optional[Narrator] = None,
        audit: Optional[AuditLogger] = None,
        scope_reasoner: Optional[ScopeReasoner] = None,
        hunts_dir: Optional[Path] = None,
        db_path: Optional[Path] = None,
    ) -> "HackMode":
        """Convenience: build a HackMode with auto-detected profile + audit."""
        if profile is None:
            profile = detect_profile(
                target, scope_file=scope_file,
                explicit=explicit_profile, go=go,
            )
        if audit is None:
            audit = AuditLogger.for_hunt(
                target, hunts_dir=hunts_dir, db_path=db_path,
            )
        if narrator is None:
            narrator = Narrator(quiet=False)
        return cls(
            target=target,
            profile=profile,
            narrator=narrator,
            audit=audit,
            scope_reasoner=scope_reasoner,
        )

    # ------------------------------------------------------------------
    # Public lifecycle
    # ------------------------------------------------------------------

    async def run(self) -> HackResult:
        """Run the full hack. Returns a HackResult."""
        if self._started:
            raise RuntimeError("HackMode already started")
        self._started = True

        t0 = time.time()
        self.narrator.banner(self.target, mode=self.profile.name.replace("Profile", ""))
        self.audit.event(
            "hunt.started",
            target=self.target,
            payload={
                "profile": self.profile.to_dict(),
                "hunt_id": self.audit.hunt_id,
            },
        )
        await self.bus.start()

        result = HackResult(
            target=self.target,
            profile=self.profile.name,
            hunt_id=self.audit.hunt_id,
            audit_path=self.audit.jsonl_path,
        )

        try:
            await asyncio.wait_for(
                self._run_loop(result),
                timeout=self.profile.time_budget_s,
            )
        except asyncio.TimeoutError:
            result.timed_out = True
            result.stop_reason = "time_budget"
            self.narrator.warn(
                f"time budget ({self.profile.time_budget_s/60:.1f} min) exhausted"
            )
        finally:
            await self._teardown(result, started_at=t0)

        return result

    async def _teardown(self, result: HackResult, *, started_at: float) -> None:
        if self._stopped:
            return
        self._stopped = True
        result.elapsed_s = time.time() - started_at
        try:
            await self.bus.stop()
        except Exception:
            pass
        self.audit.event(
            "hunt.completed",
            target=self.target,
            duration_ms=int(result.elapsed_s * 1000),
            outcome="success" if not result.timed_out else "timed_out",
            findings_count=result.findings_count,
            payload={
                "iterations": result.iterations,
                "stop_reason": result.stop_reason,
                "phases": list(result.phase_results.keys()),
            },
        )
        self.narrator.summary(
            target=self.target,
            profile=self.profile.name,
            hunt_id=self.audit.hunt_id,
            iterations=result.iterations,
            stop_reason=result.stop_reason or "completed",
            findings=result.findings_count,
        )

    # ------------------------------------------------------------------
    # The main loop
    # ------------------------------------------------------------------

    async def _run_loop(self, result: HackResult) -> None:
        """Persistence loop: phases × iterations, gated by profile.stop_conditions."""
        phases_to_run = [p for p in self.profile.phases if p != "report"]
        max_iterations = self.profile.max_iterations
        total_phases = len(phases_to_run)

        while self._state["iteration"] < max_iterations:
            self._state["iteration"] += 1
            result.iterations = self._state["iteration"]
            findings_this_iter = 0
            self.audit.event(
                "loop.iteration",
                target=self.target,
                payload={"iteration": self._state["iteration"]},
            )

            for idx, phase in enumerate(phases_to_run, start=1):
                # The narrator stage uses 1-indexed counters
                self.narrator.stage(
                    f"{phase.upper()} swarm",
                    current=idx, total=total_phases,
                )
                phase_res = await self._run_phase(phase)
                # Save the most recent run of each phase
                result.phase_results[phase] = phase_res
                # Surface findings to top-level + state
                for f in phase_res.findings:
                    result.findings.append(f)
                    self._state["findings"].append(f)
                    self.narrator.emit_finding(f)
                findings_this_iter += phase_res.findings_count
                self.narrator.finish_stage(
                    "success" if phase_res.workers_failed == 0 else "success",
                )

                # Cheap inter-phase stop check (e.g. flag found mid-iteration).
                # Only named stop_conditions fire here — NOT max_iterations,
                # which is a between-iteration check.
                early_stop, why = self._check_named_stop()
                if early_stop:
                    result.stop_reason = why or "stop_condition"
                    self.audit.event(
                        "stop_condition.met",
                        target=self.target,
                        payload={"reason": why},
                    )
                    self.narrator.info(f"stop condition met: {why}")
                    self._state["findings_per_iteration"].append(findings_this_iter)
                    return

            self._state["findings_per_iteration"].append(findings_this_iter)
            # Iteration-level stop check (includes max_iterations)
            stop, why = self.profile.should_stop(self._state)
            if stop:
                result.stop_reason = why or "stop_condition"
                self.audit.event(
                    "stop_condition.met",
                    target=self.target,
                    payload={"reason": why},
                )
                self.narrator.info(f"stop condition met: {why}")
                return

        result.stop_reason = f"max_iterations ({max_iterations})"

    # ------------------------------------------------------------------
    # Phase dispatch
    # ------------------------------------------------------------------

    def _check_named_stop(self) -> tuple[bool, Optional[str]]:
        """Check ONLY the profile.stop_conditions (skip the max_iterations
        rule) — used by the inter-phase check inside an iteration."""
        for cond in self.profile.stop_conditions:
            try:
                if cond.check and cond.check(self._state):
                    return True, cond.name
            except Exception:
                continue
        return False, None

    async def _run_phase(self, phase: str) -> CoordinatorResult:
        """Dispatch one phase's coordinator. Returns its CoordinatorResult."""
        # Build coordinator
        common = {
            "bus": self.bus,
            "audit_logger": self.audit,
            "max_concurrent": self.profile.max_concurrent,
            "per_worker_timeout": self.profile.per_worker_timeout,
        }
        coord = self._coord_factory(phase, common)

        # Build payload
        techniques = self.profile.workers.get(phase, [])
        payload = {
            "target": self.target,
            "scope_reasoner": self.scope_reasoner,
            # Empty techniques list → use all registered for the phase
            "techniques": techniques or None,
        }
        return await coord.handle_message(payload)

    # ------------------------------------------------------------------
    # Default coordinator wiring
    # ------------------------------------------------------------------

    def _default_coordinator(self, phase: str, common: dict) -> SwarmCoordinator:
        """Map phase → coordinator class. Phase 1 wires recon only; the
        rest fall back to a no-op coordinator (returns empty results).
        Phase 2/3 will replace these with their real subclasses."""
        if phase == "recon":
            return ReconSwarmCoordinator(**common)
        return _NoOpCoordinator(phase=phase, **common)


# ---------------------------------------------------------------------------
# No-op coordinator (stub for phases not yet implemented)
# ---------------------------------------------------------------------------


class _NoOpCoordinator(SwarmCoordinator):
    """Placeholder for phases without a real coordinator yet. Logs and exits."""
    PHASE = "noop"

    def __init__(self, *, phase: str, **kw):
        self.PHASE = phase
        super().__init__(**kw)

    def build_manifest(self, target: str, context: dict) -> list:
        return []
