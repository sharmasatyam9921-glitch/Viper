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
import copy
import logging
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Awaitable, Callable, Optional

from .agent_bus import AgentBus, Priority
from .audit_logger import AuditLogger
from .chain_planner import CHAIN_REQUIRED, ChainPlanner
from .guardrail_hard import is_blocked
from .hack_profile import (
    BugBountyProfile,
    CTFProfile,
    LabProfile,
    Profile,
    detect_profile,
)
from .narrator import Narrator
from .scope_reasoner import ScopeReasoner
from .session_context import SessionContext
from .world_model import WorldModel
from .swarm_coordinator import (
    CoordinatorResult,
    ExploitSwarmCoordinator,
    FindingDedup,
    PostSwarmCoordinator,
    ReconSwarmCoordinator,
    SwarmCoordinator,
    VulnSwarmCoordinator,
)

logger = logging.getLogger("viper.hack_mode")


# ---------------------------------------------------------------------------
# Result type
# ---------------------------------------------------------------------------


# Recon / attack-surface artifact classes — discovered endpoints, DNS records,
# open ports, subdomains, tech fingerprints. These are MAP DATA, not
# vulnerabilities, and must not inflate the vulnerability findings count or reach
# the validation gate. (github_secret / shodan_cve / js_secret ARE real findings
# and are deliberately NOT here.)
_SURFACE_PREFIXES = frozenset({
    "endpoint", "historical_url", "open_port", "port", "service", "http_service",
    "subdomain", "subdomain_alive", "technology", "tech", "asset", "wayback",
    "js_file", "dns_a", "dns_aaaa", "dns_mx", "dns_ns", "dns_txt", "dns_cname",
    "dns_soa", "dns_ptr", "dns", "shodan_port", "shodan_tag", "shodan_intel",
})


def _is_surface(finding: dict) -> bool:
    """True if `finding` is recon/attack-surface map data, not a vulnerability."""
    head = str(finding.get("vuln_type") or finding.get("type") or "").split(":")[0].lower()
    return head in _SURFACE_PREFIXES


@dataclass
class HackResult:
    target: str
    profile: str
    hunt_id: str
    audit_path: Path
    phase_results: dict[str, CoordinatorResult] = field(default_factory=dict)
    findings: list[dict] = field(default_factory=list)
    surface: list[dict] = field(default_factory=list)
    iterations: int = 0
    elapsed_s: float = 0.0
    stop_reason: str = ""
    timed_out: bool = False
    # Compact, secret-free summary of the per-hunt SessionContext (roles seen,
    # endpoints observed, reachability entries). Set at teardown.
    session_context: dict = field(default_factory=dict)

    @property
    def findings_count(self) -> int:
        return len(self.findings)

    @property
    def submittable_count(self) -> int:
        """Findings an INDEPENDENT validation pass re-confirmed (see the gate)."""
        return sum(1 for f in self.findings if f.get("submittable"))

    @property
    def surface_count(self) -> int:
        """Recon / attack-surface artifacts (endpoints, DNS, ports) — not vulns."""
        return len(self.surface)

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
            "submittable_count": self.submittable_count,
            "surface_count": self.surface_count,
            "session_context": self.session_context,
            # Normalized findings list so consumers (reports, the benchmark
            # scorer) can read individual findings, not just the count.
            "findings": [
                {
                    "vuln_type": f.get("vuln_type") or f.get("type") or "finding",
                    "type": f.get("type"),
                    "severity": str(f.get("severity") or "info"),
                    "title": f.get("title"),
                    "url": f.get("url"),
                    "parameter": f.get("parameter"),
                    "payload": f.get("payload"),
                    "evidence": f.get("evidence"),
                    "confidence": f.get("confidence"),
                    "validated": f.get("validated"),
                    "validation_confidence": f.get("validation_confidence"),
                    "validation_reason": f.get("validation_reason"),
                    "submittable": f.get("submittable"),
                }
                for f in self.findings
            ],
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
        approval_gate=None,
        bus_queue_size: int = 10_000,
        coordinator_factory: Optional[
            Callable[[str, dict], SwarmCoordinator]
        ] = None,
        auth_headers: Optional[dict] = None,
        bola_config: Optional[dict] = None,
        proxy: Optional[str] = None,
        validate: bool = True,
        oob=None,
        mcp_plan: Optional[list] = None,
    ) -> None:
        """
        coordinator_factory: optional override for tests. Takes
        (phase_name, common_kw) and returns a SwarmCoordinator. Default
        wires the built-in coordinators per phase.
        auth_headers: optional session auth (e.g. {"Authorization": "Bearer …"}
        or {"Cookie": "…"}) applied to every worker request so the hunt tests
        the app as a logged-in user.
        bola_config: optional two-account config that activates the BOLA/IDOR
        specialist worker (core.specialist.bola_engine). Shape:
        {"owner_headers", "owner_markers", "attacker_headers", ...}. When set,
        it is threaded into the vuln phase so bola_multi replays identity A's
        object URLs as identity B and confirms cross-user reads.
        """
        self.target = target
        self.profile = profile
        self.narrator = narrator
        self.audit = audit
        self.scope_reasoner = scope_reasoner
        self.approval_gate = approval_gate
        self._auth_headers = dict(auth_headers) if auth_headers else {}
        # Deep copy so a coordinator/worker mutating an inner dict (headers/
        # markers) cannot reach back into the caller's config or the seeded roles.
        self._bola_config = copy.deepcopy(bola_config) if bola_config else None
        self._proxy = proxy or None
        self._validate = validate
        # Optional out-of-band interaction server. When set, blind-capable workers
        # fire canary payloads and the validation gate confirms a finding iff the
        # target's backend calls the listener back.
        self._oob = oob
        # Optional plan of external MCP tool calls to run in-pipeline. Their output
        # is appended (confidence-capped) before the gate, so the gate filters the
        # external arsenal's findings like any other.
        self._mcp_plan = list(mcp_plan) if mcp_plan else None
        # Per-hunt shared session context: holds the authenticated identities
        # under test and the (role, url) -> status reachability matrix that
        # captured traffic populates. Seeded from the supplied identities so the
        # BOLA bridge is ready even before any browser/HAR capture runs.
        self._session_context = SessionContext(
            hunt_id=getattr(audit, "hunt_id", "") or "")
        if self._auth_headers:
            self._session_context.add_role("session", self._auth_headers, [])
        if self._bola_config:
            self._session_context.add_role(
                self._bola_config.get("owner_name", "A"),
                self._bola_config.get("owner_headers"),
                self._bola_config.get("owner_markers"))
            self._session_context.add_role(
                self._bola_config.get("attacker_name", "B"),
                self._bola_config.get("attacker_headers"),
                self._bola_config.get("attacker_markers"))
        self.bus = AgentBus(max_queue_size=bus_queue_size)
        self._coord_factory = coordinator_factory or self._default_coordinator
        # Phase 5: a single FindingDedup is shared by every coordinator
        # so cross-phase duplicates (same SQLi found by probe AND exploit)
        # don't get republished to the bus.
        self.dedup = FindingDedup()
        # Live per-hunt belief state — updated on every finding (Section 7.2).
        self.world_model = WorldModel(target=target)
        # Mythos-style finding-driven chaining. Enabled only when the profile
        # opts in (max_chain_depth > 0); None keeps the legacy linear loop.
        _depth = int(getattr(profile, "max_chain_depth", 0) or 0)
        self.chain_planner: Optional[ChainPlanner] = (
            ChainPlanner(
                max_depth=_depth,
                max_tasks=int(getattr(profile, "max_chain_tasks", 24) or 24),
            )
            if _depth > 0 else None
        )
        self._started = False
        self._stopped = False
        # Cross-hunt attack priors (best-effort learning). Built lazily at hunt
        # start (see _run_loop) so unit-constructing HackMode never opens the
        # evograph DB; None until then. Never touches the validation gate.
        self._priors = None
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

    @classmethod
    def resume(
        cls,
        hunt_id: str,
        *,
        hunts_dir: Optional[Path] = None,
        db_path: Optional[Path] = None,
        profile: Optional[Profile] = None,
        narrator: Optional[Narrator] = None,
        scope_reasoner: Optional[ScopeReasoner] = None,
        approval_gate=None,
    ) -> "HackMode":
        """Reconstruct a HackMode from an existing hunt's audit log.

        Replays prior `phase.completed` events into `_state` so the
        persistence loop skips finished phases on the next iteration.
        The target is recovered from the first `hunt.started` event.

        Raises FileNotFoundError if the hunt's audit.jsonl doesn't exist.
        """
        hunts_dir_p = Path(hunts_dir) if hunts_dir else Path("state/hunts")
        audit_path = hunts_dir_p / hunt_id / "audit.jsonl"
        if not audit_path.exists():
            raise FileNotFoundError(
                f"audit log not found for hunt_id={hunt_id!r}: {audit_path}"
            )

        # Rebuild the audit logger pointing at the SAME files
        audit = AuditLogger(
            hunt_id=hunt_id,
            jsonl_path=audit_path,
            db_path=Path(db_path) if db_path else Path("data/viper.db"),
        )

        # Replay events to recover target, profile (best-effort), and state
        events = audit.read_jsonl()
        target = ""
        recovered_profile_dict: dict = {}
        completed_phases: list[str] = []
        prior_findings: list[dict] = []
        iteration = 0
        for ev in events:
            if ev.action == "hunt.started":
                target = ev.target or target
                p = (ev.payload or {}).get("profile")
                if isinstance(p, dict):
                    recovered_profile_dict = p
            elif ev.action == "phase.completed":
                if ev.phase and ev.phase not in completed_phases:
                    completed_phases.append(ev.phase)
            elif ev.action == "loop.iteration":
                iteration = max(iteration, int(
                    (ev.payload or {}).get("iteration") or 0
                ))
            elif ev.action == "finding.published":
                # Carry forward the published findings so the next iteration
                # can re-use them as asset inputs without re-running recon.
                p = ev.payload or {}
                prior_findings.append({
                    "type": (p.get("title") or "").split(":")[0] or "finding",
                    "vuln_type": (p.get("technique") or "") + ":" + (p.get("title") or ""),
                    "title": p.get("title"),
                    "url": p.get("url"),
                    "severity": ev.severity or "info",
                    "phase": ev.phase,
                })

        if not target:
            raise RuntimeError(
                f"audit log for hunt_id={hunt_id!r} is missing a "
                "hunt.started event — cannot recover target"
            )

        # Profile resolution priority: explicit arg → audited profile → default
        if profile is None and recovered_profile_dict:
            name = recovered_profile_dict.get("name", "").lower()
            if "ctf" in name:
                profile = CTFProfile()
            elif "bug" in name:
                profile = BugBountyProfile(
                    allow_destructive=recovered_profile_dict.get(
                        "allow_destructive", False,
                    ),
                )
            else:
                profile = LabProfile(
                    allow_destructive=recovered_profile_dict.get(
                        "allow_destructive", False,
                    ),
                )
        if profile is None:
            profile = detect_profile(target)

        if narrator is None:
            narrator = Narrator(quiet=False)

        hm = cls(
            target=target,
            profile=profile,
            narrator=narrator,
            audit=audit,
            scope_reasoner=scope_reasoner,
            approval_gate=approval_gate,
        )
        # Seed state so completed phases are skipped + findings flow forward
        hm._state["iteration"] = iteration
        hm._state["findings"] = prior_findings
        hm._state["resumed_completed_phases"] = completed_phases
        hm._state["resumed"] = True
        return hm

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

        result = HackResult(
            target=self.target,
            profile=self.profile.name,
            hunt_id=self.audit.hunt_id,
            audit_path=self.audit.jsonl_path,
        )

        # Hard guardrail — deterministic blocklist (gov/mil/edu/intl TLDs +
        # protected major domains). Applies to EVERY profile; a blocked domain
        # is never a legitimate target. Fails the run closed before any work.
        blocked, reason = is_blocked(self.target)
        if blocked:
            result.stop_reason = "guardrail_blocked"
            result.elapsed_s = time.time() - t0
            self.narrator.warn(f"target blocked by guardrail: {reason}")
            self.audit.event(
                "guardrail.blocked", target=self.target,
                outcome="blocked", payload={"reason": reason},
            )
            self.audit.event(
                "hunt.completed", target=self.target, outcome="blocked",
                findings_count=0, payload={"stop_reason": result.stop_reason},
            )
            self._stopped = True  # nothing to tear down; bus never started
            return result

        await self.bus.start()
        # Install the per-hunt scope gate so every worker HTTP request is
        # checked before it leaves the box (fail-closed). Set inside this task
        # so worker child-tasks inherit it via contextvars.
        self._install_scope_guard()

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
        # Independent validation gate BEFORE scope/auth/proxy are torn down, so
        # re-tests stay in scope and authenticated. Tags validated/submittable.
        await self._run_validation_gate(result)
        # Tamper-evident chain of custody for the submittable set.
        self._write_evidence_manifest(result)
        # Capture the compact, secret-free session-context summary AFTER the gate
        # so it reflects the final state of the hunt.
        try:
            result.session_context = self._session_context.summary()
        except Exception:
            pass
        self._clear_scope_guard()
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
        # Persist the final belief state so the dashboard/report can show what
        # the agent ended up believing about the target (Section 7.2).
        try:
            self.audit.event(
                "world.snapshot", target=self.target,
                payload=self.world_model.to_dict(),
            )
        except Exception:
            pass
        self.narrator.summary(
            target=self.target,
            profile=self.profile.name,
            hunt_id=self.audit.hunt_id,
            iterations=result.iterations,
            stop_reason=result.stop_reason or "completed",
            findings=result.findings_count,
        )
        # Auto-generate the HTML report on completion. Offloaded to a thread:
        # generate_report_sync spins its own event loop, which cannot run
        # inside this live async loop. Failure here must not break teardown.
        try:
            await asyncio.to_thread(self._write_report, result, started_at)
        except Exception as exc:
            self.audit.event(
                "report.failed", target=self.target,
                payload={"error": f"{type(exc).__name__}: {exc}"},
            )

    async def _run_mcp_tools(self, result: "HackResult") -> None:
        """Run the configured external MCP tool plan and append its candidate
        findings (confidence-capped) so the gate filters them. Opt-in + best-effort."""
        if not self._mcp_plan:
            return
        reg = None
        try:
            from core.mcp.registry import MCPRegistry
            from core.mcp_tool_bridge import collect_mcp_findings
            reg = MCPRegistry.from_config()
            fs = await collect_mcp_findings(reg, self._mcp_plan,
                                            default_url=self.target)
            for f in fs:
                (result.surface if _is_surface(f) else result.findings).append(f)
            if fs:
                self.audit.event("mcp.tools", target=self.target,
                                 payload={"candidates": len(fs)})
                self.narrator.info(
                    f"external MCP tools contributed {len(fs)} candidate "
                    f"finding(s) (gate will re-confirm)")
        except Exception as exc:  # noqa: BLE001 — external tools never break the hunt
            logger.warning("mcp tools step failed: %s", exc)
            self.audit.event("mcp.tools", target=self.target, outcome="error",
                             payload={"error": str(exc)})
        finally:
            if reg is not None:
                try:
                    reg.close_all()
                except Exception:
                    pass

    async def _await_late_oob_callbacks(self, result: "HackResult", *,
                                        max_wait_s: float = 5.0,
                                        poll_s: float = 0.5) -> None:
        """Wait (bounded) for any still-outstanding blind-vuln OOB canaries to call
        back before the gate runs. A DNS/HTTP callback for a token WE minted is
        irrefutable whether it arrives during the hunt or a few seconds after, so
        polling here promotes a genuine late-firing blind vuln that would otherwise be
        a lead. Only waits WHILE tokens are outstanding (returns the moment they all
        fire), and only when an OOB server is attached. FP-safe: it merely lets the
        existing OOB confirmation path see a late interaction — the gate logic is
        unchanged."""
        if self._oob is None:
            return
        store = getattr(self._oob, "store", None)
        if store is None:
            return

        def _pending() -> list[str]:
            out = []
            for f in result.findings:
                tok = f.get("oob_token")
                if not tok:
                    continue
                try:
                    if not store.has_interaction(tok):
                        out.append(tok)
                except Exception:   # noqa: BLE001 — a flaky store never blocks the gate
                    pass
            return out

        pending = _pending()
        if not pending:
            return
        self.narrator.info(
            f"awaiting late OOB callbacks for {len(pending)} blind canary(s) "
            f"(up to {max_wait_s:.0f}s)")
        deadline = time.time() + max_wait_s
        while time.time() < deadline:
            await asyncio.sleep(poll_s)
            still = _pending()
            if len(still) < len(pending):
                try:
                    self.audit.event(
                        "oob.late_callback", target=self.target,
                        payload={"fired": len(pending) - len(still)})
                except Exception:
                    pass
            if not still:
                break
            pending = still

    async def _run_validation_gate(self, result: "HackResult") -> None:
        """Re-confirm every finding via an INDEPENDENT code path and tag each
        validated/submittable. A worker that finds a bug is not allowed to be the
        only thing that confirms it — this is what keeps autonomous runs from
        submitting false positives. Fail-open on gate error (findings still
        reported, just untagged); fail-CLOSED per-finding (un-reconfirmed =
        not submittable)."""
        # Pull in external MCP tool findings (if any) BEFORE the gate, so the gate
        # re-confirms them like everything else.
        await self._run_mcp_tools(result)
        if not self._validate or not result.findings:
            return
        # Give blind-vuln canaries that hadn't called back yet a brief, bounded window
        # to fire BEFORE the gate decides — a late OOB callback is just as irrefutable
        # as an early one, so this rescues a real blind SSRF/RCE/XXE from being filed
        # as a lead. No-op when there is no OOB server or no outstanding token.
        await self._await_late_oob_callbacks(result)
        try:
            from core.swarm_validation import partition, validate_findings
            annotated = await validate_findings(
                result.findings, default_target=self.target,
                bola_config=self._bola_config,
                oob_store=(self._oob.store if self._oob is not None else None))
            # Adversarial self-verifier: independently RE-run the gate's confirmation
            # on each submittable finding and demote any that does not reproduce
            # (transient/flaky). Only ever demotes, so it can improve precision but
            # never cost recall on a deterministic true positive. Opt out with
            # profile.adversarial_verify = False.
            if getattr(self.profile, "adversarial_verify", True):
                try:
                    from core.adversarial_verifier import refute_unreproducible
                    n_ref = await refute_unreproducible(
                        annotated, bola_config=self._bola_config,
                        oob_store=(self._oob.store if self._oob is not None else None))
                    if n_ref:
                        self.audit.event("findings.refuted", target=self.target,
                                         payload={"demoted": n_ref})
                        self.narrator.info(
                            f"adversarial verifier: demoted {n_ref} non-reproducible "
                            "finding(s) to leads")
                except Exception as exc:   # noqa: BLE001 — refutation is best-effort
                    logger.warning("adversarial verifier failed: %s", exc)
            # Attack-chain correlation: recognize low->critical escalations across
            # the confirmed findings and emit synthetic chain:* findings (each
            # submittable iff all its components are).
            try:
                from core.chain_recipes import correlate_chains
                chains = correlate_chains(annotated)
                if chains:
                    annotated = annotated + chains
                    self.audit.event(
                        "chains.correlated", target=self.target,
                        payload={"count": len(chains),
                                 "chains": [c["vuln_type"] for c in chains]})
                    self.narrator.info(
                        f"attack-chain correlation: {len(chains)} escalation chain(s)")
            except Exception as exc:  # noqa: BLE001 — chaining is best-effort
                logger.warning("chain correlation failed: %s", exc)
                self.audit.event("chains.correlated", target=self.target,
                                 outcome="error", payload={"error": str(exc)})
            result.findings[:] = annotated
            sub, leads = partition(annotated)
            self.audit.event(
                "findings.validated", target=self.target,
                payload={"total": len(annotated), "submittable": len(sub),
                         "leads": len(leads)})
            self.narrator.info(
                f"validation gate: {len(sub)} submittable, {len(leads)} lead(s) "
                f"of {len(annotated)} finding(s)")
            # Cross-hunt duplicate suppression: don't re-draft a class already
            # drafted on the same endpoint in a prior hunt (a dup earns nothing).
            dups: list[dict] = []
            if sub:
                try:
                    from core.submission_ledger import SubmissionLedger
                    ledger = SubmissionLedger()
                    fresh, dups = ledger.partition_new(sub)
                    for f in dups:
                        f["duplicate"] = True
                    if dups:
                        self.narrator.info(
                            f"duplicate suppression: {len(dups)} finding(s) already "
                            f"drafted in a prior hunt — skipping")
                        self.audit.event("submission.duplicates", target=self.target,
                                         payload={"count": len(dups)})
                    sub = fresh
                    for f in fresh:
                        ledger.record(f)
                    ledger.save()
                except Exception as exc:  # noqa: BLE001 — dedup never blocks drafting
                    logger.warning("duplicate suppression failed: %s", exc)
            # Draft a platform-ready report for each NEW submittable finding (human
            # reviews + submits; VIPER never submits on its own).
            if sub:
                try:
                    from core.submission_draft import write_drafts
                    ddir = Path("reports/submissions") / self.audit.hunt_id
                    paths = write_drafts(sub, ddir, target=self.target)
                    if paths:
                        self.narrator.info(
                            f"drafted {len(paths)} submission report(s) -> {ddir}")
                        self.audit.event("submission.drafted", target=self.target,
                                         payload={"count": len(paths), "dir": str(ddir)})
                except Exception as exc:  # noqa: BLE001
                    logger.warning("submission draft generation failed: %s", exc)
        except Exception as exc:  # noqa: BLE001 — gate must never break the hunt
            logger.warning("validation gate failed: %s", exc)

    def _write_report(self, result: "HackResult", started_at: float) -> None:
        """Render hunt_<id>.html from in-memory findings (no LLM, blocking)."""
        from core.html_reporter import generate_report_sync, save_report
        report_findings = []
        for f in result.findings:
            report_findings.append({
                "severity": str(f.get("severity") or "info").lower(),
                "vuln_type": (f.get("vuln_type") or f.get("title")
                              or f.get("type") or "Finding"),
                "url": f.get("url") or self.target,
                "source": f.get("technique") or f.get("source") or "swarm",
                "payload": f.get("payload") or "",
                "evidence": (f.get("evidence") or f.get("marker")
                             or f.get("details") or ""),
                "confidence": f.get("confidence", 0.0),
                "validated": f.get("validated", True),
                "submittable": f.get("submittable", False),
                "validation_confidence": f.get("validation_confidence"),
                "validation_reason": f.get("validation_reason", ""),
            })
        metadata = {
            "start_time": time.strftime(
                "%Y-%m-%dT%H:%M:%S", time.localtime(started_at)),
            "elapsed_seconds": result.elapsed_s,
            "hunt_id": result.hunt_id,
            "phases": {p: {} for p in result.phase_results},
        }
        html = generate_report_sync(report_findings, self.target, metadata)
        path = save_report(html, f"hunt_{result.hunt_id}.html")
        self.audit.event(
            "report.generated", target=self.target,
            outcome="success", findings_count=len(report_findings),
            payload={"report": path.name},
        )

    # ------------------------------------------------------------------
    # Scope gate (worker HTTP fail-closed)
    # ------------------------------------------------------------------

    def _scope_allows(self, url: str) -> bool:
        """Predicate installed into the worker HTTP layer. Fails closed."""
        sr = self.scope_reasoner
        if sr is None:
            return True
        try:
            return bool(sr.decide(url).allowed)
        except Exception:  # noqa: BLE001 — any scope error denies the request
            return False

    def _install_scope_guard(self) -> None:
        # Intercepting proxy (Burp/ZAP) applies to every worker request, in any
        # scope mode — install it first so even early probes are visible in Burp.
        if self._proxy:
            try:
                from .swarm_workers.vuln._http import set_proxy
                set_proxy(self._proxy)
                self.narrator.info(f"worker traffic routed through {self._proxy}")
            except Exception as exc:  # noqa: BLE001
                logger.warning("could not install upstream proxy: %s", exc)
        # Session auth applies regardless of scope mode (lab/CTF too), so install
        # it before the scope early-return below.
        if self._auth_headers:
            try:
                from .swarm_workers.vuln._http import set_auth
                set_auth(self._auth_headers)
                self.narrator.info("session auth installed — testing as a logged-in user")
            except Exception as exc:  # noqa: BLE001
                logger.warning("could not install session auth: %s", exc)
        # Out-of-band interaction server — lets blind-capable workers fire canaries.
        if self._oob is not None:
            try:
                from .swarm_workers.vuln._http import set_oob
                set_oob(self._oob)
                self.narrator.info("out-of-band interaction listener active (blind-vuln confirmation)")
            except Exception as exc:  # noqa: BLE001
                logger.warning("could not install OOB server: %s", exc)
        if self.scope_reasoner is None:
            return  # owned box (lab/CTF) — no gate
        try:
            from .swarm_workers.vuln._http import set_scope_guard
            set_scope_guard(self._scope_allows)
        except Exception as exc:  # noqa: BLE001
            logger.warning("could not install worker scope guard: %s", exc)
        # Install the typed egress context (scope + audit) so anything routed
        # through core.tool_gateway is checked + audited under this hunt.
        try:
            from .tool_gateway import EgressContext, set_context
            set_context(EgressContext(
                scope=self._scope_allows,
                audit=lambda action, payload: self.audit.event(
                    action, target=self.target, payload=payload),
                hunt_id=self.audit.hunt_id,
            ))
        except Exception as exc:  # noqa: BLE001
            logger.warning("could not install egress context: %s", exc)

    def _clear_scope_guard(self) -> None:
        try:
            from .swarm_workers.vuln._http import (
                clear_auth, clear_oob, clear_proxy, clear_scope_guard,
            )
            clear_scope_guard()
            clear_auth()
            clear_proxy()
            clear_oob()
        except Exception:
            pass
        try:
            from .tool_gateway import clear_context
            clear_context()
        except Exception:
            pass

    # ------------------------------------------------------------------
    # The main loop
    # ------------------------------------------------------------------

    async def _run_loop(self, result: HackResult) -> None:
        """Persistence loop: phases × iterations, gated by profile.stop_conditions."""
        phases_to_run = [p for p in self.profile.phases if p != "report"]
        max_iterations = self.profile.max_iterations
        total_phases = len(phases_to_run)

        # Build the cross-hunt attack priors here (not __init__) so unit tests that
        # merely construct HackMode never open the evograph DB. Best-effort: any
        # failure leaves self._priors None and the hunt runs exactly as before. It
        # reorders technique dispatch and records outcomes — never the gate.
        if self._priors is None:
            try:
                from core.attack_priors import AttackPriors
                self._priors = AttackPriors(
                    enabled=bool(getattr(self.profile, "learn_priors", True)))
                self._priors.start(self.target, [])
            except Exception:   # noqa: BLE001 — learning must never block a hunt
                self._priors = None

        # Authenticated per-role crawl: if the operator supplied identities (session
        # roles, or the two-account BOLA config), crawl the target as each so admin/
        # user-only surface enters the attack surface and per-role reachability is
        # recorded for the BOLA/BFLA engine. Read-only, discovery only, no-op without
        # roles — never blocks the hunt.
        await self._run_authenticated_crawl()

        # On resume: skip phases that already completed in the prior run.
        # Applies only to the FIRST iteration after a resume; subsequent
        # iterations re-run the full pipeline.
        resumed_skip = set(self._state.get("resumed_completed_phases", []))
        first_iter_after_resume = self._state.get("resumed", False)
        if resumed_skip:
            self.narrator.info(
                f"resuming: skipping already-completed phases on iter 1: "
                f"{sorted(resumed_skip)}"
            )
            self.audit.event(
                "loop.resumed",
                target=self.target,
                payload={"skipped_phases": sorted(resumed_skip)},
            )

        while self._state["iteration"] < max_iterations:
            self._state["iteration"] += 1
            result.iterations = self._state["iteration"]
            findings_this_iter = 0
            iter_findings: list[dict] = []
            self.audit.event(
                "loop.iteration",
                target=self.target,
                payload={"iteration": self._state["iteration"]},
            )

            for idx, phase in enumerate(phases_to_run, start=1):
                # Skip already-completed phases on the first iteration after resume
                if first_iter_after_resume and phase in resumed_skip:
                    self.narrator.info(f"  resume: skipped {phase}")
                    continue
                # The narrator stage uses 1-indexed counters
                self.narrator.stage(
                    f"{phase.upper()} swarm",
                    current=idx, total=total_phases,
                )
                phase_res = await self._run_phase(phase)
                # Save the most recent run of each phase
                result.phase_results[phase] = phase_res
                # Surface findings to top-level + state. Recon/attack-surface
                # artifacts (endpoints, DNS, ports) go to result.surface, not the
                # vulnerability findings count / the validation gate.
                for f in phase_res.findings:
                    (result.surface if _is_surface(f) else result.findings).append(f)
                    self._state["findings"].append(f)
                    iter_findings.append(f)
                    # Fold every finding into the live belief state (Section 7.2)
                    # so planning/reporting reason over a structured world model,
                    # not just a flat findings list.
                    try:
                        self.world_model.observe_finding(f)
                    except Exception:
                        pass
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

            # Mythos-style bounded chaining: take the confirmed findings from
            # this iteration and drive them deeper — re-dispatch vuln→exploit→
            # post against the new attack surface they reveal, until the
            # surface stops growing (convergence) or the depth budget is hit.
            if self.chain_planner is not None:
                chained = await self._run_chain(result, iter_findings)
                findings_this_iter += chained
                # A flag (or other stop) can surface mid-chain — honor it.
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
            # After the first iteration, drop the resume-skip flag so
            # subsequent iterations re-run the full pipeline.
            first_iter_after_resume = False
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

    def _write_evidence_manifest(self, result: HackResult) -> None:
        """Write a signed chain-of-custody manifest for the SUBMITTABLE findings — each
        SHA-256 hashed over its full content (INCLUDING the gate's proof_requests), then
        the manifest HMAC-signed. So the exact confirming evidence the human submits is
        tamper-evident: re-hashing a finding later must match the recorded hash.
        Best-effort; a failure never blocks teardown."""
        try:
            submittable = [f for f in result.findings
                           if isinstance(f, dict) and f.get("submittable")]
            if not submittable:
                return
            from pathlib import Path as _Path

            from core.chain_of_custody import ChainOfCustody
            hunt_dir = _Path(self.audit.jsonl_path).parent
            coc = ChainOfCustody(custody_dir=hunt_dir)
            for i, f in enumerate(submittable):
                fid = f"{(f.get('vuln_type') or f.get('type') or 'finding')}#{i}"
                coc.record_finding(fid, f, agent_id="swarm", target=self.target)
            coc.generate_evidence_manifest(session_id=self.audit.hunt_id)
            proof_backed = sum(1 for f in submittable if f.get("proof_requests"))
            self.audit.event(
                "evidence.manifest", target=self.target,
                payload={"path": str(hunt_dir / f"{self.audit.hunt_id}_manifest.json"),
                         "findings": len(submittable), "proof_backed": proof_backed})
            self.narrator.info(
                f"evidence manifest: {len(submittable)} submittable finding(s) "
                f"SHA-256 hashed + HMAC-signed ({proof_backed} with a captured proof "
                "request) — tamper-evident chain of custody")
        except Exception as exc:   # noqa: BLE001 — evidence manifest is best-effort
            logger.debug("evidence manifest failed: %s", exc)

    async def _run_authenticated_crawl(self) -> None:
        """Crawl the target once per authenticated role (operator-supplied), recording
        per-role reachability for the BOLA/BFLA engine and folding the authed-only
        endpoints + params into the attack surface. Seeds roles from the two-account
        BOLA config when none were captured. Best-effort; no-op without roles."""
        from urllib.parse import urlsplit
        sc = self._session_context
        try:
            if sc is not None and not sc.roles and self._bola_config:
                b = self._bola_config
                sc.add_role(b.get("owner_name", "A"), b.get("owner_headers", {}),
                            b.get("owner_markers", []))
                sc.add_role(b.get("attacker_name", "B"), b.get("attacker_headers", {}),
                            b.get("attacker_markers", []))
            if sc is None or not sc.roles:
                return
            from core.authenticated_crawl import crawl_roles
            endpoints, params = await crawl_roles(sc, self.target)
            if params:
                from core.payload_library import add_discovered_params
                add_discovered_params(params)
            for u in endpoints:
                self._state.setdefault("findings", []).append({
                    "type": "endpoint", "vuln_type": f"endpoint:{u}", "title": u,
                    "asset": urlsplit(u).netloc, "url": u, "severity": "info",
                    "evidence": "reachable under an authenticated role (per-role crawl)",
                })
            if endpoints or params:
                self.narrator.info(
                    f"authenticated crawl: {len(endpoints)} authed endpoint(s), "
                    f"{len(params)} param(s) across {len(sc.roles)} role(s)")
                self.audit.event(
                    "recon.authenticated_crawl", target=self.target,
                    payload={"endpoints": len(endpoints), "params": len(params),
                             "roles": len(sc.roles)})
        except Exception as exc:   # noqa: BLE001 — discovery is best-effort
            logger.debug("authenticated crawl failed: %s", exc)

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

    async def _run_phase(
        self,
        phase: str,
        *,
        assets: Optional[list[str]] = None,
        findings: Optional[list[dict]] = None,
        chain_depth: int = 0,
        techniques: Optional[list[str]] = None,
    ) -> CoordinatorResult:
        """Dispatch one phase's coordinator. Returns its CoordinatorResult.

        `assets`/`findings` override the default context (used by the chain
        loop to scope a phase to just the newly-revealed surface); `chain_depth`
        is passed through for audit/telemetry. `techniques`, when given, scopes
        the phase to just those workers (targeted expansion) instead of the full
        profile set.
        """
        # Per-phase budget (Phase 5): split the total time across phases
        # so slow workers in one phase can't starve downstream phases.
        phase_count = max(1, len([
            p for p in self.profile.phases if p != "report"
        ]))
        phase_budget = self.profile.get_phase_budget(phase_count)
        # Build coordinator
        common = {
            "bus": self.bus,
            "audit_logger": self.audit,
            "max_concurrent": self.profile.max_concurrent,
            "per_worker_timeout": self.profile.per_worker_timeout,
            "overall_timeout": phase_budget,
            "dedup": self.dedup,
        }
        coord = self._coord_factory(phase, common)

        # Build payload. A targeted-expansion override scopes to just the probes
        # that escalate the seed finding; otherwise use the profile's phase set.
        phase_techniques = techniques or self.profile.workers.get(phase, [])
        # Cross-hunt priors: run techniques that have historically succeeded against
        # this target's detected stack first (more value inside the time budget).
        # No-op unless an explicit ordered list exists and priors have history; the
        # SET of techniques is never changed, so coverage is identical.
        _tech_tokens = self._priors_tech_tokens()
        if self._priors is not None and phase_techniques:
            phase_techniques = self._priors.rank(phase_techniques, _tech_tokens)
        payload = {
            "target": self.target,
            "scope_reasoner": self.scope_reasoner,
            # Empty techniques list → use all registered for the phase
            "techniques": phase_techniques or None,
            # Shared per-hunt session/reachability state (additive; workers that
            # don't read it are unaffected).
            "session_context": self._session_context,
        }
        # Two-account BOLA/IDOR specialist config — only the vuln phase's
        # bola_multi worker consumes it; harmless on other phases. The captured
        # reachability matrix lets find_bola skip provably-pointless probes.
        if self._bola_config and phase == "vuln":
            bola = dict(self._bola_config)
            reach = self._session_context.reachability_matrix()
            if reach:
                bola["reachability"] = reach
            payload["bola"] = bola

        # Chain overrides: scope this phase to explicit assets/findings.
        if assets is not None:
            payload["assets"] = assets
        if chain_depth:
            payload["chain_depth"] = chain_depth
        if findings is not None:
            payload["findings"] = findings
        # Feed prior-phase findings forward as the new phase's input
        # (recon → vuln especially: every discovered subdomain/port
        # becomes a vuln-probe target).
        elif phase != "recon":
            payload["findings"] = list(self._state.get("findings", []))

        res = await coord.handle_message(payload)
        # Record each attempted technique's outcome (success = it produced a finding)
        # so the next hunt of a similar stack starts smarter. Best-effort.
        self._record_priors(phase_techniques, res, _tech_tokens)
        return res

    def _priors_tech_tokens(self) -> list[str]:
        """Stable technology tokens from the hunt's accumulated `technology`
        findings (recon runs before vuln, so these are populated by then)."""
        if self._priors is None:
            return []
        try:
            from core.attack_priors import tech_tokens_from_findings
            return tech_tokens_from_findings(self._state.get("findings", []))
        except Exception:   # noqa: BLE001
            return []

    def _record_priors(self, attempted, res, tech_tokens) -> None:
        """Record per-technique outcomes for this phase (best-effort, never fatal)."""
        if self._priors is None:
            return
        try:
            produced = {str(f.get("technique") or "") for f in (res.findings or [])}
            produced.discard("")
            for t in (set(attempted or []) | produced):
                self._priors.record(t, tech_tokens, success=t in produced)
        except Exception:   # noqa: BLE001
            pass

    # ------------------------------------------------------------------
    # Bounded finding-driven chaining (mythos-style)
    # ------------------------------------------------------------------

    async def _run_chain(
        self, result: HackResult, seed_findings: list[dict],
    ) -> int:
        """Drive confirmed findings deeper until convergence / depth budget.

        For each round, the ChainPlanner classifies the frontier findings and
        emits follow-up tasks for the ones that opened new surface (a confirmed
        primitive, a foothold, or a high-sev hit with a URL). We then re-run the
        enabled offensive phases against just that surface, feed the results
        back, and repeat. Termination is convergence-first (no new surface),
        never a wall-clock timeout — the global time budget is the only timer,
        enforced by the `asyncio.wait_for` around `_run_loop`.
        """
        planner = self.chain_planner
        if planner is None:
            return 0
        # Chaining only makes sense when offensive phases are enabled — it
        # drives exploits deeper. Default recon+vuln runs stay linear.
        if "exploit" not in self.profile.phases:
            return 0
        chain_phases = [p for p in ("vuln", "exploit", "post")
                        if p in self.profile.phases]

        total_chained = 0
        frontier = list(seed_findings)
        depth = 0
        while depth < planner.max_depth:
            # Annotate each frontier finding with its verdict for the report.
            for f in frontier:
                if isinstance(f, dict):
                    f.setdefault("chain_verdict", planner.verdict(f))

            decision = planner.plan(frontier, depth)
            if decision.converged:
                break

            # Fail-closed scope gate on chained surface: a finding's URL must
            # never pull workers onto an off-scope host. When a scope reasoner
            # is present (bug-bounty), drop any task it doesn't allow; CTF/lab
            # run on owned boxes without one.
            tasks = decision.new_tasks
            if self.scope_reasoner is not None:
                kept = []
                for t in tasks:
                    try:
                        allowed = bool(self.scope_reasoner.decide(t.asset_url).allowed)
                    except Exception:
                        allowed = False  # any error → fail closed
                    if allowed:
                        kept.append(t)
                    else:
                        self.audit.event(
                            "chain.scope_blocked",
                            target=self.target,
                            payload={"asset": t.asset_url, "origin": t.origin_type},
                        )
                        self.narrator.warn(
                            f"  chain: dropped off-scope surface {t.asset_url}"
                        )
                tasks = kept
            if not tasks:
                break  # nothing in-scope left to chain → converge

            assets = [t.asset_url for t in tasks]
            # Targeted-expansion scope: the union of the probes each task asked
            # for. A new-host sweep (or any task with no specific techniques)
            # falls back to the full phase so we never under-probe new surface.
            chain_techs: set[str] = set()
            full_sweep = False
            for t in tasks:
                if t.new_host or not t.techniques:
                    full_sweep = True
                else:
                    chain_techs.update(t.techniques)
            vuln_scope = None if full_sweep else (sorted(chain_techs) or None)
            self.audit.event(
                "chain.expanded",
                target=self.target,
                payload={
                    "depth": depth + 1,
                    "tasks": len(tasks),
                    "assets": assets[:20],
                    "origins": sorted({t.origin_type for t in tasks}),
                    "scope": vuln_scope or "full",
                },
            )
            self.narrator.info(
                f"  chaining (depth {depth + 1}): {len(tasks)} "
                f"new surface(s) from confirmed findings"
            )

            round_findings: list[dict] = []
            vuln_findings: list[dict] = []
            for phase in chain_phases:
                if phase == "vuln":
                    pr = await self._run_phase(
                        phase, assets=assets, chain_depth=depth + 1,
                        techniques=vuln_scope)
                    vuln_findings = list(pr.findings)
                elif phase == "exploit":
                    pr = await self._run_phase(
                        phase,
                        findings=(vuln_findings or list(self._state["findings"])),
                        chain_depth=depth + 1)
                else:  # post
                    pr = await self._run_phase(
                        phase,
                        findings=(round_findings or list(self._state["findings"])),
                        chain_depth=depth + 1)
                result.phase_results[f"{phase}@chain{depth + 1}"] = pr
                for f in pr.findings:
                    (result.surface if _is_surface(f) else result.findings).append(f)
                    self._state["findings"].append(f)
                    round_findings.append(f)
                    self.narrator.emit_finding(f)

            total_chained += len(round_findings)
            if not round_findings:
                break  # convergence: nothing new produced this round
            frontier = round_findings
            depth += 1

        if total_chained:
            self.audit.event(
                "chain.completed",
                target=self.target,
                payload={"depth_reached": depth, "findings_chained": total_chained},
            )
        return total_chained

    # ------------------------------------------------------------------
    # Default coordinator wiring
    # ------------------------------------------------------------------

    def _default_coordinator(self, phase: str, common: dict) -> SwarmCoordinator:
        """Map phase → coordinator class. Wired through Phase 3; report
        phase is still a no-op (handled by --report flag in CLI)."""
        if phase == "recon":
            return ReconSwarmCoordinator(**common)
        if phase == "vuln":
            return VulnSwarmCoordinator(**common)
        if phase == "exploit":
            return ExploitSwarmCoordinator(
                approval_gate=self.approval_gate,
                auto_approve_destructive=(
                    self.profile.allow_destructive and self.approval_gate is None
                ),
                **common,
            )
        if phase == "post":
            return PostSwarmCoordinator(
                approval_gate=self.approval_gate,
                auto_approve_destructive=(
                    self.profile.allow_destructive and self.approval_gate is None
                ),
                **common,
            )
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
