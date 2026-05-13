"""Swarm coordinator — fans out N parallel workers per phase.

A `SwarmCoordinator` subscribes to one phase topic on `core.agent_bus.AgentBus`,
and when it receives a `{target, ...}` request:

  1. Builds a **worker manifest** — list of `(technique, runner_fn)` pairs
     from `core.swarm_workers` for that phase.
  2. Dispatches them in parallel via the existing
     `core.swarm_engine.SwarmEngine.run_swarm()` (bounded concurrency,
     per-worker timeout, in-swarm finding dedup).
  3. **Each finding is published immediately** to the next phase's topic
     via `AgentBus.publish()` — downstream coordinators can start work
     before the upstream phase finishes (the streaming property is what
     makes the "while one runs nmap, another runs subfinder" UX possible).
  4. Emits `swarm.*` events (via the audit logger and the bus's `swarm`
     topic) so the dashboard's `useSwarm` hook can render the live
     worker grid + findings stream.
  5. When all workers drain (or `time_budget` expires), publishes a
     `phase.completed` event so `HackMode` can advance.

Each `SwarmCoordinator` runs as a normal `AgentRegistry`-registered
agent. Workers register with `transient=True` so the registry doesn't
try to auto-restart them.
"""

from __future__ import annotations

import asyncio
import logging
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable, Optional

from .agent_bus import AgentBus, Priority
from .swarm_engine import AgentRunner, SwarmAgent, SwarmEngine, SwarmStats

logger = logging.getLogger("viper.swarm_coordinator")


# ----- Manifest schema ------------------------------------------------------


@dataclass
class WorkerSpec:
    """One worker that the coordinator will dispatch."""
    technique: str                 # short name (e.g. "subdomain", "nuclei")
    runner: AgentRunner            # async (SwarmAgent) -> List[finding dict]
    timeout_s: float = 60.0
    priority: int = 5              # 1=high, 10=low; matches SwarmEngine
    payload: Optional[dict] = None  # extra config passed to the runner

    def __post_init__(self) -> None:
        if not self.technique:
            raise ValueError("WorkerSpec.technique cannot be empty")


@dataclass
class CoordinatorResult:
    """What the coordinator returns when its run is done."""
    phase: str
    target: str
    workers_dispatched: int = 0
    workers_completed: int = 0
    workers_failed: int = 0
    findings: list[dict] = field(default_factory=list)  # deduped
    duration_s: float = 0.0
    timed_out: bool = False

    @property
    def findings_count(self) -> int:
        return len(self.findings)


# ----- Base coordinator -----------------------------------------------------


class SwarmCoordinator:
    """Base class. Subclass and override `build_manifest()` per phase."""

    # Phase this coordinator owns ("recon", "vuln", "exploit", "post").
    PHASE: str = "abstract"
    # Topic on the bus to publish each finding to (usually the next phase).
    OUTPUT_TOPIC: str = ""
    # Topic to publish phase-lifecycle events to (always "phase").
    PHASE_TOPIC: str = "phase"
    # Topic to publish swarm-visualization events to (consumed by dashboard).
    SWARM_TOPIC: str = "swarm"

    def __init__(
        self,
        *,
        bus: AgentBus,
        audit_logger=None,            # core.audit_logger.AuditLogger | None
        max_concurrent: int = 12,
        per_worker_timeout: float = 60.0,
        overall_timeout: float = 300.0,
        rate_limit_s: float = 0.0,    # delay between worker spawns
    ) -> None:
        self.bus = bus
        self.audit = audit_logger
        self.max_concurrent = max_concurrent
        self.per_worker_timeout = per_worker_timeout
        self.overall_timeout = overall_timeout
        self.rate_limit_s = rate_limit_s

        self.coordinator_id = f"{self.PHASE}_coord_{uuid.uuid4().hex[:8]}"
        # Each coordinator owns one engine per run (engines are stateful per run).
        # See `_make_engine` below.

    # ------------------------------------------------------------------
    # Subclass hook
    # ------------------------------------------------------------------

    def build_manifest(self, target: str, context: dict) -> list[WorkerSpec]:
        """Return the workers to dispatch for `target`.

        Override in subclasses. Context is the bus-message payload, so the
        caller can pass discovered assets, scope, profile flags, etc.
        """
        raise NotImplementedError

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def handle_message(self, payload: dict) -> CoordinatorResult:
        """Process one inbound phase request. Public entrypoint.

        Expected payload shape:
            {"target": "<url|ip>", "swarm_id": "<run_id>", ...other context}

        Returns the CoordinatorResult after all workers complete.
        Also publishes findings + lifecycle events to the bus along the way.
        """
        target = payload.get("target", "")
        if not target:
            raise ValueError("payload missing 'target'")

        manifest = self.build_manifest(target, payload)
        if not manifest:
            await self._publish_phase_event(
                "phase.skipped", target,
                payload={"reason": "no workers in manifest"},
            )
            return CoordinatorResult(phase=self.PHASE, target=target)

        return await self._run_manifest(target, manifest, payload)

    async def _run_manifest(
        self, target: str, manifest: list[WorkerSpec], context: dict,
    ) -> CoordinatorResult:
        t0 = time.time()
        await self._publish_phase_event(
            "phase.started", target,
            payload={
                "workers_planned": len(manifest),
                "techniques": [w.technique for w in manifest],
                "max_concurrent": self.max_concurrent,
            },
        )

        engine = self._make_engine()
        engine_findings: list[dict] = []

        # Wrap each runner so we can:
        #   - emit `swarm.worker_started` / `_completed` events
        #   - stream findings to the bus as they arrive
        #   - audit-log every dispatch + outcome
        agents: list[SwarmAgent] = []
        for spec in manifest:
            wrapped = self._wrap_runner(spec, target, engine_findings, context)
            engine.register_runner(spec.technique, wrapped)
            agent = engine.spawn(
                objective=f"{spec.technique} on {target}",
                target=target,
                technique=spec.technique,
                payload=spec.payload,
                priority=spec.priority,
                timeout_s=spec.timeout_s,
            )
            agents.append(agent)

        # Bounded overall timeout — workers individually time out too.
        try:
            stats: SwarmStats = await asyncio.wait_for(
                engine.run_swarm(), timeout=self.overall_timeout,
            )
            timed_out = False
        except asyncio.TimeoutError:
            stats = SwarmStats(spawned=len(agents))
            timed_out = True

        elapsed = time.time() - t0
        result = CoordinatorResult(
            phase=self.PHASE,
            target=target,
            workers_dispatched=len(agents),
            workers_completed=stats.completed,
            workers_failed=stats.failed + stats.timed_out,
            findings=engine.get_findings(),
            duration_s=elapsed,
            timed_out=timed_out,
        )

        await self._publish_phase_event(
            "phase.completed", target,
            payload={
                "workers_completed": result.workers_completed,
                "workers_failed": result.workers_failed,
                "findings_count": result.findings_count,
                "duration_s": round(elapsed, 2),
                "timed_out": timed_out,
            },
        )
        return result

    # ------------------------------------------------------------------
    # Worker wrapping — adds streaming + audit + event emission
    # ------------------------------------------------------------------

    @staticmethod
    def _ensure_dedup_key(finding: dict) -> dict:
        """SwarmEngine.dedup hashes on vuln_type:target:parameter:payload.
        Recon findings rarely populate vuln_type, so without this every
        recon finding from one worker collapses to a single deduped entry.
        Inject a stable vuln_type derived from `type:title` when missing.
        """
        if not finding.get("vuln_type"):
            t = finding.get("type", "finding")
            ident = (
                finding.get("title")
                or finding.get("url")
                or finding.get("asset")
                or finding.get("port")
                or ""
            )
            finding["vuln_type"] = f"{t}:{ident}"
        return finding

    def _wrap_runner(
        self,
        spec: WorkerSpec,
        target: str,
        engine_findings: list[dict],
        context: dict,
    ) -> AgentRunner:
        """Return a runner that wraps `spec.runner` with audit + bus events."""

        async def wrapped(agent: SwarmAgent) -> list[dict]:
            t_start = time.time()
            await self._publish_swarm_event(
                "swarm.worker_started",
                payload={
                    "worker_id": agent.agent_id,
                    "phase": self.PHASE,
                    "technique": spec.technique,
                    "target": target,
                    "coordinator_id": self.coordinator_id,
                },
            )
            if self.audit:
                self.audit.event(
                    "worker.dispatched",
                    phase=self.PHASE,
                    actor=agent.agent_id,
                    target=target,
                    payload={"technique": spec.technique},
                )

            # Optional rate-limit between launches
            if self.rate_limit_s > 0:
                await asyncio.sleep(self.rate_limit_s)

            findings: list[dict] = []
            outcome = "success"
            err: Optional[str] = None
            reraise: Optional[BaseException] = None
            try:
                findings = await spec.runner(agent) or []
                # Ensure each finding has a stable dedup key — see docstring above.
                findings = [self._ensure_dedup_key(f) for f in findings]
            except asyncio.CancelledError:
                raise
            except Exception as e:                          # noqa: BLE001
                logger.warning("worker %s (%s) raised: %s",
                               agent.agent_id, spec.technique, e)
                outcome = "failure"
                err = repr(e)
                reraise = e  # propagate to SwarmEngine for accurate stats

            duration_ms = int((time.time() - t_start) * 1000)

            # Stream each finding to the next-phase topic immediately.
            for f in findings:
                await self._publish_finding(f, target=target, technique=spec.technique)

            # Audit + swarm event for completion
            if self.audit:
                self.audit.event(
                    "worker.completed" if outcome == "success" else "worker.failed",
                    phase=self.PHASE,
                    actor=agent.agent_id,
                    target=target,
                    duration_ms=duration_ms,
                    outcome=outcome,
                    findings_count=len(findings),
                    payload={"technique": spec.technique, "error": err} if err else {"technique": spec.technique},
                )
            await self._publish_swarm_event(
                "swarm.worker_completed",
                payload={
                    "worker_id": agent.agent_id,
                    "phase": self.PHASE,
                    "technique": spec.technique,
                    "duration_ms": duration_ms,
                    "findings_count": len(findings),
                    "outcome": outcome,
                    "error": err,
                },
            )
            engine_findings.extend(findings)
            # Re-raise AFTER we've published every finding + event so the
            # SwarmEngine's failure stats reflect reality. The engine
            # catches this and marks the agent FAILED.
            if reraise is not None:
                raise reraise
            return findings

        return wrapped

    # ------------------------------------------------------------------
    # Event helpers
    # ------------------------------------------------------------------

    async def _publish_phase_event(
        self, action: str, target: str, *, payload: Optional[dict] = None,
    ) -> None:
        payload = payload or {}
        full = {
            "phase": self.PHASE,
            "target": target,
            "coordinator_id": self.coordinator_id,
            **payload,
        }
        await self.bus.publish(
            self.PHASE_TOPIC, full, priority=Priority.HIGH,
            agent_id=self.coordinator_id,
        )
        # Also fan out to the swarm-events stream for the dashboard.
        await self.bus.publish(
            self.SWARM_TOPIC, {"event": action, **full},
            priority=Priority.MEDIUM, agent_id=self.coordinator_id,
        )
        if self.audit:
            self.audit.event(action, phase=self.PHASE, target=target, payload=payload)

    async def _publish_swarm_event(
        self, event: str, *, payload: Optional[dict] = None,
    ) -> None:
        payload = payload or {}
        await self.bus.publish(
            self.SWARM_TOPIC, {"event": event, **payload},
            priority=Priority.MEDIUM, agent_id=self.coordinator_id,
        )

    async def _publish_finding(self, finding: dict, *, target: str, technique: str) -> None:
        """Stream one finding onto the OUTPUT_TOPIC + dashboard swarm channel."""
        # Enrich for downstream coordinators
        f = {
            "target": target,
            "source_technique": technique,
            "source_phase": self.PHASE,
            "discovered_at": time.time(),
            **finding,
        }
        if self.OUTPUT_TOPIC:
            await self.bus.publish(
                self.OUTPUT_TOPIC, f,
                priority=Priority.MEDIUM,
                agent_id=self.coordinator_id,
            )
        await self.bus.publish(
            self.SWARM_TOPIC,
            {"event": "swarm.worker_finding", "phase": self.PHASE,
             "technique": technique, "finding": f},
            priority=Priority.MEDIUM,
            agent_id=self.coordinator_id,
        )
        if self.audit:
            self.audit.event(
                "finding.published",
                phase=self.PHASE,
                target=target,
                severity=str(f.get("severity", "info")),
                payload={
                    "title": f.get("title") or f.get("type") or technique,
                    "technique": technique,
                    "url": f.get("url"),
                },
            )

    # ------------------------------------------------------------------
    # Engine factory (subclass-overridable for custom dedup / concurrency)
    # ------------------------------------------------------------------

    def _make_engine(self) -> SwarmEngine:
        return SwarmEngine(
            max_concurrent=self.max_concurrent,
            default_timeout_s=self.per_worker_timeout,
        )

    def _available_techniques(self) -> list[str]:
        """Default: every registered worker for this coordinator's PHASE.
        Subclasses can override."""
        try:
            from .swarm_workers import list_workers
            return list_workers(self.PHASE)
        except Exception:
            return []


# ----- Concrete recon coordinator ------------------------------------------


class ReconSwarmCoordinator(SwarmCoordinator):
    """Recon phase: fan out 8 in-parallel discovery workers per target.

    The manifest is built from `core.swarm_workers.recon.RECON_WORKERS`.
    Override `default_techniques` if you want a subset.
    """

    PHASE = "recon"
    OUTPUT_TOPIC = "vuln"

    def __init__(self, *, default_techniques: Optional[list[str]] = None, **kw: Any) -> None:
        super().__init__(**kw)
        self.default_techniques = default_techniques

    def build_manifest(self, target: str, context: dict) -> list[WorkerSpec]:
        # Lazy import — avoids a hard dependency on the worker package at
        # coordinator-import time (used by tests that pass their own manifest
        # via ``context["techniques"]``).
        techniques = (
            context.get("techniques")
            or self.default_techniques
            or self._available_techniques()
        )

        from .swarm_workers import get_worker_runner  # lazy

        manifest: list[WorkerSpec] = []
        for tech in techniques:
            try:
                runner = get_worker_runner("recon", tech)
            except KeyError:
                logger.warning("unknown recon technique: %s — skipping", tech)
                continue
            manifest.append(WorkerSpec(
                technique=tech,
                runner=runner,
                timeout_s=context.get("per_worker_timeout", self.per_worker_timeout),
                priority=5,
                payload={
                    "scope_reasoner": context.get("scope_reasoner"),
                    "rate_limiter": context.get("rate_limiter"),
                },
            ))
        return manifest


# ----- Concrete vuln coordinator -------------------------------------------


class VulnSwarmCoordinator(SwarmCoordinator):
    """Vuln-discovery phase: fan out N vuln workers across each discovered
    asset.

    Recon publishes asset-shaped findings ({type: subdomain/open_port/...,
    asset: <hostname>, url: <url>}) to the "vuln" topic incrementally.
    The orchestrator (HackMode) does NOT have to wait for recon to finish
    — it can call this coordinator with the assets discovered so far, or
    feed each finding as it arrives.

    Manifest expansion: workers x assets. With 9 vuln workers and 25
    assets, that's 225 worker slots (bounded by `max_concurrent`).
    """

    PHASE = "vuln"
    OUTPUT_TOPIC = "exploit"

    # Asset keys we consider "vuln-actionable". Open-port findings get
    # converted to URLs where the port suggests HTTP.
    _HTTP_PORTS = {80, 81, 8000, 8001, 8008, 8080, 8081, 8088, 9000, 9001,
                   9090, 9100, 3000, 5000, 5001, 8443, 443, 9443, 8888,
                   9999, 10000}

    def __init__(self, *, default_techniques: Optional[list[str]] = None, **kw: Any) -> None:
        super().__init__(**kw)
        self.default_techniques = default_techniques

    def build_manifest(self, target: str, context: dict) -> list[WorkerSpec]:
        from .swarm_workers import get_worker_runner  # lazy

        techniques = (
            context.get("techniques")
            or self.default_techniques
            or self._available_techniques()
        )
        assets = self._collect_assets(target, context)
        if not assets:
            return []

        manifest: list[WorkerSpec] = []
        for asset_url in assets:
            for tech in techniques:
                try:
                    runner = get_worker_runner("vuln", tech)
                except KeyError:
                    logger.warning("unknown vuln technique: %s — skipping", tech)
                    continue
                manifest.append(WorkerSpec(
                    technique=f"{tech}@{asset_url}",
                    runner=self._make_asset_runner(runner, asset_url),
                    timeout_s=context.get(
                        "per_worker_timeout", self.per_worker_timeout
                    ),
                    priority=5,
                    payload={
                        "scope_reasoner": context.get("scope_reasoner"),
                        "rate_limiter": context.get("rate_limiter"),
                        "asset_url": asset_url,
                    },
                ))
        return manifest

    def _make_asset_runner(self, base_runner: AgentRunner, asset_url: str) -> AgentRunner:
        """Wrap a per-target vuln runner so it operates on the asset_url
        instead of the coordinator's primary target."""

        async def runner(agent: SwarmAgent) -> list[dict]:
            # Override the agent's target for this run so workers probe
            # the discovered asset, not the parent target.
            original = agent.target
            agent.target = asset_url
            try:
                return await base_runner(agent)
            finally:
                agent.target = original

        return runner

    def _collect_assets(self, target: str, context: dict) -> list[str]:
        """Build the list of asset URLs to probe.

        Sources (in priority order):
          1. context["assets"] — explicit list (used by tests + HackMode
             when re-running over discovered assets).
          2. context["findings"] — recon findings to enrich into URLs.
          3. fallback to [target] so this coordinator works standalone.
        """
        explicit = context.get("assets")
        if explicit:
            return [self._coerce_url(a, target) for a in explicit]

        findings = context.get("findings") or []
        urls: set[str] = set()
        for f in findings:
            asset_url = self._asset_to_url(f)
            if asset_url:
                urls.add(asset_url)
        if urls:
            return sorted(urls)

        # Last fallback: probe the primary target itself
        return [self._coerce_url(target, target)]

    @staticmethod
    def _coerce_url(asset: str, default: str) -> str:
        """If `asset` already looks like a URL, return as-is. If it's a
        bare host, default to https://<host>."""
        s = (asset or "").strip()
        if not s:
            return default
        if "://" in s:
            return s
        # Bare host — prefer https
        return f"https://{s}"

    def _asset_to_url(self, finding: dict) -> Optional[str]:
        """Best-effort: turn a recon finding into a probable URL."""
        # Explicit URL wins
        url = finding.get("url")
        if url:
            return url
        # subdomain / dns
        t = (finding.get("type") or "").lower()
        host = finding.get("asset") or finding.get("title")
        if not host:
            return None
        if t in ("subdomain", "dns_a", "dns_aaaa", "dns_cname"):
            return f"https://{host}"
        if t == "open_port":
            port = finding.get("port") or 0
            try:
                port = int(port)
            except (TypeError, ValueError):
                return None
            if port in self._HTTP_PORTS:
                scheme = "https" if port in (443, 8443, 9443) else "http"
                return f"{scheme}://{host}:{port}"
            # Non-HTTP port — skip for vuln workers (could still go to
            # nuclei but most vuln workers are HTTP-only)
            return None
        return None
