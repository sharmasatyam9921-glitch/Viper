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
from urllib.parse import urlsplit

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


# ----- Cross-coordinator finding dedup (Phase 5) ----------------------------

import hashlib as _hashlib


class FindingDedup:
    """Hash-based dedup across coordinators within one hunt.

    SwarmEngine dedups WITHIN one swarm. This dedups ACROSS swarms so the
    same SQLi finding doesn't get republished by both vuln/sqli_probe
    (low confidence) and exploit/sqli_exploit (high confidence) — the
    first wins on the bus.

    Hash key: target + vuln_type + parameter + payload.
    Empty / missing keys are always allowed (can't fingerprint).
    """

    def __init__(self) -> None:
        self._seen: set[str] = set()

    def is_new(self, finding: dict) -> bool:
        key = self._key(finding)
        if not key:
            return True
        if key in self._seen:
            return False
        self._seen.add(key)
        return True

    @staticmethod
    def _key(finding: dict) -> str:
        parts = [
            str(finding.get("target", "") or finding.get("url", "")),
            str(finding.get("vuln_type", "") or finding.get("type", "")),
            str(finding.get("parameter", "")),
            str(finding.get("payload", "")),
        ]
        if all(not p for p in parts):
            return ""
        return _hashlib.sha1("|".join(parts).encode()).hexdigest()

    def reset(self) -> None:
        self._seen.clear()


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
        dedup: Optional["FindingDedup"] = None,  # cross-coord dedup (Phase 5)
    ) -> None:
        self.bus = bus
        self.audit = audit_logger
        self.max_concurrent = max_concurrent
        self.per_worker_timeout = per_worker_timeout
        self.overall_timeout = overall_timeout
        self.rate_limit_s = rate_limit_s
        self.dedup = dedup  # None = no cross-coord dedup; HackMode injects one

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
        # Cross-coordinator dedup (Phase 5) — if a hash-equivalent finding
        # was already published by an earlier coordinator, drop it here.
        # The audit log still records the publish attempt below as
        # finding.deduped so the dashboard can show the suppression.
        if self.dedup is not None and not self.dedup.is_new(finding):
            if self.audit:
                self.audit.event(
                    "finding.deduped",
                    phase=self.PHASE,
                    target=target,
                    severity=str(finding.get("severity", "info")),
                    payload={
                        "title": finding.get("title") or finding.get("type"),
                        "technique": technique,
                    },
                )
            return
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

    # Targeting affinity (Section 4/5 fix): a blind workers×assets cross-product
    # explodes the manifest, so under a time budget high-yield combos (e.g. the
    # LFI worker against a ?page= endpoint) lose the race and never run. Route
    # each worker only to the assets where its class can actually fire.
    #   PARAM workers inject into query parameters -> param-bearing endpoints.
    #   ROOT  workers probe root-relative paths / whole responses -> one per origin.
    #   anything else (custom/test techniques, nuclei) -> all assets (legacy).
    _PARAM_TECHNIQUES = frozenset({
        "sqli_probe", "xss_probe", "lfi", "ssti_probe", "ssrf", "open_redirect",
        "command_injection", "nosql_injection", "idor", "bola", "bola_multi", "crlf",
    })
    _ROOT_TECHNIQUES = frozenset({
        "secrets", "broken_access_control", "cors", "jwt", "xxe", "csrf",
        "mass_assignment", "path_bypass", "login_sqli", "graphql",
        "request_smuggling",  # host-level desync — probe once per origin
        "clickjacking", "race_condition",  # page/host-level; race self-gates off
    })
    # Per-technique asset cap — keeps the manifest bounded on large sites so the
    # phase budget covers every technique at least once.
    _MAX_ASSETS_PER_TECH = 40

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
        root = self._coerce_url(target, target)

        manifest: list[WorkerSpec] = []
        for tech in techniques:
            try:
                runner = get_worker_runner("vuln", tech)
            except KeyError:
                logger.warning("unknown vuln technique: %s — skipping", tech)
                continue
            for asset_url in self._assets_for_technique(tech, assets, root):
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

    def _assets_for_technique(
        self, tech: str, assets: list[str], root: str,
    ) -> list[str]:
        """Pick the assets a given technique should actually probe.

        PARAM techniques -> param-bearing endpoints (+ root for default-param
        probing); ROOT techniques -> one asset per origin; anything else ->
        all assets (preserves legacy behavior for custom/test techniques)."""
        if tech in self._PARAM_TECHNIQUES:
            param_assets = [a for a in assets if urlsplit(a).query]
            chosen = param_assets or list(assets)
            if root not in chosen:
                chosen = [root, *chosen]
            return chosen[: self._MAX_ASSETS_PER_TECH]
        if tech in self._ROOT_TECHNIQUES:
            origins: list[str] = []
            seen: set[str] = set()
            for a in assets:
                p = urlsplit(a)
                origin = f"{p.scheme}://{p.netloc}"
                if origin not in seen:
                    seen.add(origin)
                    origins.append(origin)
            return (origins or [root])[: self._MAX_ASSETS_PER_TECH]
        return list(assets)[: self._MAX_ASSETS_PER_TECH]

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
        # Dedupe by endpoint signature (origin + path + the SET of param names)
        # so /fi/?page=a, /fi/?page=b, /fi/?page=c collapse to one probe target.
        # Without this, near-identical endpoints flood the manifest and starve
        # the phase budget. Keep the first URL seen for each signature.
        by_sig: dict[tuple, str] = {}
        for f in findings:
            asset_url = self._asset_to_url(f)
            if not asset_url:
                continue
            by_sig.setdefault(self._asset_signature(asset_url), asset_url)
        if by_sig:
            return sorted(by_sig.values())

        # Last fallback: probe the primary target itself
        return [self._coerce_url(target, target)]

    @staticmethod
    def _asset_signature(url: str) -> tuple:
        """(scheme, host, path-no-trailing-slash, sorted param-name tuple)."""
        p = urlsplit(url)
        param_names = tuple(sorted(
            kv.split("=", 1)[0] for kv in p.query.split("&") if kv
        ))
        return (p.scheme, p.netloc, p.path.rstrip("/"), param_names)

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


# ----- Exploit coordinator (gated) ------------------------------------------


class ExploitSwarmCoordinator(SwarmCoordinator):
    """Exploit phase: drive past vuln findings into actual access.

    Critical difference from VulnSwarmCoordinator: every worker dispatch
    is gated by `approval_gate`. The gate is checked at dispatch time
    so a denial just skips the worker without crashing the swarm.

    Inputs (via context):
      - `findings`: list of VULN findings (each has type/vuln_type
        identifying the exploit technique to dispatch).
      - `approval_gate`: a `core.approval_gate.ApprovalGate` instance,
        or None → all workers skipped (safe default).
      - `auto_approve_destructive`: if True and gate is None, exploits
        run without approval (used by lab profile).

    Worker selection: maps vuln_type prefix → exploit technique:
      sqli       → sqli_exploit
      xss        → xss_exploit
      idor       → idor_exploit
      bola       → idor_exploit (same exploit shape)
      ssti       → ssti_exploit
      cmdi       → cmdi_exploit
      ssrf       → cmdi_exploit (similar verification flow)
      auth_bypass / login → auth_bypass
    """

    PHASE = "exploit"
    OUTPUT_TOPIC = "post"

    # Vuln-finding → exploit-worker technique
    _EXPLOIT_MAP = {
        "sqli": "sqli_exploit",
        "sqli_blind": "sqli_exploit",
        "xss": "xss_exploit",
        "xss_reflected": "xss_exploit",
        "xss_tag": "xss_exploit",
        "xss_text": "xss_exploit",
        "idor": "idor_exploit",
        "idor_candidate": "idor_exploit",
        "bola": "idor_exploit",
        "bola_candidate": "idor_exploit",
        "ssti": "ssti_exploit",
        "ssti_candidate": "ssti_exploit",
        "cmdi": "cmdi_exploit",
        "rce": "cmdi_exploit",
        "auth_bypass": "auth_bypass",
        "login": "auth_bypass",
    }

    def __init__(
        self,
        *,
        approval_gate=None,
        auto_approve_destructive: bool = False,
        **kw: Any,
    ) -> None:
        super().__init__(**kw)
        self.approval_gate = approval_gate
        self.auto_approve_destructive = auto_approve_destructive

    def build_manifest(self, target: str, context: dict) -> list[WorkerSpec]:
        from .swarm_workers import get_worker_runner  # lazy

        findings = context.get("findings") or []
        if not findings:
            return []

        manifest: list[WorkerSpec] = []
        for finding in findings:
            # Skip recon-only findings (subdomain, open_port, dns_*, etc.)
            tech = self._exploit_for_finding(finding)
            if not tech:
                continue
            try:
                base_runner = get_worker_runner("exploit", tech)
            except KeyError:
                logger.debug("no exploit worker for technique %s", tech)
                continue
            # Each finding gets its own gated runner
            target_url = (
                finding.get("url")
                or context.get("target")
                or target
            )
            manifest.append(WorkerSpec(
                technique=f"{tech}@{target_url}",
                runner=self._gated_runner(base_runner, finding, target_url),
                timeout_s=context.get(
                    "per_worker_timeout", self.per_worker_timeout
                ),
                priority=4,  # higher priority than vuln (lower-numeric=higher)
                payload={
                    "finding": finding,
                    "target_url": target_url,
                    "scope_reasoner": context.get("scope_reasoner"),
                },
            ))
        return manifest

    def _exploit_for_finding(self, finding: dict) -> Optional[str]:
        """Pick the exploit worker for a vuln finding, or None if none matches."""
        # Try `type`, then prefix of `vuln_type`
        t = (finding.get("type") or "").lower()
        if t in self._EXPLOIT_MAP:
            return self._EXPLOIT_MAP[t]
        vt = (finding.get("vuln_type") or "").lower()
        for prefix, tech in self._EXPLOIT_MAP.items():
            if vt.startswith(prefix):
                return tech
        return None

    def _gated_runner(self, base_runner: AgentRunner, finding: dict,
                       target_url: str) -> AgentRunner:
        """Wrap a runner with the approval gate."""

        async def gated(agent: SwarmAgent) -> list[dict]:
            # Re-bind agent.target so the worker probes the vuln's URL
            agent.target = target_url
            if not await self._approve(agent.technique, finding, target_url):
                # Approval denied — emit a "skipped" finding for audit
                return [{
                    "type": "exploit_skipped",
                    "vuln_type": f"exploit_skipped:{agent.technique}",
                    "title": f"Exploit gated: {agent.technique} on {target_url}",
                    "severity": "info",
                    "url": target_url,
                    "evidence": "Approval gate denied or unavailable.",
                }]
            return await base_runner(agent)

        return gated

    async def _approve(self, technique: str, finding: dict,
                        target_url: str) -> bool:
        """Approval gate check. Returns True if the runner may proceed."""
        gate = self.approval_gate
        if gate is None:
            return self.auto_approve_destructive
        try:
            approved, _modified = await gate.confirm_tool(
                tool_name=technique,
                args={"target": target_url, "finding": finding},
                rationale=(
                    f"Confirm finding via {technique} against {target_url}. "
                    f"Source finding: {finding.get('title', finding.get('type'))}"
                ),
            )
            return bool(approved)
        except Exception as e:  # noqa: BLE001
            logger.warning("approval_gate raised: %s — failing closed", e)
            return False


# ----- Post-exploit coordinator (gated) -------------------------------------


class PostSwarmCoordinator(SwarmCoordinator):
    """Post-exploit phase: privesc enum + lateral + flag hunting.

    Inputs (via context):
      - `findings`: list of exploit-phase findings indicating foothold.
        Each foothold finding should set `foothold: True` and may
        include `os`, `shell`, `host` keys.
      - `approval_gate`: same semantics as ExploitSwarmCoordinator.

    All post workers are gated. The CTF `flag_hunter` worker is unique
    in that it runs even WITHOUT explicit exploit findings (it searches
    the original target's HTML for embedded flags — useful for web
    CTF challenges where the flag is visible without a shell).
    """

    PHASE = "post"
    OUTPUT_TOPIC = "report"

    # Default workers always considered. flag_hunter is the only one
    # safe to run on plain HTTP responses without a foothold; the rest
    # need shell-like access (gated upstream).
    _DEFAULT_TECHNIQUES = ["flag_hunter"]
    _FOOTHOLD_TECHNIQUES = ["linpeas", "windows_privesc", "ad_enum",
                             "gtfobins", "flag_hunter"]

    def __init__(
        self,
        *,
        approval_gate=None,
        auto_approve_destructive: bool = False,
        **kw: Any,
    ) -> None:
        super().__init__(**kw)
        self.approval_gate = approval_gate
        self.auto_approve_destructive = auto_approve_destructive

    def build_manifest(self, target: str, context: dict) -> list[WorkerSpec]:
        from .swarm_workers import get_worker_runner  # lazy

        findings = context.get("findings") or []
        # A foothold is an explicit `foothold:True` flag OR any confirmed
        # exploit primitive (sqli_exploited, ssti_exploited, …). Previously
        # only cmdi/auth_bypass set the flag, so a confirmed SQLi/XSS/IDOR
        # never engaged the post-exploit workers — chains dead-ended here.
        has_foothold = any(
            f.get("foothold")
            or str(f.get("type", "")).lower().endswith(("_exploited", "_confirmed"))
            for f in findings
        )
        techniques = (
            context.get("techniques")
            or (self._FOOTHOLD_TECHNIQUES if has_foothold else self._DEFAULT_TECHNIQUES)
        )

        manifest: list[WorkerSpec] = []
        for tech in techniques:
            try:
                base_runner = get_worker_runner("post", tech)
            except KeyError:
                logger.debug("no post worker for technique %s", tech)
                continue
            # flag_hunter is non-destructive — only it bypasses gate
            requires_gate = tech != "flag_hunter"
            runner = (
                self._gated_runner(base_runner, tech)
                if requires_gate else base_runner
            )
            manifest.append(WorkerSpec(
                technique=tech,
                runner=runner,
                timeout_s=context.get(
                    "per_worker_timeout", self.per_worker_timeout
                ),
                priority=3,
                payload={
                    "findings": findings,
                    "scope_reasoner": context.get("scope_reasoner"),
                },
            ))
        return manifest

    def _gated_runner(self, base_runner: AgentRunner, technique: str) -> AgentRunner:
        async def gated(agent: SwarmAgent) -> list[dict]:
            if not await self._approve(technique, agent.target):
                return [{
                    "type": "post_skipped",
                    "vuln_type": f"post_skipped:{technique}",
                    "title": f"Post-exploit gated: {technique}",
                    "severity": "info",
                    "evidence": "Approval gate denied or unavailable.",
                }]
            return await base_runner(agent)
        return gated

    async def _approve(self, technique: str, target: str) -> bool:
        gate = self.approval_gate
        if gate is None:
            return self.auto_approve_destructive
        try:
            approved, _ = await gate.confirm_tool(
                tool_name=technique,
                args={"target": target},
                rationale=f"Post-exploit: {technique} on {target}",
            )
            return bool(approved)
        except Exception:
            return False
