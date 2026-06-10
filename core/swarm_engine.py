"""
VIPER 6.0 - Massive Parallel Swarm Engine (XBOW-inspired)

Spawns hundreds-to-thousands of short-lived, narrowly-scoped attack agents,
each with a specific objective (e.g. "test param X for SQLi", "fuzz endpoint Y").
Collects results in real-time, dedupes, and routes high-confidence findings to
the validator engine.

Design principles (from XBOW's playbook):
- Small, narrowly-scoped objectives (1 agent = 1 attack hypothesis)
- Short-lived (timeout ~30s-5min per agent)
- Independent (no shared state during execution)
- Async/await with bounded concurrency
- Cheap to spawn (no LLM call required for trivial probes)
"""

import asyncio
import hashlib
import logging
import time
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime
from enum import Enum
from typing import Any, Awaitable, Callable, Dict, List, Optional, Set

logger = logging.getLogger("viper.swarm_engine")


class AgentStatus(Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    TIMEOUT = "timeout"
    KILLED = "killed"


@dataclass
class SwarmAgent:
    """A single short-lived attack agent."""
    agent_id: str
    objective: str  # short narrow objective ("test ?id= for SQLi")
    target: str
    technique: str  # attack pattern key
    payload: Optional[Dict[str, Any]] = None
    parent_id: Optional[str] = None  # if spawned by another agent
    timeout_s: float = 60.0
    priority: int = 5  # 1=high, 10=low
    status: AgentStatus = AgentStatus.PENDING
    started_at: Optional[float] = None
    completed_at: Optional[float] = None
    findings: List[Dict[str, Any]] = field(default_factory=list)
    error: Optional[str] = None

    def duration_ms(self) -> int:
        if self.started_at and self.completed_at:
            return int((self.completed_at - self.started_at) * 1000)
        return 0

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["status"] = self.status.value
        return d


# Type alias for an agent's execution function
AgentRunner = Callable[[SwarmAgent], Awaitable[List[Dict[str, Any]]]]


@dataclass
class SwarmStats:
    spawned: int = 0
    completed: int = 0
    failed: int = 0
    timed_out: int = 0
    findings_total: int = 0
    findings_validated: int = 0
    avg_duration_ms: float = 0.0
    elapsed_s: float = 0.0


class SwarmEngine:
    """Coordinates massively-parallel short-lived agents.

    Key methods:
    - spawn(): create new agent with narrow objective
    - run_swarm(): execute all pending with bounded concurrency
    - get_findings(): aggregate, dedupe, return validated-only
    """

    def __init__(self, max_concurrent: int = 50,
                 dedup_findings: bool = True,
                 default_timeout_s: float = 60.0):
        self.max_concurrent = max_concurrent
        self.dedup_findings = dedup_findings
        self.default_timeout_s = default_timeout_s

        self.agents: Dict[str, SwarmAgent] = {}
        self.runners: Dict[str, AgentRunner] = {}
        self._finding_hashes: Set[str] = set()
        self._stats = SwarmStats()
        self._sem: Optional[asyncio.Semaphore] = None
        self._start_time: Optional[float] = None

    def register_runner(self, technique: str, runner: AgentRunner):
        """Register the function that executes a particular technique."""
        self.runners[technique] = runner

    def spawn(self, objective: str, target: str, technique: str,
              payload: Optional[Dict[str, Any]] = None,
              parent_id: Optional[str] = None,
              timeout_s: Optional[float] = None,
              priority: int = 5) -> SwarmAgent:
        """Create a new agent. Returns the agent (not yet executed)."""
        agent = SwarmAgent(
            agent_id=str(uuid.uuid4())[:12],
            objective=objective,
            target=target,
            technique=technique,
            payload=payload,
            parent_id=parent_id,
            timeout_s=timeout_s or self.default_timeout_s,
            priority=priority
        )
        self.agents[agent.agent_id] = agent
        self._stats.spawned += 1
        return agent

    def spawn_many(self, specs: List[Dict[str, Any]]) -> List[SwarmAgent]:
        """Spawn many agents at once. specs is list of kwargs dicts."""
        return [self.spawn(**s) for s in specs]

    async def _run_one(self, agent: SwarmAgent) -> SwarmAgent:
        async with self._sem:
            agent.status = AgentStatus.RUNNING
            agent.started_at = time.time()
            try:
                runner = self.runners.get(agent.technique)
                if runner is None:
                    raise RuntimeError(f"No runner registered for technique '{agent.technique}'")

                findings = await asyncio.wait_for(runner(agent), timeout=agent.timeout_s)
                agent.findings = findings or []
                agent.status = AgentStatus.COMPLETED
                self._stats.completed += 1
                self._stats.findings_total += len(agent.findings)

                # Dedup
                if self.dedup_findings:
                    deduped = []
                    for f in agent.findings:
                        h = self._finding_hash(f)
                        if h not in self._finding_hashes:
                            self._finding_hashes.add(h)
                            deduped.append(f)
                    agent.findings = deduped
            except asyncio.TimeoutError:
                agent.status = AgentStatus.TIMEOUT
                agent.error = f"timeout after {agent.timeout_s}s"
                self._stats.timed_out += 1
            except Exception as e:
                agent.status = AgentStatus.FAILED
                agent.error = str(e)
                self._stats.failed += 1
                logger.debug("swarm agent %s (%s) failed: %s",
                             agent.agent_id, agent.technique, e, exc_info=True)
            finally:
                agent.completed_at = time.time()
        return agent

    async def run_swarm(self) -> SwarmStats:
        """Execute all pending agents in parallel with bounded concurrency."""
        self._sem = asyncio.Semaphore(self.max_concurrent)
        self._start_time = time.time()

        pending = [a for a in self.agents.values() if a.status == AgentStatus.PENDING]
        # Sort by priority
        pending.sort(key=lambda a: a.priority)

        await asyncio.gather(*(self._run_one(a) for a in pending))

        self._stats.elapsed_s = time.time() - self._start_time
        durations = [a.duration_ms() for a in self.agents.values() if a.duration_ms() > 0]
        if durations:
            self._stats.avg_duration_ms = sum(durations) / len(durations)
        return self._stats

    def get_findings(self, only_validated: bool = False,
                     min_confidence: float = 0.0) -> List[Dict[str, Any]]:
        all_findings = []
        for a in self.agents.values():
            for f in a.findings:
                if only_validated and not f.get("validated", False):
                    continue
                if f.get("confidence", 0.0) < min_confidence:
                    continue
                all_findings.append({**f, "agent_id": a.agent_id, "technique": a.technique})
        return all_findings

    def _finding_hash(self, finding: Dict[str, Any]) -> str:
        key = f"{finding.get('vuln_type','')}:{finding.get('target','')}:{finding.get('parameter','')}:{finding.get('payload','')}"
        return hashlib.sha256(key.encode()).hexdigest()

    def stats(self) -> Dict[str, Any]:
        s = asdict(self._stats)
        s["dedup_findings_unique"] = len(self._finding_hashes)
        s["concurrent_max"] = self.max_concurrent
        return s

    def export_telemetry(self) -> Dict[str, Any]:
        """Full state for debugging/audit."""
        return {
            "stats": self.stats(),
            "agents": [a.to_dict() for a in self.agents.values()]
        }


# ============================================================
# BUILT-IN AGENT RUNNERS (small, focused techniques)
# ============================================================

import aiohttp
import urllib.parse


async def runner_param_sqli_probe(agent: SwarmAgent) -> List[Dict[str, Any]]:
    """Agent that probes ONE parameter on ONE URL for SQLi indicators."""
    findings = []
    target = agent.target
    param = (agent.payload or {}).get("parameter", "id")
    timeout = aiohttp.ClientTimeout(total=10)

    async with aiohttp.ClientSession(timeout=timeout) as sess:
        # Time-based probe
        for payload, expected_delay in [("' AND SLEEP(3)-- -", 3.0),
                                         ("'; pg_sleep(3)-- -", 3.0)]:
            try:
                t0 = time.time()
                sep = "&" if "?" in target else "?"
                url = f"{target}{sep}{param}={urllib.parse.quote(payload)}"
                async with sess.get(url) as r:
                    await r.text()
                    elapsed = time.time() - t0
                    if elapsed >= expected_delay * 0.85:
                        findings.append({
                            "vuln_type": "sql_injection",
                            "target": target, "parameter": param,
                            "payload": payload, "method": "time_based",
                            "evidence": f"delay={elapsed:.2f}s",
                            "confidence": 0.85, "validated": False,
                            "needs_validation": True
                        })
                        return findings  # one finding per agent
            except Exception as e:
                logger.debug("sqli probe error on %s: %s", target, e)
    return findings


async def runner_param_xss_probe(agent: SwarmAgent) -> List[Dict[str, Any]]:
    """Probes ONE parameter for reflected XSS via canary."""
    findings = []
    target = agent.target
    param = (agent.payload or {}).get("parameter", "q")
    canary = f"vipxss{int(time.time()*1000)}"
    payload = f"<script>{canary}</script>"

    async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=10)) as sess:
        try:
            sep = "&" if "?" in target else "?"
            url = f"{target}{sep}{param}={urllib.parse.quote(payload)}"
            async with sess.get(url) as r:
                body = await r.text(errors='replace')
                if payload in body and canary in body:
                    findings.append({
                        "vuln_type": "xss", "target": target, "parameter": param,
                        "payload": payload, "method": "canary_reflection",
                        "confidence": 0.85, "validated": False,
                        "needs_validation": True
                    })
        except Exception as e:
            logger.debug("xss probe error on %s: %s", target, e)
    return findings


async def runner_directory_probe(agent: SwarmAgent) -> List[Dict[str, Any]]:
    """Probes ONE directory path on target."""
    findings = []
    base = agent.target.rstrip("/")
    path = (agent.payload or {}).get("path", "/admin")
    url = base + path

    async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=8)) as sess:
        try:
            async with sess.get(url, allow_redirects=False) as r:
                if r.status in (200, 401, 403):
                    body = await r.text(errors='replace')
                    findings.append({
                        "vuln_type": "exposed_path",
                        "target": url, "status": r.status,
                        "method": "directory_probe",
                        "confidence": 0.7 if r.status == 200 else 0.4,
                        "evidence": body[:200],
                        "validated": True if r.status == 200 else False
                    })
        except Exception as e:
            logger.debug("directory probe error on %s: %s", url, e)
    return findings


async def runner_subdomain_probe(agent: SwarmAgent) -> List[Dict[str, Any]]:
    """Probes ONE subdomain candidate."""
    findings = []
    sub = agent.target

    async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=6)) as sess:
        for proto in ["https", "http"]:
            url = f"{proto}://{sub}"
            try:
                async with sess.get(url, allow_redirects=False) as r:
                    if r.status < 500:
                        findings.append({
                            "vuln_type": "subdomain_alive",
                            "target": url, "status": r.status,
                            "method": "http_probe",
                            "confidence": 1.0, "validated": True,
                            "title": (await r.text(errors='replace'))[:100]
                        })
                        return findings
            except Exception as e:
                logger.debug("subdomain probe error on %s: %s", url, e)
                continue
    return findings


# ============================================================
# DEMO USAGE
# ============================================================
if __name__ == "__main__":
    async def demo():
        engine = SwarmEngine(max_concurrent=20)
        engine.register_runner("sqli_probe", runner_param_sqli_probe)
        engine.register_runner("xss_probe", runner_param_xss_probe)
        engine.register_runner("dir_probe", runner_directory_probe)
        engine.register_runner("subdomain_probe", runner_subdomain_probe)

        # Spawn 100 narrowly-scoped agents (XBOW style)
        for path in ["/admin", "/api", "/login", "/dashboard", "/v1",
                     "/.git", "/.env", "/backup", "/uploads", "/debug"]:
            engine.spawn(
                objective=f"Probe {path}",
                target="http://example.com",
                technique="dir_probe",
                payload={"path": path}
            )
        for param in ["id", "user", "search", "q", "name"]:
            engine.spawn(
                objective=f"Test param {param} for SQLi",
                target="http://example.com/search",
                technique="sqli_probe",
                payload={"parameter": param}
            )
            engine.spawn(
                objective=f"Test param {param} for XSS",
                target="http://example.com/search",
                technique="xss_probe",
                payload={"parameter": param}
            )

        print(f"Spawned {len(engine.agents)} agents. Running...")
        stats = await engine.run_swarm()
        print(f"\nDone in {stats.elapsed_s:.2f}s")
        print(f"Stats: {engine.stats()}")
        print(f"Findings: {len(engine.get_findings())}")

    asyncio.run(demo())
