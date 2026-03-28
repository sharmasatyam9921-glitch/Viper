#!/usr/bin/env python3
"""
VIPER Agent Registry — Tracks active agents, health checks, load balancing.

Provides registration, health monitoring, auto-restart, and least-busy routing.
"""

import asyncio
import logging
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Coroutine, Dict, List, Optional

logger = logging.getLogger("viper.agent_registry")


class AgentStatus(Enum):
    IDLE = "idle"
    BUSY = "busy"
    CRASHED = "crashed"
    STOPPING = "stopping"


@dataclass
class AgentInfo:
    """Metadata about a registered agent."""
    agent_id: str
    name: str
    capabilities: List[str]  # topics this agent handles
    status: AgentStatus = AgentStatus.IDLE
    task_count: int = 0
    last_heartbeat: float = field(default_factory=time.monotonic)
    error_count: int = 0
    factory: Optional[Callable[[], Coroutine]] = field(default=None, repr=False)

    def to_dict(self) -> dict:
        return {
            "agent_id": self.agent_id,
            "name": self.name,
            "capabilities": self.capabilities,
            "status": self.status.value,
            "task_count": self.task_count,
            "error_count": self.error_count,
            "last_heartbeat": self.last_heartbeat,
        }


class AgentRegistry:
    """Registry of all active VIPER agents.

    Features:
    - register / deregister agents
    - heartbeat-based health check (every ``check_interval`` seconds)
    - auto-restart crashed agents via their factory callable
    - least-busy routing: ``get_agent(topic)`` returns the agent with the
      lowest ``task_count`` among those that handle *topic*

    Usage::

        registry = AgentRegistry()
        registry.register("recon-1", "recon_agent", capabilities=["recon"], factory=make_recon)
        agent = registry.get_agent("recon")
        ...
        await registry.start()   # launches health-check loop
        await registry.stop()
    """

    def __init__(self, check_interval: float = 30.0, heartbeat_timeout: float = 90.0):
        self._agents: Dict[str, AgentInfo] = {}
        self._check_interval = check_interval
        self._heartbeat_timeout = heartbeat_timeout
        self._health_task: Optional[asyncio.Task] = None
        self._running = False

    # ── Registration ──

    def register(
        self,
        agent_id: str,
        name: str,
        capabilities: List[str],
        factory: Optional[Callable[[], Coroutine]] = None,
    ) -> AgentInfo:
        """Register a new agent. *factory* is called to restart it if it crashes."""
        info = AgentInfo(
            agent_id=agent_id,
            name=name,
            capabilities=capabilities,
            factory=factory,
        )
        self._agents[agent_id] = info
        logger.info("Registered agent '%s' (%s) for topics %s", name, agent_id, capabilities)
        return info

    def deregister(self, agent_id: str) -> None:
        """Remove an agent from the registry."""
        removed = self._agents.pop(agent_id, None)
        if removed:
            logger.info("Deregistered agent '%s' (%s)", removed.name, agent_id)

    # ── Queries ──

    def get_agent(self, topic: str) -> Optional[AgentInfo]:
        """Return the least-busy agent that handles *topic*, or None."""
        candidates = [
            a for a in self._agents.values()
            if topic in a.capabilities and a.status != AgentStatus.CRASHED
        ]
        if not candidates:
            return None
        return min(candidates, key=lambda a: a.task_count)

    def list_agents(self, topic: Optional[str] = None) -> List[AgentInfo]:
        """List all agents, optionally filtered by *topic*."""
        agents = list(self._agents.values())
        if topic:
            agents = [a for a in agents if topic in a.capabilities]
        return agents

    # ── Heartbeat ──

    def heartbeat(self, agent_id: str) -> None:
        """Update heartbeat timestamp for an agent."""
        info = self._agents.get(agent_id)
        if info:
            info.last_heartbeat = time.monotonic()
            if info.status == AgentStatus.CRASHED:
                info.status = AgentStatus.IDLE
                logger.info("Agent '%s' recovered", info.name)

    def mark_busy(self, agent_id: str) -> None:
        info = self._agents.get(agent_id)
        if info:
            info.status = AgentStatus.BUSY
            info.task_count += 1

    def mark_idle(self, agent_id: str) -> None:
        info = self._agents.get(agent_id)
        if info:
            info.status = AgentStatus.IDLE

    # ── Health check loop ──

    async def start(self) -> None:
        """Start the periodic health-check loop."""
        if self._running:
            return
        self._running = True
        self._health_task = asyncio.create_task(self._health_loop(), name="registry-health")
        logger.info("AgentRegistry health-check started (interval=%ss)", self._check_interval)

    async def stop(self) -> None:
        """Stop the health-check loop."""
        self._running = False
        if self._health_task:
            self._health_task.cancel()
            try:
                await self._health_task
            except asyncio.CancelledError:
                pass
        logger.info("AgentRegistry stopped")

    async def _health_loop(self) -> None:
        """Periodically check agent heartbeats and restart crashed ones."""
        while self._running:
            try:
                await asyncio.sleep(self._check_interval)
            except asyncio.CancelledError:
                break

            now = time.monotonic()
            for agent_id, info in list(self._agents.items()):
                if info.status == AgentStatus.STOPPING:
                    continue
                elapsed = now - info.last_heartbeat
                if elapsed > self._heartbeat_timeout and info.status != AgentStatus.CRASHED:
                    logger.warning(
                        "Agent '%s' (%s) missed heartbeat (%.0fs) — marking CRASHED",
                        info.name, agent_id, elapsed,
                    )
                    info.status = AgentStatus.CRASHED
                    info.error_count += 1

                    # Auto-restart via factory
                    if info.factory:
                        logger.info("Auto-restarting agent '%s'", info.name)
                        try:
                            await info.factory()
                            info.last_heartbeat = time.monotonic()
                            info.status = AgentStatus.IDLE
                            logger.info("Agent '%s' restarted successfully", info.name)
                        except Exception as exc:
                            logger.error("Failed to restart agent '%s': %s", info.name, exc)

    # ── Stats ──

    def get_stats(self) -> dict:
        return {
            "total_agents": len(self._agents),
            "by_status": {
                s.value: sum(1 for a in self._agents.values() if a.status == s)
                for s in AgentStatus
            },
            "agents": [a.to_dict() for a in self._agents.values()],
        }


__all__ = ["AgentRegistry", "AgentInfo", "AgentStatus"]
