"""
VIPER 6.0 — Redis-backed cross-container AgentBus
==================================================
Drop-in compatible with ``core.agent_bus.AgentBus`` but distributes work
across many containers via Redis lists (BLPOP) + pub/sub (PUBLISH).

USAGE
-----
The API container publishes phase jobs::

    bus = await get_bus()                 # reads REDIS_URL env
    await bus.publish("vuln", {"target": "https://...", "worker": "sqli_probe"})

A pool of worker containers (run with ``MODE=worker``) does::

    bus = await get_bus()
    async for msg in bus.consume("vuln"):
        ...run worker, publish findings to next phase

Two backends live behind the same interface:

* ``AsyncioBus``   — single-process fallback (no Redis env). Wraps
  ``core.agent_bus.AgentBus`` for backwards compatibility.
* ``RedisBus``     — Redis lists + pub/sub. Selected when ``REDIS_URL`` is
  present in the environment.

``get_bus()`` picks the right one and caches it.

Schema
------
* Job queue per phase :: ``viper:queue:<phase>`` (Redis LIST, BLPOP).
* Findings broadcast    :: ``viper:findings`` (Redis PUB/SUB channel).
* Heartbeats             :: ``viper:workers:<worker_id>`` (string with TTL).

Each message is JSON: ``{message_id, agent_id, topic, payload, priority,
ts, hunt_id?}``.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import time
import uuid
from dataclasses import dataclass, field
from typing import AsyncIterator, Optional

logger = logging.getLogger("viper.redis_bus")

# Match priority levels from core.agent_bus
PRIORITY_CRITICAL = 0
PRIORITY_HIGH = 1
PRIORITY_MEDIUM = 2
PRIORITY_LOW = 3


@dataclass
class Envelope:
    """Bus message — serialised to JSON on the wire."""

    topic: str
    payload: dict
    priority: int = PRIORITY_MEDIUM
    message_id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    agent_id: str = ""
    ts: float = field(default_factory=time.time)
    hunt_id: Optional[str] = None

    def to_json(self) -> bytes:
        return json.dumps(self.__dict__, default=str).encode("utf-8")

    @classmethod
    def from_json(cls, data: bytes | str) -> "Envelope":
        if isinstance(data, bytes):
            data = data.decode("utf-8", errors="replace")
        d = json.loads(data)
        return cls(**d)


# ─── Async-io fallback ───────────────────────────────────────────────────

class _AsyncioBus:
    """In-process bus — used when REDIS_URL is not set."""

    def __init__(self) -> None:
        self._queues: dict[str, asyncio.Queue] = {}
        logger.info("AgentBus mode: asyncio (single-process)")

    def _q(self, topic: str) -> asyncio.Queue:
        if topic not in self._queues:
            self._queues[topic] = asyncio.Queue()
        return self._queues[topic]

    async def publish(self, topic: str, payload: dict, *,
                      priority: int = PRIORITY_MEDIUM,
                      hunt_id: Optional[str] = None) -> str:
        env = Envelope(topic=topic, payload=payload, priority=priority,
                       hunt_id=hunt_id)
        await self._q(topic).put(env)
        return env.message_id

    async def consume(self, topic: str) -> AsyncIterator[Envelope]:
        q = self._q(topic)
        while True:
            env = await q.get()
            yield env

    async def heartbeat(self, worker_id: str, payload: dict | None = None) -> None:
        # No-op for asyncio backend
        return None

    async def close(self) -> None:
        return None


# ─── Redis backend ───────────────────────────────────────────────────────

class _RedisBus:
    """Cross-container bus via Redis lists + pub/sub."""

    def __init__(self, redis_url: str) -> None:
        try:
            import redis.asyncio as aioredis
        except ImportError as exc:
            raise RuntimeError(
                "redis-py not installed. `pip install redis hiredis`"
            ) from exc

        self._url = redis_url
        self._client = aioredis.from_url(redis_url, decode_responses=False)
        logger.info("AgentBus mode: redis @ %s", redis_url)

    @staticmethod
    def _queue_key(topic: str) -> str:
        return f"viper:queue:{topic}"

    async def publish(self, topic: str, payload: dict, *,
                      priority: int = PRIORITY_MEDIUM,
                      hunt_id: Optional[str] = None) -> str:
        env = Envelope(topic=topic, payload=payload, priority=priority,
                       hunt_id=hunt_id)
        body = env.to_json()
        # Higher priority → push to head; otherwise tail.
        if priority <= PRIORITY_HIGH:
            await self._client.lpush(self._queue_key(topic), body)
        else:
            await self._client.rpush(self._queue_key(topic), body)
        # Also fan-out via pub/sub for monitor UIs
        await self._client.publish(f"viper:bus:{topic}", body)
        return env.message_id

    async def consume(self, topic: str) -> AsyncIterator[Envelope]:
        """Block on the queue with BLPOP — many workers can share the queue."""
        key = self._queue_key(topic)
        while True:
            try:
                # 5-second timeout so we can react to shutdown signals
                pair = await self._client.blpop([key], timeout=5)
            except Exception as exc:
                logger.warning("Redis BLPOP failed (%s); retrying in 1s", exc)
                await asyncio.sleep(1)
                continue
            if not pair:
                continue  # timeout — loop
            _, body = pair
            try:
                yield Envelope.from_json(body)
            except Exception as exc:
                logger.warning("Bad envelope (%s): %r", exc, body[:120])

    async def heartbeat(self, worker_id: str, payload: dict | None = None) -> None:
        """Set TTL-keyed heartbeat so the dashboard can list live workers."""
        key = f"viper:workers:{worker_id}"
        value = json.dumps({"ts": time.time(), **(payload or {})}).encode()
        await self._client.set(key, value, ex=30)  # auto-expire after 30s

    async def list_workers(self) -> list[dict]:
        keys = await self._client.keys("viper:workers:*")
        out: list[dict] = []
        for k in keys:
            v = await self._client.get(k)
            if not v:
                continue
            try:
                d = json.loads(v)
                d["worker_id"] = (k.decode() if isinstance(k, bytes) else k).split(":")[-1]
                out.append(d)
            except Exception:
                pass
        return out

    async def close(self) -> None:
        try:
            await self._client.close()
        except Exception:
            pass


# ─── Singleton selector ──────────────────────────────────────────────────

_BUS: Optional[object] = None


async def get_bus():
    """Returns the configured bus instance (RedisBus or AsyncioBus)."""
    global _BUS
    if _BUS is not None:
        return _BUS
    url = os.environ.get("REDIS_URL", "").strip()
    if url:
        try:
            _BUS = _RedisBus(url)
            # Ping early to fail-fast on misconfig
            try:
                import redis.asyncio as aioredis  # type: ignore
                client = aioredis.from_url(url)
                pong = await client.ping()
                await client.close()
                if not pong:
                    raise RuntimeError("Redis PING returned falsy")
            except Exception as exc:
                logger.warning("Redis unreachable (%s); falling back to asyncio bus", exc)
                _BUS = _AsyncioBus()
        except Exception as exc:
            logger.warning("Redis bus init failed (%s); using asyncio bus", exc)
            _BUS = _AsyncioBus()
    else:
        _BUS = _AsyncioBus()
    return _BUS
