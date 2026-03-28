#!/usr/bin/env python3
"""
VIPER Agent Bus — Asyncio-based pub/sub message bus for multi-agent coordination.

Agents subscribe to topics and exchange messages with priority queuing.
Topics: "recon", "vuln", "exploit", "chain", "report"
"""

import asyncio
import logging
import time
import uuid
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Any, Callable, Coroutine, Dict, List, Optional, Set

logger = logging.getLogger("viper.agent_bus")


class Priority(IntEnum):
    """Message priority levels. Lower value = higher priority."""
    CRITICAL = 0
    HIGH = 1
    MEDIUM = 2
    LOW = 3


@dataclass(order=True)
class BusMessage:
    """A message on the agent bus.

    Ordered by (priority, timestamp) so that asyncio.PriorityQueue
    dequeues the most urgent and oldest messages first.
    """
    priority: Priority = field(compare=True)
    timestamp: float = field(compare=True, default_factory=time.monotonic)
    agent_id: str = field(compare=False, default="")
    topic: str = field(compare=False, default="")
    payload: Any = field(compare=False, default=None)
    message_id: str = field(compare=False, default_factory=lambda: uuid.uuid4().hex[:12])

    def to_dict(self) -> dict:
        return {
            "message_id": self.message_id,
            "agent_id": self.agent_id,
            "topic": self.topic,
            "priority": self.priority.name,
            "timestamp": self.timestamp,
            "payload": str(self.payload)[:500] if self.payload else None,
        }


# Type alias for subscriber callbacks
SubscriberCallback = Callable[[BusMessage], Coroutine[Any, Any, None]]


class AgentBus:
    """Asyncio-based pub/sub message bus with per-topic priority queues.

    Thread-safe: all mutation goes through asyncio primitives.
    Each topic has its own ``asyncio.PriorityQueue`` so subscribers
    on one topic don't block another.

    Usage::

        bus = AgentBus()
        bus.subscribe("recon", my_callback)
        await bus.publish("recon", payload={"target": "example.com"}, priority=Priority.HIGH)
        await bus.start()   # starts dispatcher tasks
        ...
        await bus.stop()
    """

    def __init__(self, max_queue_size: int = 1000):
        self._queues: Dict[str, asyncio.PriorityQueue] = {}
        self._subscribers: Dict[str, List[SubscriberCallback]] = {}
        self._max_queue_size = max_queue_size
        self._dispatchers: Dict[str, asyncio.Task] = {}
        self._running = False
        self._stats: Dict[str, int] = {"published": 0, "delivered": 0, "errors": 0}

    # ── Subscription ──

    def subscribe(self, topic: str, callback: SubscriberCallback) -> None:
        """Register *callback* as a subscriber for *topic*."""
        self._subscribers.setdefault(topic, []).append(callback)
        if topic not in self._queues:
            self._queues[topic] = asyncio.PriorityQueue(maxsize=self._max_queue_size)
        logger.debug("Subscribed callback to topic '%s'", topic)

    def unsubscribe(self, topic: str, callback: SubscriberCallback) -> None:
        """Remove *callback* from *topic* subscribers."""
        subs = self._subscribers.get(topic, [])
        if callback in subs:
            subs.remove(callback)
            logger.debug("Unsubscribed callback from topic '%s'", topic)

    # ── Publishing ──

    async def publish(
        self,
        topic: str,
        payload: Any = None,
        priority: Priority = Priority.MEDIUM,
        agent_id: str = "system",
    ) -> str:
        """Publish a message to *topic*. Returns the message_id."""
        if topic not in self._queues:
            self._queues[topic] = asyncio.PriorityQueue(maxsize=self._max_queue_size)

        msg = BusMessage(
            priority=priority,
            agent_id=agent_id,
            topic=topic,
            payload=payload,
        )

        try:
            self._queues[topic].put_nowait(msg)
        except asyncio.QueueFull:
            logger.warning("Queue for topic '%s' is full — dropping message %s", topic, msg.message_id)
            return ""

        self._stats["published"] += 1
        logger.debug("Published %s to '%s' (priority=%s)", msg.message_id, topic, priority.name)
        return msg.message_id

    # ── Lifecycle ──

    async def start(self) -> None:
        """Start dispatcher tasks for every registered topic."""
        if self._running:
            return
        self._running = True
        for topic in list(self._queues.keys()):
            self._dispatchers[topic] = asyncio.create_task(
                self._dispatch_loop(topic), name=f"bus-dispatch-{topic}"
            )
        logger.info("AgentBus started with topics: %s", list(self._queues.keys()))

    async def stop(self) -> None:
        """Gracefully stop all dispatcher tasks."""
        self._running = False
        for task in self._dispatchers.values():
            task.cancel()
        await asyncio.gather(*self._dispatchers.values(), return_exceptions=True)
        self._dispatchers.clear()
        logger.info("AgentBus stopped. Stats: %s", self._stats)

    # ── Internal dispatcher ──

    async def _dispatch_loop(self, topic: str) -> None:
        """Continuously dequeue and fan-out messages to subscribers."""
        queue = self._queues[topic]
        while self._running:
            try:
                msg: BusMessage = await asyncio.wait_for(queue.get(), timeout=1.0)
            except asyncio.TimeoutError:
                continue
            except asyncio.CancelledError:
                break

            subscribers = self._subscribers.get(topic, [])
            for cb in subscribers:
                try:
                    await cb(msg)
                    self._stats["delivered"] += 1
                except Exception as exc:
                    self._stats["errors"] += 1
                    logger.error(
                        "Subscriber error on topic '%s' (msg=%s): %s",
                        topic, msg.message_id, exc,
                    )

    # ── Introspection ──

    def get_stats(self) -> dict:
        """Return bus statistics."""
        queue_sizes = {t: q.qsize() for t, q in self._queues.items()}
        return {**self._stats, "queue_sizes": queue_sizes, "running": self._running}

    @property
    def topics(self) -> List[str]:
        return list(self._queues.keys())

    @property
    def running(self) -> bool:
        return self._running


__all__ = ["AgentBus", "BusMessage", "Priority", "SubscriberCallback"]
