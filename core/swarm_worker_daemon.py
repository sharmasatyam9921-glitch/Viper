"""
VIPER 6.0 — Swarm worker daemon (entrypoint for `MODE=worker` containers)
==========================================================================
Subscribes to one or more phase queues (recon / vuln / exploit / post) on
the shared bus (``core.redis_bus.get_bus()``) and runs the corresponding
worker for each job, publishing findings to the next phase.

Run via Docker::

    docker run -e MODE=worker -e REDIS_URL=redis://redis:6379 \
               -e PHASES=vuln,exploit viper:latest

Or scaled via docker-compose::

    docker compose up -d --scale viper-worker=10

The CLI exposes:
  --phases recon,vuln,...    (env PHASES)
  --concurrency 4            (env WORKER_CONCURRENCY)
  --worker-id <id>           (env WORKER_ID, auto-uuid if absent)
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import os
import signal
import sys
import time
import uuid
from typing import Iterable

from .redis_bus import Envelope, get_bus
from .swarm_engine import SwarmAgent
from .swarm_workers import get_worker_runner

logger = logging.getLogger("viper.swarm_worker_daemon")


# Next-phase routing — each worker's findings advance to the next phase
PHASE_ORDER = ["recon", "vuln", "exploit", "post", "report"]


def next_phase(current: str) -> str | None:
    try:
        i = PHASE_ORDER.index(current)
    except ValueError:
        return None
    if i + 1 >= len(PHASE_ORDER):
        return None
    return PHASE_ORDER[i + 1]


async def handle_job(env: Envelope, *, worker_id: str) -> None:
    """Dispatch one job to the matching worker runner."""
    payload = env.payload or {}
    technique = payload.get("technique") or payload.get("worker")
    target = payload.get("target")
    hunt_id = env.hunt_id

    if not (technique and target):
        logger.warning("[%s] bad job env: missing technique/target: %r", worker_id, payload)
        return

    try:
        runner = get_worker_runner(env.topic, technique)
    except KeyError:
        runner = None
    if runner is None:
        logger.warning("[%s] no runner for phase=%s technique=%s", worker_id, env.topic, technique)
        return

    started = time.time()
    logger.info("[%s] phase=%s technique=%s target=%s START", worker_id, env.topic, technique, target)

    findings: list[dict] = []
    try:
        # Workers in core/swarm_workers/* take a SwarmAgent. We build one
        # from the bus envelope and pass it to the registered runner.
        agent = SwarmAgent(
            agent_id=payload.get("agent_id") or env.message_id,
            objective=payload.get("objective") or f"{technique} on {target}",
            target=target,
            technique=technique,
            payload=payload.get("kwargs") or {},
            timeout_s=float(payload.get("timeout_s") or 60.0),
            priority=env.priority,
        )
        result = await runner(agent)
        if isinstance(result, list):
            findings = result
        elif isinstance(result, dict):
            findings = [result]
    except Exception as exc:
        logger.exception("[%s] worker crashed: %s", worker_id, exc)
        findings = [{"error": str(exc), "technique": technique, "target": target}]

    elapsed = round(time.time() - started, 2)
    logger.info("[%s] phase=%s technique=%s target=%s DONE findings=%d elapsed=%.2fs",
                worker_id, env.topic, technique, target, len(findings), elapsed)

    bus = await get_bus()

    # Publish each finding to the next phase (streaming downstream)
    nxt = next_phase(env.topic)
    for f in findings:
        # Always publish to the global findings channel for the dashboard
        await bus.publish("findings", {
            "phase": env.topic,
            "technique": technique,
            "target": target,
            "elapsed_s": elapsed,
            "worker_id": worker_id,
            **f,
        }, hunt_id=hunt_id)
        # And if the finding should advance the kill chain, push to next phase
        if nxt and f.get("advance", True) and not f.get("error"):
            await bus.publish(nxt, {
                "target": f.get("target") or target,
                "technique": f.get("next_technique"),
                "kwargs": f.get("next_kwargs", {}),
                "upstream_finding": f.get("id") or "",
            }, hunt_id=hunt_id)


async def heartbeat_loop(worker_id: str, phases: list[str], stop: asyncio.Event) -> None:
    bus = await get_bus()
    while not stop.is_set():
        try:
            await bus.heartbeat(worker_id, {"phases": phases, "version": "6.0"})
        except Exception as exc:
            logger.debug("heartbeat failed: %s", exc)
        try:
            await asyncio.wait_for(stop.wait(), timeout=10)
        except asyncio.TimeoutError:
            pass


async def consume_phase(phase: str, *, worker_id: str, concurrency: int,
                       stop: asyncio.Event) -> None:
    bus = await get_bus()
    sem = asyncio.Semaphore(concurrency)
    active: set[asyncio.Task] = set()

    async def _wrap(env: Envelope) -> None:
        async with sem:
            await handle_job(env, worker_id=worker_id)

    logger.info("[%s] subscribing to phase=%s (concurrency=%d)", worker_id, phase, concurrency)

    async for env in bus.consume(phase):
        if stop.is_set():
            break
        task = asyncio.create_task(_wrap(env))
        active.add(task)
        task.add_done_callback(active.discard)

    # Drain on shutdown
    if active:
        logger.info("[%s] draining %d active jobs", worker_id, len(active))
        await asyncio.gather(*active, return_exceptions=True)


async def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="VIPER 6.0 swarm worker daemon")
    parser.add_argument(
        "--phases",
        default=os.environ.get("PHASES", "recon,vuln,exploit,post"),
        help="Comma-separated phase queues to subscribe to",
    )
    parser.add_argument(
        "--concurrency",
        type=int,
        default=int(os.environ.get("WORKER_CONCURRENCY", "4")),
        help="Max concurrent jobs per phase per worker",
    )
    parser.add_argument(
        "--worker-id",
        default=os.environ.get("WORKER_ID") or f"w-{uuid.uuid4().hex[:8]}",
    )
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=os.environ.get("LOG_LEVEL", "INFO").upper(),
        format="%(asctime)s %(levelname)s %(name)s — %(message)s",
        datefmt="%H:%M:%S",
    )

    phases = [p.strip() for p in args.phases.split(",") if p.strip()]
    if not phases:
        logger.error("no phases configured")
        return 2

    logger.info("VIPER worker %s starting — phases=%s concurrency=%d",
                args.worker_id, phases, args.concurrency)

    stop = asyncio.Event()

    def _shutdown(*_):
        if not stop.is_set():
            logger.info("shutdown signal received")
            stop.set()

    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            asyncio.get_running_loop().add_signal_handler(sig, _shutdown)
        except (NotImplementedError, RuntimeError):
            signal.signal(sig, _shutdown)

    tasks: list[asyncio.Task] = [
        asyncio.create_task(heartbeat_loop(args.worker_id, phases, stop), name="heartbeat"),
    ]
    for p in phases:
        tasks.append(asyncio.create_task(
            consume_phase(p, worker_id=args.worker_id,
                          concurrency=args.concurrency, stop=stop),
            name=f"consume-{p}",
        ))

    await stop.wait()
    for t in tasks:
        t.cancel()
    await asyncio.gather(*tasks, return_exceptions=True)

    bus = await get_bus()
    await bus.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
