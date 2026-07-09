"""Per-host adaptive CONCURRENCY ceiling (orthogonal to the RPS token bucket): caps
simultaneous in-flight requests per host, halves on 429/503, recovers on sustained
success, floors at 1, and is bypassed when unthrottled."""
from __future__ import annotations

import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.swarm_workers.vuln._rate_limit import (  # noqa: E402
    _MIN_CONCURRENCY, HostRateLimiter, enter_host, leave_host, set_unthrottled,
)


def test_concurrency_ceiling_blocks_until_release():
    async def go():
        rl = HostRateLimiter(base_concurrency=2)
        assert await rl.acquire_slot("h") is True
        assert await rl.acquire_slot("h") is True
        # At the ceiling of 2 -> the third waits and times out.
        assert await rl.acquire_slot("h", max_wait_s=0.1) is False
        await rl.release_slot("h")               # free one slot
        assert await rl.acquire_slot("h", max_wait_s=0.5) is True
    asyncio.run(go())


def test_overload_halves_concurrency():
    async def go():
        rl = HostRateLimiter(base_concurrency=8)
        await rl.acquire_slot("h"); await rl.release_slot("h")   # create the bucket
        await rl.record("h", 429)
        assert rl._buckets["h"].conc_limit == 4
        await rl.record("h", 503)
        assert rl._buckets["h"].conc_limit == 2
    asyncio.run(go())


def test_concurrency_recovers_on_sustained_success():
    async def go():
        rl = HostRateLimiter(base_concurrency=8)
        await rl.acquire_slot("h"); await rl.release_slot("h")
        await rl.record("h", 429)
        b = rl._buckets["h"]
        assert b.conc_limit == 4
        for _ in range(12):                       # one recovery step after _RECOVER_AFTER
            await rl.record("h", 200)
        assert b.conc_limit == 5
    asyncio.run(go())


def test_concurrency_floor_is_one():
    async def go():
        rl = HostRateLimiter(base_concurrency=2)
        await rl.acquire_slot("h"); await rl.release_slot("h")
        for _ in range(5):
            await rl.record("h", 429)
        assert rl._buckets["h"].conc_limit == _MIN_CONCURRENCY
    asyncio.run(go())


def test_release_never_underflows():
    async def go():
        rl = HostRateLimiter(base_concurrency=2)
        await rl.release_slot("h")                # no bucket yet -> no-op
        await rl.acquire_slot("h")
        await rl.release_slot("h")
        await rl.release_slot("h")                # extra release must not go negative
        assert rl._buckets["h"].in_flight == 0
    asyncio.run(go())


def test_hostless_target_is_never_gated():
    async def go():
        rl = HostRateLimiter(base_concurrency=1)
        assert await rl.acquire_slot("") is True
        assert await rl.acquire_slot("") is True   # no host -> no ceiling
    asyncio.run(go())


def test_unthrottled_bypasses_concurrency():
    async def go():
        set_unthrottled(True)
        try:
            for _ in range(20):                    # would block at any real ceiling
                assert await enter_host("h") is True
            await leave_host("h")                  # no-op, must not raise
        finally:
            set_unthrottled(False)
    asyncio.run(go())
