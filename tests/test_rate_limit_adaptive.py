"""Per-host adaptive backoff: a target's own 429/503 signals throttle it down, and
sustained healthy responses recover it toward the configured ceiling. Pacing only —
never touches findings or the gate."""
from __future__ import annotations

import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.swarm_workers.vuln._rate_limit import (  # noqa: E402
    _MIN_RATE_PER_S, _RECOVER_AFTER, HostRateLimiter,
)


def _rate(rl: HostRateLimiter, host: str) -> float:
    return rl._buckets[host].rate_per_s


def test_backoff_multiplicative_on_overload():
    rl = HostRateLimiter(rate_per_s=32.0, burst=64.0)

    async def go():
        await rl.acquire("http://example.com/")          # create bucket at 32
        assert _rate(rl, "example.com") == 32.0
        await rl.record("http://example.com/", 429)
        assert _rate(rl, "example.com") == 16.0            # x0.5
        await rl.record("http://example.com/", 503)
        assert _rate(rl, "example.com") == 8.0             # 503 also backs off
    asyncio.run(go())


def test_backoff_clamped_at_minimum():
    rl = HostRateLimiter(rate_per_s=1.0)

    async def go():
        await rl.acquire("http://t/")
        for _ in range(10):
            await rl.record("http://t/", 429)
        assert _rate(rl, "t") == _MIN_RATE_PER_S           # never below the floor
    asyncio.run(go())


def test_recovery_after_sustained_success():
    rl = HostRateLimiter(rate_per_s=30.0)

    async def go():
        await rl.acquire("http://t/")
        await rl.record("http://t/", 429)                  # 30 -> 15
        assert _rate(rl, "t") == 15.0
        for _ in range(_RECOVER_AFTER):
            await rl.record("http://t/", 200)
        assert _rate(rl, "t") == 18.0                      # +3 once, toward base
    asyncio.run(go())


def test_recovery_never_exceeds_base():
    rl = HostRateLimiter(rate_per_s=30.0)

    async def go():
        await rl.acquire("http://t/")
        for _ in range(_RECOVER_AFTER * 3):
            await rl.record("http://t/", 200)
        assert _rate(rl, "t") == 30.0                      # healthy stays at ceiling
    asyncio.run(go())


def test_4xx_is_healthy_but_5xx_pauses_recovery():
    rl = HostRateLimiter(rate_per_s=30.0)

    async def go():
        await rl.acquire("http://t/")
        await rl.record("http://t/", 429)                  # -> 15
        for _ in range(_RECOVER_AFTER):
            await rl.record("http://t/", 404)              # 404 is a healthy response
        assert _rate(rl, "t") == 18.0                      # recovered once
        for _ in range(_RECOVER_AFTER - 1):
            await rl.record("http://t/", 200)
        await rl.record("http://t/", 500)                  # 5xx resets the streak
        for _ in range(_RECOVER_AFTER - 1):
            await rl.record("http://t/", 200)
        assert _rate(rl, "t") == 18.0                      # never re-reached threshold
    asyncio.run(go())


def test_record_without_bucket_is_noop():
    rl = HostRateLimiter()

    async def go():
        await rl.record("http://never-acquired/", 429)     # no bucket -> no raise
        assert "never-acquired" not in rl._buckets
    asyncio.run(go())


def test_record_response_helper_respects_unthrottled():
    from core.swarm_workers.vuln import _rate_limit as rl_mod

    async def go():
        await rl_mod._DEFAULT.acquire("http://uthost/")
        base = _rate(rl_mod._DEFAULT, "uthost")
        rl_mod.set_unthrottled(True)
        try:
            await rl_mod.record_response("http://uthost/", 429)   # ignored
            assert _rate(rl_mod._DEFAULT, "uthost") == base
        finally:
            rl_mod.set_unthrottled(False)
        await rl_mod.record_response("http://uthost/", 429)       # now applies
        assert _rate(rl_mod._DEFAULT, "uthost") < base
    asyncio.run(go())
    from core.swarm_workers.vuln._rate_limit import reset_for_tests
    reset_for_tests()
