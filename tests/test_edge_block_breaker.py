"""Edge-block circuit breaker (found dogfooding a real Akamai-fronted target: two 40-min
hunts against Myntra reported a misleading '0 findings' after every worker hung on the
timeout ceiling — benign requests were null-routed while attack paths got an instant 403).

The breaker counts CONSECUTIVE request timeouts per host and, once a host times out
_EDGE_BLOCK_THRESHOLD times in a row with ZERO intervening responses, flags it edge-blocked
so _http.fetch fast-fails further requests. The invariant that matters most is RECALL-SAFETY:
a healthy or merely-slow target (that returns ANY real status) must never trip, so the gate's
fast local test targets are unaffected."""
from __future__ import annotations

import asyncio
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.swarm_workers.vuln import _rate_limit as rl  # noqa: E402
from core.swarm_workers.vuln._rate_limit import (  # noqa: E402
    _EDGE_BLOCK_THRESHOLD,
    _EDGE_COOLDOWN_S,
    HostRateLimiter,
    is_host_edge_blocked,
    record_timeout,
    reset_for_tests,
    set_unthrottled,
)

HOST = "https://api.example.com/x"


def _run(coro):
    return asyncio.run(coro)


def test_trips_after_consecutive_timeouts():
    lim = HostRateLimiter()
    async def go():
        for _ in range(_EDGE_BLOCK_THRESHOLD - 1):
            await lim.record_timeout(HOST)
            assert lim.is_edge_blocked(HOST) is False   # not yet
        await lim.record_timeout(HOST)                   # the Nth
        assert lim.is_edge_blocked(HOST) is True
    _run(go())


def test_any_real_status_clears_the_streak():
    # A 403/429/503 still proves the host is reachable — it is NOT an edge-block.
    for status in (200, 403, 429, 503, 500):
        lim = HostRateLimiter()
        async def go(s=status):
            for _ in range(_EDGE_BLOCK_THRESHOLD - 1):
                await lim.record_timeout(HOST)
            await lim.record(HOST, s)                     # a response arrives
            assert lim.is_edge_blocked(HOST) is False
            # streak was reset: it now takes a FULL new run of timeouts to trip
            for _ in range(_EDGE_BLOCK_THRESHOLD - 1):
                await lim.record_timeout(HOST)
            assert lim.is_edge_blocked(HOST) is False
            await lim.record_timeout(HOST)
            assert lim.is_edge_blocked(HOST) is True
        _run(go())


def test_response_after_trip_reopens_circuit():
    lim = HostRateLimiter()
    async def go():
        for _ in range(_EDGE_BLOCK_THRESHOLD):
            await lim.record_timeout(HOST)
        assert lim.is_edge_blocked(HOST) is True
        await lim.record(HOST, 200)                       # host came back
        assert lim.is_edge_blocked(HOST) is False
    _run(go())


def test_healthy_or_slow_target_never_trips():
    # RECALL SAFETY: a target that responds (even slowly, even with occasional single
    # timeouts) but returns a real status between them must NEVER be flagged. This is the
    # property that keeps the gate's fast local targets unaffected.
    lim = HostRateLimiter()
    async def go():
        for _ in range(50):
            await lim.record_timeout(HOST)   # one blip...
            await lim.record(HOST, 200)      # ...then a real response resets it
            assert lim.is_edge_blocked(HOST) is False
    _run(go())


def test_cooldown_self_heals():
    lim = HostRateLimiter()
    async def go():
        for _ in range(_EDGE_BLOCK_THRESHOLD):
            await lim.record_timeout(HOST)
        assert lim.is_edge_blocked(HOST) is True
        # Force the trip to be older than the cooldown -> next check re-probes (self-heal).
        host = lim._host_of(HOST)
        lim._buckets[host].blocked_at = time.time() - (_EDGE_COOLDOWN_S + 1)
        assert lim.is_edge_blocked(HOST) is False
    _run(go())


def test_distinct_hosts_are_independent():
    lim = HostRateLimiter()
    other = "https://cdn.other.com/y"
    async def go():
        for _ in range(_EDGE_BLOCK_THRESHOLD):
            await lim.record_timeout(HOST)
        assert lim.is_edge_blocked(HOST) is True
        assert lim.is_edge_blocked(other) is False       # unrelated host untouched
    _run(go())


def test_module_wrappers_and_reset():
    reset_for_tests()
    set_unthrottled(False)
    async def go():
        for _ in range(_EDGE_BLOCK_THRESHOLD):
            await record_timeout(HOST)
        assert is_host_edge_blocked(HOST) is True
    _run(go())
    reset_for_tests()
    assert is_host_edge_blocked(HOST) is False            # state cleared


def test_unthrottled_never_blocks():
    # Localhost/benchmark runs set unthrottled — the breaker must be a no-op there.
    reset_for_tests()
    set_unthrottled(True)
    try:
        async def go():
            for _ in range(_EDGE_BLOCK_THRESHOLD * 3):
                await record_timeout(HOST)
            assert is_host_edge_blocked(HOST) is False
        _run(go())
    finally:
        set_unthrottled(False)
        reset_for_tests()
