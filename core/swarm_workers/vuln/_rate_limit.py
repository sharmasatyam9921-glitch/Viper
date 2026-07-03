"""Per-host token-bucket rate limiter, shared by every worker that uses
`_http.fetch`. Prevents the dashboard's 100+ workers from collectively
hammering one target into a WAF block.

Default rate: 30 requests/second per host, burst 60. Tunable via
constructor.

Usage:
    from core.swarm_workers.vuln._rate_limit import wait_for_token

    # Inside a worker:
    await wait_for_token("example.com")
    # ... do HTTP call
"""

from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass
from typing import Optional
from urllib.parse import urlparse

logger = logging.getLogger("viper.swarm_workers.rate_limit")


# Adaptive-backoff tuning. The per-host rate starts at the configured ceiling and
# only ever drops in response to the target's OWN overload signals (429/503), then
# recovers gradually on sustained success — so a healthy target runs at full speed
# while a fragile one (or a WAF) is backed off automatically without a human tuning it.
_OVERLOAD_STATUSES = frozenset({429, 503})
_BACKOFF_FACTOR = 0.5      # multiply the host rate on each overload signal
_MIN_RATE_PER_S = 0.5      # never throttle a host below this
_RECOVER_AFTER = 12        # consecutive healthy responses between recovery steps
_RECOVER_STEP = 3.0        # additive rate recovery (req/s) per step, up to base_rate


@dataclass
class _Bucket:
    rate_per_s: float
    burst: float
    tokens: float
    last_refill: float
    base_rate: float = 0.0      # the configured ceiling to recover back toward
    ok_streak: int = 0          # consecutive non-overload responses observed


class HostRateLimiter:
    """Token-bucket per host. Shared global instance lives at
    `_DEFAULT`; tests can construct their own."""

    def __init__(self, rate_per_s: float = 30.0, burst: float = 60.0) -> None:
        self.rate_per_s = rate_per_s
        self.burst = burst
        self._buckets: dict[str, _Bucket] = {}
        self._lock = asyncio.Lock()

    @staticmethod
    def _host_of(url_or_host: str) -> str:
        if not url_or_host:
            return ""
        if "://" in url_or_host:
            return urlparse(url_or_host).hostname or url_or_host
        return url_or_host.split("/", 1)[0].split(":", 1)[0]

    async def acquire(self, url_or_host: str, *, cost: float = 1.0,
                       max_wait_s: float = 30.0) -> bool:
        """Wait until a token is available for the host. Returns True
        if acquired within max_wait_s, False if timed out (in which
        case the caller should treat the request as "blocked")."""
        host = self._host_of(url_or_host)
        if not host:
            return True  # no host → no rate limit

        deadline = time.time() + max_wait_s
        while True:
            async with self._lock:
                bucket = self._buckets.get(host)
                now = time.time()
                if bucket is None:
                    bucket = _Bucket(
                        rate_per_s=self.rate_per_s,
                        burst=self.burst,
                        tokens=self.burst,
                        last_refill=now,
                        base_rate=self.rate_per_s,
                    )
                    self._buckets[host] = bucket
                # Refill
                elapsed = now - bucket.last_refill
                bucket.tokens = min(
                    bucket.burst,
                    bucket.tokens + elapsed * bucket.rate_per_s,
                )
                bucket.last_refill = now
                if bucket.tokens >= cost:
                    bucket.tokens -= cost
                    return True
                # How long until enough tokens are refilled?
                deficit = cost - bucket.tokens
                sleep_s = deficit / bucket.rate_per_s
            # Sleep outside the lock so other coroutines can drain
            if time.time() + sleep_s > deadline:
                logger.debug("rate limit timed out for %s", host)
                return False
            await asyncio.sleep(min(sleep_s, max(deadline - time.time(), 0.001)))

    async def record(self, url_or_host: str, status: int) -> None:
        """Feed a response status back so the host's rate adapts to the target's own
        overload signals: multiplicative backoff on 429/503 (down to _MIN_RATE_PER_S),
        gradual additive recovery toward the configured base after sustained healthy
        responses. Only adapts a host that already has a bucket (created on acquire);
        never raises. FP-safe: this changes ONLY request pacing, nothing about
        findings or the validation gate."""
        host = self._host_of(url_or_host)
        if not host:
            return
        async with self._lock:
            bucket = self._buckets.get(host)
            if bucket is None:
                return
            base = bucket.base_rate or self.rate_per_s
            if status in _OVERLOAD_STATUSES:
                new_rate = max(_MIN_RATE_PER_S, bucket.rate_per_s * _BACKOFF_FACTOR)
                if new_rate < bucket.rate_per_s:
                    logger.debug("backing off %s: %.2f -> %.2f req/s (HTTP %d)",
                                 host, bucket.rate_per_s, new_rate, status)
                bucket.rate_per_s = new_rate
                bucket.ok_streak = 0
                # Drain to the new rate so the very next request pauses (cool-down).
                bucket.tokens = min(bucket.tokens, bucket.rate_per_s)
            elif status and 200 <= status < 500:      # a normal, healthy response
                bucket.ok_streak += 1
                if bucket.ok_streak >= _RECOVER_AFTER and bucket.rate_per_s < base:
                    bucket.rate_per_s = min(base, bucket.rate_per_s + _RECOVER_STEP)
                    bucket.ok_streak = 0
            else:                                       # 5xx / network failure: pause recovery
                bucket.ok_streak = 0


# Module-level singleton — every worker reaches into this one.
_DEFAULT = HostRateLimiter()

# When True, throttling is skipped entirely. ONLY for authorized localhost /
# benchmark targets where politeness/stealth is irrelevant; real hunts stay polite.
_unthrottled = False


def set_unthrottled(value: bool = True) -> None:
    global _unthrottled
    _unthrottled = bool(value)


def is_unthrottled() -> bool:
    return _unthrottled


async def wait_for_token(url_or_host: str, *, cost: float = 1.0) -> bool:
    """Convenience wrapper around the default limiter."""
    if _unthrottled:
        return True
    return await _DEFAULT.acquire(url_or_host, cost=cost)


async def record_response(url_or_host: str, status: int) -> None:
    """Feed a response status to the default limiter so a host that returns 429/503
    is automatically backed off (and recovers on sustained success). No-op when
    unthrottled or on any error — pacing must never break a request."""
    if _unthrottled:
        return
    try:
        await _DEFAULT.record(url_or_host, status)
    except Exception:   # noqa: BLE001 — adaptive pacing is never load-bearing
        pass


def reset_for_tests() -> None:
    """Test helper — clear all bucket state."""
    _DEFAULT._buckets.clear()


def get_default() -> HostRateLimiter:
    return _DEFAULT
