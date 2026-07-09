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

# Per-host CONCURRENCY ceiling — orthogonal to RPS. RPS paces the request RATE; this caps
# the number of SIMULTANEOUS in-flight requests to one host. A fragile server (or a
# connection-limited WAF) can accept 30 req/s but choke on many parallel connections, so
# the same overload signals (429/503) that back off the rate also halve the concurrency
# ceiling (down to a floor of 1), recovering by +1 on sustained success.
_BASE_CONCURRENCY = 8      # max simultaneous in-flight per host at full health
_MIN_CONCURRENCY = 1       # never below fully-serialized
_SLOT_POLL_S = 0.02        # re-check cadence while a host is at its concurrency ceiling


@dataclass
class _Bucket:
    rate_per_s: float
    burst: float
    tokens: float
    last_refill: float
    base_rate: float = 0.0      # the configured ceiling to recover back toward
    ok_streak: int = 0          # consecutive non-overload responses observed
    conc_limit: int = _BASE_CONCURRENCY   # current max simultaneous in-flight
    conc_base: int = _BASE_CONCURRENCY    # ceiling to recover concurrency back toward
    in_flight: int = 0                    # requests currently in flight to this host


class HostRateLimiter:
    """Token-bucket per host. Shared global instance lives at
    `_DEFAULT`; tests can construct their own."""

    def __init__(self, rate_per_s: float = 30.0, burst: float = 60.0,
                 base_concurrency: int = _BASE_CONCURRENCY) -> None:
        self.rate_per_s = rate_per_s
        self.burst = burst
        self.base_concurrency = max(_MIN_CONCURRENCY, int(base_concurrency))
        self._buckets: dict[str, _Bucket] = {}
        self._lock = asyncio.Lock()

    def _new_bucket(self, now: float) -> _Bucket:
        return _Bucket(
            rate_per_s=self.rate_per_s, burst=self.burst, tokens=self.burst,
            last_refill=now, base_rate=self.rate_per_s,
            conc_limit=self.base_concurrency, conc_base=self.base_concurrency,
        )

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
                    bucket = self._new_bucket(now)
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

    async def acquire_slot(self, url_or_host: str, *, max_wait_s: float = 30.0) -> bool:
        """Take a per-host concurrency slot, waiting if the host is already at its adaptive
        ceiling. Returns True once a slot is held (caller MUST later call `release_slot`),
        or False if none freed within max_wait_s. Polls without holding the lock so other
        coroutines can release. Complements `acquire` (RPS): rate AND parallelism are both
        capped per host."""
        host = self._host_of(url_or_host)
        if not host:
            return True
        deadline = time.time() + max_wait_s
        while True:
            async with self._lock:
                bucket = self._buckets.get(host)
                if bucket is None:
                    bucket = self._new_bucket(time.time())
                    self._buckets[host] = bucket
                if bucket.in_flight < bucket.conc_limit:
                    bucket.in_flight += 1
                    return True
            if time.time() >= deadline:
                logger.debug("concurrency slot timed out for %s", host)
                return False
            await asyncio.sleep(_SLOT_POLL_S)

    async def release_slot(self, url_or_host: str) -> None:
        """Release a concurrency slot previously taken by `acquire_slot`. Never underflows."""
        host = self._host_of(url_or_host)
        if not host:
            return
        async with self._lock:
            bucket = self._buckets.get(host)
            if bucket and bucket.in_flight > 0:
                bucket.in_flight -= 1

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
                new_conc = max(_MIN_CONCURRENCY, bucket.conc_limit // 2)
                if new_rate < bucket.rate_per_s or new_conc < bucket.conc_limit:
                    logger.debug("backing off %s: %.2f->%.2f req/s, conc %d->%d (HTTP %d)",
                                 host, bucket.rate_per_s, new_rate,
                                 bucket.conc_limit, new_conc, status)
                bucket.rate_per_s = new_rate
                bucket.conc_limit = new_conc
                bucket.ok_streak = 0
                # Drain to the new rate so the very next request pauses (cool-down).
                bucket.tokens = min(bucket.tokens, bucket.rate_per_s)
            elif status and 200 <= status < 500:      # a normal, healthy response
                bucket.ok_streak += 1
                if bucket.ok_streak >= _RECOVER_AFTER and (
                        bucket.rate_per_s < base or bucket.conc_limit < bucket.conc_base):
                    bucket.rate_per_s = min(base, bucket.rate_per_s + _RECOVER_STEP)
                    bucket.conc_limit = min(bucket.conc_base, bucket.conc_limit + 1)
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


async def enter_host(url_or_host: str) -> bool:
    """Take a per-host concurrency slot on the default limiter (see acquire_slot).
    Returns True if held (caller must `leave_host`), False on timeout. Always True when
    unthrottled."""
    if _unthrottled:
        return True
    try:
        return await _DEFAULT.acquire_slot(url_or_host)
    except Exception:   # noqa: BLE001 — concurrency pacing is never load-bearing
        return True


async def leave_host(url_or_host: str) -> None:
    """Release a per-host concurrency slot on the default limiter. No-op when unthrottled."""
    if _unthrottled:
        return
    try:
        await _DEFAULT.release_slot(url_or_host)
    except Exception:   # noqa: BLE001
        pass


def reset_for_tests() -> None:
    """Test helper — clear all bucket state."""
    _DEFAULT._buckets.clear()


def get_default() -> HostRateLimiter:
    return _DEFAULT
