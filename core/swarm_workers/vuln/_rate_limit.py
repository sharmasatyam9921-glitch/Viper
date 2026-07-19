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

# Edge-block circuit breaker. A hardened CDN/WAF edge (e.g. Akamai) can null-route or
# tarpit our traffic: benign requests hang to the per-request timeout ceiling while attack
# signatures get an instant 403. Left unchecked, every worker keeps hanging on the timeout
# for the whole time budget, and the run reports a misleading "0 findings" — indistinguishable
# from a genuinely clean target. So we count CONSECUTIVE request TIMEOUTS per host: once a host
# times out this many times in a row WITH ZERO intervening real responses, it is flagged
# edge-blocked and further requests fast-fail (see _http.fetch) instead of hanging. Recall-safe
# by construction: ANY real HTTP status (even a 403/429/503 — proof the host is reachable) resets
# the streak and clears the flag, so a healthy or merely-slow target never trips. The flag
# self-heals after a cooldown so a transient tarpit is re-probed rather than blocked forever.
_EDGE_BLOCK_THRESHOLD = 5   # consecutive timeouts (no intervening response) => edge-blocked
_EDGE_COOLDOWN_S = 120.0    # after this long, allow a re-probe (self-heal)


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
    timeout_streak: int = 0               # consecutive request timeouts (reset by any response)
    edge_blocked: bool = False            # host is tarpitting/blackholing us (circuit open)
    blocked_at: float = 0.0               # when edge_blocked tripped (for cooldown self-heal)


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

    async def record(self, url_or_host: str, status: int, *,
                     waf_block: bool = False) -> None:
        """Feed a response status back so the host's rate adapts to the target's own
        overload signals: multiplicative backoff on 429/503 — OR a corroborated WAF block
        (``waf_block=True``, a 403/406 whose BODY carries a WAF marker, so a benign
        auth-403 does NOT throttle) — down to _MIN_RATE_PER_S, with gradual additive
        recovery toward the configured base after sustained healthy responses. Backing off
        on a WAF block is politeness/anti-ban: a real hacker eases off when the WAF starts
        blocking rather than hammering into an IP ban. Only adapts a host that already has
        a bucket; never raises. FP-safe: changes ONLY request pacing, never a finding."""
        host = self._host_of(url_or_host)
        if not host:
            return
        async with self._lock:
            bucket = self._buckets.get(host)
            if bucket is None:
                return
            # A real HTTP status came back — proof the host is reachable (a 403/429/503
            # still counts). Clear any edge-block state so the circuit re-closes.
            bucket.timeout_streak = 0
            if bucket.edge_blocked:
                bucket.edge_blocked = False
                logger.debug("edge-block cleared for %s (HTTP %s received)", host, status)
            base = bucket.base_rate or self.rate_per_s
            if status in _OVERLOAD_STATUSES or waf_block:
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

    async def record_timeout(self, url_or_host: str) -> None:
        """Feed a request TIMEOUT / unreachable outcome (no response) back to the host's
        bucket. Increments the consecutive-timeout streak; once it reaches
        _EDGE_BLOCK_THRESHOLD with no intervening real response, flags the host edge-blocked
        so `_http.fetch` fast-fails further requests instead of hanging. Never raises;
        changes ONLY request pacing/circuit state, never a finding."""
        host = self._host_of(url_or_host)
        if not host:
            return
        async with self._lock:
            bucket = self._buckets.get(host)
            if bucket is None:
                bucket = self._new_bucket(time.time())
                self._buckets[host] = bucket
            bucket.timeout_streak += 1
            bucket.ok_streak = 0
            if bucket.timeout_streak >= _EDGE_BLOCK_THRESHOLD and not bucket.edge_blocked:
                bucket.edge_blocked = True
                bucket.blocked_at = time.time()
                logger.debug("edge-block tripped for %s after %d consecutive timeouts",
                             host, bucket.timeout_streak)

    def is_edge_blocked(self, url_or_host: str) -> bool:
        """True while a host is flagged edge-blocked and still within its cooldown. After the
        cooldown elapses the flag is cleared optimistically so the next request re-probes the
        host (self-heal) — a transient tarpit is not blocked forever. Read-mostly; a benign
        race just costs one extra probe (pacing is never load-bearing)."""
        host = self._host_of(url_or_host)
        if not host:
            return False
        bucket = self._buckets.get(host)
        if bucket is None or not bucket.edge_blocked:
            return False
        if (time.time() - bucket.blocked_at) >= _EDGE_COOLDOWN_S:
            bucket.edge_blocked = False
            bucket.timeout_streak = 0
            return False
        return True


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


async def record_response(url_or_host: str, status: int, *,
                          waf_block: bool = False) -> None:
    """Feed a response status to the default limiter so a host that returns 429/503 — or a
    corroborated WAF block (``waf_block=True``) — is automatically backed off (and recovers
    on sustained success). No-op when unthrottled or on any error — pacing must never break
    a request."""
    if _unthrottled:
        return
    try:
        await _DEFAULT.record(url_or_host, status, waf_block=waf_block)
    except Exception:   # noqa: BLE001 — adaptive pacing is never load-bearing
        pass


async def record_timeout(url_or_host: str) -> None:
    """Feed a request timeout/unreachable outcome to the default limiter's edge-block
    detector. No-op when unthrottled or on any error — pacing must never break a request."""
    if _unthrottled:
        return
    try:
        await _DEFAULT.record_timeout(url_or_host)
    except Exception:   # noqa: BLE001 — edge-block detection is never load-bearing
        pass


def is_host_edge_blocked(url_or_host: str) -> bool:
    """True if the default limiter has flagged this host edge-blocked (tarpit/blackhole)
    and it is still within cooldown. Always False when unthrottled or on any error, so a
    detector fault can never suppress a legitimate request."""
    if _unthrottled:
        return False
    try:
        return _DEFAULT.is_edge_blocked(url_or_host)
    except Exception:   # noqa: BLE001
        return False


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
