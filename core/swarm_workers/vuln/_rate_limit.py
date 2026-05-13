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


@dataclass
class _Bucket:
    rate_per_s: float
    burst: float
    tokens: float
    last_refill: float


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


# Module-level singleton — every worker reaches into this one.
_DEFAULT = HostRateLimiter()


async def wait_for_token(url_or_host: str, *, cost: float = 1.0) -> bool:
    """Convenience wrapper around the default limiter."""
    return await _DEFAULT.acquire(url_or_host, cost=cost)


def reset_for_tests() -> None:
    """Test helper — clear all bucket state."""
    _DEFAULT._buckets.clear()


def get_default() -> HostRateLimiter:
    return _DEFAULT
