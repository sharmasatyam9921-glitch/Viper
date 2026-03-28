"""Centralized rate limiter for all VIPER modules.

Usage:
    from core.rate_limiter import RateLimiter
    limiter = RateLimiter.get_instance()
    limiter.wait("http")       # blocks until a token is available
    limiter.acquire("llm")     # returns True/False
    limiter.configure("http", requests_per_second=10.0)
"""

import time
import threading


class RateLimiter:
    """Thread-safe token bucket rate limiter with per-category buckets."""

    _instance = None
    _init_lock = threading.Lock()

    @classmethod
    def get_instance(cls) -> "RateLimiter":
        if cls._instance is None:
            with cls._init_lock:
                if cls._instance is None:
                    cls._instance = cls()
        return cls._instance

    def __init__(self):
        self._buckets = {}
        self._lock = threading.Lock()
        # Sensible defaults
        self.configure("http", requests_per_second=5.0)
        self.configure("llm", requests_per_second=0.5)   # 30 RPM
        self.configure("recon", requests_per_second=2.0)
        self.configure("nuclei", requests_per_second=10.0)

    def configure(self, category: str, requests_per_second: float):
        """Set or update rate limit for a category."""
        with self._lock:
            self._buckets[category] = {
                "tokens": requests_per_second,
                "max_tokens": requests_per_second * 2,  # burst allowance
                "rate": requests_per_second,
                "last_refill": time.monotonic(),
            }

    def acquire(self, category: str = "http", timeout: float = 30.0) -> bool:
        """Try to acquire a token. Returns True if acquired within timeout."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            with self._lock:
                bucket = self._buckets.get(category)
                if not bucket:
                    return True  # unconfigured category = unlimited
                now = time.monotonic()
                elapsed = now - bucket["last_refill"]
                bucket["tokens"] = min(
                    bucket["max_tokens"],
                    bucket["tokens"] + elapsed * bucket["rate"],
                )
                bucket["last_refill"] = now
                if bucket["tokens"] >= 1.0:
                    bucket["tokens"] -= 1.0
                    return True
            time.sleep(0.05)
        return False

    def wait(self, category: str = "http"):
        """Block until a token is available (up to 60s)."""
        self.acquire(category, timeout=60.0)

    def get_stats(self) -> dict:
        """Return current bucket states."""
        with self._lock:
            return {
                cat: {
                    "tokens": round(b["tokens"], 2),
                    "rate": b["rate"],
                    "max": b["max_tokens"],
                }
                for cat, b in self._buckets.items()
            }


class HumanTimingProfile:
    """Replace fixed delays with Gaussian-distributed human-like timing.

    Profiles:
    - CAUTIOUS: mu=3.0s (sensitive targets)
    - NORMAL: mu=1.0s (default)
    - AGGRESSIVE: mu=0.3s (fast targets with high rate limits)

    Features:
    - Gaussian distribution with sigma = mu * 0.3
    - Burst detection: auto-switch to CAUTIOUS if >10 requests in 5s
    - Session-level request counter with rolling window
    """

    CAUTIOUS = "cautious"
    NORMAL = "normal"
    AGGRESSIVE = "aggressive"

    PROFILES = {
        "cautious": 3.0,
        "normal": 1.0,
        "aggressive": 0.3,
    }

    def __init__(self, profile: str = "normal"):
        import random as _random
        self._random = _random
        self._profile = profile if profile in self.PROFILES else "normal"
        self._mu = self.PROFILES[self._profile]
        self._request_times: list = []  # rolling window of timestamps
        self._burst_threshold = 10
        self._burst_window = 5.0  # seconds
        self._lock = threading.Lock()

    @property
    def profile(self) -> str:
        return self._profile

    @profile.setter
    def profile(self, value: str) -> None:
        if value in self.PROFILES:
            self._profile = value
            self._mu = self.PROFILES[value]

    def get_delay(self) -> float:
        """Return a Gaussian-distributed delay.

        Automatically detects bursts and switches to CAUTIOUS if needed.
        """
        self._check_burst()
        sigma = self._mu * 0.3
        delay = max(0.1, self._random.gauss(self._mu, sigma))

        # Record this request
        with self._lock:
            self._request_times.append(time.monotonic())

        return delay

    def _check_burst(self) -> None:
        """Detect request bursts and auto-escalate to CAUTIOUS."""
        now = time.monotonic()
        with self._lock:
            # Remove old entries outside the window
            self._request_times = [
                t for t in self._request_times
                if now - t < self._burst_window
            ]

            if len(self._request_times) >= self._burst_threshold:
                if self._profile != self.CAUTIOUS:
                    self._profile = self.CAUTIOUS
                    self._mu = self.PROFILES[self.CAUTIOUS]

    async def async_delay(self) -> None:
        """Async version: sleep for a human-like delay."""
        import asyncio
        delay = self.get_delay()
        await asyncio.sleep(delay)

    def sync_delay(self) -> None:
        """Sync version: sleep for a human-like delay."""
        delay = self.get_delay()
        time.sleep(delay)

    def get_stats(self) -> dict:
        """Return timing profile statistics."""
        now = time.monotonic()
        with self._lock:
            recent = [t for t in self._request_times if now - t < self._burst_window]
        return {
            "profile": self._profile,
            "mu": self._mu,
            "requests_in_window": len(recent),
            "burst_threshold": self._burst_threshold,
        }
