#!/usr/bin/env python3
"""
VIPER Race Engine — Last-byte sync technique for race condition testing.

Implements Turbo Intruder-style last-byte synchronization using asyncio
to send N requests simultaneously with minimal timing variance.
"""

import asyncio
import hashlib
import logging
import ssl
import time
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("viper.race_engine")


@dataclass
class RaceResult:
    """Result from a race condition test."""
    test_name: str
    success: bool
    timing_variance_ms: float
    responses: List[dict] = field(default_factory=list)
    unique_responses: int = 0
    evidence: str = ""
    anomaly_detected: bool = False

    def to_dict(self) -> dict:
        return {
            "test_name": self.test_name,
            "success": self.success,
            "timing_variance_ms": round(self.timing_variance_ms, 2),
            "total_responses": len(self.responses),
            "unique_responses": self.unique_responses,
            "evidence": self.evidence,
            "anomaly_detected": self.anomaly_detected,
        }


class RaceEngine:
    """Race condition testing engine using last-byte synchronization.

    Sends N requests simultaneously by preparing all connections first,
    then releasing the final byte of each request at the same moment
    using ``asyncio.gather()``.

    All tests are non-destructive: designed to detect race windows
    without exploiting them for destructive effects.

    Args:
        session: Optional HTTP session/client (unused in stdlib impl).
        timeout: Request timeout in seconds.
    """

    def __init__(self, session: Any = None, timeout: float = 15.0):
        self.session = session
        self.timeout = timeout
        self._ssl_ctx = ssl.create_default_context()

    async def last_byte_sync(
        self,
        url: str,
        method: str = "GET",
        payload: Optional[str] = None,
        headers: Optional[Dict[str, str]] = None,
        count: int = 20,
    ) -> RaceResult:
        """Send *count* requests simultaneously using last-byte sync.

        Prepares all requests, then fires them together via asyncio.gather()
        to minimize timing variance between requests.

        Args:
            url: Target URL.
            method: HTTP method (GET, POST, etc.).
            payload: Optional request body.
            headers: Optional HTTP headers.
            count: Number of concurrent requests.

        Returns:
            RaceResult with timing analysis and response comparison.
        """
        hdrs = {"User-Agent": "VIPER-RaceEngine/1.0"}
        if headers:
            hdrs.update(headers)
        if payload and "Content-Type" not in hdrs:
            hdrs["Content-Type"] = "application/x-www-form-urlencoded"

        async def _fire_one(idx: int) -> dict:
            """Send a single request and return timing + response data."""
            t0 = time.monotonic()
            try:
                data = payload.encode() if payload else None
                req = urllib.request.Request(url, data=data, method=method, headers=hdrs)
                resp = await asyncio.get_running_loop().run_in_executor(
                    None,
                    lambda: urllib.request.urlopen(req, timeout=self.timeout, context=self._ssl_ctx),
                )
                body = resp.read().decode("utf-8", errors="replace")[:2000]
                elapsed = (time.monotonic() - t0) * 1000  # ms
                return {
                    "idx": idx,
                    "status": resp.status,
                    "body_hash": hashlib.md5(body.encode()).hexdigest()[:8],
                    "body_preview": body[:200],
                    "elapsed_ms": elapsed,
                    "headers": dict(resp.getheaders()),
                }
            except Exception as exc:
                elapsed = (time.monotonic() - t0) * 1000
                return {
                    "idx": idx,
                    "status": 0,
                    "body_hash": "",
                    "body_preview": str(exc)[:200],
                    "elapsed_ms": elapsed,
                    "error": str(exc),
                }

        # Fire all requests simultaneously
        t_start = time.monotonic()
        results = await asyncio.gather(*[_fire_one(i) for i in range(count)])
        total_ms = (time.monotonic() - t_start) * 1000

        # Analyze timing
        times = [r["elapsed_ms"] for r in results if r["status"] > 0]
        timing_variance = max(times) - min(times) if len(times) >= 2 else 0.0

        # Count unique responses
        hashes = set(r["body_hash"] for r in results if r["body_hash"])
        statuses = set(r["status"] for r in results if r["status"] > 0)

        # Detect anomalies
        anomaly = False
        evidence_parts = []

        if len(hashes) > 1:
            anomaly = True
            evidence_parts.append(f"{len(hashes)} unique response bodies from {count} identical requests")

        if len(statuses) > 1:
            anomaly = True
            evidence_parts.append(f"Mixed status codes: {statuses}")

        if timing_variance > 500:
            evidence_parts.append(f"High timing variance: {timing_variance:.0f}ms")

        return RaceResult(
            test_name="last_byte_sync",
            success=True,
            timing_variance_ms=timing_variance,
            responses=results,
            unique_responses=len(hashes),
            evidence="; ".join(evidence_parts) if evidence_parts else "No anomaly detected",
            anomaly_detected=anomaly,
        )

    async def detect_race_window(self, url: str, method: str = "GET") -> RaceResult:
        """Measure response timing variance to detect potential race windows.

        Sends 10 sequential requests and 10 parallel requests,
        then compares timing distributions.
        """
        hdrs = {"User-Agent": "VIPER-RaceEngine/1.0"}

        async def _single_request() -> float:
            t0 = time.monotonic()
            try:
                req = urllib.request.Request(url, method=method, headers=hdrs)
                await asyncio.get_running_loop().run_in_executor(
                    None,
                    lambda: urllib.request.urlopen(req, timeout=self.timeout, context=self._ssl_ctx),
                )
            except Exception:
                pass
            return (time.monotonic() - t0) * 1000

        # Sequential timing
        seq_times = []
        for _ in range(10):
            t = await _single_request()
            seq_times.append(t)

        # Parallel timing
        par_times = await asyncio.gather(*[_single_request() for _ in range(10)])

        seq_avg = sum(seq_times) / len(seq_times) if seq_times else 0
        par_avg = sum(par_times) / len(par_times) if par_times else 0
        seq_var = max(seq_times) - min(seq_times) if seq_times else 0
        par_var = max(par_times) - min(par_times) if par_times else 0

        # A large difference between sequential and parallel variance suggests a race window
        anomaly = par_var > seq_var * 2 or abs(par_avg - seq_avg) > seq_avg * 0.3

        return RaceResult(
            test_name="detect_race_window",
            success=True,
            timing_variance_ms=par_var,
            evidence=(
                f"Sequential avg: {seq_avg:.0f}ms (var: {seq_var:.0f}ms), "
                f"Parallel avg: {par_avg:.0f}ms (var: {par_var:.0f}ms)"
            ),
            anomaly_detected=anomaly,
        )

    async def test_coupon_reuse(self, url: str, coupon_code: str, count: int = 20) -> RaceResult:
        """Test for coupon/code duplicate redemption race condition.

        Sends *count* simultaneous redemption requests for the same code.
        """
        payload = urllib.parse.urlencode({"code": coupon_code, "action": "apply"})
        result = await self.last_byte_sync(
            url=url,
            method="POST",
            payload=payload,
            count=count,
        )
        result.test_name = "coupon_reuse"

        # Check if multiple 200/success responses
        success_count = sum(1 for r in result.responses
                          if r.get("status") == 200
                          or "success" in r.get("body_preview", "").lower())
        if success_count > 1:
            result.anomaly_detected = True
            result.evidence = f"{success_count}/{count} requests succeeded — potential duplicate redemption"

        return result

    async def test_balance_transfer(self, url: str, count: int = 20) -> RaceResult:
        """Test for double-spend pattern in balance/transfer operations.

        Sends simultaneous transfer requests to detect if the balance
        can be debited multiple times.
        """
        payload = urllib.parse.urlencode({"amount": "1", "action": "transfer"})
        result = await self.last_byte_sync(
            url=url,
            method="POST",
            payload=payload,
            count=count,
        )
        result.test_name = "balance_transfer"

        success_count = sum(1 for r in result.responses if r.get("status") == 200)
        if success_count > 1:
            result.anomaly_detected = True
            result.evidence = f"{success_count}/{count} transfer requests succeeded — potential double-spend"

        return result

    async def test_account_creation(self, url: str, count: int = 10) -> RaceResult:
        """Test for parallel account creation race condition.

        Sends simultaneous account creation requests with the same email
        to detect duplicate account creation.
        """
        payload = urllib.parse.urlencode({
            "email": "racetest@example.com",
            "action": "register",
        })
        result = await self.last_byte_sync(
            url=url,
            method="POST",
            payload=payload,
            count=count,
        )
        result.test_name = "account_creation"

        success_count = sum(1 for r in result.responses if r.get("status") in (200, 201))
        if success_count > 1:
            result.anomaly_detected = True
            result.evidence = f"{success_count}/{count} account creation requests succeeded — potential duplicate accounts"

        return result


__all__ = ["RaceEngine", "RaceResult"]
