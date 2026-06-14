"""Tests for the request_smuggling worker (timing logic, mocked — no network)."""
import asyncio
import sys
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import core.swarm_workers  # noqa: F401
from core.swarm_engine import SwarmAgent
from core.swarm_workers import get_worker_runner, list_workers
import core.swarm_workers.vuln.request_smuggling as rs


def _agent(target="https://t/"):
    return SwarmAgent(agent_id="t", objective="x", target=target,
                      technique="request_smuggling", payload={}, timeout_s=10.0)


def _run_with(timings):
    """timings: callable(payload_bytes) -> (elapsed, timed_out). Patches the raw
    socket send so no network is touched."""
    async def fake_timed(host, port, use_tls, payload):
        return timings(payload)

    async def go():
        with patch.object(rs, "_timed", side_effect=fake_timed):
            return await get_worker_runner("vuln", "request_smuggling")(_agent())
    return asyncio.run(go())


def _is_probe(payload: bytes) -> bool:
    return b"Transfer-Encoding: chunked" in payload


class TestRequestSmuggling:
    def test_registered(self):
        assert "request_smuggling" in list_workers("vuln")

    def test_clte_timing_desync_flagged(self):
        # Baseline fast; ANY chunked probe hangs (timed out) and reproduces.
        def timings(payload):
            return (8.0, True) if _is_probe(payload) else (0.2, False)
        findings = _run_with(timings)
        assert findings, "expected a smuggling finding on a reproducing hang"
        f = findings[0]
        assert f["vuln_type"].startswith("request_smuggling:")
        assert f["cwe"] == "CWE-444"
        assert f["needs_manual_confirmation"] is True
        assert f["confidence"] < 0.7  # timing signal is not high-confidence

    def test_slow_backend_is_not_flagged(self):
        # Everything is slow (a sluggish backend) — baseline also slow, so the
        # differential collapses and nothing should be flagged.
        def timings(payload):
            return (9.0, True)  # baseline ALSO hangs -> bail / no differential
        assert _run_with(timings) == []

    def test_fast_clean_server_not_flagged(self):
        def timings(payload):
            return (0.3, False)  # everything fast -> no desync
        assert _run_with(timings) == []

    def test_non_reproducing_delay_suppressed(self):
        # First probe hangs but the confirmation probe is fast -> transient, drop.
        state = {"probe_calls": 0}
        def timings(payload):
            if _is_probe(payload):
                state["probe_calls"] += 1
                return (8.0, True) if state["probe_calls"] == 1 else (0.3, False)
            return (0.2, False)
        assert _run_with(timings) == []
