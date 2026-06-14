"""Tests for the race_condition vuln worker (mocked — no network).

The worker is STATE-CHANGING, so its safety contract is the most important
thing under test: it must do NOTHING unless an operator explicitly opted in
with payload {"enable_race": True}.
"""
import asyncio
import sys
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import core.swarm_workers  # noqa: F401
from core.swarm_engine import SwarmAgent
from core.swarm_workers import get_worker_runner, list_workers
from core.swarm_workers.vuln._http import HttpResp


def _agent(target="http://t/", timeout=5.0, payload=None):
    return SwarmAgent(agent_id="t", objective="x", target=target,
                      technique="race_condition",
                      payload={} if payload is None else payload,
                      timeout_s=timeout)


def _run(fake, agent):
    async def go():
        with patch("core.swarm_workers.vuln.race_condition.fetch", side_effect=fake):
            return await get_worker_runner("vuln", "race_condition")(agent)
    return asyncio.run(go())


def _resp(status, body=""):
    return HttpResp(status, {}, body, "http://t/")


class TestRaceCondition:
    def test_registered(self):
        assert "race_condition" in list_workers("vuln")

    def test_default_does_nothing(self):
        """CRITICAL SAFETY: with no enable_race flag the worker must be a
        complete no-op — return [] AND never call fetch."""
        calls = {"n": 0}

        async def fake(*a, **kw):
            calls["n"] += 1
            return _resp(200, "ok")

        # Default payload {} — not opted in.
        assert _run(fake, _agent()) == []
        # Explicit payload but flag is falsy — still off.
        assert _run(fake, _agent(payload={"enable_race": False})) == []
        # No payload at all (None) — still off.
        assert _run(fake, _agent(payload={})) == []
        assert calls["n"] == 0, "worker fired requests while disabled"

    def test_enabled_divergent_responses_flagged(self):
        """Opted-in + responses split into status clusters -> candidate."""
        # One request "wins" (200), the rest lose the race (409 Conflict).
        seq = iter([
            _resp(200, "claimed"),
            _resp(409, "already claimed"),
            _resp(409, "already claimed"),
            _resp(409, "already claimed"),
            _resp(409, "already claimed"),
            _resp(409, "already claimed"),
            _resp(409, "already claimed"),
            _resp(409, "already claimed"),
        ])

        async def fake(*a, **kw):
            return next(seq)

        findings = _run(fake, _agent(payload={"enable_race": True}))
        assert findings, "expected a race candidate on divergent responses"
        f = findings[0]
        assert "race_condition" in f["vuln_type"]
        assert f["cwe"] == "CWE-362"
        assert f["severity"] == "high"
        assert f["confidence"] <= 0.5
        assert f["needs_manual_confirmation"] is True
        assert "state-changing" in f["evidence"].lower()

    def test_enabled_identical_responses_not_flagged(self):
        """Opted-in but every response is identical -> no race signal -> []."""
        async def fake(*a, **kw):
            return _resp(200, "same body for everyone")

        assert _run(fake, _agent(payload={"enable_race": True})) == []

    def test_enabled_burst_is_capped_small(self):
        """Even when opted in, the burst stays small (<=8) and non-destructive
        — verify we never fire more than the documented cap."""
        calls = {"n": 0}

        async def fake(*a, **kw):
            calls["n"] += 1
            return _resp(200, "same")

        _run(fake, _agent(payload={"enable_race": True, "race_burst": 50}))
        assert calls["n"] <= 8, f"burst exceeded cap: {calls['n']}"
        assert calls["n"] >= 2

    def test_enabled_network_failure_no_false_positive(self):
        """If too few requests come back alive, emit nothing (no signal)."""
        state = {"n": 0}

        async def fake(*a, **kw):
            state["n"] += 1
            return _resp(200, "ok") if state["n"] == 1 else None  # rest error out

        assert _run(fake, _agent(payload={"enable_race": True})) == []
