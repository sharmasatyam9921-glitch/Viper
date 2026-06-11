"""Tests for the path_bypass vuln worker (401/403 access-control bypass)."""
from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import core.swarm_workers  # noqa: F401,E402  (registers workers)
from core.swarm_engine import SwarmAgent  # noqa: E402
from core.swarm_workers import get_worker_runner, list_workers  # noqa: E402
from core.swarm_workers.vuln._http import HttpResp  # noqa: E402

# A forbidden baseline body vs. a real unlocked body (different + larger).
_FORBIDDEN = "403 Forbidden"
_REAL = "<html><body>secret admin dashboard with lots of real content here</body></html>"


def _agent(target="http://t/admin", timeout=5.0):
    return SwarmAgent(agent_id="t", objective="path bypass", target=target,
                      technique="path_bypass", payload={}, timeout_s=timeout)


def _run(fake, target="http://t/admin"):
    import asyncio

    async def go():
        with patch("core.swarm_workers.vuln.path_bypass.fetch", side_effect=fake):
            return await get_worker_runner("vuln", "path_bypass")(_agent(target))

    return asyncio.run(go())


class TestPathBypass:
    def test_registered(self):
        assert "path_bypass" in list_workers("vuln")

    def test_detects_path_suffix_bypass(self):
        # Base GET → 403. The "/..;/" path mutation flips to a real 200 body.
        async def fake(method, url, **kw):
            if url == "http://t/admin" and not kw.get("headers"):
                return HttpResp(403, {}, _FORBIDDEN, url)
            if url.endswith("/..;/"):
                return HttpResp(200, {}, _REAL, url)
            return HttpResp(403, {}, _FORBIDDEN, url)

        result = _run(fake)
        assert result, "expected an access-control bypass finding"
        f = result[0]
        assert "access_control" in f["vuln_type"]
        assert f["vuln_type"] == "access_control:403_bypass"
        assert f["cwe"] == "CWE-285"
        assert f["severity"] == "high"
        assert f["payload"] == "/..;/"

    def test_detects_header_bypass(self):
        # The trusted-IP header flips a 401 gate to a real 200.
        async def fake(method, url, **kw):
            headers = kw.get("headers") or {}
            if "X-Forwarded-For" in headers:
                return HttpResp(200, {}, _REAL, url)
            return HttpResp(401, {}, "401 Unauthorized", url)

        result = _run(fake)
        assert result, "expected a header-based bypass finding"
        assert result[0]["vuln_type"] == "access_control:401_bypass"
        assert any("X-Forwarded-For" in f["payload"] for f in result)

    def test_no_fp_when_base_not_forbidden(self):
        # Base URL is a normal 200 — worker must not probe at all.
        async def fake(method, url, **kw):
            return HttpResp(200, {}, _REAL, url)

        assert _run(fake) == []

    def test_no_fp_when_mutations_stay_forbidden(self):
        # Base 403 but every mutation also stays forbidden → no finding.
        async def fake(method, url, **kw):
            return HttpResp(403, {}, _FORBIDDEN, url)

        assert _run(fake) == []

    def test_no_fp_when_unlock_body_same_as_baseline(self):
        # A mutation returns 200 but echoes the SAME forbidden body (error page
        # served at 200) — not a real unlock, so no finding.
        async def fake(method, url, **kw):
            if url == "http://t/admin" and not kw.get("headers"):
                return HttpResp(403, {}, _FORBIDDEN, url)
            return HttpResp(200, {}, _FORBIDDEN, url)

        assert _run(fake) == []

    def test_no_fp_on_network_error(self):
        async def fake(method, url, **kw):
            return None

        assert _run(fake) == []

    def test_scorer_matches_access_control_class(self):
        sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "benchmark"))
        from harness.scorer import score
        from harness.models import Challenge, RunResult
        ch = Challenge.from_dict({"id": "x", "mode": "vuln_class",
                                  "expect": {"vuln_types": ["access_control"],
                                             "min_severity": "medium"}})
        r = RunResult(challenge_id="x", target_url="http://t/admin", findings=[
            {"vuln_type": "access_control:403_bypass", "severity": "high",
             "url": "http://t/admin"}])
        assert score(ch, r).solved
