"""Tests for the broken_access_control vuln worker."""
from __future__ import annotations

import asyncio
import sys
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import core.swarm_workers  # noqa: F401,E402
from core.swarm_engine import SwarmAgent  # noqa: E402
from core.swarm_workers import get_worker_runner, list_workers  # noqa: E402
from core.swarm_workers.vuln._http import HttpResp  # noqa: E402


def _agent(target="http://t", timeout=5.0):
    return SwarmAgent(agent_id="t", objective="bac", target=target,
                      technique="broken_access_control", payload={}, timeout_s=timeout)


def _run(fake):
    async def go():
        with patch("core.swarm_workers.vuln.broken_access_control.fetch",
                   side_effect=fake):
            return await get_worker_runner("vuln", "broken_access_control")(_agent())
    return asyncio.run(go())


class TestBrokenAccessControl:
    def test_registered(self):
        assert "broken_access_control" in list_workers("vuln")

    def test_flags_unauth_data_endpoint(self):
        async def fake(method, url, **kw):
            if url.endswith("/api/Feedbacks"):
                return HttpResp(200, {}, '{"status":"success","data":[{"UserId":1}]}', url)
            return HttpResp(401, {}, "<html>UnauthorizedError</html>", url)

        res = _run(fake)
        assert any(f["url"].endswith("/api/Feedbacks") for f in res)
        f = next(f for f in res if f["url"].endswith("/api/Feedbacks"))
        assert f["vuln_type"] == "access_control:missing_authorization"
        assert f["severity"] == "high"

    def test_flags_admin_json_object(self):
        async def fake(method, url, **kw):
            if url.endswith("/rest/admin/application-version"):
                return HttpResp(200, {}, '{"version":"20.0.0"}', url)
            return HttpResp(404, {}, "", url)

        res = _run(fake)
        assert any(f["url"].endswith("/rest/admin/application-version") for f in res)

    def test_no_fp_when_all_protected(self):
        async def fake(method, url, **kw):
            return HttpResp(401, {}, "<html>UnauthorizedError: No Authorization</html>", url)

        assert _run(fake) == []

    def test_no_fp_on_html_200(self):
        # A 200 that returns HTML (e.g. SPA index) is not a data leak.
        async def fake(method, url, **kw):
            return HttpResp(200, {}, "<!DOCTYPE html><html>app</html>", url)

        assert _run(fake) == []

    def test_scorer_matches_access_control(self):
        sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "benchmark"))
        from harness.scorer import score
        from harness.models import Challenge, RunResult
        ch = Challenge.from_dict({"id": "x", "mode": "vuln_class",
                                  "expect": {"vuln_types": ["idor", "access_control"]}})
        r = RunResult(challenge_id="x", target_url="http://t", findings=[
            {"vuln_type": "access_control:missing_authorization", "severity": "high",
             "url": "http://t/api/Feedbacks"}])
        assert score(ch, r).solved
