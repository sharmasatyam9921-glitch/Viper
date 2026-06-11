"""Tests for the login_sqli vuln worker (JSON + form SQLi auth bypass)."""
from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import core.swarm_workers  # noqa: F401,E402  (registers workers)
from core.swarm_engine import SwarmAgent  # noqa: E402
from core.swarm_workers import get_worker_runner, list_workers  # noqa: E402
from core.swarm_workers.vuln._http import HttpResp  # noqa: E402

_JWT = "eyJhbGciOiJSUzI1NiJ9.eyJzdGF0dXMiOiJzdWNjZXNzIn0.AAAABBBBCCCCDDDD"


def _agent(target="http://t", timeout=5.0):
    return SwarmAgent(agent_id="t", objective="login sqli", target=target,
                      technique="login_sqli", payload={}, timeout_s=timeout)


def _run(fake):
    import asyncio

    async def go():
        with patch("core.swarm_workers.vuln.login_sqli.fetch", side_effect=fake):
            return await get_worker_runner("vuln", "login_sqli")(_agent())

    return asyncio.run(go())


class TestLoginSqli:
    def test_registered(self):
        assert "login_sqli" in list_workers("vuln")

    def test_detects_json_login_bypass(self):
        async def fake(method, url, **kw):
            if not url.endswith("/rest/user/login"):
                return HttpResp(404, {}, "", url)
            body = (kw.get("body") or b"").decode()
            # SQLi payload → token; bogus baseline → 401 no token.
            if "OR 1=1" in body or "1'='1" in body:
                return HttpResp(200, {}, '{"authentication":{"token":"%s"}}' % _JWT, url)
            return HttpResp(401, {}, '{"error":"invalid"}', url)

        result = _run(fake)
        assert result, "expected an auth-bypass finding"
        f = result[0]
        assert f["vuln_type"] == "auth_bypass:sqli_login"
        assert f["severity"] == "critical"
        assert "/rest/user/login" in f["url"]

    def test_no_fp_when_endpoint_tokens_everyone(self):
        # If the bogus baseline ALSO returns a token, it's not a SQLi signal.
        async def fake(method, url, **kw):
            if not url.endswith("/rest/user/login"):
                return HttpResp(404, {}, "", url)
            return HttpResp(200, {}, '{"authentication":{"token":"%s"}}' % _JWT, url)

        assert _run(fake) == []

    def test_no_fp_when_no_token(self):
        async def fake(method, url, **kw):
            return HttpResp(401, {}, '{"error":"invalid"}', url)

        assert _run(fake) == []

    def test_scorer_matches_auth_bypass_class(self):
        sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "benchmark"))
        from harness.scorer import score
        from harness.models import Challenge, RunResult
        ch = Challenge.from_dict({"id": "x", "mode": "vuln_class",
                                  "expect": {"vuln_types": ["sql_injection", "auth_bypass"],
                                             "min_severity": "medium"}})
        r = RunResult(challenge_id="x", target_url="http://t", findings=[
            {"vuln_type": "auth_bypass:sqli_login", "severity": "critical",
             "url": "http://t/rest/user/login"}])
        assert score(ch, r).solved
