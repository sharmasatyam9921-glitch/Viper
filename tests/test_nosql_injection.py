"""Tests for the nosql_injection vuln worker (operator-injection bypass + query)."""
from __future__ import annotations

import asyncio
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
    return SwarmAgent(agent_id="t", objective="nosql injection", target=target,
                      technique="nosql_injection", payload={}, timeout_s=timeout)


def _run(fake, target="http://t"):
    async def go():
        with patch("core.swarm_workers.vuln.nosql_injection.fetch", side_effect=fake):
            return await get_worker_runner("vuln", "nosql_injection")(_agent(target))

    return asyncio.run(go())


def _is_op_body(body: bytes) -> bool:
    """True when the JSON body carries a Mongo operator (the injection)."""
    s = (body or b"").decode()
    return "$gt" in s or "$ne" in s


class TestNoSqlInjection:
    def test_registered(self):
        assert "nosql_injection" in list_workers("vuln")

    def test_detects_login_operator_bypass(self):
        async def fake(method, url, **kw):
            if not url.endswith("/rest/user/login"):
                return HttpResp(404, {}, "", url)
            body = kw.get("body") or b""
            # Operator body → token; bogus baseline (plain strings) → 401.
            if _is_op_body(body):
                return HttpResp(200, {}, '{"authentication":{"token":"%s"}}' % _JWT, url)
            return HttpResp(401, {}, '{"error":"invalid"}', url)

        result = _run(fake)
        assert result, "expected a NoSQL auth-bypass finding"
        f = result[0]
        assert "nosql" in f["vuln_type"]
        assert f["vuln_type"] == "nosql_injection:login"
        assert f["severity"] == "critical"
        assert f["cwe"] == "CWE-943"
        assert "/rest/user/login" in f["url"]
        assert "$" in f["payload"]

    def test_no_fp_when_endpoint_tokens_everyone(self):
        # Baseline ALSO returns a token → not an injection signal.
        async def fake(method, url, **kw):
            if not url.endswith("/rest/user/login"):
                return HttpResp(404, {}, "", url)
            return HttpResp(200, {}, '{"authentication":{"token":"%s"}}' % _JWT, url)

        assert _run(fake) == []

    def test_no_fp_when_no_token(self):
        async def fake(method, url, **kw):
            return HttpResp(401, {}, '{"error":"invalid"}', url)

        assert _run(fake) == []

    def test_detects_query_param_divergence(self):
        # No login path responds; a query param with an operator makes the
        # false-baseline query start matching (404 → 200 with a big body).
        async def fake(method, url, **kw):
            if "/login" in url or "/signin" in url:
                return HttpResp(404, {}, "", url)
            if "viper_nomatch" in url and ("$ne" in url or "$gt" in url):
                # operator injected on the key → matches everything
                return HttpResp(200, {}, "RECORDS" + "x" * 4000, url)
            if "viper_nomatch" in url:
                # plain non-existent value → no match
                return HttpResp(404, {}, "not found", url)
            return HttpResp(200, {}, "ok", url)

        result = _run(fake, target="http://t/api/users?role=user")
        assert result, "expected a NoSQL query-param finding"
        f = result[0]
        assert "nosql" in f["vuln_type"]
        assert f["cwe"] == "CWE-943"
        assert f["parameter"] == "role"

    def test_no_fp_query_when_no_divergence(self):
        # Every variant returns the same benign 404 → no signal.
        async def fake(method, url, **kw):
            if "/login" in url or "/signin" in url:
                return HttpResp(404, {}, "", url)
            return HttpResp(404, {}, "not found", url)

        assert _run(fake, target="http://t/api/users?role=user") == []

    def test_scorer_matches_nosql_class(self):
        sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "benchmark"))
        from harness.scorer import score
        from harness.models import Challenge, RunResult
        ch = Challenge.from_dict({"id": "x", "mode": "vuln_class",
                                  "expect": {"vuln_types": ["nosql_injection"],
                                             "min_severity": "medium"}})
        r = RunResult(challenge_id="x", target_url="http://t", findings=[
            {"vuln_type": "nosql_injection:login", "severity": "critical",
             "url": "http://t/rest/user/login"}])
        assert score(ch, r).solved