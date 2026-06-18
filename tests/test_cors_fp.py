"""Regression tests for the CORS worker false positive.

Audit finding: a public, read-only JSON API / CDN endpoint that returns
``Access-Control-Allow-Origin: *`` WITHOUT ``Access-Control-Allow-Credentials:
true`` is a SAFE, intended configuration (per the Fetch spec a wildcard ACAO is
invalid together with credentials, so ``*`` alone exposes only data the server
already chose to make publicly readable). Flagging it as ``cors_wildcard`` is a
false positive (CWE-942 requires a credentialed or origin-trusting misconfig).

Test (a) reproduces the FP and must FAIL before the fix.
Test (b) proves a genuinely-vulnerable response (credentialed wildcard / reflected
attacker origin / null origin) still fires after the fix.
"""

import asyncio
from unittest.mock import patch

import core.swarm_workers  # noqa: F401 — registers workers
from core.swarm_engine import SwarmAgent
from core.swarm_workers import get_worker_runner
from core.swarm_workers.vuln._http import HttpResp


def _agent(url):
    return SwarmAgent(
        agent_id="t",
        objective="x",
        target=url,
        technique="cors",
        payload={},
        timeout_s=10.0,
    )


def _run(fake):
    async def go():
        with patch("core.swarm_workers.vuln.cors.fetch", side_effect=fake):
            run = get_worker_runner("vuln", "cors")
            return await run(_agent("http://127.0.0.1/api/v1/version"))
    return asyncio.run(go())


def test_public_wildcard_no_credentials_false_positive_not_flagged():
    """Audit scenario: public CDN/API with ACAO=* and NO ACAC. Must NOT flag."""
    async def fake(method, url, **kw):
        # Every request (attacker origin AND null origin) gets the same safe
        # public-API response: wildcard ACAO, no credentials.
        return HttpResp(
            200,
            {
                "access-control-allow-origin": "*",
                "content-type": "application/json",
                "cache-control": "public, max-age=3600",
            },
            '{"version":"1.4.2","status":"ok"}',
            url,
        )

    findings = _run(fake)
    assert findings == [], (
        "public wildcard ACAO without credentials is a safe public-API config, "
        f"not a vuln; worker should return [] but got: {findings}"
    )


def test_true_positive_still_fires():
    """A genuinely vulnerable server (credentialed wildcard + reflected attacker
    origin + null origin) must STILL produce findings."""
    async def fake(method, url, **kw):
        origin = (kw.get("headers") or {}).get("Origin", "")
        if origin == "null":
            # Server reflects/accepts null origin — exploitable.
            return HttpResp(
                200,
                {"access-control-allow-origin": "null",
                 "access-control-allow-credentials": "true"},
                "", url,
            )
        # Attacker origin probe: reflect it back WITH credentials = severe.
        return HttpResp(
            200,
            {"access-control-allow-origin": origin or "*",
             "access-control-allow-credentials": "true"},
            "", url,
        )

    findings = _run(fake)
    assert findings, "genuinely vulnerable CORS config must still fire"
    types = {f["vuln_type"] for f in findings}
    assert "cors_origin_reflect" in types, types
    assert "cors_null_origin" in types, types
    # Reflected attacker origin with credentials is high severity.
    assert any(f["severity"] == "high" for f in findings), findings


def test_credentialed_wildcard_still_fires():
    """`ACAO: *` WITH `ACAC: true` is the genuinely severe case (some non-browser
    clients honor it) and must remain a finding."""
    async def fake(method, url, **kw):
        return HttpResp(
            200,
            {"access-control-allow-origin": "*",
             "access-control-allow-credentials": "true"},
            "", url,
        )

    findings = _run(fake)
    assert findings, "credentialed wildcard must still fire"
    assert any(f["vuln_type"] == "cors_wildcard" for f in findings), findings
