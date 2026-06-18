"""False-positive regression tests for the nosql_injection vuln worker.

Audit scenario: a non-vulnerable login endpoint with always-200 error
envelopes plus a schema validator. The bogus-credential baseline returns
200 {"error":"user not found"} (no token), and the operator payload trips a
*validation* error returning 200 {"errors":{"authentication":"email and
password must be strings"}}. The bare JSON key "authentication" matched the
old _TOKEN_KEYS regex, so _has_token() reported a token even though NO session
was issued and NO Mongo query ran -> a CRITICAL auth_bypass_confirmed FP.

The fix: _has_token must require a real token VALUE (a JWT, or a
token-shaped key paired with a long token-like string value), never a bare
key name that a benign validation/error envelope happens to contain.
"""
from __future__ import annotations

import asyncio
import sys
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import core.swarm_workers  # noqa: F401,E402  (registers workers)
from core.swarm_engine import SwarmAgent  # noqa: E402
from core.swarm_workers import get_worker_runner  # noqa: E402
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


def test_nosql_login_false_positive_not_flagged():
    """The audit FP: a non-vulnerable endpoint whose validation-error envelope
    merely contains the literal key "authentication". No real token / session
    was ever issued, so the worker must NOT report an auth bypass."""
    def baseline_body():
        # bogus credential -> always-200 error envelope, no token keyword
        return '{"error":"user not found"}'

    def validator_body():
        # operator (non-string) payload trips the schema validator on a
        # SEPARATE code path. The literal key "authentication" appears but
        # there is NO token value and NO query ran.
        return '{"errors":{"authentication":"email and password must be strings"}}'

    async def fake(method, url, **kw):
        if not url.endswith("/rest/user/login"):
            # other login paths simply 404; query mode has no params on http://t
            return HttpResp(404, {}, "", url)
        body = kw.get("body") or b""
        if _is_op_body(body):
            return HttpResp(200, {}, validator_body(), url)
        return HttpResp(200, {}, baseline_body(), url)

    assert _run(fake) == [], (
        "non-vulnerable endpoint (validation error mentioning 'authentication', "
        "no token issued) was wrongly flagged as a NoSQL auth bypass"
    )


def test_nosql_login_true_positive_still_fires():
    """A GENUINELY vulnerable endpoint: bogus credentials get a 200 with NO
    token, but the operator-injection body returns a 200 carrying a real JWT
    session token. The worker MUST still report the auth bypass."""
    async def fake(method, url, **kw):
        if not url.endswith("/rest/user/login"):
            return HttpResp(404, {}, "", url)
        body = kw.get("body") or b""
        if _is_op_body(body):
            # operator made the credential comparison match anything -> real session
            return HttpResp(200, {}, '{"authentication":{"token":"%s"}}' % _JWT, url)
        # bogus credential -> rejected, no token
        return HttpResp(401, {}, '{"error":"invalid credentials"}', url)

    result = _run(fake)
    assert result, "genuinely vulnerable NoSQL auth bypass was missed"
    f = result[0]
    assert f["vuln_type"] == "nosql_injection:login"
    assert f["severity"] == "critical"
    assert f["cwe"] == "CWE-943"
    assert "/rest/user/login" in f["url"]
