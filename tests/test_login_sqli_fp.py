"""False-positive regression tests for the login_sqli vuln worker.

Audit scenario: a NON-vulnerable login endpoint whose input validation diverges
by request shape, not by authentication. The clean baseline
(no_such_user_8f31@example.com) is a syntactically valid email, so the server
returns a generic 401 with NO token -> baseline correctly yields no token. The
SQLi payload ' OR 1=1-- FAILS email-format validation, so the server returns a
200 carrying a re-rendered login form that embeds a fresh anti-CSRF field named
"token" (a short opaque nonce, NOT a session). Nobody is authenticated and no
JWT/session is issued, yet the worker's _has_token() matched the bare "token"
JSON key regardless of value and reported a critical auth bypass.

Test (a) reproduces that FP (must FAIL pre-fix). Test (b) proves a genuinely
vulnerable endpoint (real JWT issued only by the SQLi payload, absent from the
validation-error baseline) STILL fires.
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

# A real JWT: header.payload.signature with an eyJ payload carrying a subject.
# payload decodes to {"sub":"1","name":"admin","role":"admin"}
_REAL_JWT = (
    "eyJhbGciOiJIUzI1NiJ9."
    "eyJzdWIiOiIxIiwibmFtZSI6ImFkbWluIiwicm9sZSI6ImFkbWluIn0."
    "S0meRealL00kingSignature_AAAABBBBCCCC"
)

# A short anti-CSRF nonce that happens to live under a "token" JSON key. NOT a
# session credential -- it is the form-retry token, present only because the
# malformed email failed validation.
_CSRF_NONCE = "a1b2c3d4"


def _agent(target="http://t", timeout=5.0):
    return SwarmAgent(agent_id="t", objective="login sqli", target=target,
                      technique="login_sqli", payload={}, timeout_s=timeout)


def _run(fake):
    async def go():
        with patch("core.swarm_workers.vuln.login_sqli.fetch", side_effect=fake):
            return await get_worker_runner("vuln", "login_sqli")(_agent())

    return asyncio.run(go())


def _body_ident(kw) -> str:
    """The identity sent in this request (so the fake can branch on the payload)."""
    return (kw.get("body") or b"").decode("utf-8", "replace")


class TestLoginSqliFalsePositive:
    def test_validation_csrf_token_not_flagged(self):
        """Audit FP: malformed-email validation error returns a 200 with an
        anti-CSRF "token" key. Worker must NOT report an auth bypass."""

        async def fake(method, url, **kw):
            if not url.endswith("/rest/user/login"):
                return HttpResp(404, {}, "", url)
            ident = _body_ident(kw)
            # SQLi payload contains a single-quote -> fails email validation.
            if "'" in ident or "1=1" in ident or "1'='1" in ident:
                # 200 validation-error envelope carrying a CSRF retry token.
                return HttpResp(
                    200, {"content-type": "application/json"},
                    '{"error":"validation_failed","field":"email",'
                    '"token":"%s"}' % _CSRF_NONCE, url)
            # Well-formed-but-wrong baseline credential -> generic 401, no token.
            return HttpResp(401, {"content-type": "application/json"},
                            '{"error":"invalid_credentials"}', url)

        result = _run(fake)
        assert result == [], (
            "FALSE POSITIVE: a validation-error CSRF nonce under a 'token' key "
            "was reported as a SQLi auth bypass: %r" % result)

    def test_genuine_jwt_bypass_still_fires(self):
        """True positive: only the SQLi payload yields a 200 with a real JWT
        (subject claim); the validation/baseline paths carry no usable token."""

        async def fake(method, url, **kw):
            if not url.endswith("/rest/user/login"):
                return HttpResp(404, {}, "", url)
            ident = _body_ident(kw)
            if "1=1" in ident or "1'='1" in ident:
                # Genuine bypass: a live session JWT issued for the SQLi payload.
                return HttpResp(
                    200, {"content-type": "application/json"},
                    '{"authentication":{"token":"%s"}}' % _REAL_JWT, url)
            # Baseline wrong credential -> 401, no token.
            return HttpResp(401, {"content-type": "application/json"},
                            '{"error":"invalid_credentials"}', url)

        result = _run(fake)
        assert result, "expected a genuine auth-bypass finding"
        f = result[0]
        assert f["vuln_type"] == "auth_bypass:sqli_login"
        assert f["severity"] == "critical"
        assert "/rest/user/login" in f["url"]
