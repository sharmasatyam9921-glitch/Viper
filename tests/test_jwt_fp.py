"""Regression tests for the jwt vuln worker false positive.

Audit scenario: a benign 200 API-documentation page at /docs/authentication
whose HTML body contains the canonical jwt.io sample token (HS256, signed with
the published example secret "your-256-bit-secret") inside an "Example token"
code block. No auth cookie, no Set-Cookie token, nothing sensitive. The worker
scraped resp.body, parsed the sample, _try_weak_keys() succeeded against the
hardcoded weak key, and it emitted a CRITICAL jwt:weak_key finding.

A sample JWT printed in human-readable HTML is NOT an application-issued
credential. The fix only raises weak_key / alg_none from tokens that arrive as
a real credential (Set-Cookie value or an Authorization response header). Tokens
seen only in the body are downgraded to info-only.
"""

import asyncio
import base64
import hashlib
import hmac
import json
from unittest.mock import patch

from core.swarm_engine import SwarmAgent
from core.swarm_workers import get_worker_runner
from core.swarm_workers.vuln._http import HttpResp

import core.swarm_workers  # noqa: F401 — ensures workers register


def _b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def _make_jwt(header: dict, payload: dict, key: str) -> str:
    h = _b64u(json.dumps(header, separators=(",", ":")).encode())
    p = _b64u(json.dumps(payload, separators=(",", ":")).encode())
    signing_input = (h + "." + p).encode("ascii")
    sig = _b64u(hmac.new(key.encode("utf-8"), signing_input, hashlib.sha256).digest())
    return f"{h}.{p}.{sig}"


def _agent(url: str) -> SwarmAgent:
    return SwarmAgent(
        agent_id="t",
        objective="x",
        target=url,
        technique="jwt",
        payload={},
        timeout_s=10.0,
    )


def _run(resp):
    async def go():
        with patch("core.swarm_workers.vuln.jwt.fetch", return_value=resp):
            runner = get_worker_runner("vuln", "jwt")
            return await runner(_agent("http://t/docs/authentication"))
    return asyncio.run(go())


# The canonical jwt.io sample token, signed with the published example secret.
_JWT_IO_SAMPLE = _make_jwt(
    {"alg": "HS256", "typ": "JWT"},
    {"sub": "1234567890", "name": "John Doe", "iat": 1516239022},
    "your-256-bit-secret",
)


def test_doc_sample_jwt_in_body_not_flagged_critical():
    """(a) FALSE POSITIVE: the jwt.io sample token rendered in an HTML doc page
    must NOT yield a weak_key / alg_none finding. Pre-fix this FAILED (the worker
    scraped the body and emitted CRITICAL jwt:weak_key)."""
    body = (
        "<html><body><h1>Authentication</h1>"
        "<p>Example token issued by our API:</p>"
        f"<pre><code>{_JWT_IO_SAMPLE}</code></pre>"
        "<p>The signature is computed with your secret.</p>"
        "</body></html>"
    )
    resp = HttpResp(
        200,
        {"content-type": "text/html; charset=utf-8"},  # no Set-Cookie, no auth
        body,
        "http://t/docs/authentication",
    )
    result = _run(resp)

    critical = [r for r in result if r.get("vuln_type") in ("jwt:weak_key", "jwt:alg_none")]
    assert critical == [], (
        "doc-sample JWT in HTML body must not raise weak_key/alg_none; "
        f"got {[ (r['vuln_type'], r['severity']) for r in critical ]}"
    )
    # Any high/critical severity from a body-only token is the FP signature.
    severe = [r for r in result if r.get("severity") in ("critical", "high")]
    assert severe == [], f"no high/critical findings expected from body sample; got {severe}"


def test_live_cookie_weak_key_still_fires():
    """(b) TRUE POSITIVE: a genuinely weak HS256 token the server SET as a session
    cookie is a real forgeable credential — the worker must STILL emit a CRITICAL
    weak_key finding."""
    # Real application-issued token: server hands it back as the session cookie,
    # signed with a crackable key. This is the live-credential case, not a sample.
    token = _make_jwt(
        {"alg": "HS256", "typ": "JWT"},
        {"user": "alice", "role": "user", "exp": 9999999999},
        "secret",
    )
    resp = HttpResp(
        200,
        {"set-cookie": f"session={token}; HttpOnly; Path=/",
         "content-type": "application/json"},
        '{"ok":true}',
        "http://t/login",
    )
    result = _run(resp)

    cracked = [r for r in result if r.get("vuln_type") == "jwt:weak_key"]
    assert cracked, f"expected a weak_key finding from the Set-Cookie token; got {result}"
    assert cracked[0]["severity"] == "critical"
