"""Enhancement: JWT `kid` (Key ID) header injection — new gate-confirmed variant (CWE-347).
A verifier that resolves `kid` to a KEY FILE is forgeable with a path-traversal kid pointing
at an empty file (/dev/null -> empty key). Opt-in: the worker emits a lead for a forgeable
JWT that carries a `kid`; the gate confirms only via the SAME forge-accept probe (operator
jwt_probe_endpoint) — forge with alg=HS256, malicious kid, EMPTY key; require accept + a
bad-sig control reject. Read-only, no privilege escalation."""
from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import json
import sys
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.swarm_engine import SwarmAgent  # noqa: E402
from core.swarm_validation import validate_findings  # noqa: E402
from core.swarm_workers.vuln import jwt as jwt_mod  # noqa: E402
from core.swarm_workers.vuln._http import HttpResp  # noqa: E402


def _b64(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _token(kid: bool) -> str:
    header = {"alg": "HS256", "typ": "JWT"}
    if kid:
        header["kid"] = "key-1"
    h = _b64(json.dumps(header).encode())
    p = _b64(json.dumps({"sub": "admin", "role": "admin"}).encode())
    s = _b64(hmac.new(b"whatever", f"{h}.{p}".encode(), hashlib.sha256).digest())
    return f"{h}.{p}.{s}"


def _agent(t):
    return SwarmAgent(agent_id="t", objective="x", target=t, technique="jwt",
                      payload={}, timeout_s=6.0)


def test_worker_emits_kid_inject_for_token_with_kid():
    tok = _token(kid=True)

    async def fake(method, url, timeout=10, **kw):
        return HttpResp(200, {"authorization": f"Bearer {tok}",
                              "content-type": "application/json"}, "{}", url)

    with patch.object(jwt_mod, "fetch", fake):
        out = asyncio.run(jwt_mod.run(_agent("http://app.example/")))
    kid = [f for f in out if f["vuln_type"] == "jwt:kid_inject"]
    assert kid, "a forgeable JWT carrying a kid header must emit a kid-inject candidate"
    # credential is underscore-prefixed (serializers skip it); no plain jwt_token.
    assert kid[0]["_jwt_token"] == tok and "jwt_token" not in kid[0]


def test_worker_no_kid_inject_without_kid_header():
    tok = _token(kid=False)

    async def fake(method, url, timeout=10, **kw):
        return HttpResp(200, {"authorization": f"Bearer {tok}",
                              "content-type": "application/json"}, "{}", url)

    with patch.object(jwt_mod, "fetch", fake):
        out = asyncio.run(jwt_mod.run(_agent("http://app.example/")))
    assert not any(f["vuln_type"] == "jwt:kid_inject" for f in out)


# --- gate confirmation via the forge-accept probe ----------------------------------------
def _candidate(endpoint="http://t/api/me"):
    f = {"type": "jwt_kid_inject", "vuln_type": "jwt:kid_inject", "url": "http://t/",
         "_jwt_token": _token(kid=True), "jwt_source": "authorization", "severity": "high"}
    if endpoint:
        f["jwt_probe_endpoint"] = endpoint
    return f


def _server(vuln):
    async def f(method, url, *, headers=None, timeout=10, **kw):
        tok = (headers or {}).get("Authorization", "").replace("Bearer ", "")
        parts = tok.split(".")
        if len(parts) != 3:
            return HttpResp(401, {}, "", url)
        want = _b64(hmac.new(b"", f"{parts[0]}.{parts[1]}".encode(), hashlib.sha256).digest())
        # vulnerable: kid -> /dev/null empty key, so an empty-key HMAC verifies.
        return HttpResp(200, {}, "ok", url) if (vuln and parts[2] == want) \
            else HttpResp(401, {}, "no", url)
    return f


def test_confirmed_when_empty_key_forgery_accepted():
    out = asyncio.run(validate_findings([_candidate()], default_target="http://t/",
                                        fetch=_server(True)))
    assert out[0]["submittable"] is True
    assert "kid" in out[0]["validation_reason"].lower()


def test_lead_when_server_verifies_signatures():
    out = asyncio.run(validate_findings([_candidate()], default_target="http://t/",
                                        fetch=_server(False)))
    assert not out[0]["submittable"]


def test_lead_without_probe_endpoint():
    out = asyncio.run(validate_findings([_candidate(endpoint=None)], default_target="http://t/",
                                        fetch=_server(True)))
    assert not out[0]["submittable"]
    assert "jwt_probe_endpoint" in out[0]["validation_reason"]
