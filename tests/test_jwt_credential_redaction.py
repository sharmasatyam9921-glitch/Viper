"""#7c/#audit-FIX3: the JWT worker must not put a live token or a cracked key into any
serializable finding field or into title/evidence (Ethical Rule #6). The credential lives
only in underscore-prefixed fields (which disk/notification serializers skip); the gate
still confirms via those. Also checks the jwks host guard is a host comparison, not a
string prefix (target.com.attacker.com must not pass)."""
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
from core.swarm_workers.vuln import jwt as jwt_mod  # noqa: E402
from core.swarm_workers.vuln._http import HttpResp, _host_key  # noqa: E402

_KEY = "secret"


def _b64(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _make_token(key: str = _KEY) -> str:
    hdr = _b64(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    pl = _b64(json.dumps({"sub": "admin", "role": "admin"}).encode())
    sig = _b64(hmac.new(key.encode(), f"{hdr}.{pl}".encode(), hashlib.sha256).digest())
    return f"{hdr}.{pl}.{sig}"


def _agent(t):
    return SwarmAgent(agent_id="t", objective="x", target=t, technique="jwt",
                      payload={}, timeout_s=6.0)


def test_weak_key_finding_redacts_token_and_key():
    token = _make_token()

    async def fake(method, url, timeout=10, **kw):
        # Serve the weak-key JWT as a session credential (Authorization header).
        return HttpResp(200, {"authorization": f"Bearer {token}",
                              "content-type": "application/json"}, "{}", url)

    with patch.object(jwt_mod, "fetch", fake):
        findings = asyncio.run(jwt_mod.run(_agent("http://app.example/")))

    weak = [f for f in findings if f.get("vuln_type") == "jwt:weak_key"]
    assert weak, "a weak-key JWT credential must be flagged"
    f = weak[0]

    # The cracked key and the full token must appear in NO serializable field, and not in
    # title/evidence.
    for field in ("title", "evidence"):
        assert _KEY not in f.get(field, ""), f"{field} leaks the cracked key"
        assert token not in f.get(field, ""), f"{field} leaks the full token"
    # No plain-name credential fields on the finding (only underscore-prefixed).
    assert "jwt_token" not in f and "jwt_key" not in f
    # The credential IS available to the gate via the underscore-prefixed fields.
    assert f.get("_jwt_token") == token
    assert f.get("_jwt_key") == _KEY
    # And a serializer that keeps only non-underscore keys drops the secret entirely.
    serialized = {k: v for k, v in f.items() if not k.startswith("_")}
    assert _KEY not in json.dumps(serialized)
    assert token not in json.dumps(serialized)


def test_jwks_host_guard_is_a_host_comparison():
    # target.com.attacker.com and target.com@attacker.com must NOT match the target host.
    assert _host_key("https://app.example/.well-known/jwks.json") == _host_key("https://app.example")
    assert _host_key("https://app.example.attacker.com/jwks") != _host_key("https://app.example")
    assert _host_key("https://app.example@attacker.com/jwks") != _host_key("https://app.example")
