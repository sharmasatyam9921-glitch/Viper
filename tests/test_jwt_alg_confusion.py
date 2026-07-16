"""JWT RS256->HS256 algorithm confusion: reconstruct the RSA public-key PEM from a
JWK (dependency-free DER), forge an HS256 token with it, and confirm only via an
operator endpoint (forged accepted where a bad-sig control is rejected)."""
from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import json
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import core.swarm_workers  # noqa: F401,E402
from core.swarm_engine import SwarmAgent  # noqa: E402
from core.swarm_workers import get_worker_runner  # noqa: E402
from core.swarm_workers.vuln._http import HttpResp  # noqa: E402
from core.swarm_workers.vuln.jwt import (  # noqa: E402
    _b64url_encode, jwk_rsa_to_pem,
)
from core.swarm_validation import validate_findings  # noqa: E402

# A test RSA public key (n with the high bit set, to exercise the DER leading-zero).
_N = (1 << 2047) | 0x1234567
_E = 65537
_N_B64 = _b64url_encode(_N.to_bytes(256, "big"))
_E_B64 = _b64url_encode(_E.to_bytes(3, "big"))
_PEM = jwk_rsa_to_pem(_N_B64, _E_B64)

_RS_TOKEN = f'{_b64url_encode(json.dumps({"alg":"RS256","kid":"k1"}).encode())}.' \
           f'{_b64url_encode(json.dumps({"sub":"user1"}).encode())}.AAAA'


# --- minimal DER reader to prove the hand-rolled encoder round-trips ---
def _read_len(b, i):
    n = b[i]; i += 1
    if n < 0x80:
        return n, i
    k = n & 0x7F
    return int.from_bytes(b[i:i + k], "big"), i + k


def _read_tlv(b, i):
    i += 1                                   # tag
    ln, i = _read_len(b, i)
    return b[i:i + ln], i + ln


def _extract_n_e(pem: str):
    raw = base64.b64decode("".join(l for l in pem.strip().splitlines() if "---" not in l))
    spki, _ = _read_tlv(raw, 0)              # SubjectPublicKeyInfo SEQUENCE
    _algid, j = _read_tlv(spki, 0)           # AlgorithmIdentifier
    bitstr, _ = _read_tlv(spki, j)           # BIT STRING
    rsapub, _ = _read_tlv(bitstr[1:], 0)     # skip unused-bits byte -> RSAPublicKey SEQ
    nb, k = _read_tlv(rsapub, 0)
    eb, _ = _read_tlv(rsapub, k)
    return int.from_bytes(nb, "big"), int.from_bytes(eb, "big")


def test_jwk_to_pem_der_roundtrips():
    n, e = _extract_n_e(_PEM)
    assert n == _N and e == _E
    assert _PEM.startswith("-----BEGIN PUBLIC KEY-----")


# --- worker emits the opt-in alg-confusion lead ---
def _agent():
    return SwarmAgent(agent_id="t", objective="x", target="http://t/",
                      technique="jwt", payload={}, timeout_s=8.0)


def test_worker_emits_alg_confusion_lead_with_pubkey_pem():
    async def fake(method, url, **kw):
        if url.endswith("/.well-known/jwks.json"):
            return HttpResp(200, {"content-type": "application/json"}, json.dumps(
                {"keys": [{"kty": "RSA", "kid": "k1", "n": _N_B64, "e": _E_B64}]}), url)
        if url.endswith("jwks.json") or url.endswith("/jwks") or "openid" in url:
            return HttpResp(404, {}, "no", url)
        return HttpResp(200, {"set-cookie": f"session={_RS_TOKEN}; Path=/"}, "<html></html>", url)

    async def go():
        with patch("core.swarm_workers.vuln.jwt.fetch", side_effect=fake):
            return await get_worker_runner("vuln", "jwt")(_agent())
    findings = asyncio.run(go())
    ac = [f for f in findings if f["vuln_type"] == "jwt:alg_confusion"]
    # Credential token is now underscore-prefixed (serializers skip it); public-key PEM
    # stays plain (a published RSA public key is not a secret).
    assert ac and ac[0]["jwt_pubkey_pem"] == _PEM and ac[0]["_jwt_token"] == _RS_TOKEN
    assert "jwt_token" not in ac[0]
    assert ac[0]["confidence"] == 0.5          # a LEAD until the gate confirms


# --- gate confirmation against a server that HMAC-verifies with the public key ---
def _hs256_ok(tok: str, key: str) -> bool:
    p = tok.split(".")
    if len(p) != 3:
        return False
    want = _b64url_encode(hmac.new(key.encode(), (p[0] + "." + p[1]).encode(),
                                   hashlib.sha256).digest())
    return p[2] == want


def _server(mode: str):
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            auth = self.headers.get("Authorization", "")
            tok = auth[7:] if auth.startswith("Bearer ") else ""
            ok = _hs256_ok(tok, _PEM) if mode == "confused" else False
            self.send_response(200 if ok else 401)
            self.end_headers()
            self.wfile.write(b"ok" if ok else b"no")
    srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, f"http://127.0.0.1:{srv.server_address[1]}"


def _finding(base, **kw):
    f = {"vuln_type": "jwt:alg_confusion", "url": base + "/", "jwt_token": _RS_TOKEN,
         "jwt_pubkey_pem": _PEM, "jwt_source": "authorization"}
    f.update(kw)
    return f


def test_gate_confirms_when_forged_hs256_accepted():
    srv, base = _server("confused")           # HMAC-verifies with the public-key PEM
    try:
        f = asyncio.run(validate_findings([_finding(base, jwt_probe_endpoint=base + "/api")]))[0]
        assert f["submittable"] and f["validation_confidence"] >= 0.8
        assert "confusion" in f["validation_reason"].lower()
    finally:
        srv.shutdown()


def test_gate_rejects_when_server_verifies_properly():
    srv, base = _server("secure")             # rejects the HS256 forgery
    try:
        f = asyncio.run(validate_findings([_finding(base, jwt_probe_endpoint=base + "/api")]))[0]
        assert not f["submittable"]
    finally:
        srv.shutdown()


def test_no_probe_endpoint_stays_lead():
    f = asyncio.run(validate_findings([_finding("http://t")]))[0]
    assert not f["submittable"] and "jwt_probe_endpoint" in f["validation_reason"]
