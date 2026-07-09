"""The validation gate persists the EXACT confirming request(s) per submittable
finding (auth redacted), and the submission draft renders them as copyable cURL."""
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

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.submission_draft import _proof_curl, build_submission  # noqa: E402
from core.swarm_validation import _redact_headers, validate_findings  # noqa: E402

_KEY = "secret"


def _b64(o) -> str:
    return base64.urlsafe_b64encode(
        json.dumps(o, separators=(",", ":")).encode()).rstrip(b"=").decode()


_TOKEN = f'{_b64({"alg": "HS256", "typ": "JWT"})}.{_b64({"sub": "u"})}.AAAA'


def _valid_sig(tok: str) -> bool:
    p = tok.split(".")
    if len(p) != 3:
        return False
    want = base64.urlsafe_b64encode(
        hmac.new(_KEY.encode(), (p[0] + "." + p[1]).encode(),
                 hashlib.sha256).digest()).rstrip(b"=").decode()
    return p[2] == want


def _server():
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            auth = self.headers.get("Authorization", "")
            ok = _valid_sig(auth[7:] if auth.startswith("Bearer ") else "")
            self.send_response(200 if ok else 401)
            self.end_headers()
            self.wfile.write(b"ok" if ok else b"no")
    srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, f"http://127.0.0.1:{srv.server_address[1]}"


def test_redact_headers_hides_secrets_keeps_the_rest():
    red = _redact_headers({"Cookie": "s=abc", "Authorization": "Bearer x",
                           "Content-Type": "application/json", "X-Api-Key": "k"})
    assert red["Cookie"] == "<redacted>" and red["Authorization"] == "<redacted>"
    assert red["X-Api-Key"] == "<redacted>"
    assert red["Content-Type"] == "application/json"      # non-secret kept


def test_proof_curl_renders_requests():
    f = {"proof_requests": [
        {"method": "GET", "url": "http://t/a", "headers": {"Authorization": "<redacted>"},
         "body": None, "status": 200},
        {"method": "POST", "url": "http://t/b", "headers": {}, "body": '{"x":1}',
         "status": 401}]}
    out = _proof_curl(f)
    assert "curl -i -H 'Authorization: <redacted>' 'http://t/a'" in out and "HTTP 200" in out
    assert "curl -i -X POST --data '{\"x\":1}' 'http://t/b'" in out and "HTTP 401" in out
    assert _proof_curl({}) == ""


def _finding(base):
    return {"vuln_type": "jwt:weak_key", "url": base + "/",
            "jwt_token": _TOKEN, "jwt_key": _KEY, "jwt_alg": "HS256",
            "jwt_probe_endpoint": base + "/api/me"}


def test_gate_persists_confirming_request_with_auth_redacted():
    srv, base = _server()
    try:
        f = asyncio.run(validate_findings([_finding(base)]))[0]
        assert f["submittable"]
        proof = f.get("proof_requests")
        assert proof and len(proof) >= 2
        # the forge-probe sent Authorization: Bearer <token> — it must be redacted
        auths = [r["headers"].get("Authorization") for r in proof
                 if "Authorization" in r["headers"]]
        assert auths and all(a == "<redacted>" for a in auths)
        # no live token string leaked into the persisted proof
        assert all(_TOKEN.split(".")[2] not in json.dumps(r) for r in proof)
    finally:
        srv.shutdown()


def test_submission_draft_shows_exact_request():
    srv, base = _server()
    try:
        f = asyncio.run(validate_findings([_finding(base)]))[0]
        md = build_submission(f, target=base)
        assert "validation gate sent to independently confirm" in md
        assert "curl -i" in md and "Authorization: <redacted>" in md
    finally:
        srv.shutdown()


def test_no_proof_falls_back_to_template():
    # A finding with no captured request (e.g. a lead / trust path) still renders.
    md = build_submission({"vuln_type": "sqli:id", "url": "http://t/x?id=1",
                           "parameter": "id", "submittable": True}, target="http://t")
    assert "single-quote breaker" in md            # per-class template still used
    assert "validation gate sent" not in md
