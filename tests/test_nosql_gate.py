"""NoSQL operator-injection auth bypass is now gate-confirmed (token differential).

The gate independently re-runs the login differential: a bogus credential must NOT
mint a session token while the finding's operator body MUST — the same token-presence
proof login_sqli uses. The weaker query sub-class stays a lead.
"""
from __future__ import annotations

import asyncio
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.swarm_validation import validate_findings  # noqa: E402
from core.swarm_workers.vuln.nosql_injection import run as nosql_run  # noqa: E402

_JWT = b'{"token":"eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjoxfQ.' + b"s" * 24 + b'"}'
_FAIL = b'{"authentication":"failed"}'


class _Agent:
    def __init__(self, t):
        self.target = t
        self.timeout_s = 8.0
        self.payload = {}


def _server(mode: str):
    """mode: 'vuln' (match-all operator mints a token, others don't),
    'promiscuous' (any credential mints a token), 'safe' (never mints),
    'object' (any object-typed credential mints a token — not operator-driven)."""
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_POST(self):
            n = int(self.headers.get("Content-Length", 0) or 0)
            raw = self.rfile.read(n).decode("utf-8", "replace")
            has_matchall = "$ne" in raw or "$gt" in raw
            if mode == "promiscuous":
                tok = True
            elif mode == "safe":
                tok = False
            elif mode == "object":
                tok = '":{' in raw.replace(" ", "")   # ANY object body (incl. $eq control)
            else:                            # vuln: only match-all operators
                tok = has_matchall
            body = _JWT if tok else _FAIL
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
    srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, f"http://127.0.0.1:{srv.server_address[1]}"


def test_nosql_login_bypass_worker_and_gate_confirm():
    srv, base = _server("vuln")
    try:
        findings = asyncio.run(nosql_run(_Agent(base)))
        login = [f for f in findings if f["vuln_type"] == "nosql_injection:login"]
        assert login, "worker should find the operator-injection login bypass"
        out = asyncio.run(validate_findings(login, default_target=base))
        sub = [f for f in out if f["submittable"]]
        assert sub and sub[0]["validation_confidence"] >= 0.85
        assert "auth bypass" in sub[0]["validation_reason"].lower()
    finally:
        srv.shutdown()


def test_nosql_promiscuous_endpoint_is_gate_lead():
    # An endpoint that hands a token to ANY credential fails the gate's baseline
    # discipline — even a pre-existing/stale finding must not become submittable.
    srv, base = _server("promiscuous")
    try:
        f = {"vuln_type": "nosql_injection:login", "url": base + "/api/login",
             "payload": '{"email":{"$ne":null},"password":{"$ne":null}}'}
        out = asyncio.run(validate_findings([f], default_target=base))
        assert not out[0]["submittable"]
        assert "bogus credential" in out[0]["validation_reason"]
    finally:
        srv.shutdown()


def test_nosql_operator_no_token_is_gate_lead():
    srv, base = _server("safe")
    try:
        f = {"vuln_type": "nosql_injection:login", "url": base + "/api/login",
             "payload": '{"email":{"$ne":null},"password":{"$ne":null}}'}
        out = asyncio.run(validate_findings([f], default_target=base))
        assert not out[0]["submittable"]
    finally:
        srv.shutdown()


def test_nosql_object_session_is_gate_lead():
    # Adversarial review: an endpoint that hands a token to ANY object-typed
    # credential (a guest session), not driven by operator matching, must be caught
    # by the $eq-to-bogus operator-semantics control -> lead, not submittable.
    srv, base = _server("object")
    try:
        f = {"vuln_type": "nosql_injection:login", "url": base + "/api/login",
             "payload": '{"email":{"$ne":null},"password":{"$ne":null}}'}
        out = asyncio.run(validate_findings([f], default_target=base))
        assert not out[0]["submittable"]
        assert "$eq" in out[0]["validation_reason"]
    finally:
        srv.shutdown()


def test_nosql_query_candidate_stays_lead():
    # The weaker query-divergence sub-class has no safe token differential — lead.
    f = {"vuln_type": "nosql_injection:query", "url": "http://127.0.0.1:9/search?q=x",
         "parameter": "q", "payload": "[$ne]="}
    out = asyncio.run(validate_findings([f]))
    assert not out[0]["submittable"]
    assert "query" in out[0]["validation_reason"].lower()
