"""JWT weak-key finding is confirmed ONLY by a forge-accept proof against an
operator-supplied endpoint. A cracked key alone stays a lead (autonomous default)."""
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

from core.swarm_validation import validate_findings  # noqa: E402

_KEY = "secret"


def _b64(o) -> str:
    return base64.urlsafe_b64encode(
        json.dumps(o, separators=(",", ":")).encode()).rstrip(b"=").decode()


_TOKEN = f'{_b64({"alg": "HS256", "typ": "JWT"})}.{_b64({"sub": "user1"})}.AAAA'


def _valid_sig(token: str) -> bool:
    parts = token.split(".")
    if len(parts) != 3:
        return False
    want = base64.urlsafe_b64encode(
        hmac.new(_KEY.encode(), (parts[0] + "." + parts[1]).encode(),
                 hashlib.sha256).digest()).rstrip(b"=").decode()
    return parts[2] == want


def _server(mode: str):
    """mode: 'verify' (accepts a valid weak-key signature, else 401),
    'accept_all' (200 for anything), 'reject_all' (401 for anything),
    'single_use' (accepts the FIRST valid-sig token, 401 on any repeat — a stateful
    endpoint whose control-401 is order-dependent, NOT a signature verdict)."""
    seen: set = set()

    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            auth = self.headers.get("Authorization", "")
            tok = auth[7:] if auth.startswith("Bearer ") else ""
            if mode == "accept_all":
                ok = True
            elif mode == "reject_all":
                ok = False
            elif mode == "single_use":
                ok = _valid_sig(tok) and tok not in seen
                seen.add(tok)
            else:
                ok = _valid_sig(tok)
            self.send_response(200 if ok else 401)
            self.end_headers()
            self.wfile.write(b'{"ok":true}' if ok else b"unauthorized")
    srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, f"http://127.0.0.1:{srv.server_address[1]}"


def _finding(base=None, **kw):
    f = {"vuln_type": "jwt:weak_key", "url": (base or "http://t/") + "/",
         "jwt_token": _TOKEN, "jwt_key": _KEY, "jwt_alg": "HS256"}
    f.update(kw)
    return f


def _run(finding):
    return asyncio.run(validate_findings([finding]))[0]


def test_jwt_forge_accepted_is_submittable():
    srv, base = _server("verify")
    try:
        f = _run(_finding(base, jwt_probe_endpoint=base + "/api/me"))
        assert f["submittable"] and f["validation_confidence"] >= 0.8
        assert "forged" in f["validation_reason"].lower()
    finally:
        srv.shutdown()


def test_jwt_accept_all_endpoint_is_lead():
    srv, base = _server("accept_all")
    try:
        f = _run(_finding(base, jwt_probe_endpoint=base + "/api/me"))
        assert not f["submittable"]
        assert "does not verify" in f["validation_reason"]
    finally:
        srv.shutdown()


def test_jwt_reject_all_endpoint_is_lead():
    srv, base = _server("reject_all")
    try:
        f = _run(_finding(base, jwt_probe_endpoint=base + "/api/me"))
        assert not f["submittable"]
    finally:
        srv.shutdown()


def test_jwt_single_use_endpoint_is_lead():
    # Adversarial review: a stateful single-use endpoint accepts the forged token
    # once then rejects the repeat — the control-401 is order-dependent, not a
    # signature verdict. The forged-twice bracket must keep this a lead.
    srv, base = _server("single_use")
    try:
        f = _run(_finding(base, jwt_probe_endpoint=base + "/api/me"))
        assert not f["submittable"]
        assert "state-dependent" in f["validation_reason"] or "repeat" in f["validation_reason"]
    finally:
        srv.shutdown()


def test_jwt_no_probe_endpoint_stays_lead():
    f = _run(_finding())
    assert not f["submittable"]
    assert "jwt_probe_endpoint" in f["validation_reason"]


def test_jwt_observation_is_lead():
    f = _run({"vuln_type": "jwt:observed:HS256", "url": "http://t/"})
    assert not f["submittable"]


def test_jwt_missing_key_is_lead():
    f = _run({"vuln_type": "jwt:weak_key", "url": "http://t/",
              "jwt_probe_endpoint": "http://t/api"})
    assert not f["submittable"]
