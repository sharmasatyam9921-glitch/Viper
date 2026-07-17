"""Enhancement: JWT `jku`/`x5u` header injection — OOB-confirmed (CWE-347). A verifier that
fetches the token's `jku` (JWKS URL) to obtain the verification key WITHOUT validating its
host lets an attacker host their own key and forge any token. The jwt worker forges a token
whose jku/x5u point at an OOB canary and sends it; the gate confirms ONLY when the server
calls the listener back (blind — a lead otherwise, so no offline-precision impact)."""
from __future__ import annotations

import asyncio
import base64
import json
import re
import sys
import threading
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

# The canary URL uses a placeholder host (oob.local) a real server would DNS-resolve to the
# listener; the test simulates that callback by re-targeting the port+token to 127.0.0.1.
_CANARY_URL = re.compile(r"https?://[\w.-]+(?::(\d+))?/([\w-]+)")

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.oob import OOBServer  # noqa: E402
from core.swarm_validation import validate_findings  # noqa: E402
from core.swarm_workers.vuln._http import clear_oob, set_oob  # noqa: E402
from core.swarm_workers.vuln.jwt import run as jwt_run  # noqa: E402


def _b64(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _b64d(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _forgeable_jwt() -> str:
    h = _b64(json.dumps({"alg": "HS256", "typ": "JWT", "kid": "k1"}).encode())
    p = _b64(json.dumps({"sub": "admin", "role": "admin"}).encode())
    return f"{h}.{p}.{_b64('sig'.encode())}"


def _backend(follow_jku: bool):
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            auth = self.headers.get("Authorization", "")
            if auth.startswith("Bearer "):
                # This is the worker's jku PROBE. A VULNERABLE server fetches the jku URL
                # from the token header to obtain the verification key.
                if follow_jku:
                    try:
                        hdr = json.loads(_b64d(auth.split(" ", 1)[1].split(".")[0]))
                        m = _CANARY_URL.search(hdr.get("jku", ""))
                        if m:
                            port, token = m.groups()
                            urllib.request.urlopen(
                                f"http://127.0.0.1:{port}/{token}", timeout=3).read()
                    except Exception:
                        pass
                body = b"ok"
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            else:
                # Baseline: hand out a forgeable session JWT so the worker fires the probe.
                body = b"{}"
                self.send_response(200)
                self.send_header("Set-Cookie", f"session={_forgeable_jwt()}")
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

    srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, f"http://127.0.0.1:{srv.server_address[1]}/"


class _Agent:
    def __init__(self, t):
        self.target = t
        self.timeout_s = 10.0
        self.payload = {}


async def _dead(*a, **k):
    return None


def _run(follow_jku: bool):
    srv, base = _backend(follow_jku)
    try:
        with OOBServer(base_domain="oob.local", enable_dns=False) as oob:
            set_oob(oob)
            try:
                findings = asyncio.run(jwt_run(_Agent(base)))
            finally:
                clear_oob()
            jku = [f for f in findings if f.get("vuln_type") == "jwt:jku_inject"]
            out = asyncio.run(validate_findings(jku, oob_store=oob.store, fetch=_dead)) if jku else []
            return jku, out
    finally:
        srv.shutdown()


def test_jku_injection_confirmed_when_server_fetches_canary():
    jku, out = _run(follow_jku=True)
    assert jku, "worker must emit a jku_inject OOB candidate for a forgeable token"
    assert jku[0].get("oob_token")
    assert out and out[0]["submittable"] is True, "server fetched the jku canary -> confirmed"


def test_jku_injection_stays_lead_when_not_followed():
    jku, out = _run(follow_jku=False)
    assert jku, "candidate is still emitted (blind lead)"
    assert not out[0]["submittable"], "no callback -> stays a lead"
