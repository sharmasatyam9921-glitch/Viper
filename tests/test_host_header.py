"""Host header injection worker + independent gate re-check."""
from __future__ import annotations

import asyncio
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.swarm_validation import validate_findings  # noqa: E402
from core.swarm_workers.vuln._http import HttpResp  # noqa: E402
from core.swarm_workers.vuln.host_header import run as hh_run  # noqa: E402


class _Agent:
    def __init__(self, t):
        self.target = t
        self.timeout_s = 8.0
        self.payload = {}


def _server(reflect: bool):
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            xfh = self.headers.get("X-Forwarded-Host")
            if reflect and xfh:
                # builds a redirect URL from the attacker-controlled host
                self.send_response(302)
                self.send_header("Location", f"https://{xfh}/login")
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            body = b"home"
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
    srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, f"http://127.0.0.1:{srv.server_address[1]}/"


def test_worker_detects_and_gate_confirms_host_header_injection():
    srv, url = _server(reflect=True)
    try:
        findings = asyncio.run(hh_run(_Agent(url)))
        assert any(f["vuln_type"] == "host_header:x-forwarded-host" for f in findings)
        out = asyncio.run(validate_findings(findings, fetch=_fetch_reflecting(True)))
        sub = [f for f in out if f["submittable"]]
        assert sub and sub[0]["validation_confidence"] == 0.8
        assert "Location redirect" in sub[0]["validation_reason"]
    finally:
        srv.shutdown()


def test_worker_no_finding_when_host_not_reflected():
    srv, url = _server(reflect=False)
    try:
        findings = asyncio.run(hh_run(_Agent(url)))
        assert not [f for f in findings if "host_header" in f["vuln_type"]]
    finally:
        srv.shutdown()


# --- gate re-check in isolation (fake fetch) -------------------------------

def _fetch_reflecting(do_reflect):
    async def fake(method, url, *, headers=None, timeout=10.0, follow_redirects=True,
                   use_session_auth=True):
        xfh = (headers or {}).get("X-Forwarded-Host")
        if do_reflect and xfh:
            return HttpResp(302, {"location": f"https://{xfh}/login"}, "", url)
        return HttpResp(200, {}, "home", url)
    return fake


def test_gate_recheck_confirms_reflected_redirect():
    f = {"vuln_type": "host_header:x-forwarded-host", "url": "http://t/",
         "parameter": "X-Forwarded-Host"}
    out = asyncio.run(validate_findings([f], fetch=_fetch_reflecting(True)))
    assert out[0]["submittable"] and out[0]["validation_confidence"] == 0.8


def test_gate_recheck_rejects_non_reflecting():
    f = {"vuln_type": "host_header:x-forwarded-host", "url": "http://t/",
         "parameter": "X-Forwarded-Host"}
    out = asyncio.run(validate_findings([f], fetch=_fetch_reflecting(False)))
    assert not out[0]["submittable"] and out[0]["validation_confidence"] == 0.3


def test_gate_rejects_marker_in_location_query_not_host():
    # The spoofed host appears in the Location QUERY (not the redirect host) — the
    # redirect still goes to the same origin, so it is NOT attacker-controlled.
    async def fake(method, url, *, headers=None, timeout=10.0, follow_redirects=True,
                   use_session_auth=True):
        xfh = (headers or {}).get("X-Forwarded-Host")
        if xfh:
            return HttpResp(302, {"location": f"/error?original_host={xfh}"}, "", url)
        return HttpResp(200, {}, "home", url)
    f = {"vuln_type": "host_header:x-forwarded-host", "url": "http://t/",
         "parameter": "X-Forwarded-Host"}
    out = asyncio.run(validate_findings([f], fetch=fake))
    assert not out[0]["submittable"]                 # marker in query, not the host


def test_gate_confirms_protocol_relative_redirect_to_marker():
    # Location: //marker/login IS attacker-controlled (browser goes to marker).
    async def fake(method, url, *, headers=None, timeout=10.0, follow_redirects=True,
                   use_session_auth=True):
        xfh = (headers or {}).get("X-Forwarded-Host")
        if xfh:
            return HttpResp(302, {"location": f"//{xfh}/login"}, "", url)
        return HttpResp(200, {}, "home", url)
    f = {"vuln_type": "host_header:x-forwarded-host", "url": "http://t/",
         "parameter": "X-Forwarded-Host"}
    out = asyncio.run(validate_findings([f], fetch=fake))
    assert out[0]["submittable"]                     # protocol-relative -> real redirect
