"""End-to-end: blind-vuln workers fire OOB canaries, the gate confirms callbacks.

A simulated vulnerable backend dereferences any canary URL it is fed (SSRF) or
embedded in a command value (cmdi) by calling our listener back — exactly what a
real blind-vulnerable target's backend would do. The worker tags the finding with
the canary token; the gate confirms it submittable once the callback lands.
"""
from __future__ import annotations

import asyncio
import re
import sys
import threading
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.oob import OOBServer  # noqa: E402
from core.swarm_validation import validate_findings  # noqa: E402
from core.swarm_workers.vuln._http import clear_oob, set_oob  # noqa: E402
from core.swarm_workers.vuln.ssrf import run as ssrf_run  # noqa: E402
from core.swarm_workers.vuln.command_injection import run as cmdi_run  # noqa: E402

_URL = re.compile(r"http://([a-z0-9.\-]+):(\d+)/(\w*)")


class _VulnBackend(BaseHTTPRequestHandler):
    """Dereferences any canary URL found in the request (simulated SSRF/cmdi)."""

    def log_message(self, *a):
        pass

    def do_GET(self):
        m = _URL.search(urllib.parse.unquote(self.path))
        if m:
            host, port, tokpath = m.groups()
            token = host.split(".")[0] if "." in host else (tokpath or host)
            try:                                  # backend "reaches out" -> callback
                urllib.request.urlopen(f"http://127.0.0.1:{port}/{token}", timeout=3).read()
            except Exception:
                pass
        body = b"ok"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class _Agent:
    def __init__(self, target):
        self.target = target
        self.timeout_s = 10.0
        self.payload = {}


def _backend():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _VulnBackend)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, f"http://127.0.0.1:{srv.server_address[1]}/"


async def _dead_fetch(*a, **k):
    return None


def _run_worker_with_oob(worker, target):
    with OOBServer(base_domain="oob.local", enable_dns=False) as oob:
        set_oob(oob)
        try:
            findings = asyncio.run(worker(_Agent(target)))
        finally:
            clear_oob()
        blind = [f for f in findings if f.get("oob_token")]
        out = asyncio.run(validate_findings(blind, oob_store=oob.store, fetch=_dead_fetch))
        return blind, out


def test_ssrf_worker_blind_oob_is_confirmed_end_to_end():
    srv, base = _backend()
    try:
        blind, out = _run_worker_with_oob(ssrf_run, base + "?url=1")   # one param -> fast
    finally:
        srv.shutdown()
    assert blind, "SSRF worker emitted no OOB-tagged finding"
    assert all("ssrf:blind" in f["vuln_type"] for f in blind)
    submittable = [f for f in out if f["submittable"]]
    assert submittable, "blind SSRF callback was not confirmed by the gate"
    assert submittable[0]["validation_confidence"] == 0.95
    assert "out-of-band" in submittable[0]["validation_reason"]


def test_cmdi_worker_blind_oob_is_confirmed_end_to_end():
    srv, base = _backend()
    try:
        blind, out = _run_worker_with_oob(cmdi_run, base + "?cmd=1")   # one param -> fast
    finally:
        srv.shutdown()
    assert blind, "cmdi worker emitted no OOB-tagged finding"
    assert all("cmdi:blind" in f["vuln_type"] for f in blind)
    assert any(f["submittable"] for f in out), "blind cmdi callback not confirmed"


def test_workers_emit_no_oob_finding_without_a_server():
    # With no OOB server set, the workers must not emit any oob-tagged finding.
    srv, base = _backend()
    try:
        clear_oob()
        s = asyncio.run(ssrf_run(_Agent(base + "?url=1")))
        c = asyncio.run(cmdi_run(_Agent(base + "?cmd=1")))
    finally:
        srv.shutdown()
    assert not any(f.get("oob_token") for f in s + c)
