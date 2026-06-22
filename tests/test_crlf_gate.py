"""CRLF header-injection worker is now gate-confirmed (re-test with fresh token)."""
from __future__ import annotations

import asyncio
import re
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.swarm_validation import validate_findings  # noqa: E402
from core.swarm_workers.vuln.crlf import run as crlf_run  # noqa: E402


class _Agent:
    def __init__(self, t):
        self.target = t
        self.timeout_s = 8.0
        self.payload = {}


def _server(vulnerable: bool):
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            extra = {}
            if vulnerable:
                for vals in parse_qs(urlsplit(self.path).query).values():
                    for v in vals:
                        # naive: split the (already-decoded) value on CRLF/LF and
                        # treat trailing "name: value" as response headers.
                        for line in re.split(r"\r\n|\n", v)[1:]:
                            if ":" in line:
                                k, _, val = line.partition(":")
                                if k.strip():
                                    extra[k.strip()] = val.strip()
            self.send_response(200)
            for k, val in extra.items():
                try:
                    self.send_header(k, val)
                except Exception:
                    pass
            body = b"ok"
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
    srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, f"http://127.0.0.1:{srv.server_address[1]}/"


def test_crlf_worker_finds_and_gate_confirms():
    srv, base = _server(vulnerable=True)
    try:
        findings = asyncio.run(crlf_run(_Agent(base)))
        assert findings and findings[0]["vuln_type"] == "crlf_header_injection"
        out = asyncio.run(validate_findings(findings, default_target=base))
        sub = [f for f in out if f["submittable"]]
        assert sub and sub[0]["validation_confidence"] == 0.85
        assert "header injection" in sub[0]["validation_reason"]
    finally:
        srv.shutdown()


def test_crlf_not_vulnerable_no_finding_and_gate_lead():
    srv, base = _server(vulnerable=False)
    try:
        assert asyncio.run(crlf_run(_Agent(base))) == []
        # a stale/unreproducible crlf finding is a lead, not submittable
        f = {"vuln_type": "crlf_header_injection", "url": base, "parameter": "q"}
        out = asyncio.run(validate_findings([f], default_target=base))
        assert not out[0]["submittable"]
    finally:
        srv.shutdown()
