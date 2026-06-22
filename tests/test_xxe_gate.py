"""In-band XXE file read is now gate-confirmed (was stuck as a lead)."""
from __future__ import annotations

import asyncio
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.swarm_validation import validate_findings  # noqa: E402
from core.swarm_workers.vuln.xxe import run as xxe_run  # noqa: E402

_PASSWD = (b"root:x:0:0:root:/root:/bin/bash\n"
           b"daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
           b"bin:x:2:2:bin:/bin:/usr/sbin/nologin\n")


class _Agent:
    def __init__(self, t):
        self.target = t
        self.timeout_s = 8.0
        self.payload = {}


def _server(vulnerable: bool):
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_POST(self):
            n = int(self.headers.get("Content-Length", 0) or 0)
            body = self.rfile.read(n).decode("utf-8", "replace") if n else ""
            out = (_PASSWD if (vulnerable and "file:///etc/passwd" in body)
                   else b"<r>ok</r>")
            self.send_response(200)
            self.send_header("Content-Type", "application/xml")
            self.send_header("Content-Length", str(len(out)))
            self.end_headers()
            self.wfile.write(out)
    srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, f"http://127.0.0.1:{srv.server_address[1]}/"


def test_inband_xxe_file_read_is_gate_confirmed():
    srv, base = _server(vulnerable=True)
    try:
        findings = asyncio.run(xxe_run(_Agent(base)))
        assert any("file_read" in f["vuln_type"] for f in findings)
        out = asyncio.run(validate_findings(findings, default_target=base))
        sub = [f for f in out if f["submittable"]]
        assert sub and sub[0]["validation_confidence"] == 0.9
        assert "local-file read" in sub[0]["validation_reason"]
    finally:
        srv.shutdown()


def test_non_vulnerable_xxe_is_lead():
    srv, base = _server(vulnerable=False)
    try:
        f = {"vuln_type": "xxe:file_read", "url": base}
        out = asyncio.run(validate_findings([f], default_target=base))
        assert not out[0]["submittable"]            # cannot reproduce -> lead
    finally:
        srv.shutdown()
