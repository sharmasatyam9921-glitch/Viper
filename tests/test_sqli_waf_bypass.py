"""End-to-end: SQLi found AND gate-confirmed THROUGH a WAF via encoding bypass."""
from __future__ import annotations

import asyncio
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.swarm_validation import validate_findings  # noqa: E402
from core.swarm_workers.vuln.sqli_probe import run as sqli_run  # noqa: E402
from core.swarm_workers.vuln._bypass import reset_learning  # noqa: E402


class _Agent:
    def __init__(self, t):
        self.target = t
        self.timeout_s = 8.0
        self.payload = {}


def _waf_app_server():
    """A WAF in front of a SQLi-vulnerable app.

    WAF view = the once-decoded query value. A literal `'` is blocked (403). The
    app then decodes AGAIN: an UNBALANCED quote breaks the query (500 + SQL error),
    a BALANCED `''` is valid (200), a benign value is fine (200). So the raw quote
    never reaches the DB, but a URL-encoded quote slips past the WAF and injects.
    """
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            vals = parse_qs(urlsplit(self.path).query)
            value = (vals.get("id") or [""])[0]          # WAF sees this (1 decode)
            if "'" in value:                              # literal quote -> WAF block
                body = b"Request blocked by mod_security"
                self.send_response(403)
            else:
                appval = unquote(value)                   # app decodes again
                qn = appval.count("'")
                if qn % 2 == 1:                           # unbalanced -> DB error
                    body = b"You have an error in your SQL syntax near line 1"
                    self.send_response(500)
                else:                                     # balanced / benign -> ok
                    body = b"<html>ok</html>"
                    self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
    srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, f"http://127.0.0.1:{srv.server_address[1]}/"


def test_sqli_found_and_confirmed_through_waf():
    reset_learning()
    srv, base = _waf_app_server()
    try:
        target = f"{base}item?id=1"
        findings = asyncio.run(sqli_run(_Agent(target)))
        # the worker slipped a mutated quote past the WAF and saw the SQL banner
        sqli = [f for f in findings if f["vuln_type"].startswith("sqli")]
        assert sqli, "worker failed to find SQLi through the WAF"
        assert "WAF-bypassed" in sqli[0]["title"]

        # and the gate re-confirms THROUGH the WAF (fair bypass re-test holds)
        out = asyncio.run(validate_findings(sqli, default_target=target))
        sub = [f for f in out if f["submittable"]]
        assert sub and sub[0]["validation_confidence"] == 0.8
        assert "bypass reached the database" in sub[0]["validation_reason"]
    finally:
        srv.shutdown()


def test_pure_waf_block_no_app_bug_stays_lead():
    reset_learning()
    # A WAF that blocks the quote in ANY encoding, with no vulnerable app behind it.
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            value = (parse_qs(urlsplit(self.path).query).get("id") or [""])[0]
            blocked = "'" in unquote(value)               # block decoded quote always
            body = b"blocked by mod_security" if blocked else b"<html>ok</html>"
            self.send_response(403 if blocked else 200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
    srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{srv.server_address[1]}/"
    try:
        findings = asyncio.run(sqli_run(_Agent(f"{base}item?id=1")))
        assert findings == []          # WAF blocks every encoding -> no finding
    finally:
        srv.shutdown()
