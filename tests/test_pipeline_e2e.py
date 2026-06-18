"""End-to-end pipeline lock: worker FINDS -> gate CONFIRMS -> SUBMITTABLE -> DRAFT.

Drives the real stack against a live local SQLi-vulnerable server:
  sqli_probe worker  ->  core.swarm_validation.validate_findings (real re-test)
  ->  core.submission_draft.write_drafts

No mocks of the components under test — only a deliberately-vulnerable HTTP
server. This pins that a genuine vulnerability flows all the way to a
platform-ready draft, and that the gate's independent re-test agrees with the
worker.
"""
from __future__ import annotations

import asyncio
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import core.swarm_workers  # noqa: F401,E402  (registers workers)
from core.submission_draft import write_drafts  # noqa: E402
from core.swarm_engine import SwarmAgent  # noqa: E402
from core.swarm_validation import partition, validate_findings  # noqa: E402
from core.swarm_workers import get_worker_runner  # noqa: E402


class _SqliVuln(BaseHTTPRequestHandler):
    """/search?q=... — genuinely SQLi-vulnerable: a single OR double quote breaks
    the query and surfaces a DB error (500); a benign value is a clean 200."""

    def log_message(self, *a):
        pass

    def do_GET(self):
        q = ""
        if "?" in self.path and "q=" in self.path:
            from urllib.parse import urlsplit, parse_qs, unquote
            q = unquote(parse_qs(urlsplit(self.path).query).get("q", [""])[0])
        # Genuine SQLi: an UNBALANCED quote breaks the query (500 + DB error); a
        # balanced '' and a benign value do not — exactly what the gate confirms.
        if q.count("'") % 2 == 1 or q.count('"') % 2 == 1:
            body = (b"<html><title>Error</title>"
                    b"You have an error in your SQL syntax; check the manual "
                    b"near \"'\" at line 1</html>")
            self.send_response(500)
        else:
            body = b'{"status":"success","data":[]}'
            self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


@pytest.fixture()
def server():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _SqliVuln)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        yield f"http://127.0.0.1:{srv.server_address[1]}"
    finally:
        srv.shutdown(); srv.server_close()


def test_find_confirm_submittable_draft(server, tmp_path):
    target = f"{server}/search?q=apple"

    # 1. WORKER finds the SQLi.
    run = get_worker_runner("vuln", "sqli_probe")
    ag = SwarmAgent(agent_id="t", objective="x", target=target,
                    technique="sqli_probe", payload={}, timeout_s=10.0)
    findings = asyncio.run(run(ag))
    sqli = [f for f in findings if "sqli" in str(f.get("vuln_type", ""))]
    assert sqli, "worker should detect the SQLi"

    # 2. GATE independently re-confirms -> submittable.
    annotated = asyncio.run(validate_findings(sqli, default_target=server))
    sub, leads = partition(annotated)
    assert sub, f"gate should confirm the SQLi as submittable (got leads: {leads})"
    assert sub[0]["validation_confidence"] >= 0.7

    # 3. DRAFT written for the submittable finding.
    paths = write_drafts(sub, tmp_path, target=server)
    assert len(paths) == 1
    md = paths[0].read_text(encoding="utf-8")
    assert "SQL Injection" in md and "CWE-89" in md
    assert "## Steps to Reproduce" in md
    assert "validation gate" in md  # states it was independently re-confirmed
