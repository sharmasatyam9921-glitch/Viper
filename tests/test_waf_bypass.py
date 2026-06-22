"""Adaptive WAF-bypass: block detection, mutation, per-host learning."""
from __future__ import annotations

import asyncio
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, quote, urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.waf_bypass import AdaptiveBypass, BypassResult, is_blocked, mutate  # noqa: E402
from core.swarm_workers.vuln._http import HttpResp  # noqa: E402
from core.swarm_workers.vuln._bypass import adaptive_fetch, reset_learning  # noqa: E402


# --- unit: block detection + mutation -------------------------------------

def test_is_blocked_status_and_markers():
    assert is_blocked(HttpResp(403, {}, "nope", ""))
    assert is_blocked(HttpResp(200, {}, "Request blocked by mod_security", ""))
    assert not is_blocked(HttpResp(200, {}, "<html>ok</html>", ""))
    assert not is_blocked(None)


def test_mutate_includes_raw_first_and_variants():
    muts = mutate("' OR 1=1")
    assert muts[0] == ("raw", "' OR 1=1")
    labels = {m[0] for m in muts}
    assert {"comment", "case_swap", "url_encode"} <= labels
    # comment mutation removes the literal space-joined keyword
    comment = dict((l, v) for l, v in muts)["comment"]
    assert "OR 1=1" not in comment and "OR/**/1=1" in comment


# --- unit: adaptive loop over a fake send ----------------------------------

def test_loop_returns_raw_when_not_blocked():
    async def send(v):
        return HttpResp(200, {}, "ok", "")
    r = asyncio.run(AdaptiveBypass().run(send, "x", target="h"))
    assert r.label == "raw" and not r.bypassed and not r.blocked


def test_loop_learns_winning_mutation_and_reuses_it():
    eng = AdaptiveBypass()
    calls = []

    async def send(v):
        calls.append(v)
        # WAF blocks the literal "or 1=1"; the comment variant slips through
        return HttpResp(403 if "or 1=1" in v.lower() else 200, {},
                        "blocked" if "or 1=1" in v.lower() else "ok", "")

    r1 = asyncio.run(eng.run(send, "' or 1=1", target="h"))
    assert r1.bypassed and r1.label == "comment" and not r1.blocked
    assert eng.learned("h") == "comment"
    n_first = len(calls)
    # second probe: learned mutation is tried FIRST → one send, immediate bypass
    calls.clear()
    r2 = asyncio.run(eng.run(send, "' or 1=1", target="h"))
    assert r2.label == "comment" and len(calls) == 1
    assert n_first > 1                       # the first run had to escalate


def test_loop_reports_total_block_without_faking_success():
    async def send(v):
        return HttpResp(403, {}, "denied", "")
    r = asyncio.run(AdaptiveBypass().run(send, "x", target="h"))
    assert r.blocked and not r.bypassed


# --- integration: real mock-WAF HTTP server --------------------------------

def _waf_server():
    """Blocks any request whose decoded query contains the literal 'or 1=1'."""
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            q = urlsplit(self.path).query
            decoded = " ".join(v for vs in parse_qs(q).values() for v in vs).lower()
            blocked = "or 1=1" in decoded
            self.send_response(403 if blocked else 200)
            body = b"Request blocked by mod_security" if blocked else b"<html>ok</html>"
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
    srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, f"http://127.0.0.1:{srv.server_address[1]}/"


def test_adaptive_fetch_bypasses_real_waf():
    reset_learning()
    srv, base = _waf_server()
    try:
        def build(variant):
            return f"{base}search?q={quote(variant, safe='')}"
        res = asyncio.run(adaptive_fetch("GET", build, "' or 1=1", timeout=8.0))
        assert isinstance(res, BypassResult)
        assert not res.blocked and res.bypassed        # a mutation slipped past
        assert res.response.status == 200
    finally:
        srv.shutdown()
