"""Web Cache Deception worker (two-identity, cache-confirmed) + gate trust."""
from __future__ import annotations

import asyncio
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.swarm_validation import validate_findings  # noqa: E402
from core.swarm_workers.vuln.web_cache_deception import run as wcd_run  # noqa: E402

_MARKER = "alice@victim.io"


class _Agent:
    def __init__(self, t, cfg):
        self.target = t
        self.timeout_s = 8.0
        self.payload = {"wcd": cfg}


def _vuln_cache_server(vulnerable: bool):
    """A cache that (when vulnerable) stores the authed body under the static URL
    and replays it to anonymous requests."""
    cache: dict = {}

    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            path = urlsplit(self.path).path
            authed = "session=alice" in (self.headers.get("Cookie") or "")
            looks_static = path.endswith((".css", ".js"))
            # serve cached copy to anyone (the cache vuln)
            if vulnerable and looks_static and path in cache:
                return self._send(cache[path], cacheable=True)
            if authed:
                body = ('{"email":"%s","balance":4200}' % _MARKER).encode()
                if vulnerable and looks_static:
                    cache[path] = body            # cache the AUTHENTICATED page
                    return self._send(body, cacheable=True)
                return self._send(body, cacheable=False)
            return self._send(b"login required", cacheable=False, code=200)

        def _send(self, body, *, cacheable, code=200):
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Cache-Control",
                             "public, max-age=600" if cacheable else "no-store")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
    srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, f"http://127.0.0.1:{srv.server_address[1]}/"


def _cfg():
    return {"headers": {"Cookie": "session=alice"}, "markers": [_MARKER],
            "paths": ["/account"]}


def test_wcd_confirmed_and_gate_trusts_it():
    srv, base = _vuln_cache_server(vulnerable=True)
    try:
        findings = asyncio.run(wcd_run(_Agent(base, _cfg())))
        assert findings and findings[0]["cache_confirmed"] is True
        assert "web_cache_deception" in findings[0]["vuln_type"]
        out = asyncio.run(validate_findings(findings, fetch=_dead))
        assert out[0]["submittable"] and out[0]["validation_confidence"] == 0.85
    finally:
        srv.shutdown()


def test_no_finding_when_cache_does_not_leak():
    srv, base = _vuln_cache_server(vulnerable=False)   # serves authed but never caches to anon
    try:
        assert asyncio.run(wcd_run(_Agent(base, _cfg()))) == []
    finally:
        srv.shutdown()


def test_wcd_is_opt_in():
    class _A:
        target = "http://t/"
        timeout_s = 8.0
        payload = {}
    assert asyncio.run(wcd_run(_A())) == []


def test_gate_rejects_unconfirmed_wcd():
    f = {"vuln_type": "web_cache_deception:/account", "url": "http://t/account/x.css"}
    out = asyncio.run(validate_findings([f], fetch=_dead))
    assert not out[0]["submittable"]                    # no cache_confirmed flag


async def _dead(*a, **k):
    return None
