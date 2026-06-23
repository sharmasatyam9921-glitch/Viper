"""Discovery-strong lean hunt: param mining + param-aware probing + gate."""
from __future__ import annotations

import asyncio
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.lean_hunt import discover, hunt  # noqa: E402
from core.payload_library import (  # noqa: E402
    add_discovered_params,
    clear_discovered_params,
    get_discovered_params,
)


def _server(html_by_path):
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            from urllib.parse import urlsplit
            path = urlsplit(self.path).path
            body = html_by_path.get(path, "<html>ok</html>").encode()
            self.send_response(200 if path in html_by_path or path == "/" else 404)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
    srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, f"http://127.0.0.1:{srv.server_address[1]}"


# --- discovered-params channel is opt-in (no behavior change by default) -----

def test_discovered_params_channel():
    clear_discovered_params()
    assert get_discovered_params() == []          # empty by default
    add_discovered_params(["filename", "tplname", "filename"])
    got = set(get_discovered_params())
    assert {"filename", "tplname"} <= got
    clear_discovered_params()
    assert get_discovered_params() == []


# --- discover() mines params from links AND form inputs ----------------------

def test_discover_mines_links_and_form_inputs():
    html = {
        "/": '<a href="/page?ref=1">x</a>'
             '<form action="/submit"><input name="tplname"><input name="email"></form>',
    }
    srv, base = _server(html)
    try:
        surf = asyncio.run(discover(base, max_pages=8))
        eps = surf["endpoints"]
        assert "/page" in eps and "ref" in eps["/page"]          # query key mined
        assert "tplname" in eps.get("/", set())                  # form input mined
    finally:
        srv.shutdown()


# --- end-to-end: param-aware probing finds a vuln on a non-default param -----

def test_hunt_finds_xss_on_discovered_param():
    # /view reflects the 'tplname' param (NOT in xss defaults); the index form
    # exposes it, so the crawler discovers it and the worker probes it.
    import html as _h

    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            from urllib.parse import parse_qs, urlsplit
            p = urlsplit(self.path)
            if p.path == "/":
                body = b'<form action="/view"><input name="tplname"></form>'
            elif p.path == "/view":
                v = (parse_qs(p.query).get("tplname") or [""])[0]
                body = f"<html>{v}</html>".encode()       # raw reflection -> XSS
            else:
                body = b"ok"
            self.send_response(200)
            self.send_header("Content-Type", "text/html")  # so the gate sees HTML
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
    srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{srv.server_address[1]}"
    try:
        found = asyncio.run(hunt(base, classes={"xss"}))
        assert any(str(f.get("vuln_type", "")).startswith("xss") for f in found), \
            "param-aware probing should find XSS on the discovered 'tplname' param"
    finally:
        srv.shutdown()
