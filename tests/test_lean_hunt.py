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


# --- fast (unthrottled) mode: off by default, never leaks --------------------

def test_unthrottled_flag_skips_token_wait():
    import asyncio as _a
    from core.swarm_workers.vuln._rate_limit import (
        is_unthrottled, set_unthrottled, wait_for_token)
    assert is_unthrottled() is False                 # polite by default
    try:
        set_unthrottled(True)
        assert is_unthrottled() is True
        assert _a.run(wait_for_token("example.com")) is True   # immediate
    finally:
        set_unthrottled(False)
    assert is_unthrottled() is False


def test_hunt_fast_mode_resets_throttle_even_on_error():
    from core.swarm_workers.vuln._rate_limit import is_unthrottled
    # point at a dead port so discover/gate do nothing; fast mode must still reset
    asyncio.run(hunt("http://127.0.0.1:1", classes={"xss"}, fast=True, max_pages=2))
    assert is_unthrottled() is False


def test_discover_records_redirect_endpoint_without_following():
    # a 302 endpoint is attack surface (host-header/open-redirect); discover must
    # record /go itself, not the redirect target.
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            from urllib.parse import urlsplit
            if urlsplit(self.path).path == "/":
                body = b'<a href="/go?next=1">go</a>'
                self.send_response(200)
            elif urlsplit(self.path).path == "/go":
                self.send_response(302)
                self.send_header("Location", "https://evil.example/dashboard")
                body = b""
            else:
                body = b"ok"
                self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
    srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{srv.server_address[1]}"
    try:
        surf = asyncio.run(discover(base, max_pages=8))
        assert "/go" in surf["endpoints"]          # recorded, not followed away
        assert "/dashboard" not in surf["endpoints"]
    finally:
        srv.shutdown()
