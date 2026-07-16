"""#6 deeper discovery: active hidden-parameter brute-force + a bounded
depth-2 crawl, so VIPER stops concluding a target is clean off one index page. Both are
read-only, same-host, and feed the unchanged gate."""
from __future__ import annotations

import asyncio
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.swarm_engine import SwarmAgent  # noqa: E402
from core.swarm_workers.recon import endpoints as ep_mod  # noqa: E402
from core.swarm_workers.recon import param_brute as pb_mod  # noqa: E402
from core.payload_library import (  # noqa: E402
    clear_discovered_params, get_discovered_params)


def _agent(target: str, technique: str) -> SwarmAgent:
    return SwarmAgent(agent_id="t", objective="x", target=target,
                      technique=technique, payload={}, timeout_s=6.0)


def _serve(handler_cls):
    srv = ThreadingHTTPServer(("127.0.0.1", 0), handler_cls)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, f"http://127.0.0.1:{srv.server_address[1]}"


# ── param_brute: discovers a reflecting param, invents nothing on a static page ──
def test_param_brute_finds_reflecting_param():
    clear_discovered_params()

    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            qs = parse_qs(urlsplit(self.path).query)
            # Only 'q' is a real param — its value is reflected into the page.
            echo = qs.get("q", [""])[0]
            body = f"<html><body>results for {echo}</body></html>".encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    srv, base = _serve(H)
    try:
        out = asyncio.run(pb_mod.run(_agent(base + "/search", "param_brute")))
        names = {f["vuln_type"].split(":", 1)[1] for f in out}
        assert "q" in names, "reflecting param 'q' must be discovered"
        assert "q" in get_discovered_params(), "must register discovered params"
    finally:
        clear_discovered_params()
        srv.shutdown()


def test_param_brute_ignores_echo_everything_page():
    # A page that reflects ANY query value (echoes the whole query string) must NOT make
    # every probed name register — the control-name guard catches it.
    clear_discovered_params()

    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            q = parse_qs(urlsplit(self.path).query)
            echo = " ".join(v[0] for v in q.values() if v)     # echoes EVERY param's value
            body = f"<html>you sent {echo}</html>".encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    srv, base = _serve(H)
    try:
        out = asyncio.run(pb_mod.run(_agent(base + "/", "param_brute")))
        assert out == [], "an echo-everything page must not register the whole wordlist"
    finally:
        clear_discovered_params()
        srv.shutdown()


def test_endpoints_crawl_follows_same_host_redirect_only():
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            path = urlsplit(self.path).path
            if path == "/":
                self.send_response(302)
                self.send_header("Location", "/moved")          # same-host redirect
                self.end_headers()
                return
            if path == "/off":
                self.send_response(302)
                self.send_header("Location", "https://evil.example/x")  # off-host redirect
                self.end_headers()
                return
            body = b"<html><a href='/off'>off</a><p>content</p></html>"
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    srv, base = _serve(H)
    try:
        out = asyncio.run(ep_mod.run(_agent(base + "/", "endpoints")))
        urls = {f["url"] for f in out}
        assert any(u.endswith("/moved") for u in urls), "same-host redirect target discovered"
        assert not any("evil.example" in u for u in urls), "off-host redirect not followed/emitted"
    finally:
        srv.shutdown()


def test_param_brute_invents_nothing_on_static_page():
    clear_discovered_params()

    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            body = b"<html><body>static, identical every time</body></html>"
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    srv, base = _serve(H)
    try:
        out = asyncio.run(pb_mod.run(_agent(base + "/", "param_brute")))
        assert out == [], "a static page reflects/changes nothing -> no invented params"
    finally:
        clear_discovered_params()
        srv.shutdown()


# ── endpoints: bounded depth-2 crawl reaches links-of-links, stays same-host ──
def test_endpoints_crawl_reaches_depth_two():
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            path = urlsplit(self.path).path
            if path == "/":
                html = ('<a href="/a">a</a><a href="/b">b</a>'
                        '<a href="https://evil.example/x">off</a>')
            elif path == "/a":
                html = '<a href="/deep">deep</a>'   # depth-2 target
            else:
                html = "<p>leaf</p>"
            body = f"<html>{html}</html>".encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    srv, base = _serve(H)
    try:
        out = asyncio.run(ep_mod.run(_agent(base + "/", "endpoints")))
        urls = {f["url"] for f in out}
        assert any(u.endswith("/a") for u in urls)
        assert any(u.endswith("/deep") for u in urls), "depth-2 link-of-link must be found"
        assert not any("evil.example" in u for u in urls), "cross-host links excluded"
    finally:
        srv.shutdown()
