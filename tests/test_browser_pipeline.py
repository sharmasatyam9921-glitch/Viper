"""Capture pipeline: request dedup, role-diff, HAR import, optional Playwright."""
from __future__ import annotations

import asyncio
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.browser import viper_browser  # noqa: E402
from core.browser.proxy_pipeline import RequestCorpus, request_signature  # noqa: E402
from core.browser.session_capture import (  # noqa: E402
    bola_plan,
    build_session_context,
    role_diff_candidates,
    session_context_from_har,
)


def test_signature_collapses_value_variants():
    a = request_signature("GET", "http://t/api/orders?id=1")
    b = request_signature("GET", "http://t/api/orders?id=2")
    assert a == b                                        # only the value differs
    c = request_signature("GET", "http://t/api/orders?id=1&x=2")
    assert c != a                                        # different param set
    d = request_signature("POST", "http://t/api/orders?id=1")
    assert d != a                                        # different method
    # explicit port is part of the host identity
    p = request_signature("GET", "http://t:8443/api/orders?id=1")
    assert p != a and ":8443" in p


def test_corpus_dedups_and_extracts():
    c = RequestCorpus()
    for i in range(5):
        c.add("GET", f"http://t/api/orders?id={i}", status=200, role="A")
    c.add("GET", "http://t/api/users?uid=9", status=200, role="A")
    c.add("ftp", "ftp://t/x", status=0)                  # non-http dropped
    assert len(c) == 2                                   # two unique signatures
    assert c.params() == {"id", "uid"}
    assert ("GET", "t", "/api/orders") in c.endpoints()
    assert len(c.signatures()) == 2
    assert ("GET", "http://t/api/orders?id=0") in c.candidates()
    har = c.to_har()
    assert len(har["log"]["entries"]) == 2


def test_build_session_context_from_captures():
    ctx = build_session_context({
        "A": {"headers": {"Cookie": "s=alice"}, "markers": ["alice@victim.io"],
              "captures": [("GET", "http://t/api/orders/1", 200),
                           ("GET", "http://t/api/orders/2", 200)]},
        "B": {"headers": {"Cookie": "s=bob"}, "markers": ["bob@victim.io"],
              "captures": [("GET", "http://t/api/orders/1", 403)]},
    })
    assert ctx.status("A", "http://t/api/orders/1") == 200
    assert ctx.status("B", "http://t/api/orders/1") == 403


def test_role_diff_drops_attacker_denied_urls():
    ctx = build_session_context({
        "A": {"headers": {}, "markers": ["m"],
              "captures": [("GET", "http://t/o/1", 200),
                           ("GET", "http://t/o/2", 200)]},
        "B": {"headers": {}, "markers": [],
              "captures": [("GET", "http://t/o/1", 403)]},  # B denied on /o/1
    })
    cands = role_diff_candidates(ctx, "A", "B")
    assert cands == ["http://t/o/2"]            # /o/1 dropped (B already 403)


def test_bola_plan_returns_candidates_and_config():
    ctx = build_session_context({
        "A": {"headers": {"Cookie": "s=alice"}, "markers": ["alice@victim.io"],
              "captures": [("GET", "http://t/o/9", 200)]},
        "B": {"headers": {"Cookie": "s=bob"}, "markers": [], "captures": []},
    })
    cands, cfg = bola_plan(ctx, "A", "B")
    assert cands == ["http://t/o/9"]
    assert cfg["owner_headers"] == {"Cookie": "s=alice"}
    assert "alice@victim.io" in cfg["owner_markers"]


def test_har_import_populates_reachability():
    har = {"log": {"entries": [
        {"request": {"method": "GET", "url": "http://t/api/me"},
         "response": {"status": 200}},
        {"request": {"method": "POST", "url": "http://t/api/login"},
         "response": {"status": 204}},
    ]}}
    ctx = session_context_from_har(har, "A", headers={"Cookie": "s=a"},
                                   markers=["a@x.io"])
    assert ctx.status("A", "http://t/api/me") == 200
    assert ctx.status("A", "http://t/api/login") == 204


def test_har_import_drops_non_http_scheme():
    # A hostile/malformed HAR must not inject file:// (etc.) into the matrix.
    har = {"log": {"entries": [
        {"request": {"method": "GET", "url": "file:///etc/passwd"},
         "response": {"status": 200}},
        {"request": {"method": "GET", "url": "http://t/api/me"},
         "response": {"status": 200}},
    ]}}
    ctx = session_context_from_har(har, "A")
    urls = ctx.reachable_urls("A", ok_only=False)
    assert urls == ["http://t/api/me"]            # file:// dropped


def test_playwright_available_returns_bool():
    assert isinstance(viper_browser.available(), bool)


class _RoleHandler(BaseHTTPRequestHandler):
    """/private -> 200 iff an X-Role header is present, else 403."""

    def log_message(self, *a):
        pass

    def do_GET(self):
        authed = self.headers.get("X-Role") is not None
        if self.path == "/private":
            code, body = (200, b"<html>private alice@victim.io</html>") if authed \
                else (403, b"forbidden")
        else:
            code, body = 200, b"<html>home</html>"
        self.send_response(code)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(body)


@pytest.mark.skipif(not viper_browser.available(),
                    reason="Playwright not installed")
def test_capture_roles_live_role_diff_get_only():
    # Drives real Chromium as two roles; verifies the authenticated role-diff,
    # scope-guarding, and that ONLY GET/HEAD traffic is recorded (non-destructive).
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _RoleHandler)
    base = f"http://127.0.0.1:{srv.server_address[1]}"
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        ctx = asyncio.run(viper_browser.capture_roles(
            # the off-scope seed must be skipped by the scope guard, never fetched
            [f"{base}/private", f"{base}/home", "http://off-scope.example/x"],
            {"A": {"headers": {"X-Role": "alice"}, "markers": ["alice@victim.io"]},
             "B": {"headers": {}, "markers": []}},
            scope_guard=lambda u: u.startswith(base), hunt_id="t"))
    except Exception as exc:                      # no chromium binary -> skip, don't fail
        pytest.skip(f"Chromium unavailable: {type(exc).__name__}: {exc}")
    finally:
        srv.shutdown()

    assert ctx.status("A", f"{base}/private") == 200    # authed owner sees it
    assert ctx.status("B", f"{base}/private") == 403    # attacker denied
    assert all(c.method in ("GET", "HEAD") for c in ctx.corpus)   # read-only only
    assert f"{base}/private" in ctx.candidate_urls_for_bola("A")
    assert "http://off-scope.example/x" not in ctx.reachable_urls("A", ok_only=False)


def test_capture_roles_raises_without_playwright(monkeypatch):
    monkeypatch.setattr(viper_browser, "available", lambda: False)
    with pytest.raises(RuntimeError):
        asyncio.run(viper_browser.capture_roles(["http://t/x"], {"A": {}}))
