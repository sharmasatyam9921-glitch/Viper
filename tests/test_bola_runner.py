"""Tests for the focused BOLA runner (sessions + candidate URLs + proxy)."""
from __future__ import annotations

import asyncio
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.specialist.bola_runner import run_bola  # noqa: E402
from core.swarm_workers.vuln import _http  # noqa: E402

A_MARKER = "alice@victim.io"


class _Vuln(BaseHTTPRequestHandler):
    """/api/orders/1001 returns A's private data to ANY valid session (the bug)."""
    def log_message(self, *a):
        pass

    def do_GET(self):
        if not self.path.startswith("/api/orders/1001"):
            self.send_response(404); self.end_headers(); return
        cookie = self.headers.get("Cookie", "") or ""
        if "s=alice" in cookie or "s=bob" in cookie:
            body = ('{"order":1001,"owner":"%s"}' % A_MARKER).encode()
            self.send_response(200); self.send_header("Content-Length", str(len(body)))
            self.end_headers(); self.wfile.write(body)
        else:
            self.send_response(401); self.end_headers()


@pytest.fixture()
def server():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _Vuln)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        yield f"http://127.0.0.1:{srv.server_address[1]}"
    finally:
        srv.shutdown(); srv.server_close()


def test_run_bola_finds_cross_user_read(server):
    findings = asyncio.run(run_bola(
        owner_headers={"Cookie": "s=alice"},
        owner_markers=[A_MARKER],
        attacker_headers={"Cookie": "s=bob"},
        candidate_urls=[f"{server}/api/orders/1001"],
    ))
    assert len(findings) == 1
    assert findings[0]["cwe"] == "CWE-639"
    assert A_MARKER in findings[0]["evidence"]


def test_run_bola_no_finding_when_attacker_blocked(server):
    findings = asyncio.run(run_bola(
        owner_headers={"Cookie": "s=alice"},
        owner_markers=[A_MARKER],
        attacker_headers={"Cookie": "s=invalid"},  # 401 -> no access
        candidate_urls=[f"{server}/api/orders/1001"],
    ))
    assert findings == []


class _Sink(BaseHTTPRequestHandler):
    """Records the auth headers it receives — stands in for a third-party host."""
    received: list = []

    def log_message(self, *a):
        pass

    def do_GET(self):
        _Sink.received.append({
            "auth": self.headers.get("Authorization"),
            "cookie": self.headers.get("Cookie"),
        })
        self.send_response(200); self.end_headers(); self.wfile.write(b"{}")


@pytest.fixture()
def sink():
    _Sink.received = []
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _Sink)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        yield f"http://127.0.0.1:{srv.server_address[1]}"
    finally:
        srv.shutdown(); srv.server_close()


def test_allowed_hosts_blocks_credential_leak_to_foreign_host(sink):
    # A candidate URL on a DIFFERENT host than the allowlist must NOT receive the
    # operator's session — the core credential-leak fix.
    foreign_url = f"{sink}/api/users/55"
    findings = asyncio.run(run_bola(
        owner_headers={"Cookie": "session=SECRET_A", "Authorization": "Bearer TOK_A"},
        owner_markers=["alice@victim.io"],
        attacker_headers={"Cookie": "session=SECRET_B"},
        candidate_urls=[foreign_url],
        allowed_hosts={"target.example"},   # foreign sink is NOT allowed
    ))
    assert findings == []
    assert _Sink.received == [], (
        "operator session was replayed to a third-party host: "
        f"{_Sink.received}")


def test_allowed_hosts_permits_in_scope(server):
    from urllib.parse import urlsplit
    host = urlsplit(server).hostname  # "127.0.0.1" (port-agnostic match)
    findings = asyncio.run(run_bola(
        owner_headers={"Cookie": "s=alice"}, owner_markers=[A_MARKER],
        attacker_headers={"Cookie": "s=bob"},
        candidate_urls=[f"{server}/api/orders/1001"],
        allowed_hosts={host},
    ))
    assert len(findings) == 1 and findings[0]["cwe"] == "CWE-639"


def test_userinfo_spoof_does_not_pass_allowlist(sink):
    # "https://target.example@<sink>/..." resolves to the sink's host, NOT
    # target.example — the hostname compare must drop it (no creds leak).
    spoof = f"https://target.example@127.0.0.1:{sink.rsplit(':', 1)[1]}/api/users/1"
    findings = asyncio.run(run_bola(
        owner_headers={"Authorization": "Bearer TOK_A"}, owner_markers=["alice@x"],
        attacker_headers={"Cookie": "s=bob"},
        candidate_urls=[spoof],
        allowed_hosts={"target.example"},
    ))
    assert findings == []
    assert _Sink.received == [], f"userinfo spoof leaked creds: {_Sink.received}"


def test_run_bola_installs_and_restores_proxy(monkeypatch):
    seen = []

    async def fake_fetch(method, url, *, headers=None, timeout=10.0,
                         use_session_auth=True, **kw):
        seen.append(_http.get_proxy())          # proxy active during the probe?
        cookie = (headers or {}).get("Cookie", "")
        if "s=alice" in cookie or "s=bob" in cookie:
            return _http.HttpResp(200, {}, '{"owner":"%s"}' % A_MARKER, url)
        return _http.HttpResp(401, {}, "", url)

    monkeypatch.setattr(_http, "fetch", fake_fetch)
    _http.set_proxy("http://pre-existing:9")     # a prior proxy must be restored
    try:
        asyncio.run(run_bola(
            owner_headers={"Cookie": "s=alice"}, owner_markers=[A_MARKER],
            attacker_headers={"Cookie": "s=bob"},
            candidate_urls=["http://t/api/orders/1001"],
            proxy="http://127.0.0.1:8080",
        ))
        assert seen and all(p == "http://127.0.0.1:8080" for p in seen)
        assert _http.get_proxy() == "http://pre-existing:9"  # restored
    finally:
        _http.clear_proxy()
