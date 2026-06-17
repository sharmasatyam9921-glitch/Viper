"""End-to-end integration test for two-account BOLA.

Drives the REAL stack below the CLI against a REAL local HTTP server:
    VulnSwarmCoordinator.handle_message  →  bola_multi worker  →  find_bola
    →  core.swarm_workers.vuln._http.fetch  →  localhost server

Crucially it installs a global session auth via set_auth() — exactly what a
live hunt does (HackMode.run installs identity A's session for every worker).
This pins the wiring bug that unit tests (which bypass the global _auth_var)
cannot see: the anon-control / attacker probes must NOT inherit the global
session, or every real BOLA finding is suppressed (false negative) — or, with
mixed header types, falsely confirmed.
"""
from __future__ import annotations

import asyncio
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import core.swarm_workers  # noqa: F401  (registers workers)
from core.agent_bus import AgentBus  # noqa: E402
from core.swarm_coordinator import VulnSwarmCoordinator  # noqa: E402
from core.swarm_workers.vuln._http import set_auth, clear_auth  # noqa: E402

# Identity A's private marker — leaks to anyone with a valid session (the bug).
A_MARKER = "alice@victim.io"


class _BolaVulnHandler(BaseHTTPRequestHandler):
    """A deliberately BOLA-vulnerable object endpoint.

    /api/orders/1001 returns A's private data to ANY authenticated session
    (alice OR bob) — that's the broken authorization. With NO session it 401s,
    so the data is genuinely private (not public).
    """

    def log_message(self, *a):  # silence
        pass

    def do_GET(self):
        if not self.path.startswith("/api/orders/1001"):
            self.send_response(404)
            self.end_headers()
            return
        cookie = self.headers.get("Cookie", "") or ""
        authed = ("s=alice" in cookie) or ("s=bob" in cookie)
        if authed:
            body = ('{"order":1001,"owner":"%s","total":42}' % A_MARKER).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        else:
            self.send_response(401)
            self.end_headers()


@pytest.fixture()
def server():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _BolaVulnHandler)
    port = srv.server_address[1]
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    try:
        yield f"http://127.0.0.1:{port}"
    finally:
        srv.shutdown()
        srv.server_close()


def _run_vuln_phase(base: str) -> list[dict]:
    coord = VulnSwarmCoordinator(bus=AgentBus(max_queue_size=1000))
    payload = {
        "target": base,
        "assets": [f"{base}/api/orders/1001"],
        "techniques": ["bola_multi"],
        "bola": {
            "owner_name": "alice",
            "owner_headers": {"Cookie": "s=alice"},
            "owner_markers": [A_MARKER],
            "attacker_name": "bob",
            "attacker_headers": {"Cookie": "s=bob"},
            "unauth_control": True,
        },
    }
    result = asyncio.run(coord.handle_message(payload))
    return result.findings


def test_bola_detected_end_to_end_with_global_session_auth(server):
    # Simulate the live hunt: identity A's session is installed globally for
    # EVERY worker. The bola worker must still send clean per-identity probes.
    set_auth({"Cookie": "s=alice"})
    try:
        findings = _run_vuln_phase(server)
    finally:
        clear_auth()

    bola = [f for f in findings if "idor" in (f.get("vuln_type") or "")
            or f.get("type") == "bola"]
    assert bola, (
        "expected a BOLA finding end-to-end. If empty, the anon-control probe "
        "inherited the global session (s=alice) and made the private object "
        "look public — the use_session_auth=False fix regressed."
    )
    f = bola[0]
    assert f["cwe"] == "CWE-639"
    assert A_MARKER in f["evidence"]
    assert "/api/orders/1001" in f["url"]


def test_no_false_positive_when_attacker_blocked(server):
    # Same server but B has no valid session → the worker should find nothing.
    set_auth({"Cookie": "s=alice"})
    try:
        coord = VulnSwarmCoordinator(bus=AgentBus(max_queue_size=1000))
        payload = {
            "target": server,
            "assets": [f"{server}/api/orders/1001"],
            "techniques": ["bola_multi"],
            "bola": {
                "owner_name": "alice",
                "owner_headers": {"Cookie": "s=alice"},
                "owner_markers": [A_MARKER],
                "attacker_name": "bob",
                "attacker_headers": {"Cookie": "s=invalid"},  # 401 → no access
                "unauth_control": True,
            },
        }
        findings = asyncio.run(coord.handle_message(payload)).findings
    finally:
        clear_auth()
    bola = [f for f in findings if "idor" in (f.get("vuln_type") or "")]
    assert not bola, "attacker with no valid session must not yield a finding"
