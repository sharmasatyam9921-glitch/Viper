"""Regression: anonymous-premise vuln workers must NOT inherit the hunt's
globally-installed session auth.

A live hunt installs identity A's session via set_auth() so most workers test
the app as the logged-in user. But a family of workers detect a vuln precisely
by sending an UNAUTHENTICATED probe (broken_access_control, path_bypass, idor,
bola) or by observing what an anonymous visitor receives (csrf). If the global
session leaks into those probes it silently flips findings — false positives
(an authed 200 misread as "accessible without auth") or false negatives.

These tests install a global session and assert each such worker still sends
its probe WITHOUT the session header. We assert at the HTTP boundary by patching
_fetch_sync (the single sync sink inside _http.fetch), so the full
set_auth → fetch → use_session_auth merge path is exercised for real.
"""
from __future__ import annotations

import asyncio
import sys
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import core.swarm_workers  # noqa: F401  (registers workers)
from core.swarm_engine import SwarmAgent
from core.swarm_workers import get_worker_runner
from core.swarm_workers.vuln import _http
from core.swarm_workers.vuln._http import HttpResp, set_auth, clear_auth

A_SESSION = {"Cookie": "session=ALICE_PRIVATE"}


def _agent(target, technique):
    return SwarmAgent(agent_id="t", objective="x", target=target,
                      technique=technique, payload={}, timeout_s=5.0)


def _capture_run(target, technique, responder):
    """Run a worker with A's session installed globally; capture the headers
    actually sent to the sync HTTP sink. Returns the list of header dicts."""
    sent_headers: list[dict] = []

    def fake_sync(method, url, *, headers=None, body=None, timeout=10.0,
                  follow_redirects=True):
        sent_headers.append(dict(headers or {}))
        return responder(method, url, headers or {})

    set_auth(A_SESSION)
    try:
        with patch.object(_http, "_fetch_sync", side_effect=fake_sync):
            asyncio.run(get_worker_runner("vuln", technique)(_agent(target, technique)))
    finally:
        clear_auth()
    return sent_headers


def _assert_no_session(sent_headers):
    leaked = [h for h in sent_headers
              if any("ALICE_PRIVATE" in str(v) for v in h.values())]
    assert not leaked, (
        f"global session leaked into an anonymous-premise probe: {leaked}. "
        "The worker must pass use_session_auth=False on that fetch."
    )
    assert sent_headers, "expected the worker to make at least one request"


def test_broken_access_control_probes_anonymously():
    def responder(method, url, headers):
        return HttpResp(200, {"content-type": "application/json"},
                        '[{"email":"a@b.c"}]', url)
    sent = _capture_run("http://t/", "broken_access_control", responder)
    _assert_no_session(sent)


def test_path_bypass_probes_anonymously():
    def responder(method, url, headers):
        # base 403 so the worker proceeds into its mutation arms
        return HttpResp(403, {}, "forbidden", url)
    sent = _capture_run("http://t/admin", "path_bypass", responder)
    _assert_no_session(sent)


def test_idor_probes_anonymously():
    def responder(method, url, headers):
        body = "B" if "id=2" in url else "A"
        return HttpResp(200, {}, body, url)
    sent = _capture_run("http://t/item?id=1", "idor", responder)
    _assert_no_session(sent)


def test_bola_single_session_probes_anonymously():
    page = '<a href="/api/orders/1001">o</a>'

    def responder(method, url, headers):
        if url.endswith("/orders/1001"):
            return HttpResp(200, {}, "alice-order", url)
        if url.endswith("/orders/1002"):
            return HttpResp(200, {}, "bob-order", url)
        return HttpResp(200, {}, page, url)
    sent = _capture_run("http://t/", "bola", responder)
    _assert_no_session(sent)


def test_csrf_base_probe_anonymous():
    def responder(method, url, headers):
        return HttpResp(200, {"set-cookie": "sid=x; Path=/"},
                        '<form method="post"><input name="q"></form>', url)
    sent = _capture_run("http://t/", "csrf", responder)
    # The base GET (Set-Cookie observation) must be anonymous. The OPTIONS
    # preflight arm is CORS-keyed and intentionally left as-is, so only assert
    # that the SESSION cookie never rode along on any probe.
    _assert_no_session(sent)
