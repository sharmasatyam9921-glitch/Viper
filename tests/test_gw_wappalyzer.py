"""Gateway-migration tests for the recon `wappalyzer` worker.

The worker's raw `urllib.request.urlopen` egress was replaced with
`await core.tool_gateway.http(...)`. These tests monkeypatch that single
chokepoint with an async stub returning a canned `HttpResp`, run the worker
against a fake `SwarmAgent`, and assert:

  * Path B (stdlib signature scan) parses a canned target response into the
    expected `technology` findings (and uses is_infra=False — the target host).
  * A None return from the gateway (scope-denied / network error) yields an
    empty list, never an exception.

Fully self-contained and deterministic — no real network, no real fingerprint
DB (`recon.wappalyzer` is forced absent so Path B runs).
"""

from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import patch

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import core.swarm_workers  # noqa: E402,F401  (registers recon workers on import)
from core.swarm_engine import SwarmAgent  # noqa: E402
from core.swarm_workers import get_worker_runner  # noqa: E402
from core.swarm_workers.vuln._http import HttpResp  # noqa: E402


def _agent(target: str, *, timeout: float = 5.0) -> SwarmAgent:
    return SwarmAgent(
        agent_id="test_agent",
        objective=f"wappalyzer on {target}",
        target=target,
        technique="wappalyzer",
        payload={},
        timeout_s=timeout,
    )


def _canned_resp() -> HttpResp:
    # HttpResp header keys are lowercased per the helper's contract.
    return HttpResp(
        status=200,
        headers={
            "server": "nginx/1.18.0",
            "x-powered-by": "PHP/7.4.30",
        },
        body="<html><head><meta name=generator content=WordPress 5.8></head>"
             "<body>React app</body></html>",
        final_url="https://example.com",
    )


def _stub_http(resp):
    """Return an async stub for gateway.http that records is_infra and returns `resp`."""
    calls: list[dict] = []

    async def _http(method, url, *, is_infra=False, timeout=None,
                    rate_limit=True, **kw):
        calls.append({"method": method, "url": url, "is_infra": is_infra,
                      "timeout": timeout, "kw": kw})
        return resp

    return _http, calls


async def test_parses_canned_response_into_findings():
    stub, calls = _stub_http(_canned_resp())
    # Force the full-DB path (recon.wappalyzer) to be unimportable so the
    # worker falls through to the stdlib signature scan (Path B).
    with patch.dict(sys.modules, {"recon.wappalyzer": None}):
        with patch("core.tool_gateway.http", new=stub):
            runner = get_worker_runner("recon", "wappalyzer")
            results = await runner(_agent("example.com"))

    assert isinstance(results, list) and results
    tech_blob = " ".join(r["title"].lower() for r in results)
    # Server / X-Powered-By / body signatures should all be detected.
    assert "nginx" in tech_blob
    assert "php" in tech_blob
    assert "wordpress" in tech_blob

    for r in results:
        assert r["type"] == "technology"
        assert r["asset"] == "example.com"
        assert r["url"] == "https://example.com"
        assert r["severity"] == "info"
        assert r["evidence"] == "signature match in headers/body"

    # The target fetch must NOT be flagged as infra (scope predicate must apply).
    assert calls and all(c["is_infra"] is False for c in calls)
    assert all(c["method"] == "GET" for c in calls)


async def test_version_extracted_from_server_header():
    stub, _ = _stub_http(_canned_resp())
    with patch.dict(sys.modules, {"recon.wappalyzer": None}):
        with patch("core.tool_gateway.http", new=stub):
            runner = get_worker_runner("recon", "wappalyzer")
            results = await runner(_agent("example.com"))

    titles = {r["title"] for r in results}
    assert "nginx 1.18.0" in titles


async def test_scope_denied_returns_empty_list():
    # gateway.http returns None on scope-denial OR network error.
    stub, calls = _stub_http(None)
    with patch.dict(sys.modules, {"recon.wappalyzer": None}):
        with patch("core.tool_gateway.http", new=stub):
            runner = get_worker_runner("recon", "wappalyzer")
            results = await runner(_agent("example.com"))

    assert results == []
    # Worker still attempted egress through the gateway (not raw urllib).
    assert calls and calls[0]["is_infra"] is False


async def test_passes_user_agent_header_to_gateway():
    stub, calls = _stub_http(_canned_resp())
    with patch.dict(sys.modules, {"recon.wappalyzer": None}):
        with patch("core.tool_gateway.http", new=stub):
            runner = get_worker_runner("recon", "wappalyzer")
            await runner(_agent("example.com"))

    assert calls
    hdrs = calls[0]["kw"].get("headers", {})
    assert hdrs.get("User-Agent") == "viper-swarm/1.0"
