"""Gateway-migration tests for the wayback recon worker.

Verifies the worker parses a canned CDX response (via a monkeypatched
``core.tool_gateway.http`` async stub) into ``historical_url`` findings, and
returns an empty list when the gateway denies the request (scope/network).

Self-contained and deterministic: no real network.
"""

from __future__ import annotations

import json

import pytest

from core import tool_gateway as gateway
from core.swarm_engine import SwarmAgent
from core.swarm_workers.recon import wayback
from core.swarm_workers.vuln._http import HttpResp


def _make_agent() -> SwarmAgent:
    return SwarmAgent(
        agent_id="t-wayback",
        objective="mine wayback urls",
        target="https://example.com",
        technique="wayback",
        timeout_s=10.0,
    )


def _canned_resp(rows: list) -> HttpResp:
    return HttpResp(
        status=200,
        headers={"content-type": "application/json"},
        body=json.dumps(rows),
        final_url="https://web.archive.org/cdx/search/cdx",
    )


async def test_wayback_parses_findings(monkeypatch):
    # CDX returns a header row followed by [original] columns.
    rows = [
        ["original"],
        ["https://example.com/admin"],
        ["https://example.com/index.html"],
        ["https://example.com/admin"],  # duplicate -> deduped
    ]

    captured = {}

    async def fake_http(method, url, *, is_infra=False, timeout=None, **kw):
        captured["method"] = method
        captured["url"] = url
        captured["is_infra"] = is_infra
        captured["headers"] = kw.get("headers")
        return _canned_resp(rows)

    monkeypatch.setattr(gateway, "http", fake_http)

    findings = await wayback.run(_make_agent())

    # Output shape preserved exactly.
    titles = {f["title"] for f in findings}
    assert titles == {"https://example.com/admin", "https://example.com/index.html"}
    assert all(f["type"] == "historical_url" for f in findings)
    assert all(f["evidence"] == "wayback machine archive" for f in findings)
    assert all(f["url"] == f["title"] for f in findings)

    admin = next(f for f in findings if f["title"].endswith("/admin"))
    plain = next(f for f in findings if f["title"].endswith("/index.html"))
    assert admin["severity"] == "low"   # interesting path
    assert plain["severity"] == "info"

    # web.archive.org is third-party OSINT infra, not the target.
    assert captured["is_infra"] is True
    assert captured["method"] == "GET"
    assert "web.archive.org" in captured["url"]
    assert captured["headers"]["User-Agent"] == "viper-swarm/1.0"


async def test_wayback_scope_denied_returns_empty(monkeypatch):
    async def fake_http(method, url, *, is_infra=False, timeout=None, **kw):
        return None  # gateway denied (scope) or network error

    monkeypatch.setattr(gateway, "http", fake_http)

    findings = await wayback.run(_make_agent())
    assert findings == []
