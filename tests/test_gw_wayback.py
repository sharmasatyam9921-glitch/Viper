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


def _make_agent(target: str = "https://example.com") -> SwarmAgent:
    return SwarmAgent(
        agent_id="t-wayback",
        objective="mine wayback urls",
        target=target,
        technique="wayback",
        timeout_s=10.0,
    )


@pytest.mark.parametrize("target", [
    "http://127.0.0.1:4000", "http://localhost:3000", "http://10.0.0.5",
    "http://192.168.1.20:8080", "http://juice-shop",
])
async def test_wayback_skips_non_public_targets(monkeypatch, target):
    # Loopback/private/intranet hosts have no meaningful public archive; the
    # worker must NOT query it (would flood findings with internet-wide noise).
    called = {"n": 0}

    async def fake_http(method, url, **kw):
        called["n"] += 1
        return None

    monkeypatch.setattr(gateway, "http", fake_http)
    findings = await wayback.run(_make_agent(target))
    assert findings == []
    assert called["n"] == 0, "must not hit the archive for a non-public target"


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

    # Only the INTERESTING historical path (/admin) is surfaced; plain bulk
    # URLs (/index.html) are filtered to avoid flooding the findings stream and
    # the vuln-probe asset set.
    titles = {f["title"] for f in findings}
    assert titles == {"https://example.com/admin"}
    assert all(f["type"] == "historical_url" for f in findings)
    assert all(f["url"] == f["title"] for f in findings)
    admin = next(f for f in findings if f["title"].endswith("/admin"))
    assert admin["severity"] == "low"   # interesting path

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
