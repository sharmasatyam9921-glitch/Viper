"""Gateway-migration tests for the recon `subdomain` worker.

Verifies the worker parses crt.sh JSON fetched via core.tool_gateway.http
into subdomain findings, and returns [] when the gateway denies (None).

Self-contained + deterministic: no real network. ReconEngine (Path A) is
forced to fail so the crt.sh fallback (Path B) — the migrated egress — runs.
"""

from __future__ import annotations

import json

import pytest

from core import tool_gateway
from core.swarm_engine import SwarmAgent
from core.swarm_workers.recon import subdomain as worker
from core.swarm_workers.vuln._http import HttpResp


def _make_agent(target: str = "example.com") -> SwarmAgent:
    return SwarmAgent(
        agent_id="t1",
        objective="enumerate subdomains",
        target=target,
        technique="subdomain",
        payload={},
        timeout_s=15.0,
    )


@pytest.fixture(autouse=True)
def _force_crtsh_path(monkeypatch):
    """Make Path A (ReconEngine) unavailable so Path B (crt.sh) always runs."""
    import recon.recon_engine as re_mod

    class _Boom:
        def __init__(self, *a, **kw):
            raise RuntimeError("no recon engine in test")

    monkeypatch.setattr(re_mod, "ReconEngine", _Boom)


_CRTSH_BODY = json.dumps([
    {"name_value": "api.example.com"},
    {"name_value": "www.example.com\nmail.example.com"},
    {"name_value": "*.example.com"},        # wildcard → dropped
    {"name_value": "other.notexample.org"},  # out-of-zone → dropped
])


async def test_parses_crtsh_into_findings(monkeypatch):
    async def fake_http(method, url, **kw):
        assert method == "GET"
        assert "crt.sh" in url
        assert kw.get("is_infra") is True  # third-party OSINT
        return HttpResp(status=200, headers={}, body=_CRTSH_BODY,
                        final_url=url)

    monkeypatch.setattr(tool_gateway, "http", fake_http)

    findings = await worker.run(_make_agent())

    titles = sorted(f["title"] for f in findings)
    assert titles == ["api.example.com", "mail.example.com", "www.example.com"]
    for f in findings:
        assert f["type"] == "subdomain"
        assert f["severity"] == "info"
        assert f["url"] == f"https://{f['title']}"
        assert f["asset"] == f["title"]
        assert f["evidence"] == "discovered via subdomain"


async def test_scope_denied_returns_empty(monkeypatch):
    async def fake_http(method, url, **kw):
        return None  # scope-denied or network error

    monkeypatch.setattr(tool_gateway, "http", fake_http)

    findings = await worker.run(_make_agent())
    assert findings == []
