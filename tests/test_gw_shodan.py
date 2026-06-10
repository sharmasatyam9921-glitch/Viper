"""Gateway-migration tests for the recon `shodan` worker.

Verifies the worker parses Shodan InternetDB JSON fetched via
core.tool_gateway.http into shodan findings, and returns [] when the
gateway denies (None).

Self-contained + deterministic: no real network and no real DNS. The
worker's _resolve() is monkeypatched to a fixed IP so only the migrated
egress (gateway.http) is exercised.
"""

from __future__ import annotations

import json

import pytest

from core import tool_gateway
from core.swarm_engine import SwarmAgent
from core.swarm_workers.recon import shodan as worker
from core.swarm_workers.vuln._http import HttpResp


def _make_agent(target: str = "example.com") -> SwarmAgent:
    return SwarmAgent(
        agent_id="t1",
        objective="shodan internetdb lookup",
        target=target,
        technique="shodan",
        payload={},
        timeout_s=8.0,
    )


@pytest.fixture(autouse=True)
def _fixed_resolve(monkeypatch):
    """Pin DNS resolution so no real lookup happens."""
    monkeypatch.setattr(worker, "_resolve", lambda target: ["1.2.3.4"])


_INTERNETDB_BODY = json.dumps({
    "ip": "1.2.3.4",
    "vulns": ["CVE-2021-44228"],
    "ports": [80, 443],
    "tags": ["cdn"],
})


async def test_parses_internetdb_into_findings(monkeypatch):
    seen = {}

    async def fake_http(method, url, **kw):
        seen["method"] = method
        seen["url"] = url
        seen["is_infra"] = kw.get("is_infra")
        return HttpResp(status=200, headers={}, body=_INTERNETDB_BODY,
                        final_url=url)

    monkeypatch.setattr(tool_gateway, "http", fake_http)

    findings = await worker.run(_make_agent())

    # Egress went through the gateway as third-party OSINT infra.
    assert seen["method"] == "GET"
    assert "internetdb.shodan.io/1.2.3.4" in seen["url"]
    assert seen["is_infra"] is True

    by_type = {}
    for f in findings:
        by_type.setdefault(f["type"], []).append(f)
        assert f["asset"] == "1.2.3.4"

    # CVE finding
    assert len(by_type["shodan_cve"]) == 1
    cve = by_type["shodan_cve"][0]
    assert cve["title"] == "CVE-2021-44228"
    assert cve["cve"] == "CVE-2021-44228"
    assert cve["severity"] == "high"
    assert cve["evidence"] == "shodan internetdb reports CVE-2021-44228 on 1.2.3.4"

    # Port findings
    ports = sorted(f["port"] for f in by_type["shodan_port"])
    assert ports == [80, 443]
    for f in by_type["shodan_port"]:
        assert f["title"] == f"{f['port']}/tcp"
        assert f["severity"] == "info"
        assert f["evidence"] == "shodan internetdb"

    # Tag finding
    assert len(by_type["shodan_tag"]) == 1
    tag = by_type["shodan_tag"][0]
    assert tag["title"] == "cdn"
    assert tag["severity"] == "info"
    assert tag["evidence"] == "shodan tag: cdn"


async def test_scope_denied_returns_empty(monkeypatch):
    async def fake_http(method, url, **kw):
        return None  # scope-denied or network error

    monkeypatch.setattr(tool_gateway, "http", fake_http)

    findings = await worker.run(_make_agent())
    assert findings == []
