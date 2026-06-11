"""Tests for the open_redirect vuln worker."""

import asyncio
import sys
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import core.swarm_workers  # noqa: F401  (registers workers)
from core.swarm_engine import SwarmAgent
from core.swarm_workers import get_worker_runner, list_workers
from core.swarm_workers.vuln._http import HttpResp

ATTACKER_HOST = "evil-redirect.example"


def _agent(target="http://t", timeout=5.0):
    return SwarmAgent(
        agent_id="t", objective="x", target=target,
        technique="open_redirect", payload={}, timeout_s=timeout,
    )


def _run(fake):
    async def go():
        with patch(
            "core.swarm_workers.vuln.open_redirect.fetch", side_effect=fake
        ):
            return await get_worker_runner("vuln", "open_redirect")(_agent())
    return asyncio.run(go())


def test_registered():
    assert "open_redirect" in list_workers("vuln")


def test_location_header_redirect_flagged():
    async def fake(method, url, **kwargs):
        # Vulnerable: any redirect param bounces to attacker via Location.
        return HttpResp(
            302,
            {"location": f"https://{ATTACKER_HOST}/x"},
            "",
            url,
        )

    findings = _run(fake)
    assert findings, "expected an open-redirect finding"
    f = findings[0]
    assert "open_redirect" in f["vuln_type"]
    assert f["cwe"] == "CWE-601"
    assert f["parameter"] in f["vuln_type"]
    assert f["severity"] in {"info", "low", "medium", "high", "critical"}
    assert 0 <= f["confidence"] <= 1


def test_meta_refresh_redirect_flagged():
    async def fake(method, url, **kwargs):
        body = (
            '<html><head><meta http-equiv="refresh" '
            f'content="0;url=https://{ATTACKER_HOST}/x"></head></html>'
        )
        return HttpResp(200, {}, body, url)

    findings = _run(fake)
    assert findings
    assert findings[0]["vuln_type"].startswith("open_redirect")
    assert "meta_refresh" in findings[0]["title"] or "meta" in findings[0]["evidence"]


def test_js_location_redirect_flagged():
    async def fake(method, url, **kwargs):
        body = f'<script>location.href = "https://{ATTACKER_HOST}/x";</script>'
        return HttpResp(200, {}, body, url)

    findings = _run(fake)
    assert findings
    assert findings[0]["vuln_type"].startswith("open_redirect")


def test_benign_no_redirect_not_flagged():
    # FP guard: server ignores the param and returns a normal page.
    async def fake(method, url, **kwargs):
        return HttpResp(200, {}, "<html><body>welcome</body></html>", url)

    assert _run(fake) == []


def test_redirect_to_same_host_not_flagged():
    # FP guard: a redirect that stays on the legitimate host is not a finding.
    async def fake(method, url, **kwargs):
        return HttpResp(
            302, {"location": "https://legit-app.example/dashboard"}, "", url
        )

    assert _run(fake) == []


def test_network_error_no_finding():
    async def fake(method, url, **kwargs):
        return None

    assert _run(fake) == []


def test_one_finding_per_param_max():
    # Every request looks vulnerable; ensure we don't emit duplicate findings
    # for the same parameter (abs + scheme-relative payloads).
    async def fake(method, url, **kwargs):
        return HttpResp(302, {"location": f"//{ATTACKER_HOST}/x"}, "", url)

    findings = _run(fake)
    params = [f["parameter"] for f in findings]
    assert len(params) == len(set(params)), "duplicate parameter findings"
