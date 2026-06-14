import asyncio
import sys
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import core.swarm_workers  # noqa: F401
from core.swarm_engine import SwarmAgent
from core.swarm_workers import get_worker_runner, list_workers
from core.swarm_workers.vuln._http import HttpResp


def _agent(target="http://t/", timeout=5.0):
    return SwarmAgent(
        agent_id="t",
        objective="x",
        target=target,
        technique="clickjacking",
        payload={},
        timeout_s=timeout,
    )


def _run(fake):
    async def go():
        with patch("core.swarm_workers.vuln.clickjacking.fetch", side_effect=fake):
            return await get_worker_runner("vuln", "clickjacking")(_agent())

    return asyncio.run(go())


# --- registration -----------------------------------------------------------

def test_registered():
    assert "clickjacking" in list_workers("vuln")


# --- true positives ---------------------------------------------------------

def test_no_xfo_no_csp_flagged():
    """No X-Frame-Options and no CSP at all → page is frameable."""

    async def fake(method, url, **kw):
        return HttpResp(200, {}, "<html><body>app</body></html>", "http://t/")

    findings = _run(fake)
    assert any("clickjacking" in f["vuln_type"] for f in findings)
    f = next(f for f in findings if "clickjacking" in f["vuln_type"])
    assert f["cwe"] == "CWE-1021"
    assert f["severity"] == "low"
    assert f["url"] == "http://t/"
    # Evidence must flag the sensitive-action caveat.
    assert "sensitive" in f["evidence"].lower()


def test_csp_without_frame_ancestors_flagged():
    """CSP present but lacking frame-ancestors → no framing protection."""

    async def fake(method, url, **kw):
        return HttpResp(
            200,
            {"content-security-policy": "default-src 'self'; script-src 'self'"},
            "<html></html>",
            "http://t/",
        )

    findings = _run(fake)
    assert any("clickjacking" in f["vuln_type"] for f in findings)
    f = next(f for f in findings if "clickjacking" in f["vuln_type"])
    assert "no frame-ancestors" in f["evidence"].lower()


def test_permissive_frame_ancestors_wildcard_flagged():
    """frame-ancestors * is permissive → still frameable by any origin."""

    async def fake(method, url, **kw):
        return HttpResp(
            200,
            {"content-security-policy": "frame-ancestors *"},
            "<html></html>",
            "http://t/",
        )

    findings = _run(fake)
    assert any("clickjacking" in f["vuln_type"] for f in findings)
    f = next(f for f in findings if "clickjacking" in f["vuln_type"])
    assert "permissive" in f["evidence"].lower()


# --- false-positive guards --------------------------------------------------

def test_xfo_deny_not_flagged():
    """X-Frame-Options: DENY → protected-by-XFO guard."""

    async def fake(method, url, **kw):
        return HttpResp(200, {"x-frame-options": "DENY"}, "<html></html>", "http://t/")

    assert _run(fake) == []


def test_xfo_sameorigin_not_flagged():
    """X-Frame-Options: SAMEORIGIN (mixed case) → protected-by-XFO guard."""

    async def fake(method, url, **kw):
        return HttpResp(
            200, {"x-frame-options": "SameOrigin"}, "<html></html>", "http://t/"
        )

    assert _run(fake) == []


def test_csp_frame_ancestors_none_not_flagged():
    """CSP frame-ancestors 'none' → protected-by-CSP-frame-ancestors guard."""

    async def fake(method, url, **kw):
        return HttpResp(
            200,
            {"content-security-policy": "default-src 'self'; frame-ancestors 'none'"},
            "<html></html>",
            "http://t/",
        )

    assert _run(fake) == []


def test_csp_frame_ancestors_self_not_flagged():
    """CSP frame-ancestors 'self' → protected-by-CSP-frame-ancestors guard."""

    async def fake(method, url, **kw):
        return HttpResp(
            200,
            {"content-security-policy": "frame-ancestors 'self'"},
            "<html></html>",
            "http://t/",
        )

    assert _run(fake) == []


def test_csp_protects_even_when_xfo_absent():
    """No XFO but restrictive CSP frame-ancestors → still protected."""

    async def fake(method, url, **kw):
        return HttpResp(
            200,
            {"content-security-policy": "frame-ancestors 'self' https://trusted.example"},
            "<html></html>",
            "http://t/",
        )

    assert _run(fake) == []


def test_network_failure_returns_empty():
    async def fake(method, url, **kw):
        return None

    assert _run(fake) == []
