import asyncio
import sys
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import core.swarm_workers  # noqa: F401
from core.swarm_engine import SwarmAgent
from core.swarm_workers import get_worker_runner, list_workers
from core.swarm_workers.vuln._http import HttpResp


def _agent(target="http://t", timeout=5.0):
    return SwarmAgent(
        agent_id="t",
        objective="x",
        target=target,
        technique="csrf",
        payload={},
        timeout_s=timeout,
    )


def _run(fake):
    async def go():
        with patch("core.swarm_workers.vuln.csrf.fetch", side_effect=fake):
            return await get_worker_runner("vuln", "csrf")(_agent())

    return asyncio.run(go())


# --- registration -----------------------------------------------------------

def test_registered():
    assert "csrf" in list_workers("vuln")


# --- true positives ---------------------------------------------------------

def test_post_form_no_token_weak_cookie_flagged():
    """POST form without anti-CSRF token + session cookie lacking SameSite."""
    body = (
        "<html><body>"
        "<form method='POST' action='/transfer'>"
        "<input name='amount'><input name='to'>"
        "</form></body></html>"
    )

    async def fake(method, url, **kw):
        if method == "GET":
            return HttpResp(
                200,
                {"set-cookie": "sessionid=abc123; Path=/; HttpOnly"},
                body,
                "http://t/",
            )
        return None

    findings = _run(fake)
    assert any(f["vuln_type"] == "csrf_missing_token" for f in findings)
    f = next(f for f in findings if f["vuln_type"] == "csrf_missing_token")
    assert "csrf" in f["vuln_type"]
    assert f["cwe"] == "CWE-352"
    assert f["url"].endswith("/transfer")
    assert f["severity"] == "medium"


def test_json_api_no_token_flagged():
    """JSON /api/ POST endpoint that preflights without requiring a token."""
    body = (
        "<html><body><script>"
        "fetch('/api/v1/update', {method:'POST'})"
        "</script></body></html>"
    )

    async def fake(method, url, **kw):
        if method == "GET":
            # cookie HAS SameSite so the form path won't fire; isolates API test
            return HttpResp(
                200,
                {"set-cookie": "sessionid=x; SameSite=Strict"},
                body,
                "http://t/",
            )
        if method == "OPTIONS":
            return HttpResp(
                204,
                {
                    "access-control-allow-methods": "GET, POST, OPTIONS",
                    "access-control-allow-headers": "content-type",
                },
                "",
                url,
            )
        return None

    findings = _run(fake)
    assert any(f["vuln_type"] == "csrf_json_api" for f in findings)
    f = next(f for f in findings if f["vuln_type"] == "csrf_json_api")
    assert "csrf" in f["vuln_type"]
    assert f["cwe"] == "CWE-352"
    assert f["url"].endswith("/api/v1/update")


# --- false-positive guards --------------------------------------------------

def test_form_with_token_not_flagged():
    """POST form carrying an authenticity_token field is defended."""
    body = (
        "<html><body>"
        "<form method='POST' action='/transfer'>"
        "<input name='amount'>"
        "<input type='hidden' name='authenticity_token' value='zzz'>"
        "</form></body></html>"
    )

    async def fake(method, url, **kw):
        if method == "GET":
            return HttpResp(
                200,
                {"set-cookie": "sessionid=abc; HttpOnly"},
                body,
                "http://t/",
            )
        return None

    findings = _run(fake)
    assert not any(f["vuln_type"] == "csrf_missing_token" for f in findings)


def test_form_no_token_but_samesite_cookie_not_flagged():
    """No token, but session cookie has SameSite=Lax → browser blocks cross-site."""
    body = (
        "<html><body>"
        "<form method='POST' action='/transfer'>"
        "<input name='amount'>"
        "</form></body></html>"
    )

    async def fake(method, url, **kw):
        if method == "GET":
            return HttpResp(
                200,
                {"set-cookie": "sessionid=abc; SameSite=Lax; HttpOnly"},
                body,
                "http://t/",
            )
        return None

    findings = _run(fake)
    assert not any(f["vuln_type"] == "csrf_missing_token" for f in findings)


def test_get_form_not_flagged():
    """GET forms are not state-changing — never flagged."""
    body = (
        "<html><body>"
        "<form method='GET' action='/search'>"
        "<input name='q'>"
        "</form></body></html>"
    )

    async def fake(method, url, **kw):
        if method == "GET":
            return HttpResp(
                200,
                {"set-cookie": "sessionid=abc; HttpOnly"},
                body,
                "http://t/",
            )
        return None

    findings = _run(fake)
    assert findings == []


def test_benign_page_no_findings():
    """Plain page, no forms, no API, no cookie → nothing flagged."""

    async def fake(method, url, **kw):
        if method == "GET":
            return HttpResp(200, {}, "<html><body>hello</body></html>", "http://t/")
        return None

    findings = _run(fake)
    assert findings == []


def test_network_failure_returns_empty():
    async def fake(method, url, **kw):
        return None

    assert _run(fake) == []