"""Tests for the crlf vuln worker (CRLF / HTTP response-header injection)."""

import asyncio
import sys
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import core.swarm_workers  # noqa: F401  (registers workers)
from core.swarm_engine import SwarmAgent
from core.swarm_workers import get_worker_runner, list_workers
from core.swarm_workers.vuln._http import HttpResp


def _agent(target="http://t/", timeout=5.0):
    return SwarmAgent(
        agent_id="t", objective="x", target=target,
        technique="crlf", payload={}, timeout_s=timeout,
    )


def _run(fake):
    async def go():
        with patch("core.swarm_workers.vuln.crlf.fetch", side_effect=fake):
            return await get_worker_runner("vuln", "crlf")(_agent())
    return asyncio.run(go())


def _injected_token(url):
    """Recover the viper<token> marker the worker put in the payload.

    The worker injects `x-crlf-test: viper<token>` via the query string, so a
    realistic vulnerable server would echo exactly that value back as a header.
    We parse it out of the request URL to emulate that faithfully.
    """
    import urllib.parse
    q = urllib.parse.urlsplit(url).query
    for _, vals in urllib.parse.parse_qs(q).items():
        for v in vals:
            # value contains either "viper<token>" (raw/encoded already decoded
            # by parse_qs) somewhere after the injected-header marker.
            if "viper" in v:
                idx = v.find("viper")
                # token is hex chars following "viper"
                tail = v[idx:]
                # strip any trailing non-token chars
                return tail.split()[0] if tail.split() else tail
    return None


def test_registered():
    assert "crlf" in list_workers("vuln")


def test_header_injection_flagged():
    # True positive: the server reflects our payload's injected header back as
    # a genuine response header carrying our unique token.
    async def fake(method, url, **kwargs):
        marker = _injected_token(url)
        headers = {"content-type": "text/html"}
        if marker:
            headers["x-crlf-test"] = marker
        return HttpResp(200, headers, "<html>ok</html>", url)

    findings = _run(fake)
    assert findings, "expected a CRLF header-injection finding"
    f = findings[0]
    assert "crlf" in f["vuln_type"]
    assert f["cwe"] == "CWE-93"
    assert f["severity"] in {"info", "low", "medium", "high", "critical"}
    assert 0 <= f["confidence"] <= 1
    assert f["parameter"] in (
        "q", "url", "redirect", "next", "return",
        "lang", "page", "search", "callback", "id",
    )
    assert "x-crlf-test" in f["evidence"].lower()


def test_body_reflection_only_not_flagged():
    # FP guard: the token is reflected in the BODY but NOT emitted as a header.
    # That's reflection/XSS territory, not header injection — must not flag.
    async def fake(method, url, **kwargs):
        marker = _injected_token(url) or "viperxxxx"
        body = f"<html>you searched for {marker}</html>"
        return HttpResp(200, {"content-type": "text/html"}, body, url)

    assert _run(fake) == []


def test_wrong_token_in_header_not_flagged():
    # FP guard: a static/pre-existing x-crlf-test header that does NOT carry our
    # per-run random token must not be mistaken for injection.
    async def fake(method, url, **kwargs):
        return HttpResp(
            200, {"x-crlf-test": "viperUNRELATED-static-value"}, "ok", url
        )

    assert _run(fake) == []


def test_benign_no_header_not_flagged():
    # FP guard: server sanitises the param, no injected header at all.
    async def fake(method, url, **kwargs):
        return HttpResp(200, {"content-type": "text/html"}, "welcome", url)

    assert _run(fake) == []


def test_network_error_no_finding():
    async def fake(method, url, **kwargs):
        return None

    assert _run(fake) == []


def test_one_finding_per_param_max():
    # Every request looks vulnerable; ensure no duplicate findings per param
    # (worker tries 3 encodings per param but should stop at the first hit).
    async def fake(method, url, **kwargs):
        marker = _injected_token(url)
        headers = {}
        if marker:
            headers["x-crlf-test"] = marker
        return HttpResp(200, headers, "ok", url)

    findings = _run(fake)
    params = [f["parameter"] for f in findings]
    assert len(params) == len(set(params)), "duplicate parameter findings"
