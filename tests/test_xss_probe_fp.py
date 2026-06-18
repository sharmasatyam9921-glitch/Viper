"""Regression test for the xss_probe false positive confirmed by audit.

FP scenario (from /tmp/audit_ref.json -> xss_probe):
  A non-vulnerable endpoint reflects the query value WITHOUT executing it,
  in a NON-HTML content type:
    (1) text/plain 400 error page echoing the search term, and
    (2) a JSON search API echoing {"query": "<payload>"}.
  Both set X-Content-Type-Options: nosniff, so no browser parses them as
  HTML. Neither is XSS, yet the worker flagged high/medium reflected XSS.

The fix makes detection content-type aware: reflection is only XSS when it
lands in an HTML/SVG/XML (or sniffable empty) parsing context.
"""

from __future__ import annotations

import asyncio
import sys
import urllib.parse
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import core.swarm_workers  # noqa: F401,E402  auto-imports vuln workers
from core.swarm_engine import SwarmAgent  # noqa: E402
from core.swarm_workers import get_worker_runner  # noqa: E402
from core.swarm_workers.vuln._http import HttpResp  # noqa: E402


def _agent(target: str) -> SwarmAgent:
    return SwarmAgent(
        agent_id="t",
        objective="xss_probe",
        target=target,
        technique="xss_probe",
        payload={},
        timeout_s=10.0,
    )


def _echoed_payload(url: str) -> str:
    """The q= value the worker just sent (its randomized marker payload)."""
    qs = urllib.parse.urlsplit(url).query
    return urllib.parse.parse_qs(qs).get("q", [""])[0]


def _run_against(fake) -> list:
    async def go():
        with patch("core.swarm_workers.vuln.xss_probe.fetch", side_effect=fake):
            runner = get_worker_runner("vuln", "xss_probe")
            return await runner(_agent("http://t/?q=hi"))
    return asyncio.run(go())


# ---------------------------------------------------------------------------
# (a) FALSE POSITIVE — must return [] after the fix.
# ---------------------------------------------------------------------------


def test_non_html_reflection_not_flagged():
    """text/plain and application/json reflections are NOT XSS.

    Reproduces both audit mocks: the payload is echoed verbatim, but the
    content-type is non-HTML and nosniff is set, so a browser never parses
    it as markup. The worker must return no finding.
    """
    # Scenario 1: text/plain 400 error page echoing the search term.
    def fake_plain(method, url, **kw):
        payload = _echoed_payload(url)
        body = f"Unrecognized search term: {payload}"
        headers = {
            "content-type": "text/plain; charset=utf-8",
            "x-content-type-options": "nosniff",
        }
        return HttpResp(400, headers, body, url)

    # Scenario 2: JSON search API echoing the marker tag (angle brackets
    # survive json.dumps even though the quote gets escaped).
    def fake_json(method, url, **kw):
        payload = _echoed_payload(url)
        import json
        body = json.dumps({
            "query": payload,
            "message": f"No results found for: {payload}",
        })
        headers = {
            "content-type": "application/json; charset=utf-8",
            "x-content-type-options": "nosniff",
        }
        return HttpResp(200, headers, body, url)

    async def af_plain(method, url, **kw):
        return fake_plain(method, url, **kw)

    async def af_json(method, url, **kw):
        return fake_json(method, url, **kw)

    plain = _run_against(af_plain)
    assert plain == [], (
        f"FALSE POSITIVE: text/plain reflection flagged as XSS: {plain}"
    )

    js = _run_against(af_json)
    assert js == [], (
        f"FALSE POSITIVE: application/json reflection flagged as XSS: {js}"
    )


# ---------------------------------------------------------------------------
# (b) TRUE POSITIVE — must still fire after the fix.
# ---------------------------------------------------------------------------


def test_html_reflection_still_fires():
    """A genuine reflected XSS in text/html must still be detected.

    The payload is echoed unencoded inside an HTML document served as
    text/html — exactly where a <script>/<svg onload> would execute.
    The baseline (control request without the payload) does NOT contain
    the marker, so this is a true reflection, not static content.
    """
    async def fake_html(method, url, **kw):
        payload = _echoed_payload(url)
        # Genuinely dangerous: unencoded reflection between tags in HTML.
        body = f"<html><body><h1>Results for {payload}</h1></body></html>"
        headers = {"content-type": "text/html; charset=utf-8"}
        return HttpResp(200, headers, body, url)

    result = _run_against(fake_html)
    high = [r for r in result if r["severity"] == "high"]
    assert high, f"expected high-severity reflected XSS, got {result}"
    assert high[0]["cwe"] == "CWE-79"
    assert high[0]["type"] == "xss_reflected"
