"""FP regression for the open_redirect vuln worker.

Audit finding: a SAFE external-link interstitial page (a *correct*
anti-open-redirect mitigation that never auto-redirects) echoes the
requested destination into a click handler:

    document.getElementById("continue").addEventListener("click",
        function(){ location.href = "https://evil-redirect.example/x"; });

The old worker matched the raw `location.href = "..."` substring anywhere
in the body, saw the attacker host, and emitted a `js_location` finding —
once per redirect parameter (14 findings on one non-vulnerable 200 page).

That is a FALSE POSITIVE: the page only *reflects* the URL inside a
user-gesture handler; it never redirects. A real open redirect either
returns a 3xx Location to the attacker host, or runs the assignment at page
load (top-level script), or a meta-refresh fires it automatically.
"""

import asyncio
import sys
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import core.swarm_workers  # noqa: F401  (registers workers)
from core.swarm_engine import SwarmAgent
from core.swarm_workers import get_worker_runner
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


# The exact non-vulnerable mock from the audit scenario: a safe interstitial
# that reflects the destination into a *click handler* and never auto-redirects.
def _interstitial_body() -> str:
    return (
        "<!DOCTYPE html><html><head><title>Leaving example.com</title></head>"
        "<body><h1>You are about to leave example.com</h1>"
        "<p>We do NOT redirect you automatically. Click Continue only if you "
        "trust this destination.</p>"
        '<a id="continue" href="#">Continue</a>'
        "<script>"
        'document.getElementById("continue").addEventListener("click", '
        'function(){ location.href = "https://' + ATTACKER_HOST + '/x"; });'
        "</script>"
        "</body></html>"
    )


def test_safe_interstitial_false_positive_not_flagged():
    """(a) The non-vulnerable interstitial must yield NO findings.

    Pre-fix this FAILS (worker emits js_location findings), proving the FP.
    """
    async def fake(method, url, **kwargs):
        # 200, no Location header, body only reflects the URL in a click handler.
        return HttpResp(200, {}, _interstitial_body(), url)

    findings = _run(fake)
    assert findings == [], (
        f"FALSE POSITIVE: safe interstitial flagged {len(findings)} finding(s); "
        "the page reflects the URL only inside an addEventListener click handler "
        "and never redirects."
    )


def test_js_location_top_level_true_positive_still_fires():
    """(b) A GENUINE open redirect via a top-level (load-time) JS assignment
    must STILL be flagged."""
    async def fake(method, url, **kwargs):
        # Vulnerable: assignment runs immediately at page load, no user gesture.
        body = (
            "<!DOCTYPE html><html><head><script>"
            'location.href = "https://' + ATTACKER_HOST + '/x";'
            "</script></head><body>redirecting...</body></html>"
        )
        return HttpResp(200, {}, body, url)

    findings = _run(fake)
    assert findings, "expected a finding for a load-time location.href redirect"
    assert findings[0]["vuln_type"].startswith("open_redirect")
    assert findings[0]["cwe"] == "CWE-601"


def test_location_header_true_positive_still_fires():
    """Sanity: the classic 3xx Location open redirect is unaffected."""
    async def fake(method, url, **kwargs):
        return HttpResp(302, {"location": f"https://{ATTACKER_HOST}/x"}, "", url)

    findings = _run(fake)
    assert findings, "expected a finding for a 302 Location redirect to attacker"
    assert findings[0]["vuln_type"].startswith("open_redirect")
