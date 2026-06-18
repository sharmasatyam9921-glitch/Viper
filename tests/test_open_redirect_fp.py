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


# ---------------------------------------------------------------------------
# Round-2 audit: legacy/disabled redirect code left inside an INERT region.
#
# A non-vulnerable login page returns 200 with no Location header. It reflects
# the `next` param ONLY into a server-side-validated hidden form field (the
# safe pattern). But its <head> still carries legacy client-side redirect code
# that was DISABLED during a prior fix by wrapping it in an HTML comment:
#
#   <!-- LEGACY redirect handler removed in SEC-1423 (open-redirect fix).
#        location.href = "https://evil-redirect.example/x";
#   -->
#
# A browser NEVER executes commented-out code, so the page is safe. The old
# worker scanned the raw body, matched `location.href = "..."` inside the
# comment, and — because the gesture gate only looks for click/handler markers
# in the preceding 200 chars, not for inert containers — classified it as a
# load-time assignment and emitted a finding per redirect param.
#
# Same FP fires for redirect code reflected into <template>, <pre>/<code>,
# <noscript>, <textarea>, and JSON/template <script type> blocks (all inert).
# ---------------------------------------------------------------------------
def _commented_out_redirect_body() -> str:
    return (
        "<!DOCTYPE html><html><head><title>Sign in</title>"
        "<!-- LEGACY redirect handler removed in SEC-1423 (open-redirect fix).\n"
        '     location.href = "https://' + ATTACKER_HOST + '/x";\n'
        "-->"
        "</head><body>"
        "<form method=\"post\" action=\"/login\">"
        # Safe: `next` reflected into a server-side-validated hidden field only.
        '<input type="hidden" name="next" value="/dashboard">'
        '<input type="submit" value="Sign in">'
        "</form>"
        "</body></html>"
    )


def test_commented_out_redirect_false_positive_not_flagged():
    """The disabled (HTML-commented) redirect handler must yield NO findings.

    Pre-fix this FAILS: the worker matches `location.href = "..."` inside the
    comment and emits js_location findings on a non-vulnerable page.
    """
    async def fake(method, url, **kwargs):
        return HttpResp(200, {}, _commented_out_redirect_body(), url)

    findings = _run(fake)
    assert findings == [], (
        f"FALSE POSITIVE: commented-out/disabled redirect flagged "
        f"{len(findings)} finding(s); the redirect code is inside an HTML "
        "comment and never executes."
    )


def test_inert_container_redirect_false_positive_not_flagged():
    """Redirect code shown inside inert containers (<template>/<pre>/<noscript>/
    <textarea> and JSON <script type>) is documentation/data, not executable —
    it must not be flagged."""
    inert_bodies = [
        '<template>location.href = "https://' + ATTACKER_HOST + '/x";</template>',
        '<pre>location.href = "https://' + ATTACKER_HOST + '/x";</pre>',
        '<code>location.href = "https://' + ATTACKER_HOST + '/x";</code>',
        '<noscript>location.href = "https://' + ATTACKER_HOST + '/x";</noscript>',
        '<textarea>location.href = "https://' + ATTACKER_HOST + '/x";</textarea>',
        '<script type="application/json">'
        '{"redirect":"https://' + ATTACKER_HOST + '/x"}</script>',
        '<script type="text/template">'
        'location.href = "https://' + ATTACKER_HOST + '/x";</script>',
    ]
    for snippet in inert_bodies:
        body = (
            "<!DOCTYPE html><html><head><title>Sign in</title></head>"
            "<body>" + snippet + "</body></html>"
        )

        async def fake(method, url, _body=body, **kwargs):
            return HttpResp(200, {}, _body, url)

        findings = _run(fake)
        assert findings == [], (
            f"FALSE POSITIVE: inert container flagged {len(findings)} "
            f"finding(s) for snippet: {snippet[:40]}..."
        )


def test_inert_meta_refresh_in_comment_not_flagged():
    """A meta-refresh directive that is itself commented out must not fire."""
    async def fake(method, url, **kwargs):
        body = (
            "<!DOCTYPE html><html><head>"
            '<!-- <meta http-equiv="refresh" content="0;url=https://'
            + ATTACKER_HOST + '/x"> -->'
            "</head><body>safe</body></html>"
        )
        return HttpResp(200, {}, body, url)

    findings = _run(fake)
    assert findings == [], (
        f"FALSE POSITIVE: commented-out meta-refresh flagged {len(findings)} "
        "finding(s)."
    )
