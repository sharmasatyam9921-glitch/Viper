"""False-positive regression for the clickjacking swarm worker.

Audit finding: a hardened 200/HTML endpoint that omits X-Frame-Options and
CSP frame-ancestors but establishes its session via a SameSite=Strict cookie
is NOT clickjackable -- a cross-site iframe sends no session cookie, so no
state-changing action can be triggered through an overlay. The worker
previously flagged it (FALSE POSITIVE).

Fix: a protected-by-SameSite-cookie guard mirroring the existing XFO / CSP
guards. These tests pin both the FP suppression and that a genuinely
clickjackable page (no framing headers, no SameSite session cookie) STILL
fires.
"""

import asyncio
import sys
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import core.swarm_workers  # noqa: F401
from core.swarm_engine import SwarmAgent
from core.swarm_workers import get_worker_runner
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


# --- (a) confirmed false positive: must NOT be flagged ----------------------

def test_samesite_strict_session_cookie_false_positive_not_flagged():
    """Hardened page: no XFO, no CSP frame-ancestors, BUT session cookie is
    SameSite=Strict. A cross-site frame carries no session -> not clickjackable.

    Pre-fix this returned a clickjacking_frameable finding (FALSE POSITIVE).
    """

    async def fake(method, url, **kw):
        return HttpResp(
            200,
            {
                # No x-frame-options, no content-security-policy.
                "content-type": "text/html; charset=utf-8",
                "set-cookie": (
                    "sessionid=abc123def456; Path=/; HttpOnly; Secure; "
                    "SameSite=Strict"
                ),
            },
            "<html><body><h1>Account dashboard</h1>"
            "<form method=POST action=/transfer>...</form></body></html>",
            "http://t/dashboard",
        )

    findings = _run(fake)
    assert findings == [], (
        "SameSite=Strict session cookie should suppress the clickjacking "
        f"finding; got: {findings}"
    )


def test_samesite_lax_session_cookie_false_positive_not_flagged():
    """SameSite=Lax on a session cookie also blocks cross-site iframe loads."""

    async def fake(method, url, **kw):
        return HttpResp(
            200,
            {
                "content-type": "text/html",
                "set-cookie": "auth_token=xyz; Path=/; SameSite=Lax; Secure",
            },
            "<html><body>app</body></html>",
            "http://t/",
        )

    assert _run(fake) == []


# --- (b) genuine vulnerability: must STILL fire -----------------------------

def test_no_samesite_protection_true_positive_still_fires():
    """Genuinely clickjackable: no XFO, no CSP frame-ancestors, and the session
    cookie has NO SameSite protection (SameSite=None) -> a cross-site frame DOES
    carry the session, so the state-changing form is reachable via overlay.

    The worker MUST still emit a clickjacking finding.
    """

    async def fake(method, url, **kw):
        return HttpResp(
            200,
            {
                "content-type": "text/html; charset=utf-8",
                # SameSite=None => cookie IS sent in cross-site frames.
                "set-cookie": (
                    "sessionid=abc123; Path=/; Secure; SameSite=None"
                ),
            },
            "<html><body><h1>Settings</h1>"
            "<form method=POST action=/change-email>...</form></body></html>",
            "http://t/settings",
        )

    findings = _run(fake)
    assert any("clickjacking" in f["vuln_type"] for f in findings), (
        "A frameable page with a SameSite=None session cookie is still "
        f"clickjackable and must be flagged; got: {findings}"
    )
    f = next(f for f in findings if "clickjacking" in f["vuln_type"])
    assert f["cwe"] == "CWE-1021"
    assert f["severity"] == "low"


def test_non_session_samesite_cookie_does_not_suppress():
    """A SameSite=Strict cookie that is NOT session-bearing (e.g. a locale
    preference) must NOT suppress: the session, if any, is unprotected, so the
    page stays clickjackable. Guards against an over-broad SameSite suppression.
    """

    async def fake(method, url, **kw):
        return HttpResp(
            200,
            {
                "content-type": "text/html",
                "set-cookie": "locale=en_US; Path=/; SameSite=Strict",
            },
            "<html><body>app</body></html>",
            "http://t/",
        )

    findings = _run(fake)
    assert any("clickjacking" in f["vuln_type"] for f in findings), (
        "A non-session SameSite cookie must not suppress the finding; "
        f"got: {findings}"
    )
