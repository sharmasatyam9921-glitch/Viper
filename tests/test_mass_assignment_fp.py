"""False-positive regression tests for the mass_assignment vuln worker.

Audit scenario (confirmed FP): a standard self-profile endpoint
(GET /api/me, /api/profile, /api/account) returns the logged-in user's OWN
record as benign JSON exposing only display-grade fields like `role` (a UI
badge label) and `verified` (the email-verified checkmark). Those are
read-only display data surfaced by virtually every authenticated REST API —
they are NOT evidence of mass assignment (CWE-915). The worker previously
emitted a medium finding per matching self-profile path.

Principle of the fix: on a SELF-profile path, a privileged-sounding field is
only a lead, not a finding, unless a GENUINELY sensitive field
(isAdmin/is_superuser/permissions/balance/wallet/credit) is present. The
benign self badge fields (`role` singular, `verified`, `account_type`,
`created_at`) must not, on their own, fire on a self-profile path.
"""

import asyncio
import json
import sys
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import core.swarm_workers  # noqa: F401
from core.swarm_engine import SwarmAgent
from core.swarm_workers import get_worker_runner
from core.swarm_workers.vuln._http import HttpResp


_JSON = {"content-type": "application/json"}


def _agent(target="http://t", timeout=5.0):
    return SwarmAgent(
        agent_id="t", objective="x", target=target,
        technique="mass_assignment", payload={}, timeout_s=timeout,
    )


def _run(fake):
    async def go():
        with patch(
            "core.swarm_workers.vuln.mass_assignment.fetch", side_effect=fake
        ):
            return await get_worker_runner("vuln", "mass_assignment")(_agent())
    return asyncio.run(go())


def test_self_profile_benign_badge_fields_false_positive_not_flagged():
    """The audit FP: GET /api/me|/api/profile|/api/account self record with
    only `role` (display label) + `verified` (checkmark) must NOT be flagged."""
    body = json.dumps({
        "id": 4021,
        "username": "jdoe",
        "email": "jdoe@example.com",
        "role": "member",
        "verified": True,
        "created_at": "2021-04-02T10:00:00Z",
    })

    self_paths = ("/api/me", "/api/profile", "/api/account")

    async def fake(method, url, **kw):
        if any(url.endswith(p) for p in self_paths):
            return HttpResp(200, dict(_JSON), body, url)
        return HttpResp(404, {}, "", url)

    findings = _run(fake)
    assert findings == [], (
        "self-profile badge fields (role label + verified checkmark) must not "
        f"be flagged as mass assignment; got: {findings}"
    )


def test_self_profile_with_truly_sensitive_field_still_fires():
    """Even a self-profile path STILL fires when a genuinely sensitive,
    client-uncontrollable field (isAdmin/permissions/balance) is exposed —
    that is a real over-binding lead, not a benign badge."""
    body = json.dumps({
        "id": 4021,
        "username": "jdoe",
        "email": "jdoe@example.com",
        "role": "member",
        "isAdmin": False,
        "balance": 0,
    })

    async def fake(method, url, **kw):
        if url.endswith("/api/me"):
            return HttpResp(200, dict(_JSON), body, url)
        return HttpResp(404, {}, "", url)

    findings = _run(fake)
    assert len(findings) >= 1
    f = findings[0]
    assert f["vuln_type"] == "access_control:mass_assignment"
    assert f["cwe"] == "CWE-915"
    # the sensitive field — not the benign badge — drives the finding
    assert "isAdmin" in f["evidence"] or "balance" in f["evidence"]


def test_true_positive_other_users_collection_still_fires():
    """A collection of OTHER users (data the requester shouldn't control)
    exposing role/isAdmin remains a finding on a non-self path."""
    body = json.dumps([
        {"id": 1, "username": "alice", "role": "admin", "isAdmin": True},
        {"id": 2, "username": "bob", "role": "member", "isAdmin": False},
    ])

    async def fake(method, url, **kw):
        if url.endswith("/api/Users") or url.endswith("/api/users"):
            return HttpResp(200, dict(_JSON), body, url)
        return HttpResp(404, {}, "", url)

    findings = _run(fake)
    assert len(findings) >= 1
    assert findings[0]["vuln_type"] == "access_control:mass_assignment"


def test_singular_self_user_route_benign_badge_fields_not_flagged():
    """Round-2 audit FP: the SINGULAR current-user routes /api/user and
    /rest/user (Laravel Sanctum's default, GitHub's /user, countless SPA
    backends) return the requester's OWN record exactly like /api/me — yet
    they were absent from the self-profile gate, so the benign `role` badge +
    `verified` checkmark leaked through as a mass_assignment finding. The same
    body on /api/me is correctly suppressed; only the path differed.

    The self-profile gate must be SEMANTIC (final path segment is a singular
    self-noun with no trailing id/collection), so /api/user and /rest/user are
    treated identically to /api/me: benign badge fields alone do NOT fire.
    """
    body = json.dumps({
        "id": 4021,
        "name": "Jane Doe",
        "username": "jdoe",
        "email": "jdoe@example.com",
        "role": "member",
        "verified": True,
        "created_at": "2021-04-02T10:00:00Z",
    })

    self_paths = ("/api/user", "/rest/user")

    async def fake(method, url, **kw):
        if any(url.endswith(p) for p in self_paths):
            return HttpResp(200, dict(_JSON), body, url)
        return HttpResp(404, {}, "", url)

    findings = _run(fake)
    assert findings == [], (
        "singular self-user routes (/api/user, /rest/user) returning the "
        "requester's own record with only badge fields (role label + verified "
        f"checkmark) must not be flagged as mass assignment; got: {findings}"
    )


def test_singular_self_user_route_with_sensitive_field_still_fires():
    """Symmetric guard: /api/user STILL fires when a genuinely sensitive,
    client-uncontrollable field (permissions/balance) rides along — the
    semantic self gate suppresses only the benign-badge case, never a real
    over-binding lead."""
    body = json.dumps({
        "id": 4021,
        "username": "jdoe",
        "email": "jdoe@example.com",
        "role": "member",
        "permissions": ["read", "write"],
        "balance": 0,
    })

    async def fake(method, url, **kw):
        if url.endswith("/api/user"):
            return HttpResp(200, dict(_JSON), body, url)
        return HttpResp(404, {}, "", url)

    findings = _run(fake)
    assert len(findings) >= 1
    f = findings[0]
    assert f["vuln_type"] == "access_control:mass_assignment"
    assert "permissions" in f["evidence"] or "balance" in f["evidence"]
