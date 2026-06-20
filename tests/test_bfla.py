"""Broken Function-Level Authorization engine, worker, gate trust, session bridge."""
from __future__ import annotations

import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.specialist.bfla_engine import Identity, find_bfla, is_privileged_path  # noqa: E402
from core.swarm_workers.vuln._http import HttpResp  # noqa: E402
from core.swarm_validation import validate_findings  # noqa: E402


def _fetch(responder):
    async def fake(method, url, *, headers=None, timeout=10.0):
        return responder(url, headers or {})
    return fake


_ADMIN = {"Cookie": "s=admin"}
_USER = {"Cookie": "s=user"}


def _run(responder, urls, **kw):
    return asyncio.run(find_bfla(
        Identity("admin", _ADMIN), Identity("user", _USER), urls,
        fetch=_fetch(responder), **kw))


def test_is_privileged_path():
    assert is_privileged_path("http://t/api/admin/users")
    assert is_privileged_path("http://t/actuator/env")
    assert is_privileged_path("http://t/manage/config")
    assert not is_privileged_path("http://t/api/profile")
    assert not is_privileged_path("http://t/orders/5")


def test_bfla_confirmed_when_low_priv_reaches_admin_function():
    def resp(url, h):
        ck = h.get("Cookie", "")
        if "s=admin" in ck or "s=user" in ck:        # both authed roles get in
            return HttpResp(200, {}, '{"users":[1,2,3]}', url)
        return HttpResp(401, {}, "", url)            # anon denied -> not public
    out = _run(resp, ["http://t/api/admin/users"])
    assert len(out) == 1 and out[0]["cwe"] == "CWE-863"
    assert ":bfla:" in out[0]["vuln_type"]


def test_proper_role_enforcement_is_not_flagged():
    def resp(url, h):
        ck = h.get("Cookie", "")
        if "s=admin" in ck:
            return HttpResp(200, {}, "{}", url)
        return HttpResp(403, {}, "", url)            # low-priv correctly denied
    assert _run(resp, ["http://t/api/admin/users"]) == []


def test_public_endpoint_is_not_bfla():
    def resp(url, h):
        return HttpResp(200, {}, "{}", url)          # everyone incl. anon -> public
    assert _run(resp, ["http://t/api/admin/stats"]) == []


def test_non_admin_path_skipped_when_admin_only():
    def resp(url, h):
        ck = h.get("Cookie", "")
        return HttpResp(200 if ck else 401, {}, "{}", url)
    # /api/profile is not admin-shaped -> skipped under admin_only (default)
    assert _run(resp, ["http://t/api/profile"]) == []
    # but with admin_only=False it IS evaluated and flagged
    out = _run(resp, ["http://t/api/profile"], admin_only=False)
    assert len(out) == 1


def test_soft_deny_200_login_page_is_not_bfla():
    def resp(url, h):
        ck = h.get("Cookie", "")
        if "s=admin" in ck:
            return HttpResp(200, {}, '{"ok":true}', url)
        if "s=user" in ck:
            return HttpResp(200, {}, "<html>Please log in to continue</html>", url)
        return HttpResp(401, {}, "", url)
    assert _run(resp, ["http://t/admin/panel"]) == []


def test_bfla_worker_is_opt_in():
    from core.swarm_workers.vuln.bfla_multi import run

    class _A:
        target = "http://t/admin"
        timeout_s = 10.0
        payload = {}
    assert asyncio.run(run(_A())) == []              # no config -> nothing


def test_gate_trusts_a_bfla_finding():
    f = {"vuln_type": "access_control:bfla:/api/admin/users", "url": "http://t/api/admin/users"}
    out = asyncio.run(validate_findings([f], fetch=_fetch(lambda u, h: None)))
    assert out[0]["submittable"] and out[0]["validation_confidence"] == 0.85
    assert "BFLA engine" in out[0]["validation_reason"]


def test_bfla_plan_from_session_context():
    from core.session_context import SessionContext
    from core.browser.session_capture import bfla_plan
    ctx = SessionContext()
    ctx.add_role("admin", _ADMIN, [])
    ctx.add_role("user", _USER, [])
    ctx.record("admin", "GET", "http://t/api/admin/users", 200)   # privileged + reachable
    ctx.record("admin", "GET", "http://t/api/profile", 200)        # not privileged
    cands, cfg = bfla_plan(ctx, "admin", "user")
    assert cands == ["http://t/api/admin/users"]
    assert cfg["privileged_headers"] == _ADMIN and cfg["low_headers"] == _USER
