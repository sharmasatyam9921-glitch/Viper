"""Authenticated per-role crawl: records per-role reachability + surfaces authed-only
endpoints/params, using operator-supplied sessions. Read-only; never touches the gate."""
from __future__ import annotations

import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.authenticated_crawl import crawl_roles  # noqa: E402
from core.session_context import SessionContext  # noqa: E402
from core.swarm_workers.vuln._http import HttpResp  # noqa: E402

_BASE = "http://t/"
# The home page links to a shared dashboard and an admin-only page.
_HOME = '<a href="/dashboard?tab=main">dash</a><a href="/admin/users?id=1">admin</a>'


def _fetch_factory(role_status):
    """role_status: role-cookie -> status returned for /admin URLs (default 403).
    The home page (root path) serves the links; /admin is role-gated."""
    from urllib.parse import urlsplit

    async def fetch(method, url, *, headers=None, timeout=8.0, **kw):
        cookie = (headers or {}).get("Cookie", "")
        body = _HOME if urlsplit(url).path in ("", "/") else ""
        status = role_status.get(cookie, 403) if "/admin" in url else 200
        return HttpResp(status, {"content-type": "text/html"}, body, url)
    return fetch


def _ctx():
    sc = SessionContext(hunt_id="t")
    sc.add_role("admin", {"Cookie": "role=admin"}, ["admin-marker"])
    sc.add_role("user", {"Cookie": "role=user"}, ["user-marker"])
    return sc


def test_no_roles_is_noop():
    sc = SessionContext(hunt_id="t")
    eps, params = asyncio.run(crawl_roles(sc, _BASE, fetch=_fetch_factory({})))
    assert eps == [] and params == set()


def test_records_per_role_reachability_and_returns_endpoints():
    sc = _ctx()
    # admin can reach /admin/users (200); user is 403 there
    fetch = _fetch_factory({"role=admin": 200, "role=user": 403})
    eps, params = asyncio.run(crawl_roles(sc, _BASE, fetch=fetch))
    # endpoints reachable by >=1 role are returned; query params harvested
    assert "http://t/dashboard?tab=main" in eps
    assert "http://t/admin/users?id=1" in eps           # admin reached it
    assert {"tab", "id"} <= params
    # per-role reachability recorded (feeds the BOLA/BFLA engine)
    assert sc.status("admin", "http://t/admin/users?id=1") == 200
    assert sc.status("user", "http://t/admin/users?id=1") == 403
    # role_diff exposes the cross-role access gap on that object
    diff = sc.role_diff("http://t/admin/users?id=1")
    assert diff.get("admin") == 200 and diff.get("user") == 403


def test_endpoint_only_admin_can_reach_is_still_surfaced():
    sc = _ctx()
    # only admin reaches /admin (200); user 403 -> still returned (>=1 role reached it)
    fetch = _fetch_factory({"role=admin": 200, "role=user": 403})
    eps, _ = asyncio.run(crawl_roles(sc, _BASE, fetch=fetch))
    assert any("/admin/users" in u for u in eps)


def test_unreachable_by_all_roles_is_dropped():
    sc = _ctx()
    fetch = _fetch_factory({"role=admin": 403, "role=user": 403})   # nobody reaches admin
    eps, _ = asyncio.run(crawl_roles(sc, _BASE, fetch=fetch))
    assert not any("/admin" in u for u in eps)          # 403 for all -> not surfaced
    assert "http://t/dashboard?tab=main" in eps         # dashboard (200) still surfaced


def test_hackmode_seeds_roles_from_bola_config_and_crawls(tmp_path):
    from core.audit_logger import AuditLogger
    from core.hack_mode import HackMode
    from core.hack_profile import LabProfile
    from core.narrator import Narrator
    audit = AuditLogger.for_hunt("t", hunts_dir=tmp_path / "h", db_path=tmp_path / "v.db")
    hm = HackMode(target=_BASE, profile=LabProfile(), narrator=Narrator(quiet=True),
                  audit=audit, bola_config={
                      "owner_name": "A", "owner_headers": {"Cookie": "role=admin"},
                      "owner_markers": ["m"], "attacker_name": "B",
                      "attacker_headers": {"Cookie": "role=user"}, "attacker_markers": []})
    import core.authenticated_crawl as ac
    orig = ac.crawl_roles

    async def fake_crawl(sc, base, **kw):
        return await orig(sc, base, fetch=_fetch_factory(
            {"role=admin": 200, "role=user": 403}))
    ac.crawl_roles = fake_crawl
    try:
        asyncio.run(hm._run_authenticated_crawl())
    finally:
        ac.crawl_roles = orig
    # bola_config identities became roles, and authed endpoints entered the surface
    assert set(hm._session_context.roles) == {"A", "B"}
    urls = [f["url"] for f in hm._state.get("findings", []) if f.get("type") == "endpoint"]
    assert any("/dashboard" in u for u in urls)
