"""Tests for the session-auth chokepoint in vuln workers' shared _http.

set_auth() installs headers applied to every fetch; per-call headers override.
"""
import asyncio
import sys
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.swarm_workers.vuln import _http  # noqa: E402
from core.swarm_workers.vuln._http import HttpResp  # noqa: E402


def _capture():
    """Patch _fetch_sync to capture the headers it receives; returns (holder, fake)."""
    holder = {}

    def fake_sync(method, url, *, headers=None, body=None, timeout=10.0,
                 follow_redirects=True, proxy=None):
        holder["headers"] = headers or {}
        return HttpResp(200, {}, "ok", url)

    return holder, fake_sync


def _fetch(url="http://t/x", **kw):
    holder, fake = _capture()
    async def go():
        with patch("core.swarm_workers.vuln._http._fetch_sync", side_effect=fake):
            return await _http.fetch("GET", url, rate_limit=False, **kw)
    asyncio.run(go())
    return holder["headers"]


class TestSessionAuth:
    def teardown_method(self):
        _http.clear_auth()

    def test_no_auth_by_default(self):
        _http.clear_auth()
        h = _fetch()
        assert "Authorization" not in h

    def test_set_auth_injected_into_every_request(self):
        _http.set_auth({"Authorization": "Bearer TOK"})
        h = _fetch()
        assert h.get("Authorization") == "Bearer TOK"

    def test_cookie_auth_injected(self):
        _http.set_auth({"Cookie": "session=abc"})
        assert _fetch().get("Cookie") == "session=abc"

    def test_per_call_header_overrides_session_auth(self):
        _http.set_auth({"Authorization": "Bearer SESSION"})
        h = _fetch(headers={"Authorization": "Bearer CALL"})
        assert h.get("Authorization") == "Bearer CALL"

    def test_clear_auth_removes_it(self):
        _http.set_auth({"Authorization": "Bearer X"})
        _http.clear_auth()
        assert "Authorization" not in _fetch()

    def test_get_auth_roundtrip(self):
        _http.set_auth({"Authorization": "Bearer Y"})
        assert _http.get_auth() == {"Authorization": "Bearer Y"}
        _http.set_auth(None)
        assert _http.get_auth() == {}
