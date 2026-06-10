"""Tests for the fail-closed scope enforcement added to the hack path:

  * the worker HTTP scope guard (core.swarm_workers.vuln._http)
  * the auto-scope reasoner (core.hack_cli._auto_scope_reasoner)
"""

import asyncio
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.swarm_workers.vuln import _http  # noqa: E402


class TestWorkerScopeGuard:
    def teardown_method(self):
        _http.clear_scope_guard()

    def test_default_allows_when_no_guard(self):
        _http.clear_scope_guard()
        assert _http.is_in_scope("https://anything.example") is True

    def test_blocks_off_scope(self):
        _http.set_scope_guard(lambda u: "example.com" in u)
        assert _http.is_in_scope("https://example.com/a") is True
        assert _http.is_in_scope("https://evil.test/a") is False

    def test_fails_closed_on_guard_error(self):
        def boom(_u):
            raise RuntimeError("scope check exploded")
        _http.set_scope_guard(boom)
        assert _http.is_in_scope("https://example.com") is False

    def test_fetch_short_circuits_off_scope(self):
        # A denying guard must make fetch return None WITHOUT hitting the net.
        _http.set_scope_guard(lambda _u: False)
        r = asyncio.run(_http.fetch("GET", "https://example.com", rate_limit=False))
        assert r is None


class TestAutoScope:
    def test_allows_target_and_subdomains_denies_others(self, tmp_path):
        from core.hack_cli import _auto_scope_reasoner
        sr = _auto_scope_reasoner("example.com", str(tmp_path / "v.db"))
        assert sr.decide("https://example.com/x").allowed is True
        assert sr.decide("https://api.example.com").allowed is True
        assert sr.decide("https://evil.test").allowed is False

    def test_handles_url_target(self, tmp_path):
        from core.hack_cli import _auto_scope_reasoner
        sr = _auto_scope_reasoner("https://shop.example.com:8443/path", str(tmp_path / "v.db"))
        assert sr.decide("https://shop.example.com").allowed is True
        assert sr.decide("https://other.test").allowed is False
