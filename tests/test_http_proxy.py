"""Tests for the swarm HTTP upstream-proxy seam (Burp/ZAP routing)."""
from __future__ import annotations

import asyncio
import sys
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.swarm_workers.vuln import _http  # noqa: E402


def teardown_function(_):
    _http.clear_proxy()


def test_proxy_var_set_get_clear():
    _http.set_proxy("http://127.0.0.1:8080")
    assert _http.get_proxy() == "http://127.0.0.1:8080"
    _http.clear_proxy()
    assert _http.get_proxy() is None
    _http.set_proxy("   ")  # blank -> direct
    assert _http.get_proxy() is None


def test_build_opener_routes_through_proxy():
    op = _http._build_opener(follow_redirects=True, proxy="http://127.0.0.1:8080")
    handlers = [h for h in op.handlers if isinstance(h, urllib.request.ProxyHandler)]
    assert handlers, "opener has no ProxyHandler"
    assert handlers[0].proxies.get("http") == "http://127.0.0.1:8080"
    assert handlers[0].proxies.get("https") == "http://127.0.0.1:8080"


def test_build_opener_without_proxy_is_direct():
    op = _http._build_opener(follow_redirects=True, proxy=None)
    phs = [h for h in op.handlers if isinstance(h, urllib.request.ProxyHandler)]
    # No active proxy routing: the empty ProxyHandler registers no proxy and is
    # dropped by urllib, so requests go direct (any environment proxy bypassed).
    assert all(not h.proxies for h in phs)


def test_fetch_threads_installed_proxy(monkeypatch):
    captured = {}

    def fake_sync(method, url, *, headers=None, body=None, timeout=10.0,
                  follow_redirects=True, proxy=None):
        captured["proxy"] = proxy
        return _http.HttpResp(200, {}, "ok", url)

    monkeypatch.setattr(_http, "_fetch_sync", fake_sync)
    _http.set_proxy("http://127.0.0.1:8080")
    try:
        asyncio.run(_http.fetch("GET", "http://x/", rate_limit=False))
    finally:
        _http.clear_proxy()
    assert captured["proxy"] == "http://127.0.0.1:8080"


def test_fetch_no_proxy_passes_none(monkeypatch):
    captured = {}

    def fake_sync(method, url, *, headers=None, body=None, timeout=10.0,
                  follow_redirects=True, proxy=None):
        captured["proxy"] = proxy
        return _http.HttpResp(200, {}, "ok", url)

    monkeypatch.setattr(_http, "_fetch_sync", fake_sync)
    _http.clear_proxy()
    asyncio.run(_http.fetch("GET", "http://x/", rate_limit=False))
    assert captured["proxy"] is None
