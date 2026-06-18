"""Capture pipeline: request dedup, role-diff, HAR import, optional Playwright."""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.browser import viper_browser  # noqa: E402
from core.browser.proxy_pipeline import RequestCorpus, request_signature  # noqa: E402
from core.browser.session_capture import (  # noqa: E402
    bola_plan,
    build_session_context,
    role_diff_candidates,
    session_context_from_har,
)


def test_signature_collapses_value_variants():
    a = request_signature("GET", "http://t/api/orders?id=1")
    b = request_signature("GET", "http://t/api/orders?id=2")
    assert a == b                                        # only the value differs
    c = request_signature("GET", "http://t/api/orders?id=1&x=2")
    assert c != a                                        # different param set
    d = request_signature("POST", "http://t/api/orders?id=1")
    assert d != a                                        # different method


def test_corpus_dedups_and_extracts():
    c = RequestCorpus()
    for i in range(5):
        c.add("GET", f"http://t/api/orders?id={i}", status=200, role="A")
    c.add("GET", "http://t/api/users?uid=9", status=200, role="A")
    c.add("ftp", "ftp://t/x", status=0)                  # non-http dropped
    assert len(c) == 2                                   # two unique signatures
    assert c.params() == {"id", "uid"}
    assert ("GET", "t", "/api/orders") in c.endpoints()
    har = c.to_har()
    assert len(har["log"]["entries"]) == 2


def test_build_session_context_from_captures():
    ctx = build_session_context({
        "A": {"headers": {"Cookie": "s=alice"}, "markers": ["alice@victim.io"],
              "captures": [("GET", "http://t/api/orders/1", 200),
                           ("GET", "http://t/api/orders/2", 200)]},
        "B": {"headers": {"Cookie": "s=bob"}, "markers": ["bob@victim.io"],
              "captures": [("GET", "http://t/api/orders/1", 403)]},
    })
    assert ctx.status("A", "http://t/api/orders/1") == 200
    assert ctx.status("B", "http://t/api/orders/1") == 403


def test_role_diff_drops_attacker_denied_urls():
    ctx = build_session_context({
        "A": {"headers": {}, "markers": ["m"],
              "captures": [("GET", "http://t/o/1", 200),
                           ("GET", "http://t/o/2", 200)]},
        "B": {"headers": {}, "markers": [],
              "captures": [("GET", "http://t/o/1", 403)]},  # B denied on /o/1
    })
    cands = role_diff_candidates(ctx, "A", "B")
    assert cands == ["http://t/o/2"]            # /o/1 dropped (B already 403)


def test_bola_plan_returns_candidates_and_config():
    ctx = build_session_context({
        "A": {"headers": {"Cookie": "s=alice"}, "markers": ["alice@victim.io"],
              "captures": [("GET", "http://t/o/9", 200)]},
        "B": {"headers": {"Cookie": "s=bob"}, "markers": [], "captures": []},
    })
    cands, cfg = bola_plan(ctx, "A", "B")
    assert cands == ["http://t/o/9"]
    assert cfg["owner_headers"] == {"Cookie": "s=alice"}
    assert "alice@victim.io" in cfg["owner_markers"]


def test_har_import_populates_reachability():
    har = {"log": {"entries": [
        {"request": {"method": "GET", "url": "http://t/api/me"},
         "response": {"status": 200}},
        {"request": {"method": "POST", "url": "http://t/api/login"},
         "response": {"status": 204}},
    ]}}
    ctx = session_context_from_har(har, "A", headers={"Cookie": "s=a"},
                                   markers=["a@x.io"])
    assert ctx.status("A", "http://t/api/me") == 200
    assert ctx.status("A", "http://t/api/login") == 204


def test_har_import_drops_non_http_scheme():
    # A hostile/malformed HAR must not inject file:// (etc.) into the matrix.
    har = {"log": {"entries": [
        {"request": {"method": "GET", "url": "file:///etc/passwd"},
         "response": {"status": 200}},
        {"request": {"method": "GET", "url": "http://t/api/me"},
         "response": {"status": 200}},
    ]}}
    ctx = session_context_from_har(har, "A")
    urls = ctx.reachable_urls("A", ok_only=False)
    assert urls == ["http://t/api/me"]            # file:// dropped


def test_playwright_available_returns_bool():
    assert isinstance(viper_browser.available(), bool)
