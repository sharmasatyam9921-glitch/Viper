"""Tests for core.tool_gateway — the typed egress chokepoint."""

import asyncio
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core import tool_gateway as tg  # noqa: E402


def _run(coro):
    return asyncio.run(coro)


def teardown_function():
    tg.clear_context()


def test_legacy_no_context_allows():
    tg.clear_context()
    assert tg._scope_ok(tg.current(), "https://evil.test", is_infra=False) is True


def test_scope_denies_http_without_network():
    events = []
    ctx = tg.EgressContext(scope=lambda u: "good.test" in u,
                           audit=lambda a, p: events.append((a, p)))
    tok = tg.set_context(ctx)
    try:
        r = _run(tg.http("GET", "https://evil.test/x"))
        assert r is None  # denied before any network call
        assert any(a == "egress.blocked" for a, _ in events)
    finally:
        tg.reset_context(tok)


def test_scope_fails_closed_on_predicate_error():
    def boom(_u):
        raise RuntimeError("scope exploded")
    tok = tg.set_context(tg.EgressContext(scope=boom))
    try:
        assert tg._scope_ok(tg.current(), "https://x.test", is_infra=False) is False
    finally:
        tg.reset_context(tok)


def test_infra_hosts_exempt_from_scope():
    ctx = tg.EgressContext(scope=lambda u: False,
                           infra_hosts=frozenset({"crt.sh"}))
    tok = tg.set_context(ctx)
    try:
        assert tg._scope_ok(tg.current(), "https://crt.sh/?q=x", is_infra=False) is True
        assert tg._scope_ok(tg.current(), "https://other.test", is_infra=True) is True
        assert tg._scope_ok(tg.current(), "https://other.test", is_infra=False) is False
    finally:
        tg.reset_context(tok)


def test_subprocess_scope_deny_skips_spawn():
    tok = tg.set_context(tg.EgressContext(scope=lambda u: False))
    try:
        r = _run(tg.run_subprocess(
            [sys.executable, "-c", "print('should not run')"],
            scope_target="https://evil.test"))
        assert r is None
    finally:
        tg.reset_context(tok)


def test_subprocess_runs_in_legacy_mode():
    tg.clear_context()
    r = _run(tg.run_subprocess([sys.executable, "-c", "print('hi')"]))
    assert r is not None
    assert r.returncode == 0
    assert "hi" in r.stdout


def test_context_isolation_via_clear():
    tok = tg.set_context(tg.EgressContext(scope=lambda u: False))
    tg.reset_context(tok)
    # After reset, back to permissive legacy mode.
    assert tg._scope_ok(tg.current(), "https://anything.test", is_infra=False) is True
