"""Tests for ModelRouter.complete()'s overall-timeout ceiling.

complete() wraps the provider fallback chain in a single hard timeout
(VIPER_LLM_TIMEOUT_S) and returns None on overrun — the same contract callers
already handle for "all providers failed".
"""
import asyncio
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ai.model_router import ModelRouter  # noqa: E402


class TestOverallTimeout:
    async def test_slow_chain_returns_none(self):
        r = ModelRouter()
        r._overall_timeout_s = 0.05  # force a tight ceiling

        async def _slow(*a, **kw):
            await asyncio.sleep(5)  # far longer than the ceiling
            return "should-never-arrive"

        r._complete_chain = _slow
        result = await r.complete("hello")
        assert result is None

    async def test_fast_chain_passes_through(self):
        r = ModelRouter()
        r._overall_timeout_s = 5.0
        sentinel = object()

        async def _fast(*a, **kw):
            return sentinel

        r._complete_chain = _fast
        result = await r.complete("hello")
        assert result is sentinel

    def test_timeout_configurable_from_env(self, monkeypatch):
        monkeypatch.setenv("VIPER_LLM_TIMEOUT_S", "42")
        r = ModelRouter()
        assert r._overall_timeout_s == 42.0

    def test_timeout_has_sane_default(self):
        r = ModelRouter()
        assert r._overall_timeout_s == 300.0
