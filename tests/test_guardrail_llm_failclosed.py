"""#audit-FIX4: the LLM target-authorization guardrail must FAIL CLOSED (deny) — it used to
call a nonexistent model_router.generate() and, on the resulting error, return allowed=True
(approve every target). A safety gate must never approve a target it could not adjudicate.
"""
from __future__ import annotations

import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from ai.model_router import ModelResponse  # noqa: E402
from core.guardrail_llm import _invoke_guardrail_llm  # noqa: E402


class _Router:
    def __init__(self, text=None, raise_it=False, has_generate_only=False):
        self._text = text
        self._raise = raise_it
        if has_generate_only:      # mimic the OLD bug surface: only .generate exists
            self.generate = self._boom
        else:
            self.complete = self._complete

    async def _complete(self, prompt, system="", max_tokens=None, temperature=None,
                        json_mode=False):
        if self._raise:
            raise RuntimeError("provider down")
        return ModelResponse(text=self._text, model="fake", provider="fake")

    async def _boom(self, **k):
        raise AssertionError("guardrail must call complete(), not generate()")


def test_denies_when_model_says_not_allowed():
    r = _Router(text='{"allowed": false, "reason": "out of scope"}')
    allowed, reason = asyncio.run(_invoke_guardrail_llm(r, "target: evil.gov"))
    assert allowed is False and "out of scope" in reason


def test_allows_when_model_says_allowed():
    r = _Router(text='{"allowed": true, "reason": "in scope"}')
    allowed, _ = asyncio.run(_invoke_guardrail_llm(r, "target: my-program.com"))
    assert allowed is True


def test_missing_allowed_field_defaults_to_deny():
    r = _Router(text='{"reason": "unsure"}')
    allowed, _ = asyncio.run(_invoke_guardrail_llm(r, "target: x"))
    assert allowed is False


def test_fails_closed_on_provider_error():
    r = _Router(raise_it=True)
    allowed, reason = asyncio.run(_invoke_guardrail_llm(r, "target: x"))
    assert allowed is False and "closed" in reason.lower()


def test_router_without_complete_fails_closed_not_open():
    # The old code called .generate(); a router lacking .complete() must now DENY, not allow.
    r = _Router(has_generate_only=True)
    allowed, _ = asyncio.run(_invoke_guardrail_llm(r, "target: x"))
    assert allowed is False
