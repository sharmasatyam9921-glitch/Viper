"""Portability fixes so VIPER runs without Claude on a local/other LLM:
  - ModelRouter.use_cli auto-detects (a stray `claude` binary no longer hijacks an
    explicitly-configured Ollama/OpenAI/custom backend);
  - a keyless well-known provider call is skipped so the chain falls through to a working
    fallback quietly;
  - skill_classifier calls the real complete() (not the nonexistent generate());
  - llm_analyzer routes through ModelRouter first (works on any backend).
"""
from __future__ import annotations

import asyncio
import os
import sys
from contextlib import contextmanager
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from ai.model_router import ModelResponse, ModelRouter  # noqa: E402
from core.skill_classifier import AttackPathClassification, classify_attack  # noqa: E402

_DROP = ("VIPER_USE_CLI", "VIPER_MODEL", "VIPER_API_BASE", "VIPER_FALLBACK_MODELS",
         "ANTHROPIC_API_KEY", "OPENAI_API_KEY", "DEEPSEEK_API_KEY", "VIPER_API_KEY")


@contextmanager
def _env(**overrides):
    """A clean env (all provider vars dropped) plus the given overrides. Router state AND
    _has_credentials (which reads env at call time) must both run inside this."""
    env = {k: v for k, v in os.environ.items() if k not in _DROP}
    env.update(overrides)
    with patch.dict(os.environ, env, clear=True):
        yield


# ── use_cli auto-detect ──────────────────────────────────────────────────────
def test_use_cli_defaults_on_with_no_config():
    with _env():
        assert ModelRouter().use_cli is True          # zero-config Claude user keeps free CLI


def test_use_cli_stands_down_for_ollama_model():
    with _env(VIPER_MODEL="ollama/llama3"):
        assert ModelRouter().use_cli is False


def test_use_cli_stands_down_for_openai_model():
    with _env(VIPER_MODEL="openai/gpt-4o"):
        assert ModelRouter().use_cli is False


def test_use_cli_stands_down_for_custom_api_base():
    with _env(VIPER_API_BASE="http://localhost:8000/v1"):
        assert ModelRouter().use_cli is False


def test_explicit_use_cli_true_wins_over_ollama_model():
    with _env(VIPER_USE_CLI="true", VIPER_MODEL="ollama/llama3"):
        assert ModelRouter().use_cli is True


def test_explicit_use_cli_false_wins():
    with _env(VIPER_USE_CLI="false"):
        assert ModelRouter().use_cli is False


# ── _has_credentials skip ────────────────────────────────────────────────────
def test_has_credentials_skips_keyless_anthropic():
    with _env(VIPER_USE_CLI="false"):
        assert ModelRouter()._has_credentials("anthropic/claude-sonnet-4") is False


def test_has_credentials_true_for_ollama():
    with _env(VIPER_USE_CLI="false"):
        assert ModelRouter()._has_credentials("ollama/llama3") is True


def test_has_credentials_true_with_api_base():
    with _env(VIPER_USE_CLI="false", VIPER_API_BASE="http://x/v1"):
        assert ModelRouter()._has_credentials("anthropic/claude") is True


def test_has_credentials_true_for_unknown_provider():
    with _env(VIPER_USE_CLI="false"):
        assert ModelRouter()._has_credentials("gemini/gemini-flash") is True


def test_has_credentials_true_when_key_present():
    with _env(VIPER_USE_CLI="false", OPENAI_API_KEY="sk-x"):
        assert ModelRouter()._has_credentials("openai/gpt-4o") is True


# ── skill_classifier calls complete(), not the nonexistent generate() ────────
class _FakeRouter:
    def __init__(self, text):
        self._text = text
        self.calls = []

    async def complete(self, prompt, system="", max_tokens=None, temperature=None,
                       json_mode=False):
        self.calls.append({"json_mode": json_mode})
        return ModelResponse(text=self._text, model="fake", provider="fake")
    # deliberately NO generate() — mirrors the real ModelRouter's surface


def test_classifier_uses_complete_and_parses_llm_json():
    fake = _FakeRouter('{"required_phase":"exploitation","attack_path_type":"sql_injection",'
                       '"confidence":0.9,"reasoning":"dump users"}')
    res = asyncio.run(classify_attack("dump the users table via sqli",
                                      model_router=fake, enhanced=False))
    assert isinstance(res, AttackPathClassification)
    assert res.attack_path_type == "sql_injection"
    assert res.required_phase == "exploitation"
    assert fake.calls and fake.calls[0]["json_mode"] is True   # json output requested


def test_classifier_falls_back_to_keywords_without_complete():
    # A router exposing only the OLD generate() must never be called that way now; lacking
    # complete() the classifier degrades to keywords without raising (and never hits generate).
    class _NoComplete:
        async def generate(self, **k):
            raise AssertionError("classifier must call complete(), not generate()")
    res = asyncio.run(classify_attack("sqli in id param",
                                      model_router=_NoComplete(), enhanced=False))
    assert isinstance(res, AttackPathClassification)


# ── llm_analyzer routes through ModelRouter first (no ANTHROPIC key needed) ───
def test_llm_analyzer_uses_router_first():
    from ai.llm_analyzer import LLMAnalyzer

    class _R:
        async def complete(self, prompt, system="", max_tokens=1024):
            return ModelResponse(text="ROUTER-ANSWER", model="fake", provider="fake")

    a = LLMAnalyzer(verbose=False)
    a._router_cached = _R()          # inject so _get_router returns our fake
    out = asyncio.run(a._call_claude("sys", "user"))
    assert out == "ROUTER-ANSWER"    # answered by the router, not the Anthropic urllib path
