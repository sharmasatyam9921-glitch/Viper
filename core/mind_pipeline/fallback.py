"""Fallback strategies for when "Claude mind is not working".

If every LLM provider (Claude CLI, LiteLLM, Ollama) fails, we still need
to give VIPER *something*. This module provides two strategies that
operate purely on the local DB + heuristics:

  1. **similarity_fallback** — search past successful traces for one
     whose user_prompt is similar to the current call, and replay its
     response.
  2. **rule_fallback** — purpose-keyed deterministic defaults (e.g. for
     ``vuln_classification`` return a guess based on URL keywords).

The similarity search is stdlib-only (TF-IDF over character n-grams
implemented with collections.Counter) so the fallback works even if
sklearn / sentence-transformers aren't installed.
"""

from __future__ import annotations

import dataclasses
import logging
import math
import re
from collections import Counter
from typing import Iterable, Optional

from .store import MindStore, MindTrace, OUTCOME_SUCCESS, get_store

logger = logging.getLogger("viper.mind_pipeline.fallback")


@dataclasses.dataclass
class FallbackResult:
    """What a fallback strategy produced."""
    response: str
    provider: str            # "fallback_db" or "fallback_rule"
    source_trace_id: Optional[str] = None
    score: float = 0.0       # similarity / confidence
    note: str = ""


# ── Strategy 1: similarity search over past successes ──────────────────

_WORD_RE = re.compile(r"[A-Za-z0-9_]+")


def _tokens(text: str) -> list[str]:
    """Lowercase word tokens + character 4-grams. Cheap and language-
    agnostic enough for our purposes."""
    if not text:
        return []
    words = [w.lower() for w in _WORD_RE.findall(text)]
    # Char 4-grams give us robustness to typos / paraphrases
    clean = re.sub(r"\s+", " ", text.lower())
    grams = [clean[i:i+4] for i in range(0, max(0, len(clean) - 3))]
    return words + grams[:200]   # cap to keep things fast


def _vec(tokens: Iterable[str]) -> Counter:
    return Counter(tokens)


def _cosine(a: Counter, b: Counter) -> float:
    if not a or not b:
        return 0.0
    common = set(a) & set(b)
    if not common:
        return 0.0
    dot = sum(a[k] * b[k] for k in common)
    norm_a = math.sqrt(sum(v * v for v in a.values()))
    norm_b = math.sqrt(sum(v * v for v in b.values()))
    if norm_a == 0 or norm_b == 0:
        return 0.0
    return dot / (norm_a * norm_b)


def similarity_fallback(
    user_prompt: str, *,
    purpose: Optional[str] = None,
    store: Optional[MindStore] = None,
    min_score: float = 0.25,
    candidates: int = 200,
) -> Optional[FallbackResult]:
    """Find the best-matching past successful trace and return its
    response. ``None`` if nothing similar enough exists."""
    store = store or get_store()
    # Scope to same-purpose successes first (most useful), then fall back
    # to any successful trace if the same-purpose pool is too thin.
    rows = store.list(purpose=purpose, outcome=OUTCOME_SUCCESS, limit=candidates)
    if len(rows) < 3 and purpose:
        rows = store.list(outcome=OUTCOME_SUCCESS, limit=candidates)
    if not rows:
        return None

    query_vec = _vec(_tokens(user_prompt))
    if not query_vec:
        return None

    best: Optional[tuple[float, MindTrace]] = None
    for trace in rows:
        score = _cosine(query_vec, _vec(_tokens(trace.user_prompt)))
        if best is None or score > best[0]:
            best = (score, trace)

    if best is None or best[0] < min_score:
        return None

    score, trace = best
    return FallbackResult(
        response=trace.response,
        provider="fallback_db",
        source_trace_id=trace.id,
        score=score,
        note=f"Replayed from past success (cosine={score:.2f}, "
             f"purpose={trace.purpose}, hunt={trace.hunt_id})",
    )


# ── Strategy 2: deterministic rule-based defaults ──────────────────────

# purpose → callable(user_prompt) -> response | None
_RULE_TABLE: dict[str, callable] = {}


def register_rule(purpose: str):
    """Decorator: register a rule for the given purpose."""
    def deco(fn):
        _RULE_TABLE[purpose] = fn
        return fn
    return deco


@register_rule("vuln_classification")
def _rule_vuln_classification(prompt: str) -> Optional[str]:
    """Best-effort vuln-type guess from URL/parameter keywords in the
    prompt. Useful when the LLM is down and we need *something* to keep
    the pipeline moving."""
    p = prompt.lower()
    table = [
        ("sqli", ["sql", "union select", "select * from", "drop table",
                  "' or 1", "' or '1", "'--", "' #", "or 1=1", "and 1=1",
                  "' and ", "sleep(", "benchmark("]),
        ("xss", ["<script", "onerror=", "javascript:", "alert(", "onload="]),
        ("ssrf", ["169.254.169.254", "metadata", "localhost", "127.0.0.1", "internal"]),
        ("idor", ["?id=", "user_id=", "account_id=", "/users/"]),
        ("rce", ["exec(", "system(", "shell_exec", "eval(", "${"]),
        ("ssti", ["{{", "{%", "<%=", "${"]),
        ("xxe", ["<!doctype", "<!entity", "system \""]),
        ("open_redirect", ["?redirect=", "?url=", "?next=", "?return_to="]),
        ("path_traversal", ["../", "..\\", "/etc/passwd", "%2e%2e%2f"]),
    ]
    for vuln, keys in table:
        if any(k in p for k in keys):
            return (f'{{"vuln_type": "{vuln}", "confidence": 0.55, '
                    f'"reason": "keyword-rule fallback (mind pipeline)"}}')
    return None


@register_rule("next_step")
def _rule_next_step(prompt: str) -> Optional[str]:
    """Generic fallback when asked 'what should the agent do next'."""
    return ("Continue with the current phase using the highest-priority "
            "available tool. If exhausted, advance to the next phase. "
            "(Rule-based fallback — Claude mind unavailable.)")


@register_rule("deep_think")
def _rule_deep_think(prompt: str) -> Optional[str]:
    return ('{"hypothesis": "blocked", "next_action": "Try lower-cost '
            'recon first; defer deep analysis until LLM is reachable.", '
            '"confidence": 0.4, "note": "deep_think fallback"}')


def rule_fallback(user_prompt: str, *,
                  purpose: str) -> Optional[FallbackResult]:
    """Look up a registered rule for ``purpose`` and run it. ``None`` if
    no rule applies."""
    rule = _RULE_TABLE.get(purpose)
    if rule is None:
        return None
    try:
        out = rule(user_prompt)
    except Exception as exc:  # noqa: BLE001
        logger.debug("rule_fallback %s raised: %s", purpose, exc)
        return None
    if not out:
        return None
    return FallbackResult(
        response=out,
        provider="fallback_rule",
        score=0.5,
        note=f"Rule-based fallback for purpose={purpose}",
    )


# ── Combined strategy ─────────────────────────────────────────────────

class FallbackStrategy:
    """Chains similarity → rule → giving up."""

    def __init__(self, store: Optional[MindStore] = None, *,
                 min_similarity: float = 0.25):
        self.store = store or get_store()
        self.min_similarity = min_similarity

    def try_fallback(self, user_prompt: str, *,
                     purpose: str) -> Optional[FallbackResult]:
        # 1. Past similar success
        sim = similarity_fallback(user_prompt, purpose=purpose,
                                  store=self.store,
                                  min_score=self.min_similarity)
        if sim:
            return sim
        # 2. Rule-based
        return rule_fallback(user_prompt, purpose=purpose)
