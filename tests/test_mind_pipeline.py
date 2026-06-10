"""Tests for core.mind_pipeline — outcome-linked LLM trace store, fallback,
and training corpus export.

Covers:
  - MindStore CRUD + outcome updates
  - MindRecorder context-manager flow + exception handling
  - similarity_fallback retrieves the right past success
  - rule_fallback fires for registered purposes
  - MindPipeline.complete() returns successful response + records trace
  - MindPipeline.complete() falls back when router returns None
  - link_outcome flow + score_trace heuristics
  - export_training_corpus skips noise / low-score, writes valid JSONL
  - build_similarity_index round-trip
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest

from core.mind_pipeline import (
    MindPipeline, MindRecorder, MindStore, MindTrace,
    FallbackStrategy,
    export_training_corpus, build_similarity_index,
)
from core.mind_pipeline.fallback import (
    similarity_fallback, rule_fallback, FallbackResult,
)
from core.mind_pipeline.feedback import (
    score_trace, classify_response_quality, apply_outcome,
    OUTCOME_SUCCESS, OUTCOME_FAILURE, OUTCOME_NOISE, OUTCOME_PENDING,
)
from core.mind_pipeline.store import new_trace_id


# ── Fixtures ───────────────────────────────────────────────────────────

@pytest.fixture
def store(tmp_path: Path) -> MindStore:
    return MindStore(db_path=tmp_path / "mp.db")


def _make_trace(**overrides) -> MindTrace:
    defaults = dict(
        id=new_trace_id(),
        ts=1234567890.0,
        hunt_id="hunt-test",
        agent_id="agent-test",
        phase="vuln",
        purpose="vuln_classification",
        model="claude-sonnet",
        provider="claude_cli",
        system_prompt="You are a security expert.",
        user_prompt="Classify this: ?id=1 returns SQL error",
        response='{"vuln_type": "sqli", "confidence": 0.9}',
        latency_ms=300,
        input_tokens=50,
        output_tokens=20,
        success=True,
    )
    defaults.update(overrides)
    return MindTrace(**defaults)


# ── Store ─────────────────────────────────────────────────────────────

class TestMindStore:
    def test_insert_and_get(self, store):
        t = _make_trace()
        store.insert(t)
        got = store.get(t.id)
        assert got is not None
        assert got.id == t.id
        assert got.purpose == t.purpose
        assert got.success is True

    def test_update_outcome(self, store):
        t = _make_trace()
        store.insert(t)
        ok = store.update_outcome(t.id, outcome=OUTCOME_SUCCESS,
                                   finding_id="f-abc", feedback_score=0.9)
        assert ok
        got = store.get(t.id)
        assert got.outcome == OUTCOME_SUCCESS
        assert got.finding_id == "f-abc"
        assert got.feedback_score == 0.9

    def test_update_outcome_unknown_id(self, store):
        assert store.update_outcome("does-not-exist", outcome="failure") is False

    def test_list_filters(self, store):
        for i in range(5):
            store.insert(_make_trace(
                purpose="vuln_classification" if i < 3 else "next_step",
                outcome=OUTCOME_SUCCESS if i % 2 == 0 else OUTCOME_FAILURE,
            ))
        same_purpose = store.list(purpose="vuln_classification")
        assert len(same_purpose) == 3
        successes = store.list(outcome=OUTCOME_SUCCESS)
        assert len(successes) == 3   # i=0,2,4

    def test_stats(self, store):
        store.insert(_make_trace())
        store.insert(_make_trace(success=False, error="boom"))
        s = store.stats()
        assert s["total"] == 2
        assert s["successful_calls"] == 1


# ── Recorder ───────────────────────────────────────────────────────────

class TestMindRecorder:
    def test_context_manager_persists_success(self, store):
        rec = MindRecorder(store, purpose="x", user_prompt="hello")
        with rec as t:
            t.bind("the answer", model="m", provider="p")
        got = store.get(rec.trace_id)
        assert got is not None
        assert got.response == "the answer"
        assert got.success is True
        assert got.outcome == OUTCOME_PENDING

    def test_context_manager_records_failure_on_exception(self, store):
        rec = MindRecorder(store, purpose="x", user_prompt="hello")
        with pytest.raises(RuntimeError):
            with rec as _t:
                raise RuntimeError("boom")
        got = store.get(rec.trace_id)
        assert got is not None
        assert got.success is False
        assert "boom" in (got.error or "")
        assert got.outcome == OUTCOME_FAILURE

    def test_link_finding(self, store):
        rec = MindRecorder(store, purpose="x", user_prompt="p")
        with rec as t:
            t.bind("ok", model="m", provider="claude_cli")
        ok = rec.link_finding(finding_id="f-1", outcome=OUTCOME_SUCCESS, score=0.8)
        assert ok
        got = store.get(rec.trace_id)
        assert got.outcome == OUTCOME_SUCCESS
        assert got.finding_id == "f-1"
        assert got.feedback_score == 0.8


# ── Fallback strategies ───────────────────────────────────────────────

class TestSimilarityFallback:
    def test_returns_match_when_similar_success_exists(self, store):
        # Past successful trace
        store.insert(_make_trace(
            purpose="vuln_classification",
            user_prompt="Classify ?user=1 with SQL error",
            response='{"vuln_type": "sqli"}',
            outcome=OUTCOME_SUCCESS,
            feedback_score=0.9,
        ))
        out = similarity_fallback(
            "Classify ?user=2 with SQL error in response",
            purpose="vuln_classification",
            store=store,
        )
        assert out is not None
        assert out.provider == "fallback_db"
        assert '"vuln_type"' in out.response

    def test_no_match_when_pool_empty(self, store):
        assert similarity_fallback("anything", purpose="x", store=store) is None

    def test_low_similarity_returns_none(self, store):
        store.insert(_make_trace(
            purpose="vuln_classification",
            user_prompt="totally unrelated content blah blah",
            outcome=OUTCOME_SUCCESS,
            feedback_score=0.9,
        ))
        out = similarity_fallback("classify XSS in form input",
                                  purpose="vuln_classification",
                                  store=store, min_score=0.5)
        assert out is None


class TestRuleFallback:
    def test_vuln_classification_rule_fires_on_sql_keyword(self):
        out = rule_fallback("?id=1' UNION SELECT * FROM users",
                            purpose="vuln_classification")
        assert out is not None
        assert "sqli" in out.response

    def test_vuln_classification_rule_fires_on_xss(self):
        out = rule_fallback("response contains <script>alert(1)</script>",
                            purpose="vuln_classification")
        assert out is not None
        assert "xss" in out.response

    def test_unknown_purpose_returns_none(self):
        assert rule_fallback("hello", purpose="totally_unknown") is None


class TestFallbackStrategy:
    def test_db_first_then_rule(self, store):
        # No DB entry → falls through to rule
        s = FallbackStrategy(store=store)
        out = s.try_fallback("?id=1' OR 1=1--", purpose="vuln_classification")
        assert out is not None
        assert out.provider == "fallback_rule"


# ── Feedback scoring ──────────────────────────────────────────────────

class TestFeedback:
    def test_classify_refusal(self):
        is_noisy, reason = classify_response_quality(
            "I cannot help with that request as an AI.")
        assert is_noisy
        assert "refusal" in reason

    def test_classify_useful_response(self):
        is_noisy, _ = classify_response_quality(
            '{"vuln_type": "sqli", "evidence": "MySQL error banner"}')
        assert not is_noisy

    def test_score_confirmed_finding_critical(self):
        t = _make_trace()
        tag = score_trace(t, finding_confirmed=True, finding_severity="critical")
        assert tag.outcome == OUTCOME_SUCCESS
        assert tag.score == 1.0

    def test_score_false_positive(self):
        t = _make_trace()
        tag = score_trace(t, finding_confirmed=False)
        assert tag.outcome == OUTCOME_FAILURE

    def test_score_refusal_response(self):
        t = _make_trace(response="I cannot help with that.")
        tag = score_trace(t)
        assert tag.outcome == OUTCOME_NOISE

    def test_apply_outcome_persists(self, store):
        t = _make_trace()
        store.insert(t)
        tag = apply_outcome(t.id, store=store,
                            finding_confirmed=True, finding_id="f-9",
                            finding_severity="high")
        assert tag is not None
        assert tag.outcome == OUTCOME_SUCCESS
        got = store.get(t.id)
        assert got.outcome == OUTCOME_SUCCESS
        assert got.finding_id == "f-9"


# ── MindPipeline (with fake router) ───────────────────────────────────

class FakeModelResponse:
    def __init__(self, content, model="fake-model", provider="litellm",
                 usage=None):
        self.content = content
        self.model = model
        self.provider = provider
        self.usage = usage or {"input_tokens": 10, "output_tokens": 5}


class TestMindPipelineHappyPath:
    def test_complete_records_success(self, store):
        router = MagicMock()
        router.complete = AsyncMock(return_value=FakeModelResponse('{"vuln":"sqli"}'))
        mind = MindPipeline(router=router, store=store)
        resp = asyncio.run(mind.complete(
            prompt="Classify ?id=1' error",
            purpose="vuln_classification",
            hunt_id="h-1",
        ))
        assert resp.success is True
        assert resp.used_fallback is False
        assert '"vuln":"sqli"' in resp.content
        t = store.get(resp.trace_id)
        assert t is not None
        assert t.outcome == OUTCOME_PENDING
        assert t.hunt_id == "h-1"

    def test_link_outcome_updates_trace(self, store):
        router = MagicMock()
        router.complete = AsyncMock(return_value=FakeModelResponse("OK"))
        mind = MindPipeline(router=router, store=store)
        resp = asyncio.run(mind.complete(prompt="p", purpose="x"))
        mind.link_outcome(resp.trace_id, finding_confirmed=True,
                          finding_id="f-1", finding_severity="critical")
        t = store.get(resp.trace_id)
        assert t.outcome == OUTCOME_SUCCESS
        assert t.feedback_score == 1.0


class TestMindPipelineFallback:
    def test_router_failure_uses_db_fallback(self, store):
        # Seed a past success
        store.insert(_make_trace(
            purpose="vuln_classification",
            user_prompt="Classify ?id=1' SQL error",
            response='{"vuln_type": "sqli"}',
            outcome=OUTCOME_SUCCESS,
            feedback_score=0.9,
        ))
        # Router returns None (every provider failed)
        router = MagicMock()
        router.complete = AsyncMock(return_value=None)
        mind = MindPipeline(router=router, store=store)
        resp = asyncio.run(mind.complete(
            prompt="Classify ?id=2' SQL error in body",
            purpose="vuln_classification",
        ))
        assert resp.success is True
        assert resp.used_fallback is True
        assert resp.provider == "fallback_db"
        assert "sqli" in resp.content

    def test_router_failure_uses_rule_when_no_history(self, store):
        # No history → rule fallback
        router = MagicMock()
        router.complete = AsyncMock(return_value=None)
        mind = MindPipeline(router=router, store=store)
        resp = asyncio.run(mind.complete(
            prompt="?id=1' UNION SELECT NULL--",
            purpose="vuln_classification",
        ))
        assert resp.used_fallback is True
        assert resp.provider == "fallback_rule"
        assert "sqli" in resp.content

    def test_no_router_no_fallback_no_history_returns_failure(self, store):
        # Disable fallback → response is empty + success=False
        router = MagicMock()
        router.complete = AsyncMock(return_value=None)
        mind = MindPipeline(router=router, store=store,
                            enable_fallback=False)
        resp = asyncio.run(mind.complete(prompt="hi",
                                         purpose="general"))
        assert resp.success is False
        assert resp.error

    def test_router_exception_handled(self, store):
        router = MagicMock()
        router.complete = AsyncMock(side_effect=RuntimeError("network down"))
        mind = MindPipeline(router=router, store=store)
        resp = asyncio.run(mind.complete(
            prompt="?id=1' OR 1=1",
            purpose="vuln_classification",
        ))
        # Router raised → rule fallback fires
        assert resp.used_fallback is True
        assert "sqli" in resp.content


# ── Training corpus ───────────────────────────────────────────────────

class TestTrainer:
    def test_export_writes_jsonl(self, store, tmp_path):
        # 1 success above min_score, 1 noise, 1 low-score success
        store.insert(_make_trace(
            outcome=OUTCOME_SUCCESS, feedback_score=0.9))
        store.insert(_make_trace(
            outcome=OUTCOME_NOISE, feedback_score=0.2))
        store.insert(_make_trace(
            outcome=OUTCOME_SUCCESS, feedback_score=0.3))
        out = tmp_path / "corpus.jsonl"
        summary = export_training_corpus(out, store=store, min_score=0.5)
        assert summary["written"] == 1
        # File contains one valid JSON object per line
        with out.open() as f:
            lines = [json.loads(l) for l in f if l.strip()]
        assert len(lines) == 1
        assert lines[0]["messages"][-1]["role"] == "assistant"

    def test_build_similarity_index_roundtrip(self, store, tmp_path):
        for i in range(3):
            store.insert(_make_trace(
                user_prompt=f"unique prompt {i} with sqli markers",
                outcome=OUTCOME_SUCCESS,
                feedback_score=0.8,
            ))
        out = tmp_path / "idx.pkl"
        summary = build_similarity_index(out, store=store)
        assert summary["indexed"] == 3
        assert out.exists() and out.stat().st_size > 0
