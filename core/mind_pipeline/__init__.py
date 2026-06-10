"""
VIPER 6.0 — Mind Pipeline (Claude-Mind feedback + fallback + training)
=======================================================================

Closes the loop between VIPER's LLM ("Claude mind") and the outcomes its
decisions produce. Every LLM call is:

  1. **Recorded** — prompt, system, response, model, latency, tokens
     persisted to ``data/mind_pipeline.db`` (separate from observability,
     which only tracks cost).
  2. **Linked to outcomes** — when a finding lands (or a step fails), the
     finding ID and outcome tag (``success`` / ``failure`` / ``noise``)
     get attached to the trace that produced the decision.
  3. **Falls back gracefully** — if every LLM provider is down
     (Claude CLI offline, no API key, Ollama not running), the pipeline
     looks for a similar past *successful* trace and replays its
     response (or a deterministic rule-based default).
  4. **Trains VIPER** — successful trajectories are exported as JSONL,
     ready for fine-tuning or RAG retrieval; a TF-IDF-style similarity
     index makes the fallback step fast.

The pipeline is a drop-in wrapper for ``ai.model_router.ModelRouter`` —
existing call sites only need to replace ``ModelRouter()`` with
``MindPipeline()``.

Layout
------
    store.py        SQLite schema + DAO
    recorder.py     start_trace / complete_trace / link_finding
    fallback.py     similarity retrieval + rule-based fallback
    pipeline.py     MindPipeline — drop-in replacement for ModelRouter
    feedback.py     outcome scoring (success / failure / noise)
    trainer.py      JSONL export + similarity index build
    cli.py          ``python -m core.mind_pipeline ...``

Quick start
-----------
::

    from core.mind_pipeline import MindPipeline
    mind = MindPipeline()
    # ↓ identical to ai.model_router.ModelRouter().complete(...)
    resp = await mind.complete(prompt="...", system="...",
                                purpose="vuln_classification",
                                hunt_id="hunt-123")
    # Later, when the decision produced (or didn't produce) a finding:
    mind.link_outcome(resp.trace_id, finding_id="f-abc", outcome="success")

Authorization
-------------
This module exists so authorized security researchers can audit + retrain
their own VIPER deployments. All data stays in the local SQLite store
unless you explicitly export it. No data leaves the host.
"""

from __future__ import annotations

from .store import MindStore, MindTrace
from .recorder import MindRecorder
from .fallback import FallbackStrategy, similarity_fallback
from .pipeline import MindPipeline, MindResponse
from .feedback import score_trace, OutcomeTag
from .trainer import export_training_corpus, build_similarity_index

__all__ = [
    "MindPipeline",
    "MindResponse",
    "MindRecorder",
    "MindStore",
    "MindTrace",
    "FallbackStrategy",
    "OutcomeTag",
    "similarity_fallback",
    "score_trace",
    "export_training_corpus",
    "build_similarity_index",
]
