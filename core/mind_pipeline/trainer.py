"""Build training datasets from collected mind traces.

Two exports:

  1. **JSONL training corpus** — one line per ``success`` trace, shaped
     for OpenAI-style fine-tuning OR for Anthropic prompt-caching reuse.
     Schema::

        {"messages": [{"role":"system","content":"..."},
                      {"role":"user","content":"..."},
                      {"role":"assistant","content":"..."}],
         "metadata": {"purpose":"...", "hunt_id":"...", "score": 0.9, ...}}

  2. **Similarity index** — a pickled TF-IDF-style index over user
     prompts so the fallback retrieval is O(N) once instead of per-call.

Both run cheaply on the SQLite store — no external deps.
"""

from __future__ import annotations

import json
import logging
import pickle
from collections import Counter
from pathlib import Path
from typing import Iterable, Optional

from .fallback import _tokens, _vec
from .store import MindStore, MindTrace, OUTCOME_SUCCESS, get_store

logger = logging.getLogger("viper.mind_pipeline.trainer")


# ── JSONL export ───────────────────────────────────────────────────────

def export_training_corpus(
    out_path: Path | str, *,
    store: Optional[MindStore] = None,
    purpose: Optional[str] = None,
    min_score: float = 0.5,
    include_pending: bool = False,
    max_rows: int = 50_000,
) -> dict[str, int]:
    """Dump successful (and optionally pending-but-quality) traces to a
    JSONL training corpus. Returns counts dict for logging.

    Parameters
    ----------
    out_path:
        File to write to. Parent directory is created automatically.
    purpose:
        Filter to a single purpose (e.g. ``"vuln_classification"``).
    min_score:
        Minimum feedback_score to include (0..1).
    include_pending:
        If True, include traces with outcome=pending whose response
        wasn't flagged as noise (useful for warm-starting).
    """
    store = store or get_store()
    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    outcomes = [OUTCOME_SUCCESS]
    if include_pending:
        outcomes.append("pending")

    seen = 0
    written = 0
    skipped_score = 0
    with out_path.open("w", encoding="utf-8") as f:
        for outcome in outcomes:
            rows = store.list(purpose=purpose, outcome=outcome,
                              limit=max_rows)
            for trace in rows:
                seen += 1
                if (trace.feedback_score or 0.0) < min_score and outcome == OUTCOME_SUCCESS:
                    skipped_score += 1
                    continue
                if not trace.response.strip() or not trace.user_prompt.strip():
                    continue
                example = {
                    "messages": [
                        *( [{"role": "system",
                             "content": trace.system_prompt}] if trace.system_prompt else []),
                        {"role": "user", "content": trace.user_prompt},
                        {"role": "assistant", "content": trace.response},
                    ],
                    "metadata": {
                        "trace_id": trace.id,
                        "purpose": trace.purpose,
                        "phase": trace.phase,
                        "hunt_id": trace.hunt_id,
                        "agent_id": trace.agent_id,
                        "model": trace.model,
                        "provider": trace.provider,
                        "outcome": trace.outcome,
                        "feedback_score": trace.feedback_score,
                        "finding_id": trace.finding_id,
                        "ts": trace.ts,
                    },
                }
                f.write(json.dumps(example, default=str, ensure_ascii=False))
                f.write("\n")
                written += 1

    summary = {
        "seen": seen, "written": written, "skipped_below_score": skipped_score,
    }
    logger.info("export_training_corpus → %s: %s", out_path, summary)
    return summary


# ── Similarity index ──────────────────────────────────────────────────

def build_similarity_index(
    out_path: Path | str, *,
    store: Optional[MindStore] = None,
    max_rows: int = 10_000,
) -> dict[str, int]:
    """Pre-compute the TF-IDF-ish vectors for every success trace and
    pickle them — makes the fallback lookup O(1) per query instead of
    O(N) tokenization per call.

    Index format::

        {
            "vectors": [(trace_id, response_text, Counter(token_counts)), ...],
            "doc_freq": Counter(token -> docs_containing_token),
            "n_docs": int,
        }
    """
    store = store or get_store()
    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    rows = store.list(outcome=OUTCOME_SUCCESS, limit=max_rows)
    vectors: list[tuple[str, str, Counter]] = []
    doc_freq: Counter = Counter()

    for t in rows:
        toks = _tokens(t.user_prompt)
        if not toks:
            continue
        v = _vec(toks)
        vectors.append((t.id, t.response, v))
        for k in v:
            doc_freq[k] += 1

    index = {
        "vectors": vectors,
        "doc_freq": doc_freq,
        "n_docs": len(vectors),
    }
    with out_path.open("wb") as f:
        pickle.dump(index, f, protocol=pickle.HIGHEST_PROTOCOL)
    summary = {"indexed": len(vectors), "unique_tokens": len(doc_freq)}
    logger.info("build_similarity_index → %s: %s", out_path, summary)
    return summary


def load_similarity_index(path: Path | str) -> dict:
    with Path(path).open("rb") as f:
        return pickle.load(f)
