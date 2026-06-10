"""SQLite-backed store for mind traces.

One row per LLM call, with the option to attach outcomes later. The
schema is deliberately wide so we can query by purpose, hunt, model,
outcome, or feedback score without joining other tables.

Database lives at ``data/mind_pipeline.db`` by default. Override with
``MIND_PIPELINE_DB`` env var or by passing ``db_path`` to ``MindStore``.
"""

from __future__ import annotations

import dataclasses
import json
import logging
import os
import sqlite3
import threading
import time
import uuid
from pathlib import Path
from typing import Any, Optional

logger = logging.getLogger("viper.mind_pipeline.store")

_DEFAULT_PATH = Path(__file__).parent.parent.parent / "data" / "mind_pipeline.db"


# Outcome tags — kept as strings in the DB for human-readable queries.
OUTCOME_PENDING = "pending"   # decision logged, outcome not yet known
OUTCOME_SUCCESS = "success"   # decision led to a confirmed finding / objective hit
OUTCOME_FAILURE = "failure"   # LLM call failed OR decision led to wrong action
OUTCOME_NOISE = "noise"       # LLM returned hedge / refusal / unusable answer


@dataclasses.dataclass
class MindTrace:
    """One row in the mind-pipeline DB."""

    id: str
    ts: float
    hunt_id: Optional[str]
    agent_id: Optional[str]
    phase: Optional[str]
    purpose: str
    model: str
    provider: str               # claude_cli | litellm | ollama | fallback_db | fallback_rule
    system_prompt: str
    user_prompt: str
    response: str
    latency_ms: int
    input_tokens: int
    output_tokens: int
    success: bool               # did the LLM return any usable content?
    outcome: str = OUTCOME_PENDING
    finding_id: Optional[str] = None
    feedback_score: Optional[float] = None
    error: Optional[str] = None
    metadata: dict = dataclasses.field(default_factory=dict)

    @classmethod
    def from_row(cls, row: sqlite3.Row) -> "MindTrace":
        d = dict(row)
        meta = d.pop("metadata", None) or "{}"
        try:
            d["metadata"] = json.loads(meta) if meta else {}
        except json.JSONDecodeError:
            d["metadata"] = {}
        # Bool round-trip
        d["success"] = bool(d.get("success", 0))
        return cls(**d)

    def to_dict(self) -> dict[str, Any]:
        return dataclasses.asdict(self)


# ── DB schema (kept tiny; sqlite handles JSON in TEXT) ─────────────────

_SCHEMA = """\
CREATE TABLE IF NOT EXISTS mind_traces (
    id TEXT PRIMARY KEY,
    ts REAL NOT NULL,
    hunt_id TEXT,
    agent_id TEXT,
    phase TEXT,
    purpose TEXT NOT NULL,
    model TEXT,
    provider TEXT,
    system_prompt TEXT,
    user_prompt TEXT NOT NULL,
    response TEXT,
    latency_ms INTEGER,
    input_tokens INTEGER,
    output_tokens INTEGER,
    success INTEGER NOT NULL DEFAULT 0,
    outcome TEXT NOT NULL DEFAULT 'pending',
    finding_id TEXT,
    feedback_score REAL,
    error TEXT,
    metadata TEXT
);

CREATE INDEX IF NOT EXISTS idx_purpose ON mind_traces(purpose);
CREATE INDEX IF NOT EXISTS idx_hunt    ON mind_traces(hunt_id);
CREATE INDEX IF NOT EXISTS idx_outcome ON mind_traces(outcome);
CREATE INDEX IF NOT EXISTS idx_ts      ON mind_traces(ts);
CREATE INDEX IF NOT EXISTS idx_provider ON mind_traces(provider);
"""


class MindStore:
    """Thread-safe SQLite wrapper for mind traces."""

    def __init__(self, db_path: Optional[Path | str] = None):
        path = Path(db_path) if db_path else Path(
            os.environ.get("MIND_PIPELINE_DB", str(_DEFAULT_PATH)))
        path.parent.mkdir(parents=True, exist_ok=True)
        self.db_path = path
        self._lock = threading.Lock()
        # WAL mode + same-thread-only off for read concurrency
        self._conn = sqlite3.connect(
            path, check_same_thread=False, isolation_level=None,
        )
        self._conn.row_factory = sqlite3.Row
        with self._lock:
            self._conn.executescript(_SCHEMA)
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute("PRAGMA synchronous=NORMAL")
        logger.info("MindStore ready at %s", self.db_path)

    # ── Writes ─────────────────────────────────────────────────────────

    def insert(self, trace: MindTrace) -> None:
        with self._lock:
            self._conn.execute(
                """INSERT OR REPLACE INTO mind_traces
                   (id, ts, hunt_id, agent_id, phase, purpose, model, provider,
                    system_prompt, user_prompt, response, latency_ms,
                    input_tokens, output_tokens, success, outcome,
                    finding_id, feedback_score, error, metadata)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    trace.id, trace.ts, trace.hunt_id, trace.agent_id,
                    trace.phase, trace.purpose, trace.model, trace.provider,
                    trace.system_prompt, trace.user_prompt, trace.response,
                    trace.latency_ms, trace.input_tokens, trace.output_tokens,
                    1 if trace.success else 0, trace.outcome,
                    trace.finding_id, trace.feedback_score, trace.error,
                    json.dumps(trace.metadata, default=str),
                ),
            )

    def update_outcome(self, trace_id: str, *,
                       outcome: str,
                       finding_id: Optional[str] = None,
                       feedback_score: Optional[float] = None) -> bool:
        """Attach the outcome of an earlier-logged decision. Returns True
        if a row was updated, False if the trace_id was unknown."""
        with self._lock:
            cur = self._conn.execute(
                """UPDATE mind_traces
                   SET outcome=?, finding_id=COALESCE(?, finding_id),
                       feedback_score=COALESCE(?, feedback_score)
                   WHERE id=?""",
                (outcome, finding_id, feedback_score, trace_id),
            )
            return cur.rowcount > 0

    # ── Reads ──────────────────────────────────────────────────────────

    def get(self, trace_id: str) -> Optional[MindTrace]:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM mind_traces WHERE id=?", (trace_id,)
            ).fetchone()
        return MindTrace.from_row(row) if row else None

    def list(self, *,
             purpose: Optional[str] = None,
             outcome: Optional[str] = None,
             hunt_id: Optional[str] = None,
             limit: int = 200,
             order_desc: bool = True) -> list[MindTrace]:
        sql = "SELECT * FROM mind_traces WHERE 1=1"
        args: list[Any] = []
        if purpose:
            sql += " AND purpose=?"
            args.append(purpose)
        if outcome:
            sql += " AND outcome=?"
            args.append(outcome)
        if hunt_id:
            sql += " AND hunt_id=?"
            args.append(hunt_id)
        sql += f" ORDER BY ts {'DESC' if order_desc else 'ASC'} LIMIT ?"
        args.append(limit)
        with self._lock:
            rows = self._conn.execute(sql, args).fetchall()
        return [MindTrace.from_row(r) for r in rows]

    def stats(self) -> dict[str, Any]:
        with self._lock:
            cur = self._conn.execute(
                """SELECT
                    COUNT(*) AS total,
                    SUM(CASE WHEN success=1 THEN 1 ELSE 0 END) AS successful_calls,
                    SUM(CASE WHEN outcome='success' THEN 1 ELSE 0 END) AS success_outcomes,
                    SUM(CASE WHEN outcome='failure' THEN 1 ELSE 0 END) AS failure_outcomes,
                    SUM(CASE WHEN outcome='noise'   THEN 1 ELSE 0 END) AS noise_outcomes,
                    SUM(CASE WHEN outcome='pending' THEN 1 ELSE 0 END) AS pending_outcomes,
                    AVG(latency_ms) AS avg_latency_ms,
                    SUM(input_tokens) AS in_tokens,
                    SUM(output_tokens) AS out_tokens,
                    COUNT(DISTINCT hunt_id) AS hunts,
                    COUNT(DISTINCT purpose) AS purposes
                   FROM mind_traces"""
            ).fetchone()
        return dict(cur) if cur else {}

    def provider_breakdown(self) -> dict[str, int]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT provider, COUNT(*) c FROM mind_traces GROUP BY provider"
            ).fetchall()
        return {r["provider"] or "(none)": r["c"] for r in rows}

    def purpose_breakdown(self) -> dict[str, int]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT purpose, COUNT(*) c FROM mind_traces GROUP BY purpose ORDER BY c DESC"
            ).fetchall()
        return {r["purpose"] or "(none)": r["c"] for r in rows}

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    # Context-manager convenience
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()


# ── Module-level singleton ─────────────────────────────────────────────

_default_store: Optional[MindStore] = None
_default_lock = threading.Lock()


def get_store(db_path: Optional[Path | str] = None) -> MindStore:
    """Process-wide singleton — most callers should use this."""
    global _default_store
    with _default_lock:
        if _default_store is None:
            _default_store = MindStore(db_path=db_path)
        return _default_store


def new_trace_id() -> str:
    """Stable trace ID — short prefix + uuid suffix."""
    return "mp-" + uuid.uuid4().hex[:12]


def now_ms() -> float:
    return time.time()
