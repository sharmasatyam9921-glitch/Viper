"""VIPER LLM Observability — token/cost tracking with optional Langfuse.

Tracks every LLM call: model, tokens, cost, latency.
If Langfuse is installed + configured, ships data there.
Otherwise falls back to local SQLite at data/llm_observability.db.
"""

import json
import logging
import os
import sqlite3
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger("viper.observability")

_DB_DIR = Path(__file__).parent.parent / "data"
_singleton: Optional["LLMObserver"] = None
_lock = threading.Lock()


@dataclass
class Generation:
    """A single LLM generation record."""
    trace_id: str
    name: str
    model: str
    input_tokens: int = 0
    output_tokens: int = 0
    cost: float = 0.0
    duration_ms: int = 0
    timestamp: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)


class LLMObserver:
    """LLM call observability with Langfuse or SQLite fallback.

    Env vars for Langfuse:
        LANGFUSE_PUBLIC_KEY, LANGFUSE_SECRET_KEY, LANGFUSE_HOST
    """

    def __init__(self, db_path: str = ""):
        self._langfuse = None
        self._db_path = db_path or str(_DB_DIR / "llm_observability.db")
        self._lock = threading.Lock()
        self._session_stats = {
            "total_input_tokens": 0,
            "total_output_tokens": 0,
            "total_cost": 0.0,
            "call_count": 0,
            "model_stats": {},
        }

        # Try Langfuse first
        try:
            pub_key = os.environ.get("LANGFUSE_PUBLIC_KEY", "")
            sec_key = os.environ.get("LANGFUSE_SECRET_KEY", "")
            host = os.environ.get("LANGFUSE_HOST", "https://cloud.langfuse.com")
            if pub_key and sec_key:
                from langfuse import Langfuse
                self._langfuse = Langfuse(
                    public_key=pub_key,
                    secret_key=sec_key,
                    host=host,
                )
                logger.info("[Observability] Langfuse connected at %s", host)
        except ImportError:
            logger.debug("[Observability] Langfuse not installed, using SQLite")
        except Exception as e:
            logger.debug("[Observability] Langfuse init failed: %s", e)

        # SQLite fallback
        self._init_db()

    def _init_db(self):
        _DB_DIR.mkdir(exist_ok=True)
        with self._lock:
            conn = sqlite3.connect(self._db_path)
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS generations (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    trace_id TEXT,
                    name TEXT,
                    model TEXT,
                    input_tokens INTEGER DEFAULT 0,
                    output_tokens INTEGER DEFAULT 0,
                    cost REAL DEFAULT 0.0,
                    duration_ms INTEGER DEFAULT 0,
                    metadata_json TEXT DEFAULT '{}',
                    timestamp TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS tool_calls (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    trace_id TEXT,
                    name TEXT,
                    input_args TEXT DEFAULT '',
                    output TEXT DEFAULT '',
                    duration_ms INTEGER DEFAULT 0,
                    status TEXT DEFAULT 'success',
                    timestamp TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_gen_model ON generations(model);
                CREATE INDEX IF NOT EXISTS idx_gen_trace ON generations(trace_id);
            """)
            conn.commit()
            conn.close()

    def trace(self, name: str, metadata: dict = None) -> str:
        """Start a new trace. Returns trace_id."""
        trace_id = f"viper-{int(time.time() * 1000)}"
        if self._langfuse:
            try:
                self._langfuse.trace(id=trace_id, name=name, metadata=metadata or {})
            except Exception:
                pass
        return trace_id

    def generation(self, trace_id: str, name: str, model: str,
                   input_tokens: int = 0, output_tokens: int = 0,
                   cost: float = 0.0, duration_ms: int = 0,
                   metadata: dict = None):
        """Record an LLM generation."""
        now = datetime.now().isoformat()

        # Update session stats
        with self._lock:
            self._session_stats["total_input_tokens"] += input_tokens
            self._session_stats["total_output_tokens"] += output_tokens
            self._session_stats["total_cost"] += cost
            self._session_stats["call_count"] += 1
            ms = self._session_stats["model_stats"]
            if model not in ms:
                ms[model] = {"calls": 0, "input_tokens": 0, "output_tokens": 0,
                             "cost": 0.0, "total_ms": 0}
            ms[model]["calls"] += 1
            ms[model]["input_tokens"] += input_tokens
            ms[model]["output_tokens"] += output_tokens
            ms[model]["cost"] += cost
            ms[model]["total_ms"] += duration_ms

        # Langfuse
        if self._langfuse:
            try:
                self._langfuse.generation(
                    trace_id=trace_id, name=name, model=model,
                    usage={"input": input_tokens, "output": output_tokens},
                    metadata=metadata or {},
                )
            except Exception:
                pass

        # SQLite
        try:
            conn = sqlite3.connect(self._db_path)
            conn.execute(
                "INSERT INTO generations (trace_id, name, model, input_tokens, "
                "output_tokens, cost, duration_ms, metadata_json, timestamp) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (trace_id, name, model, input_tokens, output_tokens,
                 cost, duration_ms, json.dumps(metadata or {}), now),
            )
            conn.commit()
            conn.close()
        except Exception as e:
            logger.debug("Observability DB write failed: %s", e)

    def tool_call(self, trace_id: str, name: str, input_args: str = "",
                  output: str = "", duration_ms: int = 0, status: str = "success"):
        """Record a tool execution."""
        now = datetime.now().isoformat()
        if self._langfuse:
            try:
                self._langfuse.span(
                    trace_id=trace_id, name=name,
                    metadata={"status": status, "duration_ms": duration_ms},
                )
            except Exception:
                pass
        try:
            conn = sqlite3.connect(self._db_path)
            conn.execute(
                "INSERT INTO tool_calls (trace_id, name, input_args, output, "
                "duration_ms, status, timestamp) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (trace_id, name, input_args[:1000], output[:1000],
                 duration_ms, status, now),
            )
            conn.commit()
            conn.close()
        except Exception as e:
            logger.debug("Observability tool_call write failed: %s", e)

    def get_session_stats(self) -> dict:
        """Get current session stats."""
        return dict(self._session_stats)

    def get_model_stats(self) -> dict:
        """Get per-model breakdown."""
        return dict(self._session_stats.get("model_stats", {}))

    def get_historical_stats(self, days: int = 7) -> dict:
        """Get stats from SQLite over the last N days."""
        try:
            conn = sqlite3.connect(self._db_path)
            row = conn.execute(
                "SELECT COUNT(*), SUM(input_tokens), SUM(output_tokens), SUM(cost) "
                "FROM generations WHERE timestamp > datetime('now', ?)",
                (f"-{days} days",),
            ).fetchone()
            conn.close()
            return {
                "calls": row[0] or 0,
                "input_tokens": row[1] or 0,
                "output_tokens": row[2] or 0,
                "cost": row[3] or 0.0,
            }
        except Exception:
            return {}

    def flush(self):
        """Flush pending events (Langfuse batch mode)."""
        if self._langfuse:
            try:
                self._langfuse.flush()
            except Exception:
                pass


def get_observer() -> LLMObserver:
    """Get or create the singleton observer."""
    global _singleton
    if _singleton is None:
        with _lock:
            if _singleton is None:
                _singleton = LLMObserver()
    return _singleton
