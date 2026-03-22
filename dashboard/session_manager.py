#!/usr/bin/env python3
"""
VIPER 4.0 — Multi-Session Manager.

Manages concurrent orchestrator instances, each targeting a different URL.
Sessions are persisted to SQLite and can be controlled via the dashboard API.

Usage:
    from dashboard.session_manager import SessionManager
    mgr = SessionManager()
    sid = mgr.create_session("https://target.com", profile="full")
    await mgr.run_session(sid, objective="Find all vulns")
    mgr.list_sessions()
"""

import asyncio
import json
import logging
import os
import sqlite3
import time
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger("viper.sessions")

# ── Paths ──
PROJECT_ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = PROJECT_ROOT / "data"
SESSIONS_DB = DATA_DIR / "sessions.db"


# ══════════════════════════════════════════════════════════════════════
# SESSION STATES
# ══════════════════════════════════════════════════════════════════════

STATE_CREATED = "created"
STATE_RUNNING = "running"
STATE_PAUSED = "paused"
STATE_COMPLETED = "completed"
STATE_FAILED = "failed"
STATE_STOPPED = "stopped"


# ══════════════════════════════════════════════════════════════════════
# PERSISTENCE
# ══════════════════════════════════════════════════════════════════════

def _init_db():
    """Create sessions table if needed."""
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(SESSIONS_DB))
    conn.execute("""
        CREATE TABLE IF NOT EXISTS sessions (
            id TEXT PRIMARY KEY,
            target TEXT NOT NULL,
            objective TEXT DEFAULT '',
            profile TEXT DEFAULT 'full',
            state TEXT DEFAULT 'created',
            created_at TEXT NOT NULL,
            started_at TEXT,
            ended_at TEXT,
            iteration INTEGER DEFAULT 0,
            max_iterations INTEGER DEFAULT 15,
            phase TEXT DEFAULT '',
            findings_count INTEGER DEFAULT 0,
            error TEXT DEFAULT '',
            config TEXT DEFAULT '{}',
            summary TEXT DEFAULT ''
        )
    """)
    conn.commit()
    conn.close()


def _save_session(session: dict):
    """Upsert session to SQLite."""
    conn = sqlite3.connect(str(SESSIONS_DB))
    conn.execute("""
        INSERT OR REPLACE INTO sessions
            (id, target, objective, profile, state, created_at, started_at,
             ended_at, iteration, max_iterations, phase, findings_count,
             error, config, summary)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        session["id"], session["target"], session.get("objective", ""),
        session.get("profile", "full"), session["state"],
        session["created_at"], session.get("started_at"),
        session.get("ended_at"), session.get("iteration", 0),
        session.get("max_iterations", 15), session.get("phase", ""),
        session.get("findings_count", 0), session.get("error", ""),
        json.dumps(session.get("config", {})),
        session.get("summary", ""),
    ))
    conn.commit()
    conn.close()


def _load_sessions() -> List[dict]:
    """Load all sessions from SQLite."""
    if not SESSIONS_DB.exists():
        return []
    conn = sqlite3.connect(str(SESSIONS_DB))
    conn.row_factory = sqlite3.Row
    rows = conn.execute("SELECT * FROM sessions ORDER BY created_at DESC").fetchall()
    conn.close()
    result = []
    for r in rows:
        d = dict(r)
        try:
            d["config"] = json.loads(d.get("config") or "{}")
        except Exception:
            d["config"] = {}
        result.append(d)
    return result


def _load_session(session_id: str) -> Optional[dict]:
    """Load a single session by ID."""
    if not SESSIONS_DB.exists():
        return None
    conn = sqlite3.connect(str(SESSIONS_DB))
    conn.row_factory = sqlite3.Row
    row = conn.execute("SELECT * FROM sessions WHERE id=?", (session_id,)).fetchone()
    conn.close()
    if not row:
        return None
    d = dict(row)
    try:
        d["config"] = json.loads(d.get("config") or "{}")
    except Exception:
        d["config"] = {}
    return d


def _delete_session_db(session_id: str):
    """Delete session from SQLite."""
    if not SESSIONS_DB.exists():
        return
    conn = sqlite3.connect(str(SESSIONS_DB))
    conn.execute("DELETE FROM sessions WHERE id=?", (session_id,))
    conn.commit()
    conn.close()


# ══════════════════════════════════════════════════════════════════════
# SESSION MANAGER
# ══════════════════════════════════════════════════════════════════════

class SessionManager:
    """Manage multiple concurrent VIPER sessions."""

    def __init__(self, graph_engine=None, model_router=None, ws_server=None):
        self._sessions: Dict[str, dict] = {}
        self._tasks: Dict[str, asyncio.Task] = {}
        self._stop_flags: Dict[str, asyncio.Event] = {}
        self._graph_engine = graph_engine
        self._model_router = model_router
        self._ws_server = ws_server

        # Init DB and load persisted sessions
        _init_db()
        for s in _load_sessions():
            # Mark previously running sessions as stopped (unclean shutdown)
            if s["state"] in (STATE_RUNNING, STATE_PAUSED):
                s["state"] = STATE_STOPPED
                s["ended_at"] = datetime.utcnow().isoformat()
                _save_session(s)
            self._sessions[s["id"]] = s

    # ── CRUD ─────────────────────────────────────────────────────────

    def create_session(self, target: str, objective: str = "",
                       profile: str = "full", max_iterations: int = 15,
                       **kwargs) -> str:
        """Create a new session. Returns session_id."""
        session_id = str(uuid.uuid4())[:12]
        now = datetime.utcnow().isoformat()

        session = {
            "id": session_id,
            "target": target,
            "objective": objective or f"Full security assessment of {target}",
            "profile": profile,
            "state": STATE_CREATED,
            "created_at": now,
            "started_at": None,
            "ended_at": None,
            "iteration": 0,
            "max_iterations": max_iterations,
            "phase": "",
            "findings_count": 0,
            "error": "",
            "config": kwargs,
            "summary": "",
        }

        self._sessions[session_id] = session
        _save_session(session)
        logger.info(f"Session {session_id} created for {target}")
        return session_id

    def get_session(self, session_id: str) -> Optional[dict]:
        """Get session state."""
        return self._sessions.get(session_id) or _load_session(session_id)

    def list_sessions(self) -> List[dict]:
        """List all sessions with status summary."""
        result = []
        for sid, s in sorted(
            self._sessions.items(),
            key=lambda x: x[1].get("created_at", ""),
            reverse=True,
        ):
            result.append({
                "id": s["id"],
                "target": s["target"],
                "state": s["state"],
                "phase": s.get("phase", ""),
                "iteration": s.get("iteration", 0),
                "max_iterations": s.get("max_iterations", 15),
                "findings_count": s.get("findings_count", 0),
                "created_at": s["created_at"],
                "started_at": s.get("started_at"),
                "ended_at": s.get("ended_at"),
                "profile": s.get("profile", "full"),
            })
        return result

    # ── Execution ────────────────────────────────────────────────────

    async def run_session(self, session_id: str, objective: str = ""):
        """Run orchestrator for a session. Non-blocking — spawns async task."""
        session = self._sessions.get(session_id)
        if not session:
            raise ValueError(f"Session {session_id} not found")
        if session["state"] == STATE_RUNNING:
            raise ValueError(f"Session {session_id} already running")

        if objective:
            session["objective"] = objective

        session["state"] = STATE_RUNNING
        session["started_at"] = datetime.utcnow().isoformat()
        session["ended_at"] = None
        session["error"] = ""
        _save_session(session)

        stop_flag = asyncio.Event()
        self._stop_flags[session_id] = stop_flag

        task = asyncio.create_task(self._execute_session(session_id, stop_flag))
        self._tasks[session_id] = task

        # Notify dashboard
        if self._ws_server:
            await self._ws_server.broadcast("session_update", {
                "session_id": session_id,
                "state": STATE_RUNNING,
                "target": session["target"],
            })

        logger.info(f"Session {session_id} started for {session['target']}")

    async def _execute_session(self, session_id: str, stop_flag: asyncio.Event):
        """Internal: run the orchestrator loop for a session."""
        session = self._sessions[session_id]

        try:
            # Try to import the orchestrator
            try:
                from core.orchestrator import Orchestrator
            except ImportError:
                try:
                    from core.viper_core import ViperOrchestrator as Orchestrator
                except ImportError:
                    logger.error("No orchestrator module found")
                    session["state"] = STATE_FAILED
                    session["error"] = "Orchestrator module not available"
                    session["ended_at"] = datetime.utcnow().isoformat()
                    _save_session(session)
                    return

            # Create orchestrator with session-scoped config
            orch_kwargs = {
                "target": session["target"],
                "max_iterations": session["max_iterations"],
            }
            if self._graph_engine:
                orch_kwargs["graph_engine"] = self._graph_engine
            if self._model_router:
                orch_kwargs["model_router"] = self._model_router

            # Merge extra config
            for k, v in session.get("config", {}).items():
                if k not in orch_kwargs:
                    orch_kwargs[k] = v

            orchestrator = Orchestrator(**orch_kwargs)

            # Attach WS callbacks if available
            if self._ws_server:
                orchestrator._ws_session_id = session_id
                orchestrator._ws_server = self._ws_server

            # Run the orchestrator
            result = await orchestrator.run(
                objective=session["objective"],
                stop_event=stop_flag,
            )

            session["state"] = STATE_COMPLETED
            session["summary"] = str(result.get("summary", "")) if isinstance(result, dict) else str(result)
            session["findings_count"] = result.get("findings_count", 0) if isinstance(result, dict) else 0

        except asyncio.CancelledError:
            session["state"] = STATE_STOPPED
            logger.info(f"Session {session_id} cancelled")

        except Exception as e:
            session["state"] = STATE_FAILED
            session["error"] = str(e)[:500]
            logger.error(f"Session {session_id} failed: {e}")

        finally:
            session["ended_at"] = datetime.utcnow().isoformat()
            _save_session(session)
            self._tasks.pop(session_id, None)
            self._stop_flags.pop(session_id, None)

            if self._ws_server:
                await self._ws_server.broadcast("session_update", {
                    "session_id": session_id,
                    "state": session["state"],
                    "target": session["target"],
                    "findings_count": session.get("findings_count", 0),
                })

    def stop_session(self, session_id: str):
        """Stop a running session gracefully."""
        session = self._sessions.get(session_id)
        if not session:
            raise ValueError(f"Session {session_id} not found")

        # Signal stop
        flag = self._stop_flags.get(session_id)
        if flag:
            flag.set()

        # Cancel task if still running
        task = self._tasks.get(session_id)
        if task and not task.done():
            task.cancel()

        session["state"] = STATE_STOPPED
        session["ended_at"] = datetime.utcnow().isoformat()
        _save_session(session)
        logger.info(f"Session {session_id} stopped")

    def pause_session(self, session_id: str):
        """Pause a running session (orchestrator checks flag each iteration)."""
        session = self._sessions.get(session_id)
        if not session or session["state"] != STATE_RUNNING:
            return
        session["state"] = STATE_PAUSED
        _save_session(session)
        logger.info(f"Session {session_id} paused")

    def resume_session(self, session_id: str):
        """Resume a paused session."""
        session = self._sessions.get(session_id)
        if not session or session["state"] != STATE_PAUSED:
            return
        session["state"] = STATE_RUNNING
        _save_session(session)
        logger.info(f"Session {session_id} resumed")

    def delete_session(self, session_id: str):
        """Delete session and its data."""
        # Stop if running
        if session_id in self._tasks:
            self.stop_session(session_id)

        self._sessions.pop(session_id, None)
        _delete_session_db(session_id)
        logger.info(f"Session {session_id} deleted")

    # ── Progress updates (called by orchestrator hooks) ──────────────

    def update_progress(self, session_id: str, **kwargs):
        """Update session progress fields (phase, iteration, findings_count)."""
        session = self._sessions.get(session_id)
        if not session:
            return
        for key in ("phase", "iteration", "findings_count", "error"):
            if key in kwargs:
                session[key] = kwargs[key]
        _save_session(session)

    # ── Stats ────────────────────────────────────────────────────────

    @property
    def active_count(self) -> int:
        return sum(1 for s in self._sessions.values() if s["state"] == STATE_RUNNING)

    @property
    def total_count(self) -> int:
        return len(self._sessions)

    def get_stats(self) -> dict:
        """Aggregate stats across all sessions."""
        states = {}
        total_findings = 0
        for s in self._sessions.values():
            states[s["state"]] = states.get(s["state"], 0) + 1
            total_findings += s.get("findings_count", 0)
        return {
            "total": len(self._sessions),
            "active": self.active_count,
            "by_state": states,
            "total_findings": total_findings,
        }
