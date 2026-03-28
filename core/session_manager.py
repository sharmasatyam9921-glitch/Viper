#!/usr/bin/env python3
"""
VIPER 5.0 — Session Manager (Stop/Resume)

Saves and restores hunt session state so agents can be stopped mid-hunt
and resumed later without losing progress.

Session state includes:
- Current phase and step
- Discovered assets + processed set
- Findings so far
- Agent bus message queues
- EvoGraph Q-table state
- ReACT engine todo list
"""

import json
import logging
import os
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger("viper.core.session_manager")

STATE_DIR = Path(__file__).parent.parent / "state"


@dataclass
class SessionState:
    """Serializable hunt session state."""
    session_id: str
    target: str
    status: str = "running"  # running, paused, completed, failed
    phase: str = "init"
    step: int = 0
    created_at: str = ""
    paused_at: str = ""
    resumed_at: str = ""
    completed_at: str = ""

    # Progress
    total_findings: int = 0
    total_assets: int = 0
    total_requests: int = 0

    # Discovered data
    subdomains: List[str] = field(default_factory=list)
    live_hosts: List[str] = field(default_factory=list)
    processed_urls: List[str] = field(default_factory=list)

    # Findings
    findings: List[Dict] = field(default_factory=list)

    # Agent state
    agent_states: Dict[str, Dict] = field(default_factory=dict)

    # ReACT engine state
    react_todos: List[Dict] = field(default_factory=list)
    react_step: int = 0

    # Configuration
    config: Dict[str, Any] = field(default_factory=dict)

    # Metadata
    duration_s: float = 0.0
    modules_completed: List[str] = field(default_factory=list)
    modules_pending: List[str] = field(default_factory=list)


class SessionManager:
    """Manage hunt session persistence for stop/resume.

    Usage:
        sm = SessionManager()

        # Start a new session
        session = sm.create("target.com")

        # During hunt — periodically save state
        session.phase = "recon"
        session.subdomains = ["sub1.target.com", "sub2.target.com"]
        sm.save(session)

        # Stop mid-hunt
        sm.pause(session)

        # Later — resume
        session = sm.resume(session.session_id)
        # Continue from session.phase, session.step
    """

    def __init__(self, state_dir: Optional[Path] = None):
        self.state_dir = state_dir or STATE_DIR
        self.state_dir.mkdir(parents=True, exist_ok=True)

    def create(self, target: str, config: Optional[Dict] = None) -> SessionState:
        """Create a new hunt session.

        Args:
            target: Primary target domain/IP.
            config: Hunt configuration dict.
        """
        session_id = f"hunt_{target.replace('.', '_')}_{int(time.time())}"
        session = SessionState(
            session_id=session_id,
            target=target,
            status="running",
            created_at=datetime.now().isoformat(),
            config=config or {},
        )
        self.save(session)
        logger.info("Session created: %s", session_id)
        return session

    def save(self, session: SessionState) -> Path:
        """Save session state to disk.

        Args:
            session: Session state to persist.

        Returns:
            Path to saved session file.
        """
        filepath = self.state_dir / f"{session.session_id}.json"
        data = asdict(session)
        filepath.write_text(json.dumps(data, indent=2, default=str))
        return filepath

    def load(self, session_id: str) -> Optional[SessionState]:
        """Load a session from disk.

        Args:
            session_id: Session identifier.

        Returns:
            SessionState or None if not found.
        """
        filepath = self.state_dir / f"{session_id}.json"
        if not filepath.exists():
            logger.warning("Session not found: %s", session_id)
            return None

        try:
            data = json.loads(filepath.read_text())
            return SessionState(**{k: v for k, v in data.items()
                                   if k in SessionState.__dataclass_fields__})
        except Exception as e:
            logger.error("Failed to load session %s: %s", session_id, e)
            return None

    def pause(self, session: SessionState) -> SessionState:
        """Pause a running session.

        Saves current state and marks as paused.
        """
        session.status = "paused"
        session.paused_at = datetime.now().isoformat()
        self.save(session)
        logger.info("Session paused: %s (phase=%s, step=%d, findings=%d)",
                    session.session_id, session.phase, session.step, session.total_findings)
        return session

    def resume(self, session_id: str) -> Optional[SessionState]:
        """Resume a paused session.

        Args:
            session_id: Session to resume.

        Returns:
            SessionState ready to continue, or None if not found/not paused.
        """
        session = self.load(session_id)
        if not session:
            return None

        if session.status not in ("paused", "running"):
            logger.warning("Session %s is %s, cannot resume", session_id, session.status)
            return None

        session.status = "running"
        session.resumed_at = datetime.now().isoformat()
        self.save(session)

        logger.info("Session resumed: %s (phase=%s, step=%d, %d findings, %d assets)",
                    session_id, session.phase, session.step,
                    session.total_findings, session.total_assets)
        return session

    def complete(self, session: SessionState) -> SessionState:
        """Mark session as completed."""
        session.status = "completed"
        session.completed_at = datetime.now().isoformat()
        self.save(session)
        logger.info("Session completed: %s (%d findings)", session.session_id, session.total_findings)
        return session

    def fail(self, session: SessionState, error: str) -> SessionState:
        """Mark session as failed."""
        session.status = "failed"
        session.completed_at = datetime.now().isoformat()
        session.config["error"] = error
        self.save(session)
        logger.error("Session failed: %s — %s", session.session_id, error)
        return session

    def list_sessions(self, status: Optional[str] = None) -> List[SessionState]:
        """List all sessions, optionally filtered by status.

        Args:
            status: Filter by status (running, paused, completed, failed).
        """
        sessions = []
        for f in self.state_dir.glob("hunt_*.json"):
            session = self.load(f.stem)
            if session:
                if status is None or session.status == status:
                    sessions.append(session)
        sessions.sort(key=lambda s: s.created_at, reverse=True)
        return sessions

    def get_resumable(self) -> List[SessionState]:
        """Get all sessions that can be resumed (paused or running)."""
        return self.list_sessions("paused") + self.list_sessions("running")

    def delete(self, session_id: str) -> bool:
        """Delete a session file."""
        filepath = self.state_dir / f"{session_id}.json"
        if filepath.exists():
            filepath.unlink()
            logger.info("Session deleted: %s", session_id)
            return True
        return False


__all__ = ["SessionManager", "SessionState"]
