"""VIPER Project Manager — SQLite-backed multi-project support.

Lightweight project isolation without PostgreSQL.
Each project has independent settings, scope, and metadata.
"""

import json
import logging
import sqlite3
import threading
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger("viper.project_manager")

_DB_DIR = Path(__file__).parent.parent / "data"


class ProjectManager:
    """Manage multiple bug bounty projects with isolated settings."""

    def __init__(self, db_path: str = ""):
        if not db_path:
            _DB_DIR.mkdir(exist_ok=True)
            db_path = str(_DB_DIR / "projects.db")
        self._db_path = db_path
        self._lock = threading.Lock()
        self._init_db()

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self._db_path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        return conn

    def _init_db(self):
        with self._lock:
            conn = self._conn()
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS projects (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL UNIQUE,
                    target TEXT NOT NULL,
                    scope_json TEXT DEFAULT '{}',
                    settings_json TEXT DEFAULT '{}',
                    notes TEXT DEFAULT '',
                    status TEXT DEFAULT 'active',
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS meta (
                    key TEXT PRIMARY KEY,
                    value TEXT
                );
            """)
            conn.commit()
            conn.close()

    def create(self, name: str, target: str,
               scope: Optional[dict] = None,
               settings: Optional[dict] = None,
               notes: str = "") -> int:
        """Create a new project. Returns project_id."""
        now = datetime.now().isoformat()
        with self._lock:
            conn = self._conn()
            try:
                cur = conn.execute(
                    "INSERT INTO projects (name, target, scope_json, settings_json, "
                    "notes, status, created_at, updated_at) VALUES (?, ?, ?, ?, ?, 'active', ?, ?)",
                    (name, target,
                     json.dumps(scope or {}),
                     json.dumps(settings or {}),
                     notes, now, now),
                )
                conn.commit()
                pid = cur.lastrowid
                logger.info("Created project #%d: %s (%s)", pid, name, target)
                return pid
            finally:
                conn.close()

    def list_all(self, status: str = "active") -> List[dict]:
        """List all projects with given status."""
        conn = self._conn()
        try:
            rows = conn.execute(
                "SELECT * FROM projects WHERE status = ? ORDER BY updated_at DESC",
                (status,),
            ).fetchall()
            return [self._row_to_dict(r) for r in rows]
        finally:
            conn.close()

    def get(self, project_id: int) -> Optional[dict]:
        """Get project details by ID."""
        conn = self._conn()
        try:
            row = conn.execute(
                "SELECT * FROM projects WHERE id = ?", (project_id,)
            ).fetchone()
            return self._row_to_dict(row) if row else None
        finally:
            conn.close()

    def update(self, project_id: int, **kwargs) -> bool:
        """Update project fields. Returns True if updated."""
        allowed = {"name", "target", "scope", "settings", "notes", "status"}
        updates = {}
        for k, v in kwargs.items():
            if k not in allowed:
                continue
            if k == "scope":
                updates["scope_json"] = json.dumps(v) if isinstance(v, dict) else v
            elif k == "settings":
                updates["settings_json"] = json.dumps(v) if isinstance(v, dict) else v
            else:
                updates[k] = v

        if not updates:
            return False

        updates["updated_at"] = datetime.now().isoformat()
        set_clause = ", ".join(f"{k} = ?" for k in updates)
        values = list(updates.values()) + [project_id]

        with self._lock:
            conn = self._conn()
            try:
                conn.execute(
                    f"UPDATE projects SET {set_clause} WHERE id = ?", values
                )
                conn.commit()
                return True
            finally:
                conn.close()

    def archive(self, project_id: int) -> bool:
        """Soft-delete a project."""
        return self.update(project_id, status="archived")

    def get_settings(self, project_id: int) -> dict:
        """Get project settings merged with global defaults."""
        proj = self.get(project_id)
        if not proj:
            return {}
        return proj.get("settings", {})

    def set_current(self, project_id: int):
        """Set the active project."""
        with self._lock:
            conn = self._conn()
            try:
                conn.execute(
                    "INSERT OR REPLACE INTO meta (key, value) VALUES ('current_project', ?)",
                    (str(project_id),),
                )
                conn.commit()
            finally:
                conn.close()

    def get_current(self) -> Optional[dict]:
        """Get the currently active project."""
        conn = self._conn()
        try:
            row = conn.execute(
                "SELECT value FROM meta WHERE key = 'current_project'"
            ).fetchone()
            if row:
                return self.get(int(row["value"]))
            return None
        finally:
            conn.close()

    def _row_to_dict(self, row: sqlite3.Row) -> dict:
        d = dict(row)
        for json_field in ("scope_json", "settings_json"):
            if json_field in d:
                key = json_field.replace("_json", "")
                try:
                    d[key] = json.loads(d.pop(json_field))
                except (json.JSONDecodeError, TypeError):
                    d[key] = {}
        return d
