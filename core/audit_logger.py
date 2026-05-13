"""Step-by-step audit trail for autonomous hack runs.

Every worker dispatch, finding publish, decision, approval, scope check,
and LLM call is written to two places:
  1. `state/hunts/<target>_<ts>/audit.jsonl` — newline-delimited JSON,
     append-only. Survives crashes. Easy to grep / replay.
  2. `audit_log` SQLite table in `data/viper.db` — same data,
     queryable from the dashboard via `GET /api/audit?since=...`.

Both writes are best-effort: a SQLite failure does NOT block JSONL, and
vice versa. The JSONL file is the source of truth for `--resume`.

Thread/async-safety:
- All public methods are sync (call from any context).
- Internally guarded by a Lock; writes serialized.
- For high-throughput async callers, prefer `aevent()` (awaitable shim
  that hands off to `asyncio.to_thread`).
"""

from __future__ import annotations

import asyncio
import json
import re
import sqlite3
import threading
import time
import uuid
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Iterable, Optional, Union


# ----- Event schema ---------------------------------------------------------

# Canonical event types. Any string is allowed but using this set keeps
# the dashboard's filter UI tidy.
EVENT_TYPES = (
    "hunt.started",
    "hunt.completed",
    "phase.started",
    "phase.completed",
    "loop.iteration",
    "stop_condition.met",
    "worker.dispatched",
    "worker.completed",
    "worker.failed",
    "finding.published",
    "finding.deduped",
    "scope.checked",
    "approval.requested",
    "approval.granted",
    "approval.denied",
    "llm.called",
    "error",
)


@dataclass
class AuditEvent:
    """One row of the audit log. All fields optional except ts + action."""
    ts: float                         # seconds since epoch (float so sub-ms ordering is preserved)
    action: str                       # one of EVENT_TYPES (free-form allowed; validate at write)
    hunt_id: str = ""                 # `<target>_<unix_ts>` slug
    phase: str = ""                   # recon / vuln / exploit / post / report
    actor: str = ""                   # worker_id or coordinator_id
    target: str = ""                  # asset URL / IP / hostname
    duration_ms: Optional[int] = None
    outcome: str = ""                 # success / failure / partial / skipped / blocked
    findings_count: int = 0
    severity: str = ""                # for finding events
    payload: dict = field(default_factory=dict)  # free-form details
    event_id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        if d["duration_ms"] is None:
            del d["duration_ms"]
        # Drop empty strings for compactness
        return {k: v for k, v in d.items() if v != "" and v != {}}


# ----- Helpers --------------------------------------------------------------


_SLUG_RE = re.compile(r"[^a-zA-Z0-9._-]+")


def make_hunt_id(target: str, ts: Optional[float] = None) -> str:
    """Build a hunt_id slug from a target + timestamp.

    >>> make_hunt_id("http://example.com:8080/path", ts=1700000000)
    'http___example.com_8080_path_1700000000'
    """
    ts = ts if ts is not None else time.time()
    slug = _SLUG_RE.sub("_", target).strip("_")
    return f"{slug[:80]}_{int(ts)}"


# ----- AuditLogger ----------------------------------------------------------


class AuditLogger:
    """Dual-sink audit logger.

    Usage:
        log = AuditLogger.for_hunt(target="https://example.com")
        log.event("hunt.started", payload={"profile": "scout"})
        log.event("worker.dispatched", actor="subdomain_worker_3",
                  phase="recon", duration_ms=0, payload={"technique": "crt.sh"})
        ...
        log.event("hunt.completed", outcome="success")
        log.close()
    """

    # Class-level lock used when many AuditLoggers share one DB path.
    _db_locks: dict[str, threading.Lock] = {}

    def __init__(
        self,
        hunt_id: str,
        jsonl_path: Path,
        db_path: Optional[Path] = None,
    ) -> None:
        self.hunt_id = hunt_id
        self.jsonl_path = Path(jsonl_path)
        self.db_path = Path(db_path) if db_path else None
        self._jsonl_lock = threading.Lock()
        self._closed = False
        self._t0 = time.time()
        # Prepare parent dirs
        self.jsonl_path.parent.mkdir(parents=True, exist_ok=True)
        # Open SQLite if requested; the connection is per-logger, but a
        # shared lock per db_path serializes cross-logger writes.
        self._db: Optional[sqlite3.Connection] = None
        if self.db_path:
            self.db_path.parent.mkdir(parents=True, exist_ok=True)
            self._db_lock = AuditLogger._db_locks.setdefault(
                str(self.db_path), threading.Lock()
            )
            self._db = sqlite3.connect(
                str(self.db_path), check_same_thread=False, timeout=5.0,
            )
            self._ensure_schema()
        else:
            self._db_lock = threading.Lock()

    # ------------------------------------------------------------------
    # Constructors
    # ------------------------------------------------------------------

    @classmethod
    def for_hunt(
        cls,
        target: str,
        *,
        hunts_dir: Union[str, Path, None] = None,
        db_path: Union[str, Path, None] = None,
        ts: Optional[float] = None,
    ) -> "AuditLogger":
        """Build the default JSONL path + DB and instantiate."""
        ts = ts if ts is not None else time.time()
        hunt_id = make_hunt_id(target, ts=ts)
        hunts_dir = Path(hunts_dir or "state/hunts")
        jsonl = hunts_dir / hunt_id / "audit.jsonl"
        db = Path(db_path) if db_path else Path("data/viper.db")
        return cls(hunt_id=hunt_id, jsonl_path=jsonl, db_path=db)

    # ------------------------------------------------------------------
    # Schema
    # ------------------------------------------------------------------

    def _ensure_schema(self) -> None:
        assert self._db is not None
        with self._db_lock:
            self._db.executescript(
                """
                CREATE TABLE IF NOT EXISTS audit_log (
                    event_id     TEXT PRIMARY KEY,
                    hunt_id      TEXT NOT NULL,
                    ts           REAL NOT NULL,
                    action       TEXT NOT NULL,
                    phase        TEXT,
                    actor        TEXT,
                    target       TEXT,
                    duration_ms  INTEGER,
                    outcome      TEXT,
                    findings_count INTEGER DEFAULT 0,
                    severity     TEXT,
                    payload_json TEXT
                );
                CREATE INDEX IF NOT EXISTS idx_audit_hunt_ts
                    ON audit_log(hunt_id, ts);
                CREATE INDEX IF NOT EXISTS idx_audit_action
                    ON audit_log(action);
                """
            )
            self._db.commit()

    # ------------------------------------------------------------------
    # Public write API
    # ------------------------------------------------------------------

    def event(
        self,
        action: str,
        *,
        phase: str = "",
        actor: str = "",
        target: str = "",
        duration_ms: Optional[int] = None,
        outcome: str = "",
        findings_count: int = 0,
        severity: str = "",
        payload: Optional[dict] = None,
    ) -> AuditEvent:
        """Record one event. Returns the AuditEvent for caller reference."""
        if self._closed:
            raise RuntimeError("AuditLogger is closed")
        ev = AuditEvent(
            ts=time.time(),
            action=action,
            hunt_id=self.hunt_id,
            phase=phase,
            actor=actor,
            target=target,
            duration_ms=duration_ms,
            outcome=outcome,
            findings_count=findings_count,
            severity=severity,
            payload=payload or {},
        )
        self._write_jsonl(ev)
        self._write_db(ev)
        return ev

    async def aevent(self, action: str, **kw: Any) -> AuditEvent:
        """Async shim — offloads disk I/O to a thread."""
        return await asyncio.to_thread(self.event, action, **kw)

    def bulk(self, events: Iterable[AuditEvent]) -> None:
        """Bulk-insert pre-built events (used by `--resume`)."""
        events = list(events)
        for ev in events:
            self._write_jsonl(ev)
        if self._db:
            with self._db_lock:
                self._db.executemany(
                    "INSERT OR REPLACE INTO audit_log "
                    "(event_id, hunt_id, ts, action, phase, actor, target, "
                    " duration_ms, outcome, findings_count, severity, payload_json) "
                    "VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                    [
                        (
                            ev.event_id, ev.hunt_id, ev.ts, ev.action,
                            ev.phase, ev.actor, ev.target, ev.duration_ms,
                            ev.outcome, ev.findings_count, ev.severity,
                            json.dumps(ev.payload, default=str),
                        )
                        for ev in events
                    ],
                )
                self._db.commit()

    # ------------------------------------------------------------------
    # Read API
    # ------------------------------------------------------------------

    def read_jsonl(self) -> list[AuditEvent]:
        """Read entire JSONL file back as AuditEvent objects."""
        if not self.jsonl_path.exists():
            return []
        events: list[AuditEvent] = []
        with self.jsonl_path.open(encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    d = json.loads(line)
                except json.JSONDecodeError:
                    continue
                events.append(AuditEvent(
                    ts=d.get("ts", 0.0),
                    action=d.get("action", "unknown"),
                    hunt_id=d.get("hunt_id", ""),
                    phase=d.get("phase", ""),
                    actor=d.get("actor", ""),
                    target=d.get("target", ""),
                    duration_ms=d.get("duration_ms"),
                    outcome=d.get("outcome", ""),
                    findings_count=d.get("findings_count", 0),
                    severity=d.get("severity", ""),
                    payload=d.get("payload", {}),
                    event_id=d.get("event_id", uuid.uuid4().hex[:12]),
                ))
        return events

    def query(self, *, since: float = 0.0, action: str = "", limit: int = 1000) -> list[dict]:
        """Read from the SQLite mirror. Used by the dashboard."""
        if not self._db:
            return []
        sql = "SELECT * FROM audit_log WHERE hunt_id = ? AND ts >= ?"
        args: list[Any] = [self.hunt_id, since]
        if action:
            sql += " AND action = ?"
            args.append(action)
        sql += " ORDER BY ts ASC LIMIT ?"
        args.append(limit)
        with self._db_lock:
            cur = self._db.execute(sql, args)
            cols = [c[0] for c in cur.description]
            rows = [dict(zip(cols, r)) for r in cur.fetchall()]
        for r in rows:
            if r.get("payload_json"):
                try:
                    r["payload"] = json.loads(r.pop("payload_json"))
                except Exception:
                    r["payload"] = {}
        return rows

    @staticmethod
    def list_hunts(hunts_dir: Union[str, Path] = "state/hunts") -> list[str]:
        """Enumerate hunt_ids on disk (used by --resume)."""
        p = Path(hunts_dir)
        if not p.exists():
            return []
        return sorted(d.name for d in p.iterdir() if d.is_dir() and (d / "audit.jsonl").exists())

    # ------------------------------------------------------------------
    # Stats helpers
    # ------------------------------------------------------------------

    def summary(self) -> dict[str, Any]:
        """Quick stats for terminal/UI: counts per action, top actors."""
        events = self.read_jsonl()
        by_action: dict[str, int] = {}
        by_actor: dict[str, int] = {}
        by_severity: dict[str, int] = {}
        for e in events:
            by_action[e.action] = by_action.get(e.action, 0) + 1
            if e.actor:
                by_actor[e.actor] = by_actor.get(e.actor, 0) + 1
            if e.severity:
                by_severity[e.severity] = by_severity.get(e.severity, 0) + 1
        elapsed = (events[-1].ts - events[0].ts) if events else 0.0
        return {
            "hunt_id": self.hunt_id,
            "event_count": len(events),
            "elapsed_s": elapsed,
            "by_action": by_action,
            "by_actor": dict(sorted(by_actor.items(), key=lambda kv: -kv[1])[:10]),
            "by_severity": by_severity,
        }

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        if self._db:
            with self._db_lock:
                try:
                    self._db.commit()
                    self._db.close()
                except Exception:
                    pass
            self._db = None

    def __enter__(self) -> "AuditLogger":
        return self

    def __exit__(self, *_: Any) -> None:
        self.close()

    # ------------------------------------------------------------------
    # Internal writers (best-effort, never raise)
    # ------------------------------------------------------------------

    def _write_jsonl(self, ev: AuditEvent) -> None:
        try:
            line = json.dumps(ev.to_dict(), default=str, separators=(",", ":"))
        except (TypeError, ValueError):
            # Last-resort: stringify everything that's not JSON-serializable
            line = json.dumps(
                {k: str(v) for k, v in ev.to_dict().items()},
                separators=(",", ":"),
            )
        with self._jsonl_lock:
            try:
                with self.jsonl_path.open("a", encoding="utf-8") as f:
                    f.write(line + "\n")
            except OSError:
                pass  # disk full / permission denied — don't crash the hunt

    def _write_db(self, ev: AuditEvent) -> None:
        if not self._db:
            return
        try:
            with self._db_lock:
                self._db.execute(
                    "INSERT OR REPLACE INTO audit_log "
                    "(event_id, hunt_id, ts, action, phase, actor, target, "
                    " duration_ms, outcome, findings_count, severity, payload_json) "
                    "VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                    (
                        ev.event_id, ev.hunt_id, ev.ts, ev.action,
                        ev.phase, ev.actor, ev.target, ev.duration_ms,
                        ev.outcome, ev.findings_count, ev.severity,
                        json.dumps(ev.payload, default=str),
                    ),
                )
                self._db.commit()
        except sqlite3.Error:
            pass  # JSONL is source of truth; DB is just a cache
