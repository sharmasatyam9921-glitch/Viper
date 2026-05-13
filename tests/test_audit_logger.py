"""Tests for core/audit_logger.py — dual-sink (JSONL + SQLite) audit trail.

Covers:
  - basic event write/read roundtrip
  - JSONL append-only behavior
  - SQLite mirror correctness
  - concurrent writers (multiple workers)
  - DB-failure tolerance (JSONL still works)
  - JSONL-failure tolerance (DB still works)
  - replay (read_jsonl reconstructs state)
  - query API with filters
  - summary stats
  - hunt id slug generation
  - list_hunts discovery
"""

from __future__ import annotations

import asyncio
import json
import sqlite3
import sys
import threading
import time
from pathlib import Path
from unittest.mock import patch

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.audit_logger import (  # noqa: E402
    EVENT_TYPES,
    AuditEvent,
    AuditLogger,
    make_hunt_id,
)


# ---------------------------------------------------------------------------
# hunt id slug
# ---------------------------------------------------------------------------


class TestMakeHuntId:
    def test_basic_slug(self):
        hid = make_hunt_id("example.com", ts=1700000000)
        assert hid == "example.com_1700000000"

    def test_url_with_port_and_path(self):
        hid = make_hunt_id("http://example.com:8080/path", ts=1700000000)
        assert "example.com_8080" in hid
        assert hid.endswith("_1700000000")
        assert "/" not in hid and ":" not in hid

    def test_strips_leading_trailing_underscores(self):
        hid = make_hunt_id("///bad///target///", ts=1)
        assert not hid.startswith("_")

    def test_long_target_is_truncated(self):
        long_target = "a" * 500
        hid = make_hunt_id(long_target, ts=1)
        # 80-char slug cap + "_1"
        assert len(hid) <= 82 + 2

    def test_uses_current_time_when_unspecified(self):
        before = time.time()
        hid = make_hunt_id("x")
        after = time.time()
        ts_str = hid.rsplit("_", 1)[-1]
        ts = int(ts_str)
        assert before - 1 <= ts <= after + 1


# ---------------------------------------------------------------------------
# Basic write/read roundtrip
# ---------------------------------------------------------------------------


class TestEventRoundtrip:
    def test_write_one_event_creates_jsonl(self, tmp_path):
        log = AuditLogger.for_hunt(
            "target.example",
            hunts_dir=tmp_path / "hunts",
            db_path=tmp_path / "v.db",
        )
        log.event("hunt.started", payload={"profile": "scout"})
        log.close()
        # File exists with exactly one line
        assert log.jsonl_path.exists()
        lines = log.jsonl_path.read_text(encoding="utf-8").strip().splitlines()
        assert len(lines) == 1
        rec = json.loads(lines[0])
        assert rec["action"] == "hunt.started"
        assert rec["payload"]["profile"] == "scout"
        assert "ts" in rec and "event_id" in rec

    def test_read_jsonl_returns_events(self, tmp_path):
        log = AuditLogger.for_hunt(
            "t", hunts_dir=tmp_path / "hunts", db_path=tmp_path / "v.db"
        )
        log.event("worker.dispatched", actor="recon_w1", phase="recon")
        log.event(
            "finding.published", phase="recon", severity="high", findings_count=1
        )
        log.close()
        events = log.read_jsonl()
        assert len(events) == 2
        assert events[0].action == "worker.dispatched"
        assert events[0].actor == "recon_w1"
        assert events[1].severity == "high"

    def test_query_db_matches_jsonl(self, tmp_path):
        log = AuditLogger.for_hunt(
            "t", hunts_dir=tmp_path / "hunts", db_path=tmp_path / "v.db"
        )
        log.event("phase.started", phase="recon")
        log.event("phase.completed", phase="recon", duration_ms=1234)
        rows = log.query()
        log.close()
        assert len(rows) == 2
        actions = [r["action"] for r in rows]
        assert actions == ["phase.started", "phase.completed"]
        assert rows[1]["duration_ms"] == 1234


# ---------------------------------------------------------------------------
# JSONL append-only behavior
# ---------------------------------------------------------------------------


class TestJsonlAppendOnly:
    def test_multiple_writes_only_append(self, tmp_path):
        log = AuditLogger.for_hunt(
            "t", hunts_dir=tmp_path / "hunts", db_path=tmp_path / "v.db"
        )
        log.event("phase.started", phase="recon")
        log.event("phase.completed", phase="recon")
        log.event("phase.started", phase="vuln")
        log.close()
        lines = log.jsonl_path.read_text(encoding="utf-8").splitlines()
        assert len(lines) == 3
        # Each line is independently valid JSON
        for line in lines:
            json.loads(line)

    def test_existing_file_is_preserved_on_new_logger(self, tmp_path):
        hd = tmp_path / "hunts"
        log1 = AuditLogger.for_hunt("t", hunts_dir=hd, db_path=tmp_path / "v.db", ts=100)
        log1.event("phase.started", phase="recon")
        log1.close()
        # New logger for same hunt_id (same target+ts) appends to same JSONL
        log2 = AuditLogger.for_hunt("t", hunts_dir=hd, db_path=tmp_path / "v.db", ts=100)
        log2.event("phase.completed", phase="recon")
        log2.close()
        lines = log2.jsonl_path.read_text(encoding="utf-8").splitlines()
        assert len(lines) == 2


# ---------------------------------------------------------------------------
# Concurrent writers
# ---------------------------------------------------------------------------


class TestConcurrentWriters:
    def test_many_threads_write_safely(self, tmp_path):
        log = AuditLogger.for_hunt(
            "t", hunts_dir=tmp_path / "hunts", db_path=tmp_path / "v.db"
        )
        N = 200

        def writer(i: int) -> None:
            log.event("worker.dispatched", actor=f"w{i}", phase="recon")

        threads = [threading.Thread(target=writer, args=(i,)) for i in range(N)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        log.close()
        events = log.read_jsonl()
        assert len(events) == N
        # All event_ids unique
        assert len({e.event_id for e in events}) == N

    def test_async_aevent_does_not_block_loop(self, tmp_path):
        log = AuditLogger.for_hunt(
            "t", hunts_dir=tmp_path / "hunts", db_path=tmp_path / "v.db"
        )

        async def run() -> None:
            await asyncio.gather(*(
                log.aevent("worker.dispatched", actor=f"w{i}") for i in range(50)
            ))

        asyncio.run(run())
        log.close()
        events = log.read_jsonl()
        assert len(events) == 50

    def test_shared_db_across_loggers_serializes(self, tmp_path):
        """Two AuditLoggers writing to the same db_path use a shared lock."""
        db = tmp_path / "shared.db"
        log_a = AuditLogger.for_hunt("a", hunts_dir=tmp_path / "hunts", db_path=db, ts=1)
        log_b = AuditLogger.for_hunt("b", hunts_dir=tmp_path / "hunts", db_path=db, ts=1)

        def w(log: AuditLogger, prefix: str) -> None:
            for i in range(50):
                log.event("worker.dispatched", actor=f"{prefix}{i}")

        t1 = threading.Thread(target=w, args=(log_a, "A"))
        t2 = threading.Thread(target=w, args=(log_b, "B"))
        t1.start(); t2.start(); t1.join(); t2.join()
        log_a.close(); log_b.close()

        # Read via fresh connection — both hunts present
        con = sqlite3.connect(str(db))
        rows = con.execute(
            "SELECT hunt_id, COUNT(*) FROM audit_log GROUP BY hunt_id"
        ).fetchall()
        con.close()
        counts = dict(rows)
        assert counts[log_a.hunt_id] == 50
        assert counts[log_b.hunt_id] == 50


# ---------------------------------------------------------------------------
# Failure tolerance
# ---------------------------------------------------------------------------


class TestFailureTolerance:
    def test_db_failure_doesnt_block_jsonl(self, tmp_path):
        log = AuditLogger.for_hunt(
            "t", hunts_dir=tmp_path / "hunts", db_path=tmp_path / "v.db"
        )
        # Force DB writes to fail
        with patch.object(log, "_db", new=None):
            # Without a DB connection, _write_db short-circuits — JSONL still writes.
            log.event("phase.started", phase="recon")
        log.close()
        events = log.read_jsonl()
        assert len(events) == 1

    def test_jsonl_failure_doesnt_crash(self, tmp_path):
        log = AuditLogger.for_hunt(
            "t", hunts_dir=tmp_path / "hunts", db_path=tmp_path / "v.db"
        )
        with patch("pathlib.Path.open", side_effect=OSError("disk full")):
            # Must not raise
            log.event("phase.started", phase="recon")
        log.close()

    def test_unserializable_payload_falls_back(self, tmp_path):
        log = AuditLogger.for_hunt(
            "t", hunts_dir=tmp_path / "hunts", db_path=tmp_path / "v.db"
        )

        class Weird:
            def __repr__(self):  # noqa: D401
                return "weird"

        # Not JSON-serializable natively
        log.event("phase.started", payload={"weird": Weird()})
        log.close()
        events = log.read_jsonl()
        assert len(events) == 1
        # Fallback stringified the payload — either the dict-as-string or the
        # default=str fallback recorded `weird` somewhere.
        rendered = json.dumps(events[0].payload, default=str)
        assert "weird" in rendered


# ---------------------------------------------------------------------------
# Query API with filters
# ---------------------------------------------------------------------------


class TestQueryAPI:
    def test_filter_by_action(self, tmp_path):
        log = AuditLogger.for_hunt(
            "t", hunts_dir=tmp_path / "hunts", db_path=tmp_path / "v.db"
        )
        log.event("phase.started", phase="recon")
        log.event("worker.dispatched", phase="recon", actor="w1")
        log.event("phase.completed", phase="recon")
        rows = log.query(action="worker.dispatched")
        log.close()
        assert len(rows) == 1
        assert rows[0]["actor"] == "w1"

    def test_filter_by_since(self, tmp_path):
        log = AuditLogger.for_hunt(
            "t", hunts_dir=tmp_path / "hunts", db_path=tmp_path / "v.db"
        )
        log.event("phase.started", phase="recon")
        mid = time.time()
        time.sleep(0.01)
        log.event("phase.completed", phase="recon")
        rows = log.query(since=mid)
        log.close()
        assert len(rows) == 1
        assert rows[0]["action"] == "phase.completed"

    def test_query_includes_parsed_payload(self, tmp_path):
        log = AuditLogger.for_hunt(
            "t", hunts_dir=tmp_path / "hunts", db_path=tmp_path / "v.db"
        )
        log.event("approval.requested", payload={"action": "secretsdump", "risk": "high"})
        rows = log.query(action="approval.requested")
        log.close()
        assert rows[0]["payload"]["risk"] == "high"


# ---------------------------------------------------------------------------
# Summary stats
# ---------------------------------------------------------------------------


class TestSummary:
    def test_summary_counts(self, tmp_path):
        log = AuditLogger.for_hunt(
            "t", hunts_dir=tmp_path / "hunts", db_path=tmp_path / "v.db"
        )
        log.event("phase.started", phase="recon")
        log.event("worker.dispatched", actor="w1", phase="recon")
        log.event("worker.dispatched", actor="w1", phase="recon")
        log.event("worker.dispatched", actor="w2", phase="recon")
        log.event("finding.published", severity="high")
        log.event("finding.published", severity="medium")
        log.close()
        s = log.summary()
        assert s["event_count"] == 6
        assert s["by_action"]["worker.dispatched"] == 3
        assert s["by_actor"]["w1"] == 2
        assert s["by_severity"]["high"] == 1


# ---------------------------------------------------------------------------
# list_hunts discovery
# ---------------------------------------------------------------------------


class TestListHunts:
    def test_list_hunts_finds_dirs(self, tmp_path):
        hd = tmp_path / "hunts"
        log1 = AuditLogger.for_hunt("a", hunts_dir=hd, db_path=tmp_path / "v.db", ts=100)
        log1.event("phase.started")
        log1.close()
        log2 = AuditLogger.for_hunt("b", hunts_dir=hd, db_path=tmp_path / "v.db", ts=200)
        log2.event("phase.started")
        log2.close()
        hunts = AuditLogger.list_hunts(hd)
        assert "a_100" in hunts
        assert "b_200" in hunts

    def test_list_hunts_skips_dirs_without_audit_jsonl(self, tmp_path):
        hd = tmp_path / "hunts"
        # Real hunt
        log = AuditLogger.for_hunt("real", hunts_dir=hd, db_path=tmp_path / "v.db", ts=1)
        log.event("x")
        log.close()
        # Empty dir
        (hd / "empty_2").mkdir()
        hunts = AuditLogger.list_hunts(hd)
        assert "real_1" in hunts
        assert "empty_2" not in hunts

    def test_list_hunts_returns_empty_when_no_dir(self, tmp_path):
        assert AuditLogger.list_hunts(tmp_path / "nonexistent") == []


# ---------------------------------------------------------------------------
# Bulk insert (used by --resume)
# ---------------------------------------------------------------------------


class TestBulkInsert:
    def test_bulk_writes_to_both_sinks(self, tmp_path):
        log = AuditLogger.for_hunt(
            "t", hunts_dir=tmp_path / "hunts", db_path=tmp_path / "v.db"
        )
        events = [
            AuditEvent(ts=1.0, action="phase.started", hunt_id=log.hunt_id, phase="recon"),
            AuditEvent(ts=2.0, action="worker.dispatched", hunt_id=log.hunt_id, actor="w1"),
            AuditEvent(ts=3.0, action="phase.completed", hunt_id=log.hunt_id, phase="recon"),
        ]
        log.bulk(events)
        log.close()
        jsonl = log.read_jsonl()
        assert len(jsonl) == 3
        rows = AuditLogger.for_hunt(
            "t", hunts_dir=tmp_path / "hunts", db_path=tmp_path / "v.db",
            ts=int(log.hunt_id.rsplit("_", 1)[-1]),
        ).query()
        # Bulk inserted plus possibly the new logger's own events (none yet)
        actions = {r["action"] for r in rows}
        assert {"phase.started", "worker.dispatched", "phase.completed"}.issubset(actions)


# ---------------------------------------------------------------------------
# Closed-logger guard
# ---------------------------------------------------------------------------


class TestClosedGuard:
    def test_event_after_close_raises(self, tmp_path):
        log = AuditLogger.for_hunt(
            "t", hunts_dir=tmp_path / "hunts", db_path=tmp_path / "v.db"
        )
        log.event("phase.started")
        log.close()
        with pytest.raises(RuntimeError, match="closed"):
            log.event("phase.completed")

    def test_double_close_is_idempotent(self, tmp_path):
        log = AuditLogger.for_hunt(
            "t", hunts_dir=tmp_path / "hunts", db_path=tmp_path / "v.db"
        )
        log.close()
        log.close()  # must not raise

    def test_context_manager_closes(self, tmp_path):
        with AuditLogger.for_hunt(
            "t", hunts_dir=tmp_path / "hunts", db_path=tmp_path / "v.db"
        ) as log:
            log.event("phase.started")
        # After context exit, must be closed
        with pytest.raises(RuntimeError):
            log.event("phase.completed")


# ---------------------------------------------------------------------------
# Event schema
# ---------------------------------------------------------------------------


class TestEventSchema:
    def test_canonical_event_types_defined(self):
        # Spot-check a few that the plan refers to
        assert "worker.dispatched" in EVENT_TYPES
        assert "finding.published" in EVENT_TYPES
        assert "stop_condition.met" in EVENT_TYPES
        assert "approval.requested" in EVENT_TYPES

    def test_to_dict_omits_empty_strings(self):
        ev = AuditEvent(ts=1.0, action="phase.started")
        d = ev.to_dict()
        # Empty fields should be stripped for compactness
        assert "phase" not in d  # was empty
        assert "actor" not in d  # was empty
        assert d["action"] == "phase.started"

    def test_to_dict_omits_none_duration(self):
        ev = AuditEvent(ts=1.0, action="x", duration_ms=None)
        d = ev.to_dict()
        assert "duration_ms" not in d
