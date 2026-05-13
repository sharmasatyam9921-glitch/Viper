"""Tests for the Phase 4 dashboard /api/hack/* endpoints.

These read from a tmp SQLite DB populated via AuditLogger, then exercise
the three helper functions that the dashboard's HTTP handler calls:

  _hack_list_hunts(db_path, limit) → {hunts: [...]}
  _hack_hunt_snapshot(db_path, hunt_id) → phases + workers + findings
  _hack_audit_query(db_path, hunt_id, since, action, limit) → events

Calling the helpers directly (no live HTTP) keeps these tests fast +
deterministic and doesn't require the dashboard process to be running.
"""

from __future__ import annotations

import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.audit_logger import AuditLogger  # noqa: E402
from dashboard.server import (  # noqa: E402
    _hack_audit_query,
    _hack_hunt_snapshot,
    _hack_list_hunts,
)


# ---------------------------------------------------------------------------
# fixture: build a hunt with realistic event shape
# ---------------------------------------------------------------------------


def _populate(db_path: Path, hunts_dir: Path, target: str = "example.com",
              ts_base: float = 1_700_000_000.0) -> str:
    """Create one hunt with phases + workers + findings."""
    log = AuditLogger.for_hunt(
        target, hunts_dir=hunts_dir, db_path=db_path, ts=ts_base,
    )
    hid = log.hunt_id
    log.event("hunt.started", target=target,
              payload={"profile": "lab"})
    log.event("loop.iteration", target=target, payload={"iteration": 1})
    # Recon phase
    log.event("phase.started", phase="recon", target=target)
    log.event("worker.dispatched", actor="recon_w1", phase="recon",
              target=target, payload={"technique": "subdomain"})
    log.event("worker.dispatched", actor="recon_w2", phase="recon",
              target=target, payload={"technique": "port_scan"})
    log.event("finding.published", phase="recon", target=target,
              severity="info",
              payload={"title": "api.example.com", "technique": "subdomain"})
    log.event("finding.published", phase="recon", target=target,
              severity="info",
              payload={"title": "80/tcp", "technique": "port_scan"})
    log.event("worker.completed", actor="recon_w1", phase="recon",
              target=target, duration_ms=42, outcome="success",
              findings_count=1, payload={"technique": "subdomain"})
    log.event("worker.completed", actor="recon_w2", phase="recon",
              target=target, duration_ms=88, outcome="success",
              findings_count=1, payload={"technique": "port_scan"})
    log.event("phase.completed", phase="recon", target=target,
              payload={"workers_completed": 2})
    # Vuln phase
    log.event("phase.started", phase="vuln", target=target)
    log.event("worker.dispatched", actor="vuln_w1", phase="vuln",
              target=target, payload={"technique": "sqli_probe"})
    log.event("finding.published", phase="vuln", target=target,
              severity="high",
              payload={"title": "SQLi candidate", "technique": "sqli_probe"})
    log.event("worker.failed", actor="vuln_w1", phase="vuln",
              target=target, duration_ms=120, outcome="failure")
    log.event("phase.completed", phase="vuln", target=target)
    log.event("hunt.completed", target=target, outcome="success",
              findings_count=3)
    log.close()
    return hid


# ---------------------------------------------------------------------------
# _hack_list_hunts
# ---------------------------------------------------------------------------


class TestListHunts:
    def test_returns_empty_when_db_missing(self, tmp_path):
        result = _hack_list_hunts(str(tmp_path / "nonexistent.db"), 50)
        assert result == {"hunts": []}

    def test_returns_empty_when_no_audit_table(self, tmp_path):
        import sqlite3
        db = tmp_path / "empty.db"
        sqlite3.connect(str(db)).close()  # touch
        result = _hack_list_hunts(str(db), 50)
        assert result == {"hunts": []}

    def test_returns_one_hunt(self, tmp_path):
        db = tmp_path / "v.db"
        hd = tmp_path / "hunts"
        hid = _populate(db, hd)
        result = _hack_list_hunts(str(db), 50)
        hunts = result["hunts"]
        assert len(hunts) == 1
        h = hunts[0]
        assert h["hunt_id"] == hid
        assert h["event_count"] >= 12
        # 3 findings published in the fixture
        assert h["finding_count"] == 3
        assert h["target"] == "example.com"
        # started_at <= last_event_at
        assert h["started_at"] <= h["last_event_at"]

    def test_orders_by_most_recent_first(self, tmp_path):
        db = tmp_path / "v.db"
        hd = tmp_path / "hunts"
        _populate(db, hd, target="older.com", ts_base=1_700_000_000.0)
        _populate(db, hd, target="newer.com", ts_base=1_700_000_500.0)
        result = _hack_list_hunts(str(db), 50)
        # Most recent first
        assert result["hunts"][0]["target"] == "newer.com"
        assert result["hunts"][1]["target"] == "older.com"

    def test_respects_limit(self, tmp_path):
        db = tmp_path / "v.db"
        hd = tmp_path / "hunts"
        for i in range(5):
            _populate(db, hd, target=f"t{i}.com",
                       ts_base=1_700_000_000.0 + i * 100)
        result = _hack_list_hunts(str(db), 3)
        assert len(result["hunts"]) == 3


# ---------------------------------------------------------------------------
# _hack_hunt_snapshot
# ---------------------------------------------------------------------------


class TestHuntSnapshot:
    def test_missing_db_returns_not_found(self, tmp_path):
        result = _hack_hunt_snapshot(str(tmp_path / "nope.db"), "fake")
        assert result == {"hunt_id": "fake", "found": False}

    def test_missing_hunt_id_empty_payload(self, tmp_path):
        db = tmp_path / "v.db"
        hd = tmp_path / "hunts"
        _populate(db, hd)
        result = _hack_hunt_snapshot(str(db), "totally_unknown_hunt")
        # found=True since DB exists, but phases/workers/findings are empty
        assert result["found"] is True
        assert result["phases"] == []
        assert result["workers"] == []
        assert result["findings"] == []

    def test_full_snapshot_shape(self, tmp_path):
        db = tmp_path / "v.db"
        hd = tmp_path / "hunts"
        hid = _populate(db, hd)
        result = _hack_hunt_snapshot(str(db), hid)
        assert result["found"] is True
        # Two phases recorded (recon + vuln)
        phases = result["phases"]
        phase_names = {p["phase"] for p in phases}
        assert phase_names == {"recon", "vuln"}
        # Worker counts per phase
        recon = next(p for p in phases if p["phase"] == "recon")
        assert recon["workers_dispatched"] == 2
        assert recon["workers_completed"] == 2
        assert recon["findings_count"] == 2
        vuln = next(p for p in phases if p["phase"] == "vuln")
        assert vuln["workers_failed"] == 1
        assert vuln["findings_count"] == 1
        # Workers list
        worker_ids = {w["worker_id"] for w in result["workers"]}
        assert worker_ids == {"recon_w1", "recon_w2", "vuln_w1"}
        # Findings list — 3 total, payloads parsed
        assert len(result["findings"]) == 3
        for f in result["findings"]:
            assert "payload" in f
            assert isinstance(f["payload"], dict)
        # Severity preserved
        severities = [f["severity"] for f in result["findings"]]
        assert "high" in severities  # vuln finding
        assert severities.count("info") == 2  # recon findings


# ---------------------------------------------------------------------------
# _hack_audit_query
# ---------------------------------------------------------------------------


class TestAuditQuery:
    def test_missing_db_returns_empty(self, tmp_path):
        result = _hack_audit_query(
            str(tmp_path / "nope.db"), "fake",
            since=0, action="", limit=100,
        )
        assert result == {"hunt_id": "fake", "events": []}

    def test_returns_all_events_for_hunt(self, tmp_path):
        db = tmp_path / "v.db"
        hd = tmp_path / "hunts"
        hid = _populate(db, hd)
        result = _hack_audit_query(
            str(db), hid, since=0, action="", limit=1000,
        )
        # All 13 events seeded
        assert result["count"] >= 13
        assert all(e["hunt_id"] == hid for e in result["events"])
        # Events ordered by timestamp
        timestamps = [e["ts"] for e in result["events"]]
        assert timestamps == sorted(timestamps)

    def test_filter_by_action(self, tmp_path):
        db = tmp_path / "v.db"
        hd = tmp_path / "hunts"
        hid = _populate(db, hd)
        result = _hack_audit_query(
            str(db), hid, since=0, action="finding.published", limit=100,
        )
        # Exactly 3 finding events
        assert result["count"] == 3
        assert all(e["action"] == "finding.published" for e in result["events"])
        # Payloads parsed from JSON
        assert all("payload" in e for e in result["events"])

    def test_since_filter(self, tmp_path):
        db = tmp_path / "v.db"
        hd = tmp_path / "hunts"
        hid = _populate(db, hd)
        # Pick a mid-stream timestamp
        full = _hack_audit_query(str(db), hid, since=0, action="", limit=1000)
        mid_ts = full["events"][5]["ts"]
        partial = _hack_audit_query(
            str(db), hid, since=mid_ts, action="", limit=1000,
        )
        # All returned events have ts >= mid_ts
        assert all(e["ts"] >= mid_ts for e in partial["events"])
        # Total count is less than full
        assert partial["count"] < full["count"]

    def test_respects_limit(self, tmp_path):
        db = tmp_path / "v.db"
        hd = tmp_path / "hunts"
        hid = _populate(db, hd)
        result = _hack_audit_query(
            str(db), hid, since=0, action="", limit=2,
        )
        assert result["count"] == 2

    def test_isolates_hunts(self, tmp_path):
        db = tmp_path / "v.db"
        hd = tmp_path / "hunts"
        hid_a = _populate(db, hd, target="a.com", ts_base=1_700_000_000)
        hid_b = _populate(db, hd, target="b.com", ts_base=1_700_001_000)
        result = _hack_audit_query(str(db), hid_a, since=0, action="",
                                     limit=1000)
        # Only hunt_a events
        assert all(e["hunt_id"] == hid_a for e in result["events"])
        # And not empty
        assert result["count"] > 0
