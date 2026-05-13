"""Tests for core/narrator.py — novice-friendly progress printer."""

from __future__ import annotations

import io
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.narrator import (  # noqa: E402
    Narrator,
    StageProgress,
    _ASCII_FALLBACK,
    _stream_supports_unicode,
)


# ---------------------------------------------------------------------------
# Stream encoding detection
# ---------------------------------------------------------------------------


class TestStreamEncodingDetect:
    @pytest.mark.parametrize("enc,expected", [
        ("utf-8", True),
        ("UTF-8", True),
        ("utf8", True),
        ("cp1252", False),
        ("CP1252", False),
        ("cp437", False),
        ("ascii", False),
        ("us-ascii", False),
        ("windows-1252", False),
        ("", True),       # empty means "we don't know" — assume unicode OK
        (None, True),
    ])
    def test_supports_unicode_known_encodings(self, enc, expected):
        class _Stream:
            encoding = enc
        assert _stream_supports_unicode(_Stream()) is expected


# ---------------------------------------------------------------------------
# Basic output
# ---------------------------------------------------------------------------


def _make_narrator(**kw):
    """Build a narrator writing into a fresh StringIO (no real stdout)."""
    buf = io.StringIO()
    n = Narrator(stream=buf, use_color=False, ascii_only=True, **kw)
    return n, buf


class TestBasicOutput:
    def test_banner_includes_target(self):
        n, buf = _make_narrator()
        n.banner("https://example.com")
        out = buf.getvalue()
        assert "https://example.com" in out
        assert "VIPER" in out
        assert "REMINDER" in out

    def test_stage_creates_stage_progress(self):
        n, buf = _make_narrator()
        sp = n.stage("RECON", current=1, total=2)
        assert isinstance(sp, StageProgress)
        assert sp.name == "RECON"
        assert sp.index == 1
        assert sp.total == 2
        assert sp.status == "running"

    def test_finish_stage_marks_success(self):
        n, _ = _make_narrator()
        n.stage("RECON", current=1, total=2)
        n.finish_stage("success")
        assert n.stages[0].status == "success"
        assert n.stages[0].finished_at is not None

    def test_stage_implicitly_finishes_previous(self):
        n, _ = _make_narrator()
        n.stage("RECON", current=1, total=3)
        n.stage("VULN", current=2, total=3)
        assert n.stages[0].status == "success"
        assert n.stages[1].status == "running"

    def test_step_appears_in_output(self):
        n, buf = _make_narrator()
        n.stage("RECON", current=1, total=1)
        n.step("running subfinder")
        assert "running subfinder" in buf.getvalue()

    def test_found_records_in_stage(self):
        n, _ = _make_narrator()
        n.stage("RECON", current=1, total=1)
        n.found("42 subdomains", severity="info")
        n.found("SQLi candidate", severity="high")
        assert len(n.stages[0].findings) == 2
        # Each finding tagged with severity prefix
        assert n.stages[0].findings[0].startswith("[info]")
        assert n.stages[0].findings[1].startswith("[high]")

    def test_quiet_suppresses_output(self):
        buf = io.StringIO()
        n = Narrator(stream=buf, use_color=False, quiet=True, ascii_only=True)
        n.banner("x")
        n.stage("RECON", current=1, total=1)
        n.found("nothing", severity="info")
        assert buf.getvalue() == ""

    def test_warn_fail_info_methods(self):
        n, buf = _make_narrator()
        n.warn("api key missing")
        n.fail("subfinder not installed")
        n.info("rate limited")
        out = buf.getvalue()
        assert "api key missing" in out
        assert "subfinder not installed" in out
        assert "rate limited" in out


# ---------------------------------------------------------------------------
# ASCII fallback
# ---------------------------------------------------------------------------


class TestAsciiFallback:
    def test_ascii_only_translates_box_chars(self):
        n, buf = _make_narrator()
        n.banner("x")
        out = buf.getvalue()
        # The Unicode '═' is replaced with '='
        assert "═" not in out
        assert "=" in out  # plenty of "=" in the bar

    def test_ascii_only_translates_checkmark(self):
        n, buf = _make_narrator()
        n.stage("R", current=1, total=1)
        n.found("X", severity="info")
        out = buf.getvalue()
        assert "✓" not in out
        assert "OK" in out

    def test_unicode_passthrough_on_utf8_stream(self):
        """When ascii_only=False, the original Unicode survives."""
        buf = io.StringIO()
        n = Narrator(stream=buf, use_color=False, ascii_only=False)
        n.banner("x")
        out = buf.getvalue()
        assert "═" in out  # box-drawing char preserved

    def test_translates_em_dash_and_others(self):
        # Confirm a few less-common fallbacks
        n, buf = _make_narrator()
        n._w("Hello — world")
        n._w("She said “hi”")
        out = buf.getvalue()
        assert "—" not in out
        assert "“" not in out
        assert "--" in out
        assert '"hi"' in out


# ---------------------------------------------------------------------------
# Color
# ---------------------------------------------------------------------------


class TestColor:
    def test_use_color_false_strips_ansi(self):
        n, buf = _make_narrator()
        n._w("\x1b[31mred\x1b[0m text")
        out = buf.getvalue()
        assert "\x1b[" not in out
        assert "red text" in out

    def test_use_color_true_keeps_ansi(self):
        buf = io.StringIO()
        n = Narrator(stream=buf, use_color=True, ascii_only=True)
        n._w("\x1b[31mred\x1b[0m text")
        out = buf.getvalue()
        assert "\x1b[31m" in out


# ---------------------------------------------------------------------------
# Approval gate UX
# ---------------------------------------------------------------------------


class TestGateMessage:
    def test_gate_message_includes_flag(self):
        n, buf = _make_narrator()
        n.gate("secretsdump", required_flag="--go")
        out = buf.getvalue()
        assert "GATED" in out
        assert "secretsdump" in out
        assert "--go" in out


# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------


class TestSummary:
    def test_summary_includes_total_time(self):
        n, buf = _make_narrator()
        n.banner("x")
        n.stage("R", current=1, total=1)
        n.found("a", severity="info")
        n.summary()
        out = buf.getvalue()
        assert "SUMMARY" in out
        assert "Total time" in out
        assert "Per-stage" in out

    def test_summary_finishes_running_stage(self):
        n, _ = _make_narrator()
        n.stage("R", current=1, total=1)
        # don't manually finish — summary should close it
        n.summary()
        assert n.stages[0].status == "success"

    def test_summary_extra_kwargs(self):
        n, buf = _make_narrator()
        n.summary(report_path="reports/x.html", critical_count=3)
        out = buf.getvalue()
        assert "reports/x.html" in out
        assert "3" in out


# ---------------------------------------------------------------------------
# emit_finding shortcut
# ---------------------------------------------------------------------------


class TestEmitFinding:
    def test_emit_dict_with_title_and_severity(self):
        n, buf = _make_narrator()
        n.stage("R", current=1, total=1)
        n.emit_finding({"title": "Open Redirect", "severity": "medium",
                        "url": "https://example.com/r?u=evil.com"})
        out = buf.getvalue()
        assert "Open Redirect" in out
        assert "https://example.com/r?u=evil.com" in out
        assert n.stages[0].findings[0].startswith("[medium]")

    def test_emit_uses_type_when_no_title(self):
        n, buf = _make_narrator()
        n.stage("R", current=1, total=1)
        n.emit_finding({"type": "open_port", "severity": "info"})
        out = buf.getvalue()
        assert "open_port" in out


# ---------------------------------------------------------------------------
# Snapshot
# ---------------------------------------------------------------------------


class TestSnapshot:
    def test_snapshot_returns_serializable_dict(self):
        n, _ = _make_narrator()
        n.stage("RECON", current=1, total=2)
        n.found("x", severity="info")
        n.finish_stage("success")
        n.stage("VULN", current=2, total=2)
        n.found("y", severity="high")
        snap = n.snapshot()
        assert "stages" in snap
        assert "elapsed_s" in snap
        assert "started_at" in snap
        assert len(snap["stages"]) == 2
        # First stage finished
        assert snap["stages"][0]["status"] == "success"
        # Second stage still running
        assert snap["stages"][1]["status"] == "running"
        # Findings present
        assert snap["stages"][0]["finding_count"] == 1
        assert snap["stages"][1]["finding_count"] == 1

    def test_snapshot_is_pure_json(self):
        import json
        n, _ = _make_narrator()
        n.stage("R", current=1, total=1)
        n.found("x", severity="info")
        snap = n.snapshot()
        # Round-trip through JSON
        json.dumps(snap)


# ---------------------------------------------------------------------------
# StageProgress elapsed_s
# ---------------------------------------------------------------------------


class TestStageProgress:
    def test_elapsed_s_grows(self):
        sp = StageProgress(name="x", index=1, total=1)
        time.sleep(0.02)
        assert sp.elapsed_s >= 0.02
        # After finishing, elapsed_s freezes
        sp.finished_at = sp.started_at + 0.5
        assert abs(sp.elapsed_s - 0.5) < 1e-6
