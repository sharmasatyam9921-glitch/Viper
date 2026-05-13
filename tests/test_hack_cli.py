"""Tests for core/hack_cli.py — argparse + exit-code contract."""

from __future__ import annotations

import io
import json
import sys
import time
from pathlib import Path
from unittest.mock import patch

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.hack_cli import build_parser, run_hack_cli  # noqa: E402


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------


class TestBuildParser:
    def test_target_optional_for_resume(self):
        """`target` is now optional (so `--resume HUNT_ID` works without it).
        Required-target check moved into run_hack_cli's preflight."""
        p = build_parser()
        ns = p.parse_args([])
        assert ns.target is None
        assert ns.resume is None

    def test_resume_flag_parses(self):
        p = build_parser()
        ns = p.parse_args(["--resume", "example.com_12345"])
        assert ns.resume == "example.com_12345"
        assert ns.target is None

    def test_default_flags(self):
        p = build_parser()
        ns = p.parse_args(["example.com"])
        assert ns.target == "example.com"
        assert ns.go is False
        assert ns.profile is None
        assert ns.scope is None
        assert ns.quiet is False
        assert ns.no_dashboard is False

    def test_explicit_profile(self):
        p = build_parser()
        for prof in ("ctf", "bugbounty", "lab"):
            ns = p.parse_args(["x", "--profile", prof])
            assert ns.profile == prof

    def test_invalid_profile_rejected(self):
        p = build_parser()
        with pytest.raises(SystemExit):
            p.parse_args(["x", "--profile", "invalid"])

    def test_time_int_parses(self):
        p = build_parser()
        ns = p.parse_args(["x", "--time", "5"])
        assert ns.time == 5

    def test_go_flag(self):
        p = build_parser()
        ns = p.parse_args(["x", "--go"])
        assert ns.go is True

    def test_workers_int(self):
        p = build_parser()
        ns = p.parse_args(["x", "--workers", "20"])
        assert ns.workers == 20

    def test_report_format_choices(self):
        p = build_parser()
        for fmt in ("html", "md", "json"):
            ns = p.parse_args(["x", "--report", fmt])
            assert ns.report == fmt


# ---------------------------------------------------------------------------
# run_hack_cli — preflight
# ---------------------------------------------------------------------------


class TestPreflight:
    def test_missing_scope_file_exits_1(self, tmp_path, capsys):
        rc = run_hack_cli([
            "example.com", "--scope", str(tmp_path / "nope.json"),
        ])
        assert rc == 1
        err = capsys.readouterr().err
        assert "scope file not found" in err

    def test_invalid_profile_explicit_exits_via_argparse(self):
        # argparse exits with SystemExit(2) before we get to our handler
        with pytest.raises(SystemExit):
            run_hack_cli(["example.com", "--profile", "nonexistent"])


# ---------------------------------------------------------------------------
# Stubbed end-to-end (no real network)
# ---------------------------------------------------------------------------


class _FakeHackMode:
    """Returns a HackResult-shaped object without launching a real swarm."""

    def __init__(self, **kw):
        from core.hack_mode import HackResult
        self._result = HackResult(
            target=kw["target"],
            profile=kw["profile"].name,
            hunt_id=kw["audit"].hunt_id,
            audit_path=kw["audit"].jsonl_path,
        )
        self._result.iterations = 1
        self._result.findings = [
            {"type": "test", "title": "fake", "severity": "info"},
        ]
        self._result.stop_reason = "test"
        self._kw = kw

    async def run(self):
        # Touch the audit log so the file exists
        self._kw["audit"].event("hunt.started", target=self._kw["target"])
        self._kw["audit"].event(
            "hunt.completed", outcome="success", findings_count=1,
        )
        return self._result


class TestRunHackCli:
    def test_clean_run_exits_zero(self, tmp_path, capsys):
        with patch("core.hack_cli.HackMode", _FakeHackMode):
            rc = run_hack_cli([
                "example.com",
                "--quiet",
                "--hunts-dir", str(tmp_path / "hunts"),
                "--db-path", str(tmp_path / "v.db"),
            ])
        assert rc == 0
        out = capsys.readouterr().out
        assert "hunt_id:" in out
        assert "findings:" in out

    def test_summary_file_written(self, tmp_path):
        with patch("core.hack_cli.HackMode", _FakeHackMode):
            rc = run_hack_cli([
                "example.com",
                "--quiet",
                "--hunts-dir", str(tmp_path / "hunts"),
                "--db-path", str(tmp_path / "v.db"),
            ])
        assert rc == 0
        # Find the summary.json under the hunt dir
        summaries = list((tmp_path / "hunts").rglob("summary.json"))
        assert len(summaries) == 1
        body = json.loads(summaries[0].read_text(encoding="utf-8"))
        assert body["target"] == "example.com"
        assert body["findings_count"] == 1

    def test_explicit_output_path(self, tmp_path):
        out_path = tmp_path / "summary.json"
        with patch("core.hack_cli.HackMode", _FakeHackMode):
            rc = run_hack_cli([
                "example.com",
                "--quiet",
                "--hunts-dir", str(tmp_path / "hunts"),
                "--db-path", str(tmp_path / "v.db"),
                "--output", str(out_path),
            ])
        assert rc == 0
        assert out_path.exists()
        body = json.loads(out_path.read_text(encoding="utf-8"))
        assert body["target"] == "example.com"

    def test_exit_5_on_timed_out(self, tmp_path):
        class _TimedOut(_FakeHackMode):
            async def run(self):
                r = await super().run()
                r.timed_out = True
                return r

        with patch("core.hack_cli.HackMode", _TimedOut):
            rc = run_hack_cli([
                "example.com", "--quiet",
                "--hunts-dir", str(tmp_path / "hunts"),
                "--db-path", str(tmp_path / "v.db"),
            ])
        assert rc == 5

    def test_exit_4_on_unexpected_error(self, tmp_path, capsys):
        class _Boom(_FakeHackMode):
            async def run(self):
                raise RuntimeError("boom")

        with patch("core.hack_cli.HackMode", _Boom):
            rc = run_hack_cli([
                "example.com", "--quiet",
                "--hunts-dir", str(tmp_path / "hunts"),
                "--db-path", str(tmp_path / "v.db"),
            ])
        assert rc == 4
        err = capsys.readouterr().err
        assert "scan error" in err

    def test_keyboard_interrupt_exits_130(self, tmp_path, capsys):
        class _Cancel(_FakeHackMode):
            async def run(self):
                raise KeyboardInterrupt

        with patch("core.hack_cli.HackMode", _Cancel):
            rc = run_hack_cli([
                "example.com", "--quiet",
                "--hunts-dir", str(tmp_path / "hunts"),
                "--db-path", str(tmp_path / "v.db"),
            ])
        assert rc == 130


# ---------------------------------------------------------------------------
# CLI overrides time + workers
# ---------------------------------------------------------------------------


class TestCliOverrides:
    def test_time_override_applied(self, tmp_path):
        captured = {}

        class _CaptureProfile(_FakeHackMode):
            def __init__(self, **kw):
                super().__init__(**kw)
                captured["time_budget_s"] = kw["profile"].time_budget_s

        with patch("core.hack_cli.HackMode", _CaptureProfile):
            run_hack_cli([
                "example.com", "--quiet", "--time", "7",
                "--hunts-dir", str(tmp_path / "hunts"),
                "--db-path", str(tmp_path / "v.db"),
            ])
        # 7 minutes = 420 seconds
        assert captured["time_budget_s"] == 420.0

    def test_workers_override_applied(self, tmp_path):
        captured = {}

        class _Capture(_FakeHackMode):
            def __init__(self, **kw):
                super().__init__(**kw)
                captured["max_concurrent"] = kw["profile"].max_concurrent

        with patch("core.hack_cli.HackMode", _Capture):
            run_hack_cli([
                "example.com", "--quiet", "--workers", "25",
                "--hunts-dir", str(tmp_path / "hunts"),
                "--db-path", str(tmp_path / "v.db"),
            ])
        assert captured["max_concurrent"] == 25

    def test_workers_minimum_1(self, tmp_path):
        captured = {}

        class _Capture(_FakeHackMode):
            def __init__(self, **kw):
                super().__init__(**kw)
                captured["max_concurrent"] = kw["profile"].max_concurrent

        with patch("core.hack_cli.HackMode", _Capture):
            run_hack_cli([
                "example.com", "--quiet", "--workers", "0",
                "--hunts-dir", str(tmp_path / "hunts"),
                "--db-path", str(tmp_path / "v.db"),
            ])
        # Clamped to 1
        assert captured["max_concurrent"] == 1


# ---------------------------------------------------------------------------
# viper.py shim
# ---------------------------------------------------------------------------


class TestViperShim:
    """Verify `viper.py hack ...` routes to run_hack_cli without breaking
    the existing flat argparse flow."""

    def test_hack_subcommand_help_works(self):
        """The --help flag on `viper.py hack` should output the hack-specific help."""
        import subprocess
        result = subprocess.run(
            [sys.executable, "viper.py", "hack", "--help"],
            capture_output=True, text=True, timeout=30,
            cwd=str(Path(__file__).resolve().parents[1]),
        )
        assert result.returncode == 0
        assert "Autonomous pentest" in result.stdout
        assert "--go" in result.stdout
        assert "Examples:" in result.stdout

    def test_root_help_still_works(self):
        """Existing `viper.py --help` (no hack) must still produce the original flat-arg help."""
        import subprocess
        result = subprocess.run(
            [sys.executable, "viper.py", "--help"],
            capture_output=True, text=True, timeout=30,
            cwd=str(Path(__file__).resolve().parents[1]),
        )
        assert result.returncode == 0
        assert "AI Bug Bounty Scanner" in result.stdout
        # The flat parser exposes --full / --waves etc.
        assert "--waves" in result.stdout
