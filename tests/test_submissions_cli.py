"""`viper.py submissions` review command."""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import core.submissions_cli as scli  # noqa: E402
from core.submissions_cli import run_submissions_cli  # noqa: E402


def _seed(tmp_path, monkeypatch):
    root = tmp_path / "subs"
    monkeypatch.setattr(scli, "_DRAFT_ROOT", root)
    d = root / "hunt_abc"
    d.mkdir(parents=True)
    (d / "01-sqli-q.md").write_text("# SQL Injection in parameter 'q'\nbody",
                                    encoding="utf-8")
    (d / "02-xss-q.md").write_text("# Reflected XSS in parameter 'q'\nbody",
                                   encoding="utf-8")
    return root


def test_list_hunts(tmp_path, monkeypatch, capsys):
    _seed(tmp_path, monkeypatch)
    assert run_submissions_cli([]) == 0
    out = capsys.readouterr().out
    assert "hunt_abc" in out and "2 drafts" in out


def test_list_drafts_for_hunt(tmp_path, monkeypatch, capsys):
    _seed(tmp_path, monkeypatch)
    assert run_submissions_cli(["hunt_abc"]) == 0
    out = capsys.readouterr().out
    assert "SQL Injection" in out and "Reflected XSS" in out


def test_show_by_number(tmp_path, monkeypatch, capsys):
    _seed(tmp_path, monkeypatch)
    assert run_submissions_cli(["hunt_abc", "--show", "1"]) == 0
    out = capsys.readouterr().out
    assert "# SQL Injection" in out and "body" in out


def test_show_by_filename(tmp_path, monkeypatch, capsys):
    _seed(tmp_path, monkeypatch)
    assert run_submissions_cli(["hunt_abc", "--show", "xss"]) == 0
    assert "Reflected XSS" in capsys.readouterr().out


def test_unknown_hunt_errors(tmp_path, monkeypatch):
    _seed(tmp_path, monkeypatch)
    assert run_submissions_cli(["nope"]) == 1


def test_no_drafts_at_all(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(scli, "_DRAFT_ROOT", tmp_path / "empty")
    assert run_submissions_cli([]) == 0
    assert "No submission drafts yet" in capsys.readouterr().out
