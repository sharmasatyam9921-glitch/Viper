"""Operator CLIs: viper.py classes + viper.py ledger."""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.ops_cli import run_classes_cli, run_ledger_cli  # noqa: E402


def test_classes_lists_coverage(capsys):
    rc = run_classes_cli([])
    out = capsys.readouterr().out
    assert rc == 0
    assert "vulnerability coverage" in out
    # a few known classes + their flags
    assert "host_header" in out and "subdomain_takeover" in out
    assert "gate-confirmed" in out and "OOB" in out
    assert "scorecard" in out


def test_ledger_empty(capsys, tmp_path, monkeypatch):
    import core.submission_ledger as sl
    monkeypatch.setattr(sl, "LEDGER_PATH", tmp_path / "ledger.json")
    rc = run_ledger_cli(["list"])
    assert rc == 0 and "empty" in capsys.readouterr().out


def test_ledger_list_and_clear(capsys, tmp_path, monkeypatch):
    import core.submission_ledger as sl
    p = tmp_path / "ledger.json"
    monkeypatch.setattr(sl, "LEDGER_PATH", p)
    led = sl.SubmissionLedger()
    led.record({"vuln_type": "sqli:id", "url": "http://t/item?id=1", "parameter": "id"})
    led.save()
    rc = run_ledger_cli(["list"])
    out = capsys.readouterr().out
    assert rc == 0 and "sqli:id" in out and "drafted" in out
    rc = run_ledger_cli(["clear"])
    assert rc == 0 and "cleared" in capsys.readouterr().out
    assert not p.exists()
