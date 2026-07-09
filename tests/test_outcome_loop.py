"""Outer learning loop: a submitted finding's disposition (paid/accepted/rejected)
reweights the cross-hunt attack priors and is logged in the ledger."""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


def _priors(tmp_path):
    from core.attack_priors import AttackPriors
    from core.evograph import EvoGraph
    return AttackPriors(evograph=EvoGraph(db_path=tmp_path / "evo.db"))


def test_paid_outcome_ranks_the_class_higher(tmp_path):
    p = _priors(tmp_path)
    for _ in range(2):                     # >=2 attempts so evograph counts them
        assert p.record_outcome("sqli", ["php"], "paid")
        assert p.record_outcome("xss", ["php"], "rejected")
    ranked = p.rank(["xss", "sqli"], ["php"])
    assert ranked[0] == "sqli"             # the paid class runs first next time
    assert ranked[-1] == "xss"             # the rejected class sinks


def test_unknown_disposition_and_disabled_are_noops(tmp_path):
    from core.attack_priors import AttackPriors
    assert _priors(tmp_path).record_outcome("sqli", ["php"], "banana") is False
    assert AttackPriors(enabled=False).record_outcome("sqli", ["php"], "paid") is False


def test_ledger_set_disposition_persists(tmp_path):
    from core.submission_ledger import SubmissionLedger, signature
    f = {"vuln_type": "sqli:q", "url": "http://t/x?q=1", "parameter": "q"}
    led = SubmissionLedger(path=tmp_path / "led.json")
    led.set_disposition(f, "paid")
    led.save()
    reloaded = SubmissionLedger(path=tmp_path / "led.json")
    assert reloaded._seen[signature(f)]["status"] == "paid"


def test_outcome_cli_wires_ledger_and_priors(tmp_path, monkeypatch, capsys):
    import core.attack_priors as ap
    import core.submission_ledger as sl
    monkeypatch.setattr(sl, "LEDGER_PATH", tmp_path / "led.json")

    calls = []

    class _FakePriors:
        def record_outcome(self, technique, stack, disp):
            calls.append((technique, tuple(stack), disp))
            return True
    monkeypatch.setattr(ap, "AttackPriors", _FakePriors)

    fpath = tmp_path / "f.json"
    fpath.write_text(json.dumps([{"vuln_type": "sqli:q", "url": "http://t/x?q=1",
                                  "parameter": "q", "technique": "sqli_probe"}]))
    from core.outcome_cli import run_outcome_cli
    rc = run_outcome_cli(["accepted", str(fpath), "--tech", "php,nginx"])
    assert rc == 0
    assert calls == [("sqli_probe", ("php", "nginx"), "accepted")]   # priors fed
    led = sl.SubmissionLedger()                                       # ledger updated
    assert led._seen[sl.signature({"vuln_type": "sqli:q", "url": "http://t/x?q=1",
                                   "parameter": "q"})]["status"] == "accepted"
    assert "fed into cross-hunt attack priors" in capsys.readouterr().out


def test_outcome_cli_rejects_bad_args(capsys):
    from core.outcome_cli import run_outcome_cli
    assert run_outcome_cli([]) == 2
    assert run_outcome_cli(["banana", "x.json"]) == 2
