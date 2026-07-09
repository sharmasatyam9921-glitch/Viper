"""The one-shot gate-invariant check used by CI (core/gate_ci) passes on the healthy gate,
and the strengthened `gate_benchmark --strict` fails on BOTH a precision (FP) and a recall
(FN) regression — so the CI merge-gate catches a confirmed class silently dropping to a lead,
not just a new false positive."""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core import gate_benchmark, gate_mutations  # noqa: E402
from core.gate_benchmark import ClassScore, main as bench_main  # noqa: E402
from core.gate_ci import main as gate_ci_main  # noqa: E402


def test_gate_ci_composes_both_harness_exit_codes(monkeypatch):
    # Orchestration only (the harnesses themselves are covered by their own tests, which
    # is why we don't re-run the slow 750-check pass here): gate_ci must PASS iff both
    # sub-checks pass, and FAIL if either does.
    calls = {}

    def fake_bench(argv=None):
        calls["bench"] = argv
        return calls["bench_rc"]

    def fake_mut(argv=None):
        calls["mut"] = argv
        return calls["mut_rc"]

    monkeypatch.setattr(gate_benchmark, "main", fake_bench)
    monkeypatch.setattr(gate_mutations, "main", fake_mut)

    calls.update(bench_rc=0, mut_rc=0)
    assert gate_ci_main() == 0
    assert calls["bench"] == ["--strict"] and calls["mut"] == ["--strict"]  # strict enforced

    calls.update(bench_rc=1, mut_rc=0)
    assert gate_ci_main() == 1        # precision regression fails CI
    calls.update(bench_rc=0, mut_rc=1)
    assert gate_ci_main() == 1        # mutation leak fails CI


def test_strict_fails_on_false_positive(monkeypatch):
    def fake_scores():
        s = ClassScore("xss")
        s.tp, s.fp = 1, 1          # a safe responder leaked -> precision regressed
        s.fps.append("leaky safe case")
        return {"xss": s}
    monkeypatch.setattr(gate_benchmark, "run_benchmark", fake_scores)
    assert bench_main(["--strict"]) == 1
    assert bench_main([]) == 0     # non-strict never fails


def test_strict_fails_on_recall_regression(monkeypatch):
    def fake_scores():
        s = ClassScore("ldap_injection")
        s.fn = 1                   # a confirmed class stopped confirming -> recall regressed
        return {"ldap_injection": s}
    monkeypatch.setattr(gate_benchmark, "run_benchmark", fake_scores)
    assert bench_main(["--strict"]) == 1


def test_strict_passes_when_clean(monkeypatch):
    def fake_scores():
        s = ClassScore("xss")
        s.tp, s.tn = 1, 2          # no fp, no fn
        return {"xss": s}
    monkeypatch.setattr(gate_benchmark, "run_benchmark", fake_scores)
    assert bench_main(["--strict"]) == 0
