"""The validation gate must never mark a safe responder submittable.

This locks the gate's FP-averse contract against a labeled benchmark: per-class
precision must stay 1.00 (zero false positives). Recall is checked loosely — the
safe failure direction is a missed vuln degrading to a lead, not a bogus draft.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.gate_benchmark import (  # noqa: E402
    BENCHMARK,
    format_scorecard,
    overall,
    run_benchmark,
)


def test_no_safe_responder_is_ever_submittable():
    scores = run_benchmark()
    tot = overall(scores)
    assert tot.fp == 0, f"gate leaked false positives: {tot.fps}"
    for cls, cs in scores.items():
        assert cs.precision == 1.0, f"{cls} precision {cs.precision} (FPs: {cs.fps})"


def test_every_vuln_class_has_a_confirmed_true_positive():
    # each weakness class contributes at least one vuln scenario the gate confirms,
    # except cmdi (whose offline re-test models the safe/non-reproducible direction).
    scores = run_benchmark()
    for cls, cs in scores.items():
        if cls == "cmdi":
            continue
        assert cs.tp >= 1, f"{cls} produced no confirmed true positive"


def test_overall_recall_is_high():
    tot = overall(run_benchmark())
    assert tot.recall >= 0.9


def test_benchmark_covers_both_labels_per_class():
    classes = {}
    for sc in BENCHMARK:
        classes.setdefault(sc.cls, set()).add(sc.label)
    # every class has a safe responder; all but cmdi also have a vuln responder
    for cls, labels in classes.items():
        assert "safe" in labels, f"{cls} has no safe scenario"
    assert sum("vuln" in classes[c] for c in classes) >= 10


def test_scorecard_renders_clean_when_no_fps():
    text = format_scorecard(run_benchmark())
    assert "precision scorecard" in text
    assert "No false positives" in text
    assert "OVERALL" in text
