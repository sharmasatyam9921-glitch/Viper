"""Priority scoring combines submittable + severity + gate confidence."""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.prioritization import priority_label, priority_score, prioritize  # noqa: E402


def test_submittable_high_conf_outranks_unconfirmed_critical():
    sub = {"severity": "high", "submittable": True, "validation_confidence": 0.9}
    lead = {"severity": "critical", "submittable": False}
    assert priority_score(sub) > priority_score(lead)  # 30+30+27=87 > 40


def test_score_components():
    assert priority_score({"severity": "medium"}) == 20.0          # 20 + 0 + 0
    assert priority_score({"severity": "critical", "submittable": True,
                           "validation_confidence": 0.9}) == 97.0  # 40+30+27


def test_labels():
    assert priority_label(97) == "P1"
    assert priority_label(60) == "P2"
    assert priority_label(40) == "P3"
    assert priority_label(10) == "P4"


def test_prioritize_orders_highest_first():
    fs = [
        {"vuln_type": "clickjacking", "severity": "low", "submittable": False},
        {"vuln_type": "sqli", "severity": "critical", "submittable": True,
         "validation_confidence": 0.8},
        {"vuln_type": "xss", "severity": "high", "submittable": False},
    ]
    out = prioritize(fs)
    assert out[0]["vuln_type"] == "sqli"          # submittable critical -> top
    assert out[-1]["vuln_type"] == "clickjacking"  # lead low -> bottom
