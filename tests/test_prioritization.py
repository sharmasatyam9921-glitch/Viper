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
    # A classless finding gets the neutral bounty-tier default (5).
    assert priority_score({"severity": "medium"}) == 25.0            # 20 + 0 + 0 + 5
    assert priority_score({"severity": "critical", "submittable": True,
                           "validation_confidence": 0.9}) == 100.0  # 40+30+27+5 -> capped


def test_bounty_tier_breaks_ties_within_a_severity_band():
    # Two equally-confirmed HIGH findings: an auth/access bug must outrank a clickjacking
    # (real-world payout tier), and a low-tier class must not leapfrog a high-payout one.
    authz = {"vuln_type": "graphql_authz", "severity": "high", "submittable": True,
             "validation_confidence": 0.85}
    click = {"vuln_type": "clickjacking", "severity": "high", "submittable": True,
             "validation_confidence": 0.85}
    assert priority_score(authz) > priority_score(click)
    bola = {"vuln_type": "bola", "severity": "high", "submittable": True,
            "validation_confidence": 0.85}
    oredir = {"vuln_type": "open_redirect", "severity": "high", "submittable": True,
              "validation_confidence": 0.85}
    assert priority_score(bola) > priority_score(oredir)


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
