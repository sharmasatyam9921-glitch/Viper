"""Priority scoring — surface what to review/submit first.

Combines the three signals an operator cares about into one score (0-100):
  * SUBMITTABLE — the validation gate independently re-confirmed it. The strongest
    signal: a gate-confirmed bug outranks any unconfirmed lead.
  * SEVERITY — the CVSS class of the weakness.
  * gate CONFIDENCE — how strongly the gate's re-test reproduced it.

Used to sort the HTML report and tag each finding P1-P4 so a human triages the
highest-value, highest-certainty findings first.
"""

from __future__ import annotations

_SEV_PTS = {"critical": 40, "high": 30, "medium": 20, "low": 10, "info": 5}


def priority_score(finding: dict) -> float:
    """0-100 priority. submittable (+30) + severity (5-40) + gate confidence (0-30)."""
    sev = str(finding.get("severity") or "info").lower()
    base = _SEV_PTS.get(sev, 5)
    confirmed = 30 if finding.get("submittable") else 0
    conf = finding.get("validation_confidence")
    conf_pts = float(conf) * 30 if isinstance(conf, (int, float)) else 0.0
    return round(base + confirmed + conf_pts, 1)


def priority_label(score: float) -> str:
    if score >= 80:
        return "P1"
    if score >= 55:
        return "P2"
    if score >= 30:
        return "P3"
    return "P4"


def prioritize(findings):
    """Return findings sorted by descending priority (highest first)."""
    return sorted(findings, key=priority_score, reverse=True)
