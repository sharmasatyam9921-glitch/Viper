"""Priority scoring — surface what to review/submit first.

Combines the three signals an operator cares about into one score (0-100):
  * SUBMITTABLE — the validation gate independently re-confirmed it. The strongest
    signal: a gate-confirmed bug outranks any unconfirmed lead.
  * SEVERITY — the CVSS class of the weakness.
  * gate CONFIDENCE — how strongly the gate's re-test reproduced it.

Used to sort the HTML report and tag each finding P1-P4 so a human triages the
highest-value, highest-certainty findings first.
"""

import json
from pathlib import Path

_SEV_PTS = {"critical": 40, "high": 30, "medium": 20, "low": 10, "info": 5}

_BLP_PATH = Path(__file__).parent / "selfimprove" / "business_logic_priors.json"
_blp: dict | None = None
# finding vuln_type head -> prior class in business_logic_priors.json
_ALIAS = {
    "cmdi": "command_injection", "command_injection": "command_injection",
    "idor": "access_control", "bola": "access_control", "bfla": "access_control",
    "broken_access_control": "access_control", "mass_assignment": "access_control",
    "auth_bypass": "auth_bypass", "login_sqli": "sqli", "path_traversal": "lfi",
    "secret": "secrets", "secrets": "secrets", "env_exposed": "secrets",
    "git_exposed": "secrets", "js_secret": "secrets",
}


def _class_prior(vuln_type) -> float:
    """Historical-impact prior (0-10) for the finding's class, from disclosed-report
    prevalence x criticality. A tie-breaker nudge so equally-confirmed findings of
    historically higher-impact classes (sqli, cmdi, access-control) rank first."""
    global _blp
    if _blp is None:
        try:
            _blp = json.loads(_BLP_PATH.read_text(encoding="utf-8")).get("classes", {})
        except Exception:
            _blp = {}
    head = str(vuln_type or "").lower().split(":")[0]
    cls = _ALIAS.get(head, head)
    info = _blp.get(cls)
    return round(float(info.get("impact_prior", 0.0)) * 10, 1) if info else 0.0


def priority_score(finding: dict) -> float:
    """0-100 priority. submittable (+30) + severity (5-40) + gate confidence (0-30)
    + class impact prior (0-10, from disclosed-report prevalence x criticality)."""
    sev = str(finding.get("severity") or "info").lower()
    base = _SEV_PTS.get(sev, 5)
    confirmed = 30 if finding.get("submittable") else 0
    conf = finding.get("validation_confidence")
    conf_pts = float(conf) * 30 if isinstance(conf, (int, float)) else 0.0
    prior = _class_prior(finding.get("vuln_type") or finding.get("type"))
    return round(min(100.0, base + confirmed + conf_pts + prior), 1)


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
