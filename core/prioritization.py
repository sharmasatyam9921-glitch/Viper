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


# Expected-BOUNTY tier per class (0-12) — real-world payout weighting that refines
# ordering WITHIN a severity band, so a confirmed auth/injection/access-control bug
# outranks a same-severity clickjacking / CORS / open-redirect. Offline, deterministic;
# ORDERING only — never touches the gate, scope, or whether a finding is submittable.
_BOUNTY_TIER = {
    # Tier A — command / data / identity compromise (highest payouts)
    "rce": 12, "cmdi": 12, "command_injection": 12, "sqli": 12, "login_sqli": 12,
    "auth_bypass": 12, "ssrf": 11, "ssti": 11, "nosql_injection": 11, "xxe": 10,
    "idor": 10, "bola": 10, "bola_multi": 10, "bfla": 10, "bfla_multi": 10,
    "broken_access_control": 10, "access_control": 10, "graphql_authz": 10, "jwt": 10,
    "lfi": 9, "path_traversal": 9, "web_cache_deception": 8,
    # Tier B — meaningful, usually mid-tier
    "xss": 8, "cloud_exposure": 8, "subdomain_takeover": 8, "secret": 8, "secrets": 8,
    "env_exposed": 8, "git_exposed": 7, "host_header": 7, "cors": 6,
    "xss_text": 5, "xss_tag": 5,
    # Tier C — lower payout / frequently informational
    "cache_poisoning": 4, "open_redirect": 3, "crlf": 3, "csrf": 3, "clickjacking": 2,
    "graphql": 2, "graphql_introspection": 2, "graphql_ide": 2, "information_disclosure": 2,
    "dir_listing": 2, "directory_listing": 2,
}


def _bounty_tier(vuln_type) -> float:
    """Expected-payout weight (0-12) for the finding's class — see _BOUNTY_TIER."""
    head = str(vuln_type or "").lower().split(":")[0]
    if head in _BOUNTY_TIER:
        return float(_BOUNTY_TIER[head])
    aliased = _ALIAS.get(head, head)
    return float(_BOUNTY_TIER.get(aliased, 5))


def priority_score(finding: dict) -> float:
    """0-100 priority. submittable (+30) + severity (5-40) + gate confidence (0-30)
    + class impact prior (0-10, disclosed-report prevalence x criticality) + expected
    bounty tier (0-12, real-world payout weighting that breaks ties within a severity
    band). All ORDERING signals — none affects confirmation."""
    sev = str(finding.get("severity") or "info").lower()
    base = _SEV_PTS.get(sev, 5)
    confirmed = 30 if finding.get("submittable") else 0
    conf = finding.get("validation_confidence")
    conf_pts = float(conf) * 30 if isinstance(conf, (int, float)) else 0.0
    vt = finding.get("vuln_type") or finding.get("type")
    prior = _class_prior(vt)
    bounty = _bounty_tier(vt)
    score = min(100.0, base + confirmed + conf_pts + prior + bounty)
    # A finding matching one of the program's PUBLIC disclosures is very likely a known
    # duplicate — sort it BELOW novel findings so the operator triages fresh bugs first
    # (submitting a public-disclosure dupe wastes triage + costs reputation). It is not
    # dropped; ordering only, and never affects confirmation.
    if finding.get("likely_duplicate"):
        score = max(0.0, score - 40)
    return round(score, 1)


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
