#!/usr/bin/env python3
"""
VIPER Submission Queue & Prioritizer
=====================================
Inspired by: "An Agentic Multi-Agent Architecture for Cybersecurity Risk Management"
(arXiv, March 20, 2026) — Multi-agent risk scoring framework

The paper uses 6 specialized agents for risk assessment. We adapt this into
a prioritization model for bug bounty submission order:
  Agent 1: Severity assessor (CRITICAL/HIGH/MEDIUM weight)
  Agent 2: Staleness detector (how long unsubmitted = decay in value)
  Agent 3: Program reputation scorer (bounty range + response rate)
  Agent 4: Competition risk estimator (common vuln types = higher collision risk)
  Agent 5: Effort estimator (time needed to write report)
  Agent 6: Strategic priority (is this a platform that ignores reports?)

Final score = weighted sum → sorted queue for maximum bounty yield

USAGE:
  python viper_submit_queue.py queue           # Show prioritized submission queue
  python viper_submit_queue.py draft <target>  # Generate email draft for target
  python viper_submit_queue.py summary         # Quick summary of backlog
"""

import json
import sys
from datetime import datetime
from pathlib import Path


HACKAGENT_DIR = Path(__file__).parent
STATE_FILE = HACKAGENT_DIR / "viper_state.json"

# -------------------------------------------------------------------
# Program metadata: expected bounty range and platform reputation
# (based on research + historical HackerOne/Bugcrowd/Intigriti data)
# -------------------------------------------------------------------
PROGRAM_META = {
    "security@hashnode.com": {
        "platform": "direct",
        "min_bounty": 50,
        "max_bounty": 500,
        "response_rate": 0.7,
        "notes": "3rd occurrence — shows pattern of regression. More impactful report."
    },
    "security@openpay.mx": {
        "platform": "direct",
        "min_bounty": 100,
        "max_bounty": 1000,
        "response_rate": 0.6,
        "notes": "Payment gateway — ELEVATED severity. Financial data exposure."
    },
    "app.intigriti.com/researcher/programs/liveblocks": {
        "platform": "intigriti",
        "min_bounty": 100,
        "max_bounty": 2500,
        "response_rate": 0.85,
        "notes": "Real-time collaboration — ACAC=true makes this high impact."
    },
    "bugcrowd.com/ably": {
        "platform": "bugcrowd",
        "min_bounty": 150,
        "max_bounty": 3000,
        "response_rate": 0.80,
        "notes": "Well-known realtime platform. Multiple submission channels."
    },
    "app.intigriti.com/researcher/programs/ably": {
        "platform": "intigriti",
        "min_bounty": 150,
        "max_bounty": 3000,
        "response_rate": 0.80,
        "notes": "Same vuln, extra platform coverage."
    },
    "github.com/n8n-io/n8n/security": {
        "platform": "github_advisory",
        "min_bounty": 0,
        "max_bounty": 500,
        "response_rate": 0.70,
        "notes": "Open source — may be CVE-worthy. Real data leak confirmed."
    },
    "security@appwrite.io": {
        "platform": "direct",
        "min_bounty": 100,
        "max_bounty": 1500,
        "response_rate": 0.75,
        "notes": "Growing cloud platform. accountCreate without auth key = critical misconfig."
    },
    "security@fly.io": {
        "platform": "direct",
        "min_bounty": 200,
        "max_bounty": 2000,
        "response_rate": 0.85,
        "notes": "Well-funded infra company. Known to pay promptly."
    },
    "railway.com/security": {
        "platform": "direct",
        "min_bounty": 100,
        "max_bounty": 1500,
        "response_rate": 0.80,
        "notes": "Popular dev platform. 162 sensitive mutations exposed."
    },
    "grafbase.com/security": {
        "platform": "direct",
        "min_bounty": 50,
        "max_bounty": 500,
        "response_rate": 0.65,
        "notes": "Smaller company — lower bounty expected."
    },
    "app.intigriti.com/researcher/programs/getstream": {
        "platform": "intigriti",
        "min_bounty": 100,
        "max_bounty": 1500,
        "response_rate": 0.80,
        "notes": "Stream SDK used by many apps. CORS medium due to Bearer auth."
    },
    "security@8base.com": {
        "platform": "direct",
        "min_bounty": 50,
        "max_bounty": 500,
        "response_rate": 0.55,
        "notes": "Smaller platform, lower confidence on response rate."
    },
    "security@getdbt.com": {
        "platform": "direct",
        "min_bounty": 50,
        "max_bounty": 300,
        "response_rate": 0.65,
        "notes": "Read-only introspection — lower severity, mention data model exposure."
    },
    "security@encore.dev": {
        "platform": "direct",
        "min_bounty": 50,
        "max_bounty": 300,
        "response_rate": 0.60,
        "notes": "Go panic (DoS vector) + schema exposure. Medium finding."
    },
}

# Severity weights (Agent 1)
SEVERITY_WEIGHT = {
    "CRITICAL": 1.0,
    "HIGH": 0.70,
    "MEDIUM": 0.40,
    "LOW_INFO": 0.10,
}

# Vulnerability type competition risk (Agent 4)
# Common types = higher chance someone else submitted it first
COMPETITION_RISK = {
    "CORS Origin Reflection + GraphQL Introspection": 0.3,  # specific combo = low collision
    "CORS Origin Reflection — Any Origin Reflected + ACAC=true": 0.4,
    "GraphQL Introspection Enabled (Unauthenticated)": 0.5,  # common finding
    "GraphQL Introspection + 444 mutations + accountCreate EXECUTED without API key": 0.2,  # specific
    "CORS Misconfiguration — User Data Leaked Cross-Origin": 0.3,
    "Go panic on apps query + 246 types schema exposed": 0.2,
    "Introspection + workspaceDelete + userLogin brute-forceable": 0.3,
    "Read-only schema introspection — 205 types, no mutations": 0.6,  # very common
    "CORS Origin Reflection + ACAC=true (Bearer auth primary — limited cookie vector)": 0.5,
}

# Effort to write report in hours (Agent 5)
REPORT_EFFORT = {
    "CORS Origin Reflection + GraphQL Introspection": 2.0,  # complex combo
    "CORS Origin Reflection — Any Origin Reflected + ACAC=true": 1.0,
    "GraphQL Introspection Enabled (Unauthenticated)": 1.5,
    "GraphQL Introspection + 444 mutations + accountCreate EXECUTED without API key": 2.5,
    "CORS Misconfiguration — User Data Leaked Cross-Origin": 1.5,
    "Go panic on apps query + 246 types schema exposed": 1.0,
    "Introspection + workspaceDelete + userLogin brute-forceable": 1.5,
    "Read-only schema introspection — 205 types, no mutations": 0.5,
    "CORS Origin Reflection + ACAC=true (Bearer auth primary — limited cookie vector)": 1.0,
}


def load_findings():
    """Load all unsubmitted findings from viper_state.json."""
    with open(STATE_FILE, encoding="utf-8") as f:
        state = json.load(f)

    findings = []
    active = state.get("active_findings", {})

    for severity, items in active.items():
        if severity in ("PATCHED",):
            continue
        for item in items:
            if "UNSUBMITTED" in item.get("status", "") or "UNSUBMITTED" in item.get("status", "").upper():
                findings.append({
                    "severity": severity,
                    "target": item.get("target", "Unknown"),
                    "url": item.get("url", ""),
                    "type": item.get("type", ""),
                    "program": item.get("program", ""),
                    "discovered": item.get("discovered", item.get("verified", "2026-03-10")),
                    "status": item.get("status", ""),
                    "report": item.get("report", ""),
                    "notes": item.get("severity_note", item.get("notable", "")),
                })

    return findings


def score_finding(finding: dict) -> dict:
    """
    Score a finding using the 6-agent multi-agent risk model.
    Returns scoring breakdown + final priority score.
    """
    # Agent 1: Severity weight
    severity_score = SEVERITY_WEIGHT.get(finding["severity"], 0.3)

    # Agent 2: Staleness — the longer unsubmitted, the more urgency (and risk of dupe)
    discovered_str = finding.get("discovered", "2026-03-10")
    if "-s" in discovered_str:
        discovered_str = discovered_str.split("-s")[0]
    try:
        discovered = datetime.strptime(discovered_str, "%Y-%m-%d")
        days_stale = (datetime.now() - discovered).days
    except Exception:
        days_stale = 13
    # Staleness urgency: peaks at 30 days (0.9), 0 at day 0 (0.3)
    staleness_score = min(0.9, 0.3 + (days_stale / 30) * 0.6)

    # Agent 3: Program reputation (expected bounty × response probability)
    program = finding.get("program", "")
    prog_meta = None
    for key, meta in PROGRAM_META.items():
        if key in program or program in key:
            prog_meta = meta
            break
    if prog_meta:
        expected_bounty = (prog_meta["min_bounty"] + prog_meta["max_bounty"]) / 2
        response_rate = prog_meta["response_rate"]
        # Normalize: $1000 expected = 0.8 score
        bounty_score = min(0.95, (expected_bounty * response_rate) / 1500)
    else:
        bounty_score = 0.4  # unknown program, moderate estimate

    # Agent 4: Competition risk (invert — lower collision = higher score)
    vuln_type = finding.get("type", "")
    collision_risk = 0.4  # default
    for pattern, risk in COMPETITION_RISK.items():
        if any(p in vuln_type for p in pattern.split()):
            collision_risk = risk
            break
    competition_score = 1.0 - collision_risk  # invert: lower collision = higher priority

    # Agent 5: Effort (invert — lower effort = higher priority, all else equal)
    effort_hours = 1.0  # default
    for pattern, hours in REPORT_EFFORT.items():
        if any(p in vuln_type for p in pattern.split()):
            effort_hours = hours
            break
    effort_score = 1.0 - min(0.8, effort_hours / 3.0)  # normalize effort

    # Agent 6: Strategic priority
    # - "3rd occurrence" = very high priority (shows they don't fix)
    # - Payment gateway = elevated
    # - Real data leak = elevated
    strategic_score = 0.5
    if "3rd occurrence" in finding.get("status", "") or "3rd" in str(finding.get("notes", "")):
        strategic_score = 0.9
    elif "Payment" in vuln_type or "Payment" in str(finding.get("notes", "")):
        strategic_score = 0.85
    elif "Real Data Leak" in vuln_type or "data_leaked" in str(finding):
        strategic_score = 0.80
    elif finding["severity"] == "CRITICAL":
        strategic_score = 0.75

    # Weighted final score
    # Priority order: severity > staleness > bounty > strategic > competition > effort
    final_score = (
        severity_score * 0.30 +
        staleness_score * 0.20 +
        bounty_score * 0.20 +
        strategic_score * 0.15 +
        competition_score * 0.10 +
        effort_score * 0.05
    )

    return {
        "finding": finding,
        "scores": {
            "severity": round(severity_score, 3),
            "staleness": round(staleness_score, 3),
            "bounty": round(bounty_score, 3),
            "strategic": round(strategic_score, 3),
            "competition": round(competition_score, 3),
            "effort": round(effort_score, 3),
        },
        "final_score": round(final_score, 4),
        "days_stale": days_stale,
        "expected_bounty": round(expected_bounty if prog_meta else 250, 0),
        "prog_meta": prog_meta,
    }


def generate_email_draft(scored: dict) -> str:
    """Generate a submission-ready email draft for a direct-disclosure target."""
    f = scored["finding"]
    meta = scored.get("prog_meta", {})
    target = f["target"]
    vuln_type = f["type"]
    url = f["url"]
    program = f["program"]
    severity = f["severity"]
    report_file = f.get("report", "")

    # Determine subject line based on severity
    severity_label = {
        "CRITICAL": "Critical",
        "HIGH": "High",
        "MEDIUM": "Medium",
    }.get(severity, "Medium")

    # Subject
    subject = f"[Security Report] {severity_label} — {vuln_type.split('—')[0].strip()} in {target}"

    body = f"""Subject: {subject}

Hello Security Team,

I'm a security researcher reporting a {severity_label.lower()} severity vulnerability I discovered in {target}.

**Summary**
{vuln_type}

**Affected URL**
{url}

**Severity**
{severity_label} — CVSS 3.1 estimate: {_cvss_estimate(severity, vuln_type)}

**Description**
{_description(f, scored)}

**Impact**
{_impact(f)}

**Reproduction Steps**
1. Send a cross-origin request to: {url}
2. Include the header: Origin: https://evil-attacker.com
3. Observe the response reflects the attacker-controlled origin with Access-Control-Allow-Credentials: true

**Proof of Concept**
```
curl -s -I -H "Origin: https://evil-attacker.com" \\
     -H "Authorization: Bearer <victim_token>" \\
     "{url}"
```

Expected Response:
```
Access-Control-Allow-Origin: https://evil-attacker.com
Access-Control-Allow-Credentials: true
```

**Recommendations**
- Implement an allowlist of trusted origins for CORS
- Never reflect arbitrary origins when credentials are involved
- Set Access-Control-Allow-Credentials: true ONLY for explicitly allowlisted origins

**Notes**
{f.get('notes', '')}
{f.get('status', '')}

I'm happy to provide additional details or a live demonstration.

Regards,
VIPER Security Research
HackerOne: viper-ashborn
"""

    return body


def _cvss_estimate(severity: str, vuln_type: str) -> str:
    if severity == "CRITICAL":
        return "9.1 (Critical)"
    if "CORS" in vuln_type and "ACAC" in vuln_type:
        return "8.1 (High)"
    if "GraphQL Introspection" in vuln_type and "mutation" in vuln_type.lower():
        return "7.5 (High)"
    if "Payment" in vuln_type:
        return "8.5 (High)"
    if severity == "HIGH":
        return "7.2 (High)"
    return "5.3 (Medium)"


def _description(f: dict, scored: dict) -> str:
    vuln_type = f.get("type", "")
    if "CORS" in vuln_type:
        return (
            f"{f['target']} reflects arbitrary cross-origin requests and includes "
            f"Access-Control-Allow-Credentials: true. This allows an attacker-controlled "
            f"website to make authenticated requests on behalf of a victim user and read "
            f"the response — bypassing the Same-Origin Policy."
        )
    elif "GraphQL Introspection" in vuln_type:
        mutations = ""
        types_info = f.get("types_exposed", "")
        mutations_info = f.get("mutations_exposed", "")
        return (
            f"{f['target']} exposes its full GraphQL schema via introspection without "
            f"authentication. This reveals {types_info} types and {mutations_info} mutations, "
            f"including sensitive operations that should be protected."
        )
    elif "Go panic" in vuln_type:
        return (
            f"{f['target']} crashes (Go panic) on certain GraphQL queries, causing a "
            f"denial-of-service condition. Additionally, 246 schema types are exposed via introspection."
        )
    return f"Vulnerability in {f['target']}: {vuln_type}"


def _impact(f: dict) -> str:
    vuln_type = f.get("type", "")
    severity = f.get("severity", "")
    if "Payment" in vuln_type:
        return (
            "An attacker could make authenticated API calls to the payment gateway on behalf "
            "of a victim, potentially exfiltrating payment data, initiating unauthorized charges, "
            "or reading transaction history."
        )
    elif "CORS" in vuln_type and "ACAC" in vuln_type:
        return (
            "An attacker can craft a malicious webpage that, when visited by an authenticated user, "
            "makes cross-origin API requests and reads the full response — including sensitive user data, "
            "authentication tokens, or private resources."
        )
    elif "GraphQL Introspection" in vuln_type:
        return (
            "Full schema disclosure allows attackers to map the entire API surface, discover sensitive "
            "mutations (delete, create, permission changes), and craft targeted attacks against "
            "private functionality not visible through normal application usage."
        )
    return "An attacker could exploit this to gain unauthorized access to sensitive data or functionality."


def cmd_queue(findings: list):
    """Display prioritized submission queue."""
    scored = [score_finding(f) for f in findings]
    scored.sort(key=lambda x: x["final_score"], reverse=True)

    print("\n" + "=" * 72)
    print(f"  VIPER SUBMISSION QUEUE — {len(findings)} findings pending")
    print(f"  Generated: {datetime.now().strftime('%Y-%m-%d %H:%M')}")
    print("=" * 72)

    for i, s in enumerate(scored, 1):
        f = s["finding"]
        scores = s["scores"]
        meta = s.get("prog_meta") or {}
        platform = meta.get("platform", "?")

        print(f"\n#{i} [{f['severity']}] {f['target']}")
        print(f"    Score: {s['final_score']:.3f} | Stale: {s['days_stale']}d | Platform: {platform}")
        print(f"    Type:  {f['type'][:70]}")
        print(f"    Sub:   {f['program'][:65]}")
        print(f"    💰 ~${int(s['expected_bounty'])} expected | Scores: sev={scores['severity']} stale={scores['staleness']} bounty={scores['bounty']} strat={scores['strategic']}")
        if f.get("notes"):
            print(f"    ⚠️  {f['notes'][:80]}")

    print("\n" + "=" * 72)
    total_expected = sum(s["expected_bounty"] for s in scored)
    print(f"  TOTAL EXPECTED: ~${total_expected:,.0f} if all accepted")
    print("=" * 72)
    print("\n  Run: python viper_submit_queue.py draft <target_name_fragment>")
    print("  to generate email draft for specific target.\n")


def cmd_draft(findings: list, target_fragment: str):
    """Generate and print email draft for a specific target."""
    matches = [
        f for f in findings
        if target_fragment.lower() in f["target"].lower() or
           target_fragment.lower() in f["program"].lower()
    ]
    if not matches:
        print(f"No findings match '{target_fragment}'")
        print("Available targets:", [f["target"] for f in findings])
        return

    finding = matches[0]
    scored = score_finding(finding)
    draft = generate_email_draft(scored)
    print(draft)


def cmd_summary(findings: list):
    """Quick backlog summary."""
    severity_counts = {}
    for f in findings:
        sev = f["severity"]
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    print(f"\n🐍 VIPER BACKLOG SUMMARY — {datetime.now().strftime('%Y-%m-%d')}")
    print(f"   Total unsubmitted: {len(findings)}")
    for sev, count in sorted(severity_counts.items()):
        print(f"   {sev}: {count}")

    # Oldest finding
    stale_days = []
    for f in findings:
        ds = f.get("discovered", "2026-03-10")
        if "-s" in ds:
            ds = ds.split("-s")[0]
        try:
            d = datetime.strptime(ds, "%Y-%m-%d")
            stale_days.append((datetime.now() - d).days)
        except Exception:
            stale_days.append(13)

    print(f"   Oldest finding: {max(stale_days)} days ago")
    print(f"   ⚠️  Every day unsubmitted = risk of duplication!\n")


if __name__ == "__main__":
    try:
        findings = load_findings()
    except FileNotFoundError:
        print(f"ERROR: viper_state.json not found at {STATE_FILE}")
        sys.exit(1)

    if not findings:
        print("No unsubmitted findings found in viper_state.json")
        sys.exit(0)

    cmd = sys.argv[1] if len(sys.argv) > 1 else "queue"

    if cmd == "queue":
        cmd_queue(findings)
    elif cmd == "draft":
        if len(sys.argv) < 3:
            print("Usage: python viper_submit_queue.py draft <target_name>")
            sys.exit(1)
        cmd_draft(findings, sys.argv[2])
    elif cmd == "summary":
        cmd_summary(findings)
    else:
        print(f"Unknown command: {cmd}")
        print("Commands: queue | draft <target> | summary")
