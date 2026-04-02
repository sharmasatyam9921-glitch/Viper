#!/usr/bin/env python3
"""
VIPER Swarm - PentAGI-inspired parallel specialist agents
Instead of one VIPER doing everything serially, split into:

  VIPER-RECON    → subdomains, tech fingerprint, endpoint discovery
  VIPER-HUNT     → CORS, misconfigs, API vulns
  VIPER-EXPLOIT  → PoC verification, report generation

Called by Clawdbot sessions_spawn for each role.
This script is the coordinator — it defines tasks for each agent.
"""

import json
import sys
from pathlib import Path
from datetime import datetime

HACKAGENT_DIR = Path(__file__).parent
SWARM_DIR = HACKAGENT_DIR / "memory" / "swarm"
SWARM_DIR.mkdir(parents=True, exist_ok=True)

def get_recon_task(program: str, domain: str, scope: list) -> str:
    """Generate task string for VIPER-RECON subagent."""
    return f"""You are VIPER-RECON, specialist reconnaissance agent.

Target program: {program}
Primary domain: {domain}
In-scope: {', '.join(scope)}

Your mission (complete ALL steps):
1. Enumerate subdomains using passive methods:
   - Check crt.sh: https://crt.sh/?q=%25.{domain}&output=json
   - Check hackertarget: https://api.hackertarget.com/hostsearch/?q={domain}
2. For each discovered subdomain, fingerprint tech stack (check headers, X-Powered-By, Server, etc.)
3. Discover API endpoints — check common paths: /api, /api/v1, /api/v2, /graphql, /swagger, /openapi.json
4. Check for CORS on discovered endpoints (Origin: https://evil.com header test)
5. Save results to: skills/hackagent/memory/swarm/recon_{program}_{datetime.utcnow().strftime('%Y%m%d')}.json

Format: {{
  "program": "{program}",
  "domain": "{domain}",
  "subdomains": [...],
  "tech_stack": [...],
  "api_endpoints": [...],
  "cors_candidates": [...],
  "completed_at": "..."
}}

Use Python urllib (no external deps). Work autonomously. Save results when done.
"""

def get_hunt_task(program: str, recon_file: str) -> str:
    """Generate task string for VIPER-HUNT subagent."""
    return f"""You are VIPER-HUNT, specialist vulnerability hunter.

Target program: {program}
Recon data file: {recon_file}

Your mission:
1. Read the recon results from {recon_file}
2. For CORS candidates: verify full exploitability (origin reflected + ACAC:true + cookie auth)
3. For API endpoints: test for IDOR, missing auth, information disclosure
4. For GraphQL endpoints: introspection enabled? Batch queries? Field suggestions?
5. Check for common misconfigs: exposed .git, /admin, debug endpoints, stack traces
6. For each finding, check viper_kb.py: already_tested(program, technique) — skip if yes
7. Record all attempts: record_attempt(program, technique, "pass"/"fail")
8. Save HIGH/CRIT findings to: skills/hackagent/findings/VIPER_HUNT_{program}_{datetime.utcnow().strftime('%Y%m%d')}.md
9. Alert operator for HIGH/CRIT findings via skills/hackagent/findings/ALERT_*.md

Use skills/hackagent/viper_kb.py for memory. Hunt autonomously.
"""

def get_exploit_task(program: str, finding_file: str) -> str:
    """Generate task string for VIPER-EXPLOIT subagent."""
    return f"""You are VIPER-EXPLOIT, specialist PoC and report generator.

Target program: {program}
Finding file: {finding_file}

Your mission:
1. Read the finding from {finding_file}
2. Verify the vulnerability is still live (re-test the exact steps)
3. Build a complete, clean PoC (HTML page, curl command, or Python script)
4. Write a professional HackerOne-ready report:
   - Clear title
   - CVSS score
   - Steps to reproduce
   - Impact statement
   - Remediation suggestion
5. Save report to: skills/hackagent/findings/REPORT_{program}_{datetime.utcnow().strftime('%Y%m%d')}.md
6. Update viper_kb.py with: record_finding(program, technique, severity, url, notes)

Be thorough. A well-written report = higher chance of bounty.
"""

def create_swarm_plan(program: str, domain: str, scope: list) -> dict:
    """Create a full swarm execution plan."""
    timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
    recon_file = str(SWARM_DIR / f"recon_{program}_{timestamp[:8]}.json")
    
    plan = {
        "program": program,
        "domain": domain,
        "scope": scope,
        "created_at": datetime.utcnow().isoformat(),
        "phases": {
            "recon": {
                "label": f"viper-recon-{program}",
                "task": get_recon_task(program, domain, scope),
                "output_file": recon_file,
                "status": "pending"
            },
            "hunt": {
                "label": f"viper-hunt-{program}",
                "task": get_hunt_task(program, recon_file),
                "status": "pending"
            },
            "exploit": {
                "label": f"viper-exploit-{program}",
                "task": "Generated after hunt phase finds vulns",
                "status": "pending"
            }
        }
    }
    
    plan_file = SWARM_DIR / f"plan_{program}_{timestamp}.json"
    plan_file.write_text(json.dumps(plan, indent=2), encoding="utf-8")
    print(f"[SWARM] Plan saved: {plan_file}")
    return plan

def print_swarm_usage():
    print("""
VIPER Swarm - Parallel specialist agents (PentAGI-inspired)

Usage from Clawdbot:
  1. Create plan:
     plan = create_swarm_plan("zooplus", "zooplus.com", ["*.zooplus.com"])
  
  2. Spawn RECON agent (runs immediately):
     sessions_spawn(task=plan["phases"]["recon"]["task"], label="viper-recon-zooplus")
  
  3. After recon completes, spawn HUNT agent:
     sessions_spawn(task=plan["phases"]["hunt"]["task"], label="viper-hunt-zooplus")
  
  4. After hunt finds vulns, spawn EXPLOIT agent for each finding:
     sessions_spawn(task=exploit_task, label="viper-exploit-zooplus")

Agents run in PARALLEL where possible (recon → [hunt + exploit in parallel]).
Each agent is focused, smaller context, faster execution.

Programs available: check skills/hackagent/programs/active.json
""")

if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "plan":
        program = sys.argv[2] if len(sys.argv) > 2 else "example"
        domain = sys.argv[3] if len(sys.argv) > 3 else "example.com"
        scope = sys.argv[4:] if len(sys.argv) > 4 else [f"*.{domain}"]
        plan = create_swarm_plan(program, domain, scope)
        print(json.dumps(plan, indent=2))
    else:
        print_swarm_usage()
