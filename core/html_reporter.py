#!/usr/bin/env python3
"""
VIPER HTML Report Generator — Professional pentest-quality HTML reports.

Generates standalone HTML reports with:
- Executive Summary (LLM-generated narrative)
- Methodology overview
- Technical findings with severity badges, CVSS, CWE, OWASP
- Risk assessment matrix with CSS bar charts
- Remediation roadmap (LLM-generated)
- Appendix with scan metadata

All inline CSS, no external dependencies. Dark professional theme.
"""

import html
import json
import os
import hashlib
from datetime import datetime
from pathlib import Path
from string import Template
from typing import Dict, List, Optional, Any

REPORTS_DIR = Path(__file__).parent.parent / "reports"
REPORTS_DIR.mkdir(exist_ok=True)

# ---------------------------------------------------------------------------
# Severity helpers
# ---------------------------------------------------------------------------

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
SEVERITY_COLORS = {
    "critical": "#e74c3c",
    "high": "#e67e22",
    "medium": "#f1c40f",
    "low": "#3498db",
    "info": "#95a5a6",
}
SEVERITY_LABELS = {
    "critical": "CRITICAL",
    "high": "HIGH",
    "medium": "MEDIUM",
    "low": "LOW",
    "info": "INFO",
}


def _sev(finding: Dict) -> str:
    return (finding.get("severity") or "info").lower()


def _esc(text: Any) -> str:
    return html.escape(str(text)) if text else ""


# ---------------------------------------------------------------------------
# CSS
# ---------------------------------------------------------------------------

STYLE = """
:root {
    --bg: #1a1a2e; --bg2: #16213e; --bg3: #0f3460;
    --fg: #e0e0e0; --fg2: #a0a0a0;
    --accent: #e94560; --accent2: #533483;
    --crit: #e74c3c; --high: #e67e22; --med: #f1c40f; --low: #3498db; --info: #95a5a6;
    --border: #2a2a4a; --card: #1e1e3a;
}
*, *::before, *::after { box-sizing: border-box; }
body {
    margin: 0; padding: 0;
    font-family: 'Segoe UI', system-ui, -apple-system, sans-serif;
    background: var(--bg); color: var(--fg);
    line-height: 1.6; font-size: 15px;
}
.container { max-width: 1100px; margin: 0 auto; padding: 24px 32px; }
h1, h2, h3 { color: #fff; margin-top: 2em; }
h1 { font-size: 1.8em; border-bottom: 2px solid var(--accent); padding-bottom: 12px; margin-top: 0; }
h2 { font-size: 1.4em; border-bottom: 1px solid var(--border); padding-bottom: 8px; }
h3 { font-size: 1.15em; }
a { color: var(--accent); text-decoration: none; }
a:hover { text-decoration: underline; }
code, pre {
    font-family: 'Cascadia Code', 'Fira Code', 'Consolas', monospace;
    background: #0d0d1a; border-radius: 4px;
}
code { padding: 2px 6px; font-size: 0.9em; color: #7fdbca; }
pre { padding: 14px 18px; overflow-x: auto; border: 1px solid var(--border); font-size: 0.85em; color: #d6deeb; }

/* Header */
.report-header {
    background: linear-gradient(135deg, var(--bg2) 0%, var(--bg3) 100%);
    border: 1px solid var(--border); border-radius: 8px;
    padding: 28px 32px; margin-bottom: 32px;
}
.report-header h1 { border: none; margin: 0 0 8px; font-size: 2em; }
.report-header .meta { color: var(--fg2); font-size: 0.95em; }
.report-header .meta span { margin-right: 24px; }

/* Severity badges */
.badge {
    display: inline-block; padding: 3px 10px; border-radius: 4px;
    font-size: 0.75em; font-weight: 700; text-transform: uppercase; color: #fff;
    letter-spacing: 0.5px;
}
.badge-critical { background: var(--crit); }
.badge-high { background: var(--high); }
.badge-medium { background: var(--med); color: #333; }
.badge-low { background: var(--low); }
.badge-info { background: var(--info); }

/* Stat cards */
.stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); gap: 16px; margin: 20px 0; }
.stat-card {
    background: var(--card); border: 1px solid var(--border); border-radius: 8px;
    padding: 16px; text-align: center;
}
.stat-card .value { font-size: 2em; font-weight: 700; color: #fff; }
.stat-card .label { font-size: 0.85em; color: var(--fg2); margin-top: 4px; }

/* Bar chart */
.bar-chart { margin: 16px 0; }
.bar-row { display: flex; align-items: center; margin: 6px 0; }
.bar-label { width: 80px; font-size: 0.85em; color: var(--fg2); text-transform: uppercase; }
.bar-track { flex: 1; height: 22px; background: #111; border-radius: 4px; overflow: hidden; margin: 0 10px; }
.bar-fill { height: 100%; border-radius: 4px; transition: width 0.3s; }
.bar-count { width: 30px; font-size: 0.85em; text-align: right; }

/* Finding cards */
.finding-card {
    background: var(--card); border: 1px solid var(--border); border-radius: 8px;
    margin: 16px 0; overflow: hidden;
}
.finding-card summary {
    padding: 14px 18px; cursor: pointer; display: flex; align-items: center; gap: 12px;
    list-style: none; user-select: none;
}
.finding-card summary::-webkit-details-marker { display: none; }
.finding-card summary::before { content: '\\25B6'; font-size: 0.7em; color: var(--fg2); transition: transform 0.2s; }
.finding-card[open] summary::before { transform: rotate(90deg); }
.finding-card summary .title { flex: 1; font-weight: 600; color: #fff; }
.finding-card .body { padding: 0 18px 18px; border-top: 1px solid var(--border); }
.finding-card .body table { width: 100%; border-collapse: collapse; margin: 10px 0; }
.finding-card .body td { padding: 6px 10px; border-bottom: 1px solid #222; vertical-align: top; }
.finding-card .body td:first-child { width: 130px; color: var(--fg2); font-weight: 600; }

/* Compliance tag */
.compliance-tag {
    display: inline-block; padding: 2px 8px; border-radius: 3px;
    font-size: 0.75em; background: var(--accent2); color: #ddd; margin: 2px 4px 2px 0;
}

/* Risk matrix */
.risk-matrix { margin: 16px 0; }
.risk-matrix table { width: 100%; border-collapse: collapse; }
.risk-matrix th, .risk-matrix td {
    padding: 10px 14px; text-align: center;
    border: 1px solid var(--border);
}
.risk-matrix th { background: var(--bg3); color: #fff; }

/* Remediation table */
.remediation-table { width: 100%; border-collapse: collapse; margin: 16px 0; }
.remediation-table th, .remediation-table td { padding: 10px 14px; text-align: left; border-bottom: 1px solid var(--border); }
.remediation-table th { background: var(--bg3); color: #fff; }

/* Narrative block */
.narrative { background: var(--card); border-left: 3px solid var(--accent); padding: 16px 20px; margin: 16px 0; border-radius: 0 8px 8px 0; }

/* Footer */
.report-footer { margin-top: 48px; padding-top: 16px; border-top: 1px solid var(--border); color: var(--fg2); font-size: 0.85em; text-align: center; }

/* Print styles */
@media print {
    body { background: #fff; color: #222; font-size: 12px; }
    .container { max-width: 100%; padding: 0; }
    .report-header { background: #f5f5f5; border-color: #ccc; }
    .finding-card { break-inside: avoid; }
    .finding-card, .stat-card, .narrative { border-color: #ccc; background: #fafafa; }
    h1, h2, h3, .stat-card .value, .finding-card summary .title { color: #111; }
    .bar-track { background: #ddd; }
    code { background: #eee; color: #333; }
    pre { background: #f5f5f5; color: #222; border-color: #ccc; }
}
"""

# ---------------------------------------------------------------------------
# LLM narrative generation (optional)
# ---------------------------------------------------------------------------


async def _generate_narrative(router, prompt: str, system: str = "") -> Optional[str]:
    """Ask ModelRouter for a narrative. Returns None on failure."""
    try:
        resp = await router.complete(prompt=prompt, system=system, max_tokens=800)
        if resp and resp.text:
            return resp.text.strip()
    except Exception:
        pass
    return None


async def _llm_executive_summary(
    router, target: str, findings: List[Dict], metadata: Dict
) -> Optional[str]:
    sev_counts = _severity_counts(findings)
    prompt = (
        f"Write a concise executive summary (3-4 paragraphs) for a penetration test report.\n"
        f"Target: {target}\n"
        f"Findings: {json.dumps(sev_counts)}\n"
        f"Duration: {metadata.get('elapsed_seconds', 0):.0f}s\n"
        f"Top findings: {json.dumps([{k: f.get(k) for k in ('vuln_type','severity','url')} for f in findings[:5]], default=str)}\n"
        f"Write for a non-technical audience. Focus on business impact and risk."
    )
    return await _generate_narrative(
        router, prompt,
        system="You are a senior penetration tester writing a professional report. Be precise and factual."
    )


async def _llm_scope_methodology(
    router, target: str, metadata: Dict
) -> Optional[str]:
    phases = metadata.get("phases", {})
    tools = ["VIPER Core"]
    if "nuclei" in phases:
        tools.append("Nuclei")
    if "recon" in phases:
        tools.extend(["Subfinder", "httpx", "dnsx"])
    if "surface" in phases:
        tools.append("JS Analyzer")
    elapsed = metadata.get("elapsed_seconds", 0)
    prompt = (
        f"Write a 'Scope & Methodology' section (2-3 paragraphs) for a penetration test report.\n"
        f"Target: {target}\n"
        f"Tools used: {', '.join(tools)}\n"
        f"Phases executed: {', '.join(phases.keys()) if phases else 'N/A'}\n"
        f"Duration: {elapsed:.0f}s\n"
        f"Describe the scope of the assessment, the methodology followed, and the tools employed."
    )
    return await _generate_narrative(
        router, prompt,
        system="You are a senior penetration tester writing a professional report. Be precise and factual."
    )


async def _llm_risk_assessment(
    router, findings: List[Dict]
) -> Optional[str]:
    sev_counts = _severity_counts(findings)
    vuln_types = {}
    for f in findings:
        vt = _vuln_type(f)
        vuln_types[vt] = vuln_types.get(vt, 0) + 1
    prompt = (
        f"Write a 'Risk Assessment' section (2-3 paragraphs) for a penetration test report.\n"
        f"Severity distribution: {json.dumps(sev_counts)}\n"
        f"Vulnerability types: {json.dumps(vuln_types)}\n"
        f"Total findings: {len(findings)}\n"
        f"Discuss the overall risk posture, CVSS distribution implications, and exploitation success rates."
    )
    return await _generate_narrative(
        router, prompt,
        system="You are a senior penetration tester. Provide clear risk analysis with business context."
    )


async def _llm_attack_surface(
    router, target: str, findings: List[Dict], metadata: Dict
) -> Optional[str]:
    domains = set()
    urls = set()
    for f in findings:
        if f.get("domain"):
            domains.add(f["domain"])
        if f.get("url"):
            urls.add(f["url"].split("?")[0])
    phases = metadata.get("phases", {})
    recon = phases.get("recon", {})
    subdomains = recon.get("subdomains", []) if isinstance(recon, dict) else []
    prompt = (
        f"Write an 'Attack Surface Analysis' section (2-3 paragraphs) for a penetration test report.\n"
        f"Target: {target}\n"
        f"Domains discovered: {len(domains)}\n"
        f"Unique endpoints tested: {len(urls)}\n"
        f"Subdomains found: {len(subdomains)}\n"
        f"Summarize the digital footprint, exposed services, and areas of concern."
    )
    return await _generate_narrative(
        router, prompt,
        system="You are a senior penetration tester. Provide a clear summary of the attack surface."
    )


async def _llm_remediation_roadmap(
    router, findings: List[Dict]
) -> Optional[str]:
    unique_types = {}
    for f in findings:
        vt = f.get("vuln_type", f.get("attack", f.get("type", "unknown")))
        sev = _sev(f)
        if vt not in unique_types or SEVERITY_ORDER.get(sev, 9) < SEVERITY_ORDER.get(unique_types[vt], 9):
            unique_types[vt] = sev
    prompt = (
        f"Create a 5-tier prioritized remediation roadmap for these vulnerabilities:\n"
        f"{json.dumps(unique_types, indent=2)}\n"
        f"Tiers: Immediate (within 24h), Short-term (1 week), Medium-term (1 month), "
        f"Long-term (3 months), Monitoring (ongoing).\n"
        f"For each vulnerability, assign a tier, effort estimate, and a specific remediation step.\n"
        f"Format as a structured list grouped by tier. Most critical first."
    )
    return await _generate_narrative(
        router, prompt,
        system="You are a senior application security engineer. Give actionable, specific remediation guidance."
    )


# ---------------------------------------------------------------------------
# Data helpers
# ---------------------------------------------------------------------------


def _severity_counts(findings: List[Dict]) -> Dict[str, int]:
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        s = _sev(f)
        counts[s] = counts.get(s, 0) + 1
    return counts


def _vuln_type(f: Dict) -> str:
    return f.get("vuln_type", f.get("attack", f.get("type", "unknown")))


def _finding_id(f: Dict) -> str:
    raw = f"{f.get('url','')}{_vuln_type(f)}{f.get('payload','')}"
    return hashlib.md5(raw.encode()).hexdigest()[:8].upper()


# ---------------------------------------------------------------------------
# Section builders
# ---------------------------------------------------------------------------


def _build_header(target: str, metadata: Dict) -> str:
    ts = metadata.get("start_time", datetime.now().isoformat())
    elapsed = metadata.get("elapsed_seconds", 0)
    m, s = divmod(int(elapsed), 60)
    return f"""
<div class="report-header">
    <h1>VIPER Penetration Test Report</h1>
    <div class="meta">
        <span>Target: <strong>{_esc(target)}</strong></span>
        <span>Date: <strong>{_esc(ts[:19])}</strong></span>
        <span>Duration: <strong>{m}m {s}s</strong></span>
    </div>
</div>"""


def _build_executive_summary(findings: List[Dict], narrative: Optional[str]) -> str:
    counts = _severity_counts(findings)
    total = len(findings)

    if narrative:
        narrative_html = f'<div class="narrative">{_esc(narrative)}</div>'
    else:
        if total == 0:
            narrative_html = '<div class="narrative">No vulnerabilities were identified during this assessment.</div>'
        else:
            top_sev = "critical" if counts["critical"] else "high" if counts["high"] else "medium" if counts["medium"] else "low"
            narrative_html = (
                f'<div class="narrative">'
                f"The assessment identified <strong>{total}</strong> finding(s) across the target application. "
                f"The highest severity observed was <strong>{top_sev.upper()}</strong>. "
                f"{'Immediate remediation is recommended for critical and high severity findings.' if counts['critical'] + counts['high'] > 0 else 'No critical or high severity issues were found.'}"
                f"</div>"
            )

    cards = ""
    for sev in ("critical", "high", "medium", "low", "info"):
        c = counts[sev]
        color = SEVERITY_COLORS[sev]
        cards += f'<div class="stat-card"><div class="value" style="color:{color}">{c}</div><div class="label">{sev.upper()}</div></div>\n'

    # Bar chart
    max_count = max(counts.values()) if counts.values() else 1
    bars = ""
    for sev in ("critical", "high", "medium", "low", "info"):
        c = counts[sev]
        pct = (c / max_count * 100) if max_count > 0 else 0
        color = SEVERITY_COLORS[sev]
        bars += (
            f'<div class="bar-row">'
            f'<div class="bar-label">{sev}</div>'
            f'<div class="bar-track"><div class="bar-fill" style="width:{pct}%;background:{color}"></div></div>'
            f'<div class="bar-count">{c}</div>'
            f'</div>\n'
        )

    return f"""
<h2>1. Executive Summary</h2>
{narrative_html}
<div class="stats">
    <div class="stat-card"><div class="value">{total}</div><div class="label">Total Findings</div></div>
    {cards}
</div>
<div class="bar-chart">{bars}</div>"""


def _build_methodology(metadata: Dict, narrative: Optional[str] = None) -> str:
    phases = metadata.get("phases", {})
    phase_names = {
        "recon": ("Reconnaissance", "Subdomain enumeration, port scanning, technology fingerprinting, DNS enumeration"),
        "surface": ("Surface Mapping", "Parameter discovery, API endpoint extraction, JS analysis, secret detection"),
        "nuclei": ("Nuclei Scanning", "Automated vulnerability scanning with community templates"),
        "manual": ("Manual Attacks", "Custom payload injection, fuzzing, ReACT reasoning loop"),
        "brute": ("Brute Force", "Credential testing, directory enumeration"),
        "exploit": ("Exploitation", "Active exploitation of identified vulnerabilities"),
        "post_exploit": ("Post-Exploitation", "Privilege escalation, lateral movement, data exfiltration assessment"),
    }

    rows = ""
    for key, (name, desc) in phase_names.items():
        status = "Completed" if key in phases else "Skipped"
        color = "#2ecc71" if key in phases else var_fg2
        rows += f"<tr><td><strong>{name}</strong></td><td>{desc}</td><td style='color:{color}'>{status}</td></tr>\n"

    react_info = ""
    if metadata.get("react_trace"):
        trace = metadata["react_trace"]
        steps = trace.get("steps", [])
        llm_steps = sum(1 for s in steps if s.get("llm_used"))
        react_info = (
            f'<p style="margin-top:12px">ReACT reasoning engine executed <strong>{len(steps)}</strong> steps '
            f'(<strong>{llm_steps}</strong> LLM-guided).</p>'
        )

    narrative_html = ""
    if narrative:
        narrative_html = f'<div class="narrative">{_esc(narrative)}</div>'

    return f"""
<h2>2. Scope &amp; Methodology</h2>
{narrative_html}
<table class="remediation-table">
    <tr><th>Phase</th><th>Description</th><th>Status</th></tr>
    {rows}
</table>
{react_info}"""


var_fg2 = "#a0a0a0"


def _build_findings(findings: List[Dict]) -> str:
    if not findings:
        return "<h2>3. Technical Findings</h2>\n<p>No findings to report.</p>"

    sorted_findings = sorted(findings, key=lambda f: SEVERITY_ORDER.get(_sev(f), 9))
    cards = ""
    for i, f in enumerate(sorted_findings, 1):
        sev = _sev(f)
        fid = _finding_id(f)
        vtype = _vuln_type(f)
        url = f.get("url", "N/A")
        payload = f.get("payload", "")
        evidence = f.get("marker", f.get("evidence", f.get("details", "")))
        confidence = f.get("confidence", 0)
        source = f.get("source", "manual")
        validated = f.get("validated", False)

        # Compliance data
        comp = f.get("compliance", {})
        comp_tags = ""
        if comp:
            for tag_key in ("owasp", "cwe", "pci_dss", "nist"):
                val = comp.get(tag_key)
                if val:
                    label = tag_key.upper().replace("_", " ")
                    comp_tags += f'<span class="compliance-tag">{label}: {_esc(val)}</span>'
            cvss = comp.get("cvss_base")
            if cvss:
                comp_tags += f'<span class="compliance-tag">CVSS: {cvss}</span>'

        # LLM triage
        triage_html = ""
        triage = f.get("llm_triage", {})
        if triage:
            reasoning = triage.get("reasoning", "")
            if reasoning:
                triage_html = f'<tr><td>LLM Triage</td><td><em>{_esc(reasoning[:300])}</em></td></tr>'

        validated_badge = '<span style="color:#2ecc71">Validated</span>' if validated else '<span style="color:var(--fg2)">Unvalidated</span>'

        cards += f"""
<details class="finding-card">
    <summary>
        <span class="badge badge-{sev}">{SEVERITY_LABELS.get(sev, sev.upper())}</span>
        <span class="title">VIPER-{fid} | {_esc(vtype)}</span>
        <span style="color:var(--fg2);font-size:0.85em">{validated_badge}</span>
    </summary>
    <div class="body">
        <table>
            <tr><td>Vulnerability</td><td><strong>{_esc(vtype)}</strong></td></tr>
            <tr><td>URL</td><td><code>{_esc(url)}</code></td></tr>
            <tr><td>Severity</td><td><span class="badge badge-{sev}">{sev.upper()}</span></td></tr>
            <tr><td>Confidence</td><td>{confidence:.0%}</td></tr>
            <tr><td>Source</td><td>{_esc(source)}</td></tr>
            {'<tr><td>Payload</td><td><pre>' + _esc(payload) + '</pre></td></tr>' if payload else ''}
            {'<tr><td>Evidence</td><td><pre>' + _esc(str(evidence)[:500]) + '</pre></td></tr>' if evidence else ''}
            {triage_html}
            {'<tr><td>Compliance</td><td>' + comp_tags + '</td></tr>' if comp_tags else ''}
        </table>
    </div>
</details>"""

    return f"<h2>3. Technical Findings</h2>\n{cards}"


def _build_mitre_mapping(findings: List[Dict]) -> str:
    """Build MITRE ATT&CK mapping table from findings."""
    # Map common vuln types to MITRE ATT&CK techniques
    mitre_map = {
        "sqli": ("T1190", "Exploit Public-Facing Application", "Initial Access"),
        "sql_injection": ("T1190", "Exploit Public-Facing Application", "Initial Access"),
        "xss": ("T1189", "Drive-by Compromise", "Initial Access"),
        "cross_site_scripting": ("T1189", "Drive-by Compromise", "Initial Access"),
        "reflected_xss": ("T1189", "Drive-by Compromise", "Initial Access"),
        "ssti": ("T1203", "Exploitation for Client Execution", "Execution"),
        "rce": ("T1059", "Command and Scripting Interpreter", "Execution"),
        "cmdi": ("T1059", "Command and Scripting Interpreter", "Execution"),
        "ssrf": ("T1090", "Proxy", "Command and Control"),
        "lfi": ("T1005", "Data from Local System", "Collection"),
        "idor": ("T1078", "Valid Accounts", "Privilege Escalation"),
        "auth_bypass": ("T1078", "Valid Accounts", "Initial Access"),
        "cors": ("T1557", "Adversary-in-the-Middle", "Credential Access"),
        "open_redirect": ("T1566.002", "Phishing: Spearphishing Link", "Initial Access"),
        "xxe": ("T1059.007", "JavaScript", "Execution"),
        "crlf": ("T1071", "Application Layer Protocol", "Command and Control"),
        "csrf": ("T1185", "Browser Session Hijacking", "Collection"),
        "path_traversal": ("T1083", "File and Directory Discovery", "Discovery"),
        "info_disclosure": ("T1082", "System Information Discovery", "Discovery"),
    }

    seen = set()
    rows = ""
    for f in sorted(findings, key=lambda x: SEVERITY_ORDER.get(_sev(x), 9)):
        vt = _vuln_type(f)
        if vt in seen:
            continue
        seen.add(vt)
        sev = _sev(f)
        technique_id, technique_name, tactic = mitre_map.get(
            vt, ("N/A", "Custom/Unknown", "N/A")
        )
        # Also check finding-level MITRE data
        mitre = f.get("mitre", {})
        if mitre:
            technique_id = mitre.get("technique_id", technique_id)
            technique_name = mitre.get("technique_name", technique_name)
            tactic = mitre.get("tactic", tactic)
        rows += (
            f'<tr>'
            f'<td><span class="badge badge-{sev}">{sev.upper()}</span></td>'
            f'<td><strong>{_esc(vt)}</strong></td>'
            f'<td><code>{_esc(technique_id)}</code></td>'
            f'<td>{_esc(technique_name)}</td>'
            f'<td>{_esc(tactic)}</td>'
            f'</tr>\n'
        )

    if not rows:
        return ""

    return f"""
<h3>MITRE ATT&amp;CK Mapping</h3>
<table class="remediation-table">
    <tr><th>Severity</th><th>Vulnerability</th><th>Technique ID</th><th>Technique</th><th>Tactic</th></tr>
    {rows}
</table>"""


def _build_compliance_summary(findings: List[Dict]) -> str:
    """Build compliance summary table (OWASP, CWE, PCI DSS, NIST)."""
    owasp_counts: Dict[str, int] = {}
    cwe_counts: Dict[str, int] = {}
    pci_counts: Dict[str, int] = {}
    nist_counts: Dict[str, int] = {}

    for f in findings:
        comp = f.get("compliance", {})
        if comp.get("owasp"):
            owasp_counts[comp["owasp"]] = owasp_counts.get(comp["owasp"], 0) + 1
        if comp.get("cwe"):
            cwe_counts[comp["cwe"]] = cwe_counts.get(comp["cwe"], 0) + 1
        if comp.get("pci_dss"):
            pci_counts[comp["pci_dss"]] = pci_counts.get(comp["pci_dss"], 0) + 1
        if comp.get("nist"):
            nist_counts[comp["nist"]] = nist_counts.get(comp["nist"], 0) + 1

    if not any([owasp_counts, cwe_counts, pci_counts, nist_counts]):
        return ""

    def _framework_rows(name: str, counts: Dict[str, int]) -> str:
        if not counts:
            return ""
        items = sorted(counts.items(), key=lambda x: -x[1])
        rows_html = ""
        for ref, cnt in items:
            rows_html += f'<tr><td>{_esc(name)}</td><td><code>{_esc(ref)}</code></td><td>{cnt}</td></tr>\n'
        return rows_html

    all_rows = (
        _framework_rows("OWASP", owasp_counts)
        + _framework_rows("CWE", cwe_counts)
        + _framework_rows("PCI DSS", pci_counts)
        + _framework_rows("NIST", nist_counts)
    )

    return f"""
<h3>Compliance Summary</h3>
<table class="remediation-table">
    <tr><th>Framework</th><th>Reference</th><th>Findings</th></tr>
    {all_rows}
</table>"""


def _build_attack_graph_svg(findings: List[Dict], metadata: Dict) -> str:
    """Build an embedded SVG attack graph visualization."""
    if not findings:
        return ""

    # Compute phases and flow
    phases = metadata.get("phases", {})
    recon_count = len((phases.get("recon", {}) or {}).get("subdomains", [])) if isinstance(phases.get("recon"), dict) else 0
    surface_count = len((phases.get("surface", {}) or {}).get("api_endpoints", [])) if isinstance(phases.get("surface"), dict) else 0
    nuclei_count = len((phases.get("nuclei", {}) or {}).get("findings", [])) if isinstance(phases.get("nuclei"), dict) else 0
    manual_count = len((phases.get("manual", {}) or {}).get("findings", [])) if isinstance(phases.get("manual"), dict) else 0
    total_findings = len(findings)

    # Node positions for the flow graph
    nodes = [
        ("Target", 80, 150, "#4da6ff", "1"),
        ("Recon", 230, 80, "#6366f1", str(recon_count or "?")),
        ("Surface", 230, 220, "#818cf8", str(surface_count or "?")),
        ("Nuclei", 400, 80, "#ffd700", str(nuclei_count or "?")),
        ("Manual", 400, 220, "#ff8c00", str(manual_count or "?")),
        ("Findings", 560, 150, "#ff4444", str(total_findings)),
    ]

    edges = [
        (80, 150, 230, 80), (80, 150, 230, 220),
        (230, 80, 400, 80), (230, 220, 400, 220),
        (400, 80, 560, 150), (400, 220, 560, 150),
    ]

    svg_nodes = ""
    for label, x, y, color, count in nodes:
        svg_nodes += f'''
        <circle cx="{x}" cy="{y}" r="30" fill="{color}" fill-opacity="0.2" stroke="{color}" stroke-width="2"/>
        <text x="{x}" y="{y - 8}" text-anchor="middle" fill="#fff" font-size="11" font-weight="600">{_esc(label)}</text>
        <text x="{x}" y="{y + 12}" text-anchor="middle" fill="{color}" font-size="13" font-weight="700">{_esc(count)}</text>'''

    svg_edges = ""
    for x1, y1, x2, y2 in edges:
        svg_edges += f'''
        <line x1="{x1 + 30}" y1="{y1}" x2="{x2 - 30}" y2="{y2}"
              stroke="rgba(255,255,255,0.15)" stroke-width="2" marker-end="url(#arrowhead)"/>'''

    return f"""
<h3>Attack Flow Graph</h3>
<div style="background:var(--card);border:1px solid var(--border);border-radius:8px;padding:16px;overflow-x:auto;">
<svg width="640" height="300" viewBox="0 0 640 300" xmlns="http://www.w3.org/2000/svg">
    <defs>
        <marker id="arrowhead" markerWidth="10" markerHeight="7" refX="10" refY="3.5" orient="auto">
            <polygon points="0 0, 10 3.5, 0 7" fill="rgba(255,255,255,0.3)"/>
        </marker>
    </defs>
    {svg_edges}
    {svg_nodes}
</svg>
</div>"""


def _build_risk_assessment(findings: List[Dict], narrative: Optional[str] = None) -> str:
    counts = _severity_counts(findings)
    total = len(findings)

    # Simple risk score: critical=10, high=5, medium=2, low=1
    weights = {"critical": 10, "high": 5, "medium": 2, "low": 1, "info": 0}
    risk_score = sum(counts.get(s, 0) * w for s, w in weights.items())
    max_score = total * 10 if total else 1
    risk_pct = min(100, int(risk_score / max_score * 100)) if max_score else 0

    if risk_score == 0:
        risk_level, risk_color = "LOW", "#2ecc71"
    elif risk_score <= 10:
        risk_level, risk_color = "MODERATE", "#f1c40f"
    elif risk_score <= 30:
        risk_level, risk_color = "HIGH", "#e67e22"
    else:
        risk_level, risk_color = "CRITICAL", "#e74c3c"

    narrative_html = ""
    if narrative:
        narrative_html = f'<div class="narrative">{_esc(narrative)}</div>'

    # Vuln type breakdown
    type_counts: Dict[str, Dict[str, int]] = {}
    for f in findings:
        vt = _vuln_type(f)
        sev = _sev(f)
        if vt not in type_counts:
            type_counts[vt] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        type_counts[vt][sev] = type_counts[vt].get(sev, 0) + 1

    matrix_rows = ""
    for vt, sevs in sorted(type_counts.items()):
        row_total = sum(sevs.values())
        cells = ""
        for s in ("critical", "high", "medium", "low", "info"):
            v = sevs.get(s, 0)
            cells += f'<td style="color:{SEVERITY_COLORS[s]}">{v if v else "-"}</td>'
        matrix_rows += f"<tr><td style='text-align:left'><strong>{_esc(vt)}</strong></td>{cells}<td>{row_total}</td></tr>\n"

    return f"""
<h2>4. Risk Assessment</h2>
{narrative_html}
<div class="stats">
    <div class="stat-card">
        <div class="value" style="color:{risk_color}">{risk_level}</div>
        <div class="label">Overall Risk</div>
    </div>
    <div class="stat-card">
        <div class="value">{risk_score}</div>
        <div class="label">Risk Score</div>
    </div>
    <div class="stat-card">
        <div class="value">{total}</div>
        <div class="label">Total Findings</div>
    </div>
</div>
<div class="risk-matrix">
    <table>
        <tr><th style="text-align:left">Vulnerability Type</th><th>Critical</th><th>High</th><th>Medium</th><th>Low</th><th>Info</th><th>Total</th></tr>
        {matrix_rows}
    </table>
</div>"""


def _build_attack_surface(findings: List[Dict], metadata: Dict, narrative: Optional[str] = None) -> str:
    """Section 5: Attack Surface Analysis."""
    domains = set()
    urls = set()
    techs = set()
    for f in findings:
        if f.get("domain"):
            domains.add(f["domain"])
        if f.get("url"):
            urls.add(f["url"].split("?")[0])

    phases = metadata.get("phases", {})
    recon = phases.get("recon", {})
    subdomains = recon.get("subdomains", []) if isinstance(recon, dict) else []

    # Gather technologies
    for f in findings:
        for t in (f.get("technologies") or []):
            techs.add(t if isinstance(t, str) else t.get("name", ""))

    narrative_html = ""
    if narrative:
        narrative_html = f'<div class="narrative">{_esc(narrative)}</div>'
    elif not findings:
        narrative_html = '<div class="narrative">No significant attack surface was identified during this assessment.</div>'
    else:
        narrative_html = (
            f'<div class="narrative">'
            f'The assessment identified <strong>{len(domains)}</strong> unique domain(s) with '
            f'<strong>{len(urls)}</strong> unique endpoint(s). '
            f'{f"<strong>{len(subdomains)}</strong> subdomain(s) were discovered during reconnaissance. " if subdomains else ""}'
            f'The attack surface includes {len(techs)} identified technologies.'
            f'</div>'
        )

    cards = f"""
<div class="stats">
    <div class="stat-card"><div class="value">{len(domains)}</div><div class="label">Domains</div></div>
    <div class="stat-card"><div class="value">{len(urls)}</div><div class="label">Endpoints</div></div>
    <div class="stat-card"><div class="value">{len(subdomains)}</div><div class="label">Subdomains</div></div>
    <div class="stat-card"><div class="value">{len(techs)}</div><div class="label">Technologies</div></div>
</div>"""

    return f"""
<h2>5. Attack Surface Analysis</h2>
{narrative_html}
{cards}"""


def _build_remediation(findings: List[Dict], narrative: Optional[str]) -> str:
    if narrative:
        return f"""
<h2>6. Remediation Roadmap</h2>
<div class="narrative">{_esc(narrative)}</div>"""

    # Template-based 5-tier fallback
    if not findings:
        return "<h2>6. Remediation Roadmap</h2>\n<p>No remediation actions required.</p>"

    remediation_map = {
        "sqli": ("Parameterize all database queries. Use prepared statements.", "2-4h"),
        "sql_injection": ("Parameterize all database queries. Use prepared statements.", "2-4h"),
        "xss": ("Encode output contextually. Implement Content-Security-Policy.", "2-4h"),
        "cross_site_scripting": ("Encode output contextually. Implement Content-Security-Policy.", "2-4h"),
        "reflected_xss": ("Encode output contextually. Implement Content-Security-Policy.", "2-4h"),
        "ssti": ("Sandbox template engines. Avoid user input in templates.", "4-8h"),
        "ssrf": ("Validate/whitelist URLs server-side. Block internal ranges.", "2-4h"),
        "lfi": ("Remove file path user input. Use whitelisted identifiers.", "2-4h"),
        "rce": ("Remove eval/exec usage. Sanitize all command inputs.", "4-8h"),
        "cmdi": ("Use parameterized APIs instead of shell commands.", "2-4h"),
        "idor": ("Implement authorization checks on every object access.", "4-8h"),
        "cors": ("Restrict Access-Control-Allow-Origin to trusted domains.", "1-2h"),
        "open_redirect": ("Validate redirect targets against a whitelist.", "1-2h"),
        "xxe": ("Disable external entity processing in XML parsers.", "1-2h"),
        "crlf": ("Strip CR/LF from user input used in headers.", "1-2h"),
        "auth_bypass": ("Review authentication flow. Enforce server-side checks.", "4-8h"),
    }

    # 5-tier priority mapping based on severity
    tier_map = {
        "critical": ("Immediate", "#e74c3c", "Within 24 hours"),
        "high": ("Short-term", "#e67e22", "Within 1 week"),
        "medium": ("Medium-term", "#f1c40f", "Within 1 month"),
        "low": ("Long-term", "#3498db", "Within 3 months"),
        "info": ("Monitoring", "#95a5a6", "Ongoing"),
    }

    seen = set()
    tier_groups: Dict[str, List[str]] = {
        "Immediate": [], "Short-term": [], "Medium-term": [],
        "Long-term": [], "Monitoring": [],
    }
    sorted_findings = sorted(findings, key=lambda f: SEVERITY_ORDER.get(_sev(f), 9))
    for f in sorted_findings:
        vt = _vuln_type(f)
        if vt in seen:
            continue
        seen.add(vt)
        sev = _sev(f)
        tier_name, tier_color, tier_timeline = tier_map.get(sev, ("Monitoring", "#95a5a6", "Ongoing"))
        fix, effort = remediation_map.get(vt, ("Review and remediate according to industry best practices.", "2-4h"))
        tier_groups[tier_name].append(
            f'<tr>'
            f'<td><span class="badge badge-{sev}">{sev.upper()}</span></td>'
            f'<td><strong>{_esc(vt)}</strong></td>'
            f'<td>{fix}</td><td>{effort}</td>'
            f'</tr>\n'
        )

    tables = ""
    for tier_name in ("Immediate", "Short-term", "Medium-term", "Long-term", "Monitoring"):
        items = tier_groups[tier_name]
        if not items:
            continue
        tier_info = {"Immediate": ("#e74c3c", "Within 24 hours"), "Short-term": ("#e67e22", "Within 1 week"),
                     "Medium-term": ("#f1c40f", "Within 1 month"), "Long-term": ("#3498db", "Within 3 months"),
                     "Monitoring": ("#95a5a6", "Ongoing")}
        color, timeline = tier_info[tier_name]
        tables += f"""
<h3 style="color:{color};margin-top:20px">{tier_name} <span style="font-size:0.8em;color:var(--fg2)">({timeline})</span></h3>
<table class="remediation-table">
    <tr><th>Severity</th><th>Issue</th><th>Remediation</th><th>Effort</th></tr>
    {''.join(items)}
</table>"""

    return f"""
<h2>6. Remediation Roadmap</h2>
{tables}"""


def _build_appendix(metadata: Dict) -> str:
    phases = metadata.get("phases", {})
    elapsed = metadata.get("elapsed_seconds", 0)

    # Tools used
    tools = ["VIPER Core v2"]
    if "nuclei" in phases:
        tools.append("Nuclei")
    if "recon" in phases:
        tools.extend(["Subfinder", "httpx", "dnsx"])
    if "surface" in phases:
        tools.append("JS Analyzer")

    tools_html = ", ".join(tools)

    # Phase timing
    phase_rows = ""
    for pname, pdata in phases.items():
        if isinstance(pdata, dict):
            pduration = pdata.get("duration_seconds", pdata.get("elapsed", "N/A"))
            pcount = ""
            if pname == "recon":
                pcount = f"{len(pdata.get('subdomains', []))} subdomains"
            elif pname == "nuclei":
                pcount = f"{len(pdata.get('findings', []))} findings"
            elif pname == "surface":
                pcount = f"{len(pdata.get('api_endpoints', []))} endpoints"
            elif pname == "manual":
                pcount = f"{len(pdata.get('findings', []))} findings"
            phase_rows += f"<tr><td>{_esc(pname)}</td><td>{pduration}</td><td>{pcount}</td></tr>\n"

    # ReACT trace
    react_html = ""
    react_trace = metadata.get("react_trace")
    if react_trace:
        steps = react_trace.get("steps", [])
        react_rows = ""
        for i, step in enumerate(steps, 1):
            action = step.get("action", "")
            thought = step.get("thought", "")[:120]
            llm = "LLM" if step.get("llm_used") else "Q"
            react_rows += f"<tr><td>{i}</td><td>{_esc(thought)}</td><td>{_esc(action)}</td><td>{llm}</td></tr>\n"
        react_html = f"""
<h3>ReACT Trace</h3>
<table class="remediation-table">
    <tr><th>#</th><th>Thought</th><th>Action</th><th>Engine</th></tr>
    {react_rows}
</table>"""

    # EvoGraph stats
    evograph_html = ""
    evograph = metadata.get("evograph_stats")
    if evograph:
        evograph_html = f'<p><strong>EvoGraph:</strong> {_esc(json.dumps(evograph))}</p>'

    return f"""
<h2>7. Appendix</h2>
<h3>Scan Metadata</h3>
<table class="remediation-table">
    <tr><td><strong>Total Duration</strong></td><td>{elapsed:.1f} seconds</td></tr>
    <tr><td><strong>Tools Used</strong></td><td>{tools_html}</td></tr>
    <tr><td><strong>Generated</strong></td><td>{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</td></tr>
</table>

<h3>Phase Details</h3>
<table class="remediation-table">
    <tr><th>Phase</th><th>Duration</th><th>Results</th></tr>
    {phase_rows}
</table>
{react_html}
{evograph_html}"""


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


async def generate_report(
    findings: List[Dict],
    target: str,
    metadata: Dict,
    model_router=None,
) -> str:
    """
    Generate a full HTML penetration test report.

    Args:
        findings: List of finding dicts from VIPER.
        target: Target URL.
        metadata: Dict with phases, elapsed_seconds, react_trace, etc.
        model_router: Optional ModelRouter for LLM narratives.

    Returns:
        Complete HTML string.
    """
    # LLM narratives (optional)
    exec_narrative = None
    scope_narrative = None
    risk_narrative = None
    surface_narrative = None
    remediation_narrative = None

    if model_router:
        try:
            exec_narrative = await _llm_executive_summary(model_router, target, findings, metadata)
        except Exception:
            pass
        try:
            scope_narrative = await _llm_scope_methodology(model_router, target, metadata)
        except Exception:
            pass
        try:
            risk_narrative = await _llm_risk_assessment(model_router, findings)
        except Exception:
            pass
        try:
            surface_narrative = await _llm_attack_surface(model_router, target, findings, metadata)
        except Exception:
            pass
        try:
            remediation_narrative = await _llm_remediation_roadmap(model_router, findings)
        except Exception:
            pass

    sections = [
        _build_header(target, metadata),
        _build_executive_summary(findings, exec_narrative),
        _build_methodology(metadata, scope_narrative),
        _build_findings(findings),
        _build_mitre_mapping(findings),
        _build_risk_assessment(findings, risk_narrative),
        _build_attack_surface(findings, metadata, surface_narrative),
        _build_remediation(findings, remediation_narrative),
        _build_compliance_summary(findings),
        _build_attack_graph_svg(findings, metadata),
        _build_appendix(metadata),
    ]

    body = "\n".join(sections)

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>VIPER Report — {_esc(target)}</title>
    <style>{STYLE}</style>
</head>
<body>
<div class="container">
{body}
<div class="report-footer">
    Generated by VIPER v3.0 &mdash; Autonomous Bug Bounty Scanner<br>
    This report is confidential and intended for authorized recipients only.
</div>
</div>
</body>
</html>"""


def generate_report_sync(
    findings: List[Dict],
    target: str,
    metadata: Dict,
) -> str:
    """Synchronous version without LLM narratives."""
    import asyncio
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(generate_report(findings, target, metadata))
    finally:
        loop.close()


def save_report(html_content: str, filename: Optional[str] = None) -> Path:
    """
    Write HTML report to reports/ directory.

    Args:
        html_content: Complete HTML string.
        filename: Optional filename. Auto-generated if None.

    Returns:
        Path to the saved file.
    """
    if not filename:
        filename = f"viper_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
    if not filename.endswith(".html"):
        filename += ".html"

    path = REPORTS_DIR / filename
    path.write_text(html_content, encoding="utf-8")
    return path


def export_pdf(html_path: str, pdf_path: str = None) -> str:
    """Export HTML report to PDF using wkhtmltopdf if available.

    Args:
        html_path: Path to the HTML report file.
        pdf_path: Output PDF path. Defaults to same name with .pdf extension.

    Returns:
        Path to the generated PDF.

    Raises:
        RuntimeError: If wkhtmltopdf is not installed.
    """
    import shutil
    import subprocess

    html_path = str(html_path)
    if pdf_path is None:
        pdf_path = html_path.replace(".html", ".pdf")

    wk = shutil.which("wkhtmltopdf")
    if wk:
        subprocess.run(
            [wk, "--quiet", "--enable-local-file-access", html_path, pdf_path],
            timeout=60, check=True,
        )
        return pdf_path
    else:
        raise RuntimeError(
            "wkhtmltopdf not installed. Install it for PDF export: "
            "https://wkhtmltopdf.org/downloads.html"
        )
