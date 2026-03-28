#!/usr/bin/env python3
"""
VIPER 4.0 Phase 6 — CISO-Quality Report Narrative Generator.

Generates 6 professional
narrative sections using VIPER's model_router for LLM calls.

Each section is crafted to match the depth and tone of reports from
top-tier security consultancies (NCC Group, CrowdStrike, Bishop Fox).

Stdlib only. No external dependencies.
"""

import asyncio
import json
import logging
import re
from datetime import datetime
from typing import Any, Dict, List, Optional

logger = logging.getLogger("viper.report_narrative")

REPORT_SECTIONS = [
    "executive_summary",
    "scope_narrative",
    "risk_narrative",
    "findings_narrative",
    "attack_surface_narrative",
    "recommendations_narrative",
]

# ══════════════════════════════════════════════════════════════════════
# SECTION-SPECIFIC PROMPTS
# ══════════════════════════════════════════════════════════════════════

_BASE_RULES = (
    "You are a senior penetration testing report writer at a world-class "
    "offensive security consultancy. Your output must read like a polished "
    "deliverable from NCC Group, CrowdStrike, or Bishop Fox.\n\n"
    "ABSOLUTE RULES:\n"
    "1. Write in flowing prose paragraphs with logical transitions.\n"
    "2. NEVER use markdown formatting, headings, asterisks, or hash symbols.\n"
    "3. NEVER use bullet points or numbered lists as the primary structure.\n"
    "4. NEVER use em dashes; use commas, semicolons, colons, or separate sentences.\n"
    "5. NEVER include AI disclaimers, caveats about being an AI, or meta-commentary.\n"
    "6. NEVER use filler phrases like 'in conclusion', 'it is worth noting', or 'importantly'.\n"
    "7. Reference SPECIFIC data points: CVE IDs, CVSS scores, technology versions, "
    "IP addresses, endpoint paths, CWE/CAPEC IDs, and finding counts.\n"
    "8. Explain WHY each issue matters, not just WHAT was found.\n"
    "9. Output ONLY the narrative text. No JSON wrapping, no section headers.\n"
)

SECTION_PROMPTS: Dict[str, str] = {
    "executive_summary": (
        _BASE_RULES +
        "SECTION: Executive Summary\n"
        "AUDIENCE: CISO, board members, executive stakeholders.\n"
        "LENGTH: Exactly 3-4 paragraphs. This must be readable in under 2 minutes.\n"
        "TONE: Authoritative, concise, business-focused. Zero jargon without explanation.\n\n"
        "PARAGRAPH 1 (VERDICT): Lead with the overall risk score and risk label. "
        "State the single most critical finding immediately. Declare whether the target "
        "is actively exploitable right now. Provide key metrics: total findings with "
        "critical/high breakdown, confirmed exploits count, and attack surface size "
        "(subdomains, IPs, endpoints discovered).\n\n"
        "PARAGRAPH 2 (BUSINESS IMPACT): Translate technical findings into business "
        "language. What could an attacker realistically achieve? Remote code execution "
        "on production systems? Bulk data exfiltration? Lateral movement into internal "
        "networks? Explicitly name regulatory implications (GDPR, PCI-DSS, SOC 2, HIPAA) "
        "where applicable. Reference the exploitable count and any CISA Known Exploited "
        "Vulnerabilities catalog entries.\n\n"
        "PARAGRAPH 3 (TOP ACTIONS): Name the 3 most urgent remediation actions with "
        "enough specificity that an engineer could start work immediately. Reference the "
        "total open remediation items and point the reader to the Recommendations section "
        "for the complete prioritized triage.\n\n"
        "PARAGRAPH 4 (CONCLUSION): One clear, decisive statement of overall security "
        "posture and the single most urgent action to take within the next 24 hours.\n\n"
        "FORBIDDEN: Do not enumerate every CVE here. Do not list every finding. "
        "Those details belong in later sections. The reader must grasp the situation "
        "in 60 seconds.\n"
    ),

    "scope_narrative": (
        _BASE_RULES +
        "SECTION: Scope and Methodology\n"
        "AUDIENCE: Technical leads and compliance officers.\n"
        "LENGTH: 4-6 paragraphs.\n"
        "TONE: Precise, methodical, authoritative.\n\n"
        "REQUIRED CONTENT:\n"
        "- Target domain and all subdomains enumerated (active vs total count).\n"
        "- IP addresses discovered, distinguishing CDN-fronted from directly exposed.\n"
        "- Total endpoints crawled, parameters identified, and injection surfaces mapped.\n"
        "- Services and open ports identified with version information.\n"
        "- Technologies fingerprinted with their detected versions.\n"
        "- If Rules of Engagement context is available (client name, engagement type, "
        "date range), incorporate it naturally.\n\n"
        "METHODOLOGY COVERAGE:\n"
        "Describe the multi-phase approach: (1) automated reconnaissance including "
        "subdomain enumeration, DNS resolution, port scanning, web crawling, and "
        "technology fingerprinting; (2) vulnerability correlation matching detected "
        "software versions against CVE databases; (3) exploit validation through "
        "confirmed exploitation attempts; (4) manual analysis and attack chain "
        "construction.\n\n"
        "Mention the graph-based approach to mapping relationships between assets, "
        "vulnerabilities, and attack paths. Describe the timeline and duration of "
        "the assessment.\n\n"
        "FORBIDDEN: Do not discuss specific findings here. This section establishes "
        "scope and methodology only.\n"
    ),

    "risk_narrative": (
        _BASE_RULES +
        "SECTION: Risk Analysis (Detailed Technical Assessment)\n"
        "AUDIENCE: Security engineers, penetration testers, technical management.\n"
        "LENGTH: 8-12 paragraphs minimum. This is the deep-dive technical analysis.\n"
        "TONE: Technical, evidence-based, analytical.\n\n"
        "STRUCTURE (cover ALL of these subsections in flowing prose):\n\n"
        "VULNERABILITY LANDSCAPE: Complete numerical breakdown of all vulnerability "
        "findings with per-severity counts (critical, high, medium, low). Total known "
        "CVEs with their own per-severity breakdown. Average CVSS score. Contextualize "
        "these numbers against the attack surface size.\n\n"
        "CVSS DISTRIBUTION ANALYSIS: Where do scores cluster? What does the distribution "
        "shape reveal? A concentration in medium-range suggests systematic misconfiguration; "
        "a few isolated criticals suggest targeted high-impact vulnerabilities in specific "
        "components.\n\n"
        "EXPLOITATION RESULTS: Detail EVERY confirmed exploitation success. For each, "
        "name the exact CVE exploited, the target IP address, the attack type or module "
        "used, and what level of access was achieved (RCE, file read, information disclosure, "
        "authentication bypass). Highlight any CISA KEV entries by CVE ID. State total "
        "exploitable count.\n\n"
        "TECHNOLOGY AND CVE ANALYSIS: For each concerning technology, name it with its "
        "detected version, associated CVE count, and the highest-severity CVE. Describe "
        "complete attack chains from Technology through CVE to CWE to CAPEC, showing "
        "how theoretical vulnerabilities become practical attack patterns.\n\n"
        "INFRASTRUCTURE SECURITY POSTURE: Certificate health (valid, expired, self-signed), "
        "security header deployment (which headers are present or missing, weighted coverage "
        "score), injectable parameter analysis (count and positions: query, body, header, cookie).\n\n"
        "ATTACK SURFACE METRICS: Subdomains (active vs total), IPs (direct vs CDN-fronted), "
        "endpoints, parameters, open ports, and services. Total graph nodes for scope context.\n\n"
        "SECRETS AND DATA EXPOSURE: GitHub secrets or sensitive files discovered, with counts "
        "and implications. If none found, explicitly state that no credential exposure was detected.\n\n"
        "FORBIDDEN: Do not use bullet-point lists. Every data point must be woven into "
        "analytical prose that explains significance, not just states facts.\n"
    ),

    "findings_narrative": (
        _BASE_RULES +
        "SECTION: Detailed Findings\n"
        "AUDIENCE: Security engineers and remediation teams.\n"
        "LENGTH: 6-10 paragraphs, scaling with the number of findings.\n"
        "TONE: Technical, evidence-rich, structured by category.\n\n"
        "REQUIRED CONTENT:\n"
        "Group and discuss findings by category: remote code execution, injection "
        "vulnerabilities, authentication/authorization flaws, misconfigurations, "
        "information disclosure, missing security controls, cryptographic weaknesses, "
        "and any other relevant categories present in the data.\n\n"
        "For each significant finding, describe:\n"
        "- What was found (the vulnerability or weakness)\n"
        "- Where it was found (target host, endpoint path, parameter name)\n"
        "- Severity level and CVSS score\n"
        "- Associated CVE IDs\n"
        "- CWE weakness category\n"
        "- Whether an exploit exists and was validated\n"
        "- What an attacker could achieve by exploiting it\n"
        "- The step-by-step exploitation chain for confirmed exploits\n\n"
        "Discuss any GitHub secrets or sensitive files exposed. Compare the ratio of "
        "CVE-based findings (from known vulnerable software) versus scanner-detected "
        "findings versus chain-discovered findings to characterize the nature of the "
        "security issues.\n\n"
        "Pay special attention to findings with confirmed exploits. Describe the "
        "exploitation chain step by step, including the initial access vector, "
        "the exploitation technique, and the resulting impact.\n\n"
        "FORBIDDEN: Do not simply list findings in a table-like format. Each finding "
        "or finding group must be discussed in analytical prose with context and impact.\n"
    ),

    "attack_surface_narrative": (
        _BASE_RULES +
        "SECTION: Attack Surface Analysis\n"
        "AUDIENCE: Infrastructure teams, DevOps, network security.\n"
        "LENGTH: 5-8 paragraphs.\n"
        "TONE: Technical, infrastructure-focused, diagnostic.\n\n"
        "REQUIRED CONTENT:\n"
        "DIGITAL FOOTPRINT: Number of subdomains (active vs total), IP addresses and "
        "their CDN/direct exposure status, open ports and running services with version "
        "information, web endpoints, and crawled parameters.\n\n"
        "TECHNOLOGY STACK: Web servers, frameworks, CMS platforms, JavaScript libraries, "
        "and any other detected technologies. Highlight any running outdated or end-of-life "
        "versions with their specific version numbers.\n\n"
        "INFRASTRUCTURE SECURITY: Certificate health analysis (valid, expired, self-signed "
        "with counts), security header coverage (HSTS, CSP, X-Frame-Options, X-Content-Type-Options, "
        "Referrer-Policy, Permissions-Policy) with gap analysis, and parameter injection surface "
        "(how many parameters are injectable and in what positions).\n\n"
        "SECURITY MATURITY ASSESSMENT: Based on the attack surface data, assess what it "
        "reveals about the organization's security maturity, patch management practices, "
        "configuration management discipline, and infrastructure hygiene. Identify patterns "
        "that suggest systemic issues versus isolated oversights.\n\n"
        "FORBIDDEN: Do not discuss specific CVEs or exploits here. This section focuses "
        "on infrastructure exposure and surface area, not vulnerability exploitation.\n"
    ),

    "recommendations_narrative": (
        _BASE_RULES +
        "SECTION: Remediation Recommendations\n"
        "AUDIENCE: Security engineers, system administrators, management.\n"
        "LENGTH: This MUST be the LONGEST section in the entire report. 12-20 paragraphs "
        "minimum. Every single finding, CVE, and security gap must be addressed.\n"
        "TONE: Prescriptive, actionable, prioritized by urgency.\n\n"
        "This is NOT a summary. This is a COMPLETE, EXHAUSTIVE remediation triage "
        "covering 100%% of all issues found. Organize as a ranked triage from most "
        "urgent to least urgent:\n\n"
        "TIER 1 (EMERGENCY, fix within 24-48 hours): Start with any confirmed "
        "exploitation successes. For each, name the exact CVE, target IP, attack "
        "type/module, and evidence. Then cover any CISA KEV catalog entries. For each, "
        "explain the specific vulnerability, why it is urgent (actively exploited in the "
        "wild), exact remediation steps (upgrade to version X, apply patch Y, disable "
        "feature Z), and compensating controls if patching is not immediately possible "
        "(WAF rules, network segmentation, service shutdown).\n\n"
        "TIER 2 (CRITICAL/HIGH CVEs, fix within 1 week): Address EVERY critical and "
        "high severity CVE from the data. For EACH CVE, state: the CVE ID, affected "
        "technology and version, CVSS score, CWE weakness category, CAPEC attack pattern "
        "if available, what an attacker could achieve, and the specific remediation action. "
        "Group related CVEs affecting the same technology but still address each individually.\n\n"
        "TIER 3 (MEDIUM FINDINGS, fix within 1 month): Cover ALL medium severity findings: "
        "missing security headers, missing email authentication (SPF/DMARC/DKIM), certificate "
        "issues, information disclosure, directory listings. For each, explain the risk and "
        "provide specific remediation instructions with configuration examples where possible.\n\n"
        "TIER 4 (LOW/INFORMATIONAL, fix within 1 quarter): Address remaining low severity "
        "items, outdated but not critically vulnerable software, security header improvements, "
        "and general hardening recommendations.\n\n"
        "TIER 5 (STRATEGIC RECOMMENDATIONS): Long-term program improvements: vulnerability "
        "management program establishment, patch management cadence, WAF deployment strategy, "
        "security monitoring and alerting, regular penetration testing schedule, security "
        "header policy, certificate lifecycle management, secure development training, and "
        "incident response planning.\n\n"
        "ABSOLUTE REQUIREMENT: Every CVE must be mentioned by ID. Every finding must be "
        "addressed with specific remediation steps. If there are 20 CVEs, discuss all 20. "
        "If there are 50 findings, discuss all 50. Do not summarize or skip items.\n\n"
        "FORBIDDEN: Do not use bullet points as the primary structure. Remediation "
        "instructions must be woven into analytical prose. Do not use vague advice like "
        "'keep software updated'; specify exactly which software, which version to upgrade to, "
        "and which CVE it addresses.\n"
    ),
}


# ══════════════════════════════════════════════════════════════════════
# REPORT NARRATIVE CLASS
# ══════════════════════════════════════════════════════════════════════

class ReportNarrative:
    """Generate 6 CISO-quality narrative sections for pentest reports."""

    def __init__(self, model_router=None, graph_engine=None):
        """
        Args:
            model_router: VIPER ModelRouter instance for LLM calls.
                          If None, falls back to template-based generation.
            graph_engine: Optional GraphEngine for enriching report data
                          with graph-derived metrics.
        """
        self.model_router = model_router
        self.graph_engine = graph_engine

    async def generate(self, scan_data: dict) -> dict:
        """
        Generate 6 CISO-quality narrative sections.

        scan_data should contain:
        - target: str
        - vulnerabilities: list of vuln dicts
        - technologies: list
        - endpoints: list
        - attack_chains: list
        - findings_by_severity: dict
        - scan_duration: str
        - mitre_mappings: list

        Returns dict with keys matching REPORT_SECTIONS, each containing
        the LLM-generated narrative text.
        """
        if self.model_router is None:
            logger.warning("No model_router available, using sync fallback")
            return self.generate_sync(scan_data)

        condensed = self._condense_scan_data(scan_data)
        results = {}

        # Generate all sections concurrently
        tasks = {
            section: self._generate_section(section, condensed)
            for section in REPORT_SECTIONS
        }

        gathered = await asyncio.gather(
            *tasks.values(), return_exceptions=True
        )

        for section, result in zip(tasks.keys(), gathered):
            if isinstance(result, Exception):
                logger.error(f"Section '{section}' generation failed: {result}")
                results[section] = self._fallback_section(section, condensed)
            else:
                results[section] = result

        return results

    async def _generate_section(self, section_name: str, data: dict) -> str:
        """Generate a single section using section-specific prompt."""
        system_prompt = SECTION_PROMPTS.get(section_name, "")
        if not system_prompt:
            return ""

        user_prompt = (
            f"Security assessment data for the '{section_name.replace('_', ' ').title()}' "
            f"section:\n\n{json.dumps(data, indent=2, default=str)}\n\n"
            f"Generate the narrative now."
        )

        # Use higher token limits for recommendations (longest section)
        max_tokens = 4096 if section_name == "recommendations_narrative" else 2048

        try:
            response = await self.model_router.complete(
                prompt=user_prompt,
                system=system_prompt,
                max_tokens=max_tokens,
                temperature=0.3,
            )

            if response is None:
                logger.warning(
                    f"LLM returned None for section '{section_name}', using fallback"
                )
                return self._fallback_section(section_name, data)

            text = response.text.strip()

            # Strip any accidental markdown fencing
            text = re.sub(r'^```(?:text|markdown)?\s*\n', '', text)
            text = re.sub(r'\n```\s*$', '', text)
            # Strip any JSON wrapping the LLM might add
            text = re.sub(r'^["\']|["\']$', '', text.strip())

            return text

        except Exception as e:
            logger.error(f"LLM error for section '{section_name}': {e}")
            return self._fallback_section(section_name, data)

    def generate_sync(self, scan_data: dict) -> dict:
        """Synchronous fallback (template-based, no LLM)."""
        data = self._condense_scan_data(scan_data)
        results = {}

        for section in REPORT_SECTIONS:
            results[section] = self._fallback_section(section, data)

        return results

    # ------------------------------------------------------------------
    # Data condensation
    # ------------------------------------------------------------------

    def _condense_scan_data(self, scan_data: dict) -> dict:
        """Reshape scan_data into a structured payload for LLM consumption."""
        vulns = scan_data.get("vulnerabilities", [])
        findings_by_sev = scan_data.get("findings_by_severity", {})
        technologies = scan_data.get("technologies", [])
        endpoints = scan_data.get("endpoints", [])
        attack_chains = scan_data.get("attack_chains", [])
        mitre = scan_data.get("mitre_mappings", [])

        # Severity counts
        critical = len(findings_by_sev.get("critical", []))
        high = len(findings_by_sev.get("high", []))
        medium = len(findings_by_sev.get("medium", []))
        low = len(findings_by_sev.get("low", []))

        # CVSS stats
        cvss_scores = [
            v.get("cvss", v.get("cvss_score", 0)) for v in vulns
            if v.get("cvss", v.get("cvss_score", 0))
        ]
        avg_cvss = round(sum(cvss_scores) / len(cvss_scores), 1) if cvss_scores else 0.0

        # CVE extraction
        all_cves = []
        for v in vulns:
            cve_id = v.get("cve_id") or v.get("cve")
            if cve_id:
                all_cves.append(cve_id)

        # Exploit successes
        exploit_successes = [
            v for v in vulns
            if v.get("exploit_confirmed") or v.get("exploitable")
        ]

        # Technologies with CVEs
        tech_with_cves = [
            t for t in technologies
            if t.get("cve_count", 0) > 0 or t.get("cves")
        ]

        return {
            "target": scan_data.get("target", "unknown"),
            "scan_duration": scan_data.get("scan_duration", "N/A"),
            "scan_date": scan_data.get("scan_date", datetime.now().isoformat()),
            "total_vulnerabilities": len(vulns),
            "severity_counts": {
                "critical": critical,
                "high": high,
                "medium": medium,
                "low": low,
            },
            "total_cves": len(set(all_cves)),
            "cve_ids": list(set(all_cves)),
            "cvss_average": avg_cvss,
            "cvss_scores": cvss_scores[:50],  # Cap for prompt size
            "exploitable_count": len(exploit_successes),
            "exploit_successes": [
                {
                    "name": e.get("name", ""),
                    "cve_id": e.get("cve_id", ""),
                    "target": e.get("target", ""),
                    "cvss": e.get("cvss", e.get("cvss_score", 0)),
                    "attack_type": e.get("attack_type", ""),
                    "evidence": e.get("evidence", ""),
                }
                for e in exploit_successes[:20]
            ],
            "technologies": [
                {
                    "name": t.get("name", ""),
                    "version": t.get("version", ""),
                    "cve_count": t.get("cve_count", 0),
                }
                for t in technologies[:30]
            ],
            "technologies_with_cves": [
                {
                    "name": t.get("name", ""),
                    "version": t.get("version", ""),
                    "cve_count": t.get("cve_count", 0),
                    "cves": t.get("cves", [])[:5],
                }
                for t in tech_with_cves[:15]
            ],
            "endpoints_count": len(endpoints),
            "attack_chains": [
                {
                    "name": c.get("name", ""),
                    "steps": c.get("steps", []),
                    "severity": c.get("severity", ""),
                    "impact": c.get("impact", ""),
                }
                for c in attack_chains[:10]
            ],
            "mitre_mappings": [
                {
                    "technique_id": m.get("technique_id", ""),
                    "technique_name": m.get("technique_name", ""),
                    "tactic": m.get("tactic", ""),
                    "finding": m.get("finding", ""),
                }
                for m in mitre[:20]
            ],
            "findings_summary": [
                {
                    "name": v.get("name", ""),
                    "severity": v.get("severity", ""),
                    "cvss": v.get("cvss", v.get("cvss_score", 0)),
                    "cve_id": v.get("cve_id", ""),
                    "cwe": v.get("cwe", ""),
                    "target": v.get("target", ""),
                    "category": v.get("category", ""),
                    "exploitable": v.get("exploit_confirmed", False),
                }
                for v in vulns[:50]
            ],
            # Graph-derived metrics if available
            "subdomains": scan_data.get("subdomains", []),
            "ips": scan_data.get("ips", []),
            "ports": scan_data.get("ports", []),
            "services": scan_data.get("services", []),
            "certificates": scan_data.get("certificates", {}),
            "security_headers": scan_data.get("security_headers", {}),
        }

    # ------------------------------------------------------------------
    # Template fallbacks (no LLM required)
    # ------------------------------------------------------------------

    def _fallback_section(self, section: str, data: dict) -> str:
        """Generate a basic template-based narrative when LLM is unavailable."""
        target = data.get("target", "the target")
        total = data.get("total_vulnerabilities", 0)
        sev = data.get("severity_counts", {})
        critical = sev.get("critical", 0)
        high = sev.get("high", 0)
        medium = sev.get("medium", 0)
        low = sev.get("low", 0)
        exploitable = data.get("exploitable_count", 0)
        avg_cvss = data.get("cvss_average", 0.0)
        duration = data.get("scan_duration", "N/A")
        techs = data.get("technologies", [])
        endpoints = data.get("endpoints_count", 0)

        if section == "executive_summary":
            return (
                f"A comprehensive security assessment of {target} identified "
                f"{total} vulnerabilities across the attack surface. Of these, "
                f"{critical} are rated critical, {high} high, {medium} medium, "
                f"and {low} low severity. {exploitable} vulnerabilities were "
                f"confirmed as actively exploitable through validated exploitation "
                f"attempts. The average CVSS score across all findings is {avg_cvss}.\n\n"
                f"The assessment revealed significant security concerns that require "
                f"immediate attention from the security and engineering teams. "
                f"Detailed findings and a prioritized remediation plan follow in "
                f"subsequent sections of this report."
            )

        elif section == "scope_narrative":
            tech_names = ", ".join(t.get("name", "") for t in techs[:10]) or "various technologies"
            return (
                f"This security assessment targeted {target} over a duration of "
                f"{duration}. The engagement encompassed automated reconnaissance, "
                f"vulnerability correlation, exploit validation, and manual analysis. "
                f"A total of {endpoints} endpoints were discovered and analyzed. "
                f"The technology stack includes {tech_names}."
            )

        elif section == "risk_narrative":
            return (
                f"The assessment of {target} revealed {total} total vulnerabilities "
                f"with the following severity distribution: {critical} critical, "
                f"{high} high, {medium} medium, and {low} low. The average CVSS "
                f"score is {avg_cvss}. {exploitable} findings were confirmed "
                f"exploitable through direct validation. This risk profile indicates "
                f"that the target requires immediate remediation attention, "
                f"particularly for the {critical + high} critical and high severity "
                f"findings that present the greatest organizational risk."
            )

        elif section == "findings_narrative":
            findings = data.get("findings_summary", [])
            if not findings:
                return f"No detailed findings data available for {target}."
            lines = [
                f"The assessment of {target} produced {len(findings)} documented "
                f"findings across multiple categories."
            ]
            for f in findings[:10]:
                name = f.get("name", "Unnamed finding")
                sev_label = f.get("severity", "unknown")
                cvss = f.get("cvss", 0)
                cve = f.get("cve_id", "")
                cve_str = f" ({cve})" if cve else ""
                lines.append(
                    f"{name}{cve_str} was identified with {sev_label} severity "
                    f"and a CVSS score of {cvss}."
                )
            return " ".join(lines)

        elif section == "attack_surface_narrative":
            return (
                f"The attack surface analysis of {target} identified {endpoints} "
                f"web endpoints and {len(techs)} technologies in the stack. "
                f"Infrastructure exposure analysis and security header assessment "
                f"details are provided in the full technical dataset."
            )

        elif section == "recommendations_narrative":
            return (
                f"Based on the {total} vulnerabilities identified in {target}, "
                f"remediation should be prioritized as follows. The {critical} "
                f"critical severity findings and any confirmed exploitation "
                f"successes ({exploitable} total) require emergency patching within "
                f"24-48 hours. The {high} high severity findings should be addressed "
                f"within one week. The {medium} medium severity findings should be "
                f"remediated within one month, and the {low} low severity items "
                f"within one quarter. A comprehensive vulnerability management "
                f"program and regular penetration testing cadence are recommended "
                f"as long-term strategic improvements."
            )

        return ""


# ══════════════════════════════════════════════════════════════════════
# STANDALONE CISO REPORT GENERATOR (F6)
# ══════════════════════════════════════════════════════════════════════

# Combined single-shot prompt for generate_ciso_report (used when calling
# model_router directly instead of going through the class).
_CISO_SYSTEM_PROMPT = (
    "You are a senior penetration testing report writer at a world-class "
    "offensive security consultancy. Given structured security assessment data, "
    "generate thorough, professional narrative summaries for each section of a "
    "pentest report.\n\n"
    "Your writing must be:\n"
    "- Detailed and comprehensive, each section a standalone professional deliverable.\n"
    "- Specific: reference actual CVE IDs, technology names and versions, CVSS scores, "
    "IP addresses, finding counts, exploit names, CWE/CAPEC IDs, severity levels.\n"
    "- Risk-contextualized: explain WHY it matters, what an attacker could achieve, "
    "and the business impact.\n"
    "- Professional: match depth and tone of NCC Group, CrowdStrike, Bishop Fox reports.\n"
    "- Flowing prose with logical transitions. NO markdown, headings, bullet points, "
    "or em dashes. Use commas, semicolons, colons, or separate sentences.\n"
    "- No AI disclaimers, no meta-commentary, no filler phrases.\n\n"
    "Respond with valid JSON containing exactly these keys:\n"
    "{\n"
    '  "executive_summary": "...",\n'
    '  "scope_narrative": "...",\n'
    '  "risk_narrative": "...",\n'
    '  "findings_narrative": "...",\n'
    '  "attack_surface_narrative": "...",\n'
    '  "recommendations_narrative": "..."\n'
    "}\n\n"
    "SECTION GUIDELINES:\n\n"
    "executive_summary: 3-4 paragraphs for CISO/board. "
    "P1=verdict (risk score, most critical finding, exploitability, key metrics). "
    "P2=business impact (what attacker achieves, regulatory implications, KEV entries). "
    "P3=top 3 urgent remediation actions. "
    "P4=one decisive statement of posture and most urgent action.\n\n"
    "scope_narrative: 4-6 paragraphs. Target domain, subdomains, IPs (CDN vs direct), "
    "endpoints, parameters, services, ports, technologies. Methodology: automated recon, "
    "vuln correlation, exploit validation, manual analysis, graph-based mapping.\n\n"
    "risk_narrative: 8-12 paragraphs minimum. Vulnerability landscape (per-severity counts, "
    "avg CVSS). CVSS distribution analysis. Exploitation results (every confirmed exploit "
    "with CVE, IP, module, access achieved). Technology and CVE analysis (attack chains). "
    "Infrastructure posture (certs, headers, injectable params). Attack surface metrics. "
    "Secrets and data exposure.\n\n"
    "findings_narrative: 6-10 paragraphs. Group by category (RCE, injection, auth, misconfig, "
    "info disclosure, missing controls). For each: what, where, severity, CVSS, CVE, CWE, "
    "exploit status, attacker impact. Step-by-step exploitation chains for confirmed exploits.\n\n"
    "attack_surface_narrative: 5-8 paragraphs. Digital footprint (subdomains, IPs, ports, "
    "services, endpoints, parameters). Technology stack with versions. Infrastructure security "
    "(certs, headers, injection surface). Security maturity assessment.\n\n"
    "recommendations_narrative: LONGEST section, 12-20 paragraphs. COMPLETE remediation triage. "
    "Tier 1 (24h emergency): confirmed exploits, CISA KEV, exact CVE/IP/module/evidence, "
    "compensating controls. "
    "Tier 2 (1 week): every critical/high CVE with ID, tech, version, CVSS, CWE, CAPEC, remediation. "
    "Tier 3 (1 month): medium findings, missing headers, cert issues, info disclosure. "
    "Tier 4 (1 quarter): low/informational, hardening. "
    "Tier 5 (strategic): vuln mgmt program, patch cadence, WAF, monitoring, pentest schedule. "
    "Every CVE by ID, every finding with specific remediation. No summaries, no skipping.\n"
)


async def generate_ciso_report(
    findings: List[Dict[str, Any]],
    target: str,
    metadata: Optional[Dict[str, Any]] = None,
    model_router=None,
) -> Dict[str, str]:
    """
    Generate a 6-section CISO-quality pentest report.

    This is the standalone entry point for F6. It accepts raw findings and
    metadata, condenses them, and produces narrative sections via LLM or
    template fallback.

    Args:
        findings: List of vulnerability/finding dicts. Each may contain keys
            like name, severity, cvss/cvss_score, cve_id/cve, cwe, target,
            category, exploit_confirmed, exploitable, attack_type, evidence.
        target: The primary target domain or identifier.
        metadata: Optional dict with additional context:
            - scan_duration, scan_date, technologies, endpoints, attack_chains,
              mitre_mappings, subdomains, ips, ports, services, certificates,
              security_headers, engagement_type, client_name.
        model_router: VIPER ModelRouter instance. If None, template-based
            narratives are generated (no LLM).

    Returns:
        Dict with 6 keys: executive_summary, scope_narrative, risk_narrative,
        findings_narrative, attack_surface_narrative, recommendations_narrative.
    """
    metadata = metadata or {}

    # Build condensed data payload
    condensed = _condense_ciso_data(findings, target, metadata)

    if model_router is None:
        logger.info("generate_ciso_report: no model_router, using template fallback")
        return _template_ciso_report(condensed)

    # LLM path: single-shot JSON generation (like RedAmon's approach)
    user_prompt = (
        f"Security assessment data:\n```json\n"
        f"{json.dumps(condensed, indent=2, default=str)}\n```\n\n"
        f"Generate the report section narratives."
    )

    try:
        response = await model_router.complete(
            prompt=user_prompt,
            system=_CISO_SYSTEM_PROMPT,
            max_tokens=8192,
            temperature=0.3,
        )

        if response is None:
            logger.warning("generate_ciso_report: LLM returned None, using fallback")
            return _template_ciso_report(condensed)

        content = response.text.strip()

        # Strip markdown code fences
        fence_match = re.search(
            r'```(?:json)?\s*\n(.*?)```', content, re.DOTALL | re.IGNORECASE
        )
        if fence_match:
            content = fence_match.group(1).strip()
        else:
            brace_start = content.find('{')
            if brace_start > 0:
                content = content[brace_start:]
            brace_end = content.rfind('}')
            if brace_end >= 0 and brace_end < len(content) - 1:
                content = content[:brace_end + 1]

        result = json.loads(content)

        # Ensure all 6 keys exist
        for key in REPORT_SECTIONS:
            if key not in result:
                result[key] = _template_section(key, condensed)

        return result

    except json.JSONDecodeError as e:
        logger.error(f"generate_ciso_report: invalid JSON from LLM: {e}")
        return _template_ciso_report(condensed)
    except Exception as e:
        logger.error(f"generate_ciso_report: LLM error: {e}")
        return _template_ciso_report(condensed)


def _condense_ciso_data(
    findings: List[Dict[str, Any]],
    target: str,
    metadata: Dict[str, Any],
) -> Dict[str, Any]:
    """Build a condensed data payload from findings + metadata for the LLM."""
    # Severity counts
    sev_counts: Dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for f in findings:
        sev = (f.get("severity") or "").lower()
        if sev in sev_counts:
            sev_counts[sev] += 1

    # CVSS stats
    cvss_scores: List[float] = []
    for f in findings:
        score = f.get("cvss") or f.get("cvss_score") or 0
        if score:
            cvss_scores.append(float(score))
    avg_cvss = round(sum(cvss_scores) / len(cvss_scores), 1) if cvss_scores else 0.0

    # CVE extraction
    all_cves: List[str] = []
    for f in findings:
        cve = f.get("cve_id") or f.get("cve") or ""
        if cve:
            all_cves.append(cve)
    unique_cves = list(set(all_cves))

    # Exploitable findings
    exploit_successes = [
        f for f in findings
        if f.get("exploit_confirmed") or f.get("exploitable")
    ]

    # Technologies
    technologies = metadata.get("technologies", [])
    tech_with_cves = [
        t for t in technologies
        if t.get("cve_count", 0) > 0 or t.get("cves")
    ]

    endpoints = metadata.get("endpoints", [])
    attack_chains = metadata.get("attack_chains", [])
    mitre = metadata.get("mitre_mappings", [])

    return {
        "target": target,
        "scan_duration": metadata.get("scan_duration", "N/A"),
        "scan_date": metadata.get("scan_date", datetime.now().isoformat()),
        "engagement_type": metadata.get("engagement_type", ""),
        "client_name": metadata.get("client_name", ""),
        "total_vulnerabilities": len(findings),
        "severity_counts": sev_counts,
        "total_cves": len(unique_cves),
        "cve_ids": unique_cves,
        "cvss_average": avg_cvss,
        "cvss_scores": cvss_scores[:50],
        "exploitable_count": len(exploit_successes),
        "exploit_successes": [
            {
                "name": e.get("name", ""),
                "cve_id": e.get("cve_id", e.get("cve", "")),
                "target": e.get("target", ""),
                "cvss": e.get("cvss", e.get("cvss_score", 0)),
                "attack_type": e.get("attack_type", ""),
                "evidence": e.get("evidence", ""),
            }
            for e in exploit_successes[:20]
        ],
        "technologies": [
            {
                "name": t.get("name", ""),
                "version": t.get("version", ""),
                "cve_count": t.get("cve_count", 0),
            }
            for t in technologies[:30]
        ],
        "technologies_with_cves": [
            {
                "name": t.get("name", ""),
                "version": t.get("version", ""),
                "cve_count": t.get("cve_count", 0),
                "cves": t.get("cves", [])[:5],
            }
            for t in tech_with_cves[:15]
        ],
        "endpoints_count": len(endpoints) if isinstance(endpoints, list) else endpoints,
        "attack_chains": [
            {
                "name": c.get("name", ""),
                "steps": c.get("steps", []),
                "severity": c.get("severity", ""),
                "impact": c.get("impact", ""),
            }
            for c in (attack_chains or [])[:10]
        ],
        "mitre_mappings": [
            {
                "technique_id": m.get("technique_id", ""),
                "technique_name": m.get("technique_name", ""),
                "tactic": m.get("tactic", ""),
                "finding": m.get("finding", ""),
            }
            for m in (mitre or [])[:20]
        ],
        "findings_summary": [
            {
                "name": f.get("name", ""),
                "severity": f.get("severity", ""),
                "cvss": f.get("cvss", f.get("cvss_score", 0)),
                "cve_id": f.get("cve_id", f.get("cve", "")),
                "cwe": f.get("cwe", ""),
                "target": f.get("target", ""),
                "category": f.get("category", ""),
                "exploitable": bool(
                    f.get("exploit_confirmed") or f.get("exploitable")
                ),
            }
            for f in findings[:50]
        ],
        "subdomains": metadata.get("subdomains", []),
        "ips": metadata.get("ips", []),
        "ports": metadata.get("ports", []),
        "services": metadata.get("services", []),
        "certificates": metadata.get("certificates", {}),
        "security_headers": metadata.get("security_headers", {}),
    }


def _template_ciso_report(data: Dict[str, Any]) -> Dict[str, str]:
    """Generate all 6 sections using templates (no LLM)."""
    return {section: _template_section(section, data) for section in REPORT_SECTIONS}


def _template_section(section: str, data: Dict[str, Any]) -> str:
    """Generate a single template-based narrative section."""
    target = data.get("target", "the target")
    total = data.get("total_vulnerabilities", 0)
    sev = data.get("severity_counts", {})
    critical = sev.get("critical", 0)
    high = sev.get("high", 0)
    medium = sev.get("medium", 0)
    low = sev.get("low", 0)
    exploitable = data.get("exploitable_count", 0)
    avg_cvss = data.get("cvss_average", 0.0)
    duration = data.get("scan_duration", "N/A")
    cve_count = data.get("total_cves", 0)
    techs = data.get("technologies", [])
    endpoints = data.get("endpoints_count", 0)
    findings = data.get("findings_summary", [])
    cve_ids = data.get("cve_ids", [])
    exploit_successes = data.get("exploit_successes", [])
    tech_with_cves = data.get("technologies_with_cves", [])

    if section == "executive_summary":
        risk_label = "Critical" if critical > 0 else ("High" if high > 0 else "Medium")
        paras = []
        paras.append(
            f"The security assessment of {target} has concluded with an overall "
            f"risk rating of {risk_label}. A total of {total} vulnerabilities were "
            f"identified, of which {critical} are critical severity, {high} are high "
            f"severity, {medium} are medium severity, and {low} are low severity. "
            f"The average CVSS score across all findings is {avg_cvss}. "
            f"{exploitable} vulnerabilities were confirmed as actively exploitable "
            f"through validated exploitation attempts."
        )
        paras.append(
            f"The confirmed exploitable vulnerabilities present significant risk to "
            f"the organization. An attacker leveraging these weaknesses could "
            f"potentially achieve unauthorized access to sensitive systems and data. "
            f"Organizations subject to regulatory frameworks such as GDPR, PCI-DSS, "
            f"or SOC 2 should treat these findings with elevated urgency, as "
            f"exploitation could trigger compliance violations and mandatory "
            f"disclosure obligations."
        )
        paras.append(
            f"The three most urgent remediation priorities are: addressing all "
            f"{critical} critical severity findings immediately, patching the "
            f"{exploitable} confirmed exploitable vulnerabilities, and reviewing "
            f"the {cve_count} known CVEs against vendor-published security advisories. "
            f"A total of {total} remediation items are documented in the "
            f"Recommendations section with a complete prioritized triage."
        )
        paras.append(
            f"Immediate action is required to address the critical and exploitable "
            f"findings before an adversary can leverage them for unauthorized access."
        )
        return "\n\n".join(paras)

    elif section == "scope_narrative":
        tech_names = ", ".join(t.get("name", "") for t in techs[:10]) or "various technologies"
        subdomains = data.get("subdomains", [])
        ips = data.get("ips", [])
        sub_count = len(subdomains) if isinstance(subdomains, list) else subdomains
        ip_count = len(ips) if isinstance(ips, list) else ips
        paras = []
        paras.append(
            f"This security assessment targeted {target} over a duration of "
            f"{duration}. The engagement scope encompassed the primary domain "
            f"and {sub_count} associated subdomains, with {ip_count} unique IP "
            f"addresses identified during infrastructure enumeration."
        )
        paras.append(
            f"The methodology employed a multi-phase approach: automated "
            f"reconnaissance including subdomain enumeration, DNS resolution, "
            f"port scanning, and web crawling; vulnerability correlation matching "
            f"detected software versions against CVE databases; exploit validation "
            f"through confirmed exploitation attempts; and manual analysis with "
            f"graph-based attack path mapping."
        )
        paras.append(
            f"A total of {endpoints} endpoints were discovered and analyzed across "
            f"the target infrastructure. The technology stack includes {tech_names}. "
            f"Each identified technology was fingerprinted with version information "
            f"and cross-referenced against known vulnerability databases."
        )
        paras.append(
            f"The assessment tools included automated scanners for comprehensive "
            f"coverage, custom exploit validation modules, and manual analysis for "
            f"business logic and complex attack chain identification."
        )
        return "\n\n".join(paras)

    elif section == "risk_narrative":
        paras = []
        paras.append(
            f"The vulnerability landscape of {target} comprises {total} total "
            f"findings with the following severity distribution: {critical} critical, "
            f"{high} high, {medium} medium, and {low} low. Additionally, {cve_count} "
            f"known CVEs were identified, with an average CVSS score of {avg_cvss} "
            f"across all scored findings."
        )
        paras.append(
            f"The CVSS score distribution indicates "
            + ("a concentration of high-severity issues suggesting critical "
               "vulnerabilities in key components"
               if avg_cvss >= 7.0
               else "a spread across the severity spectrum suggesting both targeted "
                    "high-impact vulnerabilities and systemic misconfigurations")
            + f". {exploitable} findings were confirmed exploitable through direct "
            f"validation, representing confirmed attack vectors that an adversary "
            f"could leverage without additional research."
        )
        if exploit_successes:
            exploit_lines = []
            for e in exploit_successes[:5]:
                name = e.get("name", "unnamed exploit")
                cve = e.get("cve_id", "")
                etarget = e.get("target", "")
                atype = e.get("attack_type", "")
                cve_str = f" ({cve})" if cve else ""
                exploit_lines.append(
                    f"{name}{cve_str} targeting {etarget} via {atype}"
                )
            paras.append(
                f"Confirmed exploitation successes include: "
                + "; ".join(exploit_lines)
                + ". Each of these represents a validated attack path that "
                f"demonstrates real-world exploitability."
            )
        if tech_with_cves:
            tech_lines = []
            for t in tech_with_cves[:5]:
                tname = t.get("name", "")
                tver = t.get("version", "")
                tcve = t.get("cve_count", 0)
                tech_lines.append(f"{tname} {tver} ({tcve} CVEs)")
            paras.append(
                f"The most concerning technologies in the stack are: "
                + ", ".join(tech_lines)
                + ". These components carry known vulnerabilities that form "
                f"the basis of potential attack chains from initial access "
                f"through exploitation to impact."
            )
        paras.append(
            f"Infrastructure analysis reveals the target's security posture "
            f"across certificate management, security header deployment, and "
            f"parameter injection surface. The combination of {critical + high} "
            f"critical and high severity findings with {exploitable} confirmed "
            f"exploitable vulnerabilities indicates that {target} requires "
            f"immediate and sustained remediation effort."
        )
        return "\n\n".join(paras)

    elif section == "findings_narrative":
        if not findings:
            return f"No detailed findings data available for {target}."
        paras = []
        paras.append(
            f"The assessment of {target} produced {len(findings)} documented "
            f"findings across multiple vulnerability categories. These findings "
            f"span remote code execution, injection vulnerabilities, authentication "
            f"flaws, misconfigurations, information disclosure, and missing security "
            f"controls."
        )
        # Group by category
        by_cat: Dict[str, List] = {}
        for f in findings:
            cat = f.get("category") or f.get("severity", "other")
            by_cat.setdefault(cat, []).append(f)
        for cat, cat_findings in list(by_cat.items())[:8]:
            lines = []
            for cf in cat_findings[:5]:
                name = cf.get("name", "Unnamed")
                sev_label = cf.get("severity", "unknown")
                cvss_val = cf.get("cvss", 0)
                cve = cf.get("cve_id", "")
                cwe = cf.get("cwe", "")
                cve_str = f" ({cve})" if cve else ""
                cwe_str = f", CWE: {cwe}" if cwe else ""
                expl = " (confirmed exploitable)" if cf.get("exploitable") else ""
                lines.append(
                    f"{name}{cve_str} was identified with {sev_label} severity "
                    f"and a CVSS score of {cvss_val}{cwe_str}{expl}"
                )
            paras.append(
                f"In the {cat} category, the following findings were documented. "
                + ". ".join(lines) + "."
            )
        return "\n\n".join(paras)

    elif section == "attack_surface_narrative":
        subdomains = data.get("subdomains", [])
        ips = data.get("ips", [])
        sub_count = len(subdomains) if isinstance(subdomains, list) else subdomains
        ip_count = len(ips) if isinstance(ips, list) else ips
        tech_names = ", ".join(t.get("name", "") for t in techs[:10]) or "various technologies"
        paras = []
        paras.append(
            f"The attack surface analysis of {target} reveals a digital footprint "
            f"spanning {sub_count} subdomains and {ip_count} unique IP addresses. "
            f"A total of {endpoints} web endpoints were discovered through "
            f"comprehensive crawling and directory enumeration."
        )
        paras.append(
            f"The technology stack comprises {tech_names}. "
            f"Version fingerprinting identified {len(tech_with_cves)} technologies "
            f"running versions with known CVEs, indicating gaps in patch management "
            f"practices."
        )
        paras.append(
            f"Infrastructure security analysis covers certificate health, security "
            f"header deployment, and parameter injection surface. The overall attack "
            f"surface size, combined with the identified technology vulnerabilities, "
            f"suggests that the organization would benefit from a more rigorous "
            f"configuration management and patching discipline."
        )
        return "\n\n".join(paras)

    elif section == "recommendations_narrative":
        paras = []
        # Tier 1
        paras.append(
            f"Tier 1, Emergency (fix within 24 to 48 hours): The {exploitable} "
            f"confirmed exploitable vulnerabilities require immediate patching or "
            f"compensating controls. "
            + (
                "Specifically, " + "; ".join(
                    f"{e.get('name', '')} ({e.get('cve_id', '')})"
                    for e in exploit_successes[:5]
                ) + " must be remediated immediately through vendor patches, "
                "configuration changes, or temporary mitigations such as WAF rules "
                "and network segmentation."
                if exploit_successes else
                "While no exploits were confirmed during this assessment, all "
                "critical findings should be treated as potentially exploitable."
            )
        )
        # Tier 2
        crit_high_cves = [
            f for f in findings
            if (f.get("severity") or "").lower() in ("critical", "high")
               and f.get("cve_id")
        ]
        if crit_high_cves:
            cve_mentions = "; ".join(
                f"{f.get('cve_id', '')} affecting {f.get('name', '')} "
                f"(CVSS {f.get('cvss', 'N/A')})"
                for f in crit_high_cves[:10]
            )
            paras.append(
                f"Tier 2, Critical and High CVEs (fix within 1 week): The following "
                f"CVEs require priority remediation: {cve_mentions}. Each should be "
                f"addressed through vendor-published patches or version upgrades to "
                f"non-vulnerable releases."
            )
        else:
            paras.append(
                f"Tier 2, Critical and High CVEs (fix within 1 week): All {critical} "
                f"critical and {high} high severity findings should be addressed "
                f"through vendor patches and configuration hardening."
            )
        # Tier 3
        paras.append(
            f"Tier 3, Medium Findings (fix within 1 month): The {medium} medium "
            f"severity findings encompass missing security headers, certificate "
            f"issues, information disclosure, and configuration weaknesses. Each "
            f"should be addressed with specific configuration changes as documented "
            f"in the individual finding details."
        )
        # Tier 4
        paras.append(
            f"Tier 4, Low and Informational (fix within 1 quarter): The {low} low "
            f"severity items include outdated but not critically vulnerable software, "
            f"informational findings, and general hardening opportunities."
        )
        # Tier 5
        paras.append(
            f"Tier 5, Strategic Recommendations: Establish a formal vulnerability "
            f"management program with regular patch cycles. Deploy a web application "
            f"firewall for defense-in-depth. Implement continuous security monitoring "
            f"and alerting. Schedule quarterly penetration testing engagements. "
            f"Enforce a security header policy across all web properties. Implement "
            f"certificate lifecycle management to prevent expiration-related exposure. "
            f"Invest in secure development training for engineering teams and "
            f"establish an incident response plan for vulnerability exploitation events."
        )
        return "\n\n".join(paras)

    return ""
