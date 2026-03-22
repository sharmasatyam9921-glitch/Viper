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
