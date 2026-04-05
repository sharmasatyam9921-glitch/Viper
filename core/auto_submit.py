#!/usr/bin/env python3
"""
VIPER Auto-Submission Pipeline — Finding -> Report -> Submission.

Takes validated findings, generates platform-format reports (HackerOne,
Bugcrowd, Intigriti, Yogosha), and queues them for submission with a
mandatory human approval gate before final send.
"""

import json
import logging
import os
import re
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("viper.auto_submit")

HACKAGENT_DIR = Path(__file__).parent.parent
REPORTS_DIR = HACKAGENT_DIR / "reports"
SUBMISSIONS_DIR = HACKAGENT_DIR / "state"
REPORTS_DIR.mkdir(exist_ok=True)
SUBMISSIONS_DIR.mkdir(exist_ok=True)

# ── Vuln type -> CWE mapping (subset used for report generation) ──
VULN_CWE_MAP = {
    "xss": "CWE-79", "xss_reflected": "CWE-79", "xss_stored": "CWE-79", "xss_dom": "CWE-79",
    "sqli": "CWE-89", "sqli_error": "CWE-89", "sqli_union": "CWE-89", "sqli_blind": "CWE-89",
    "lfi": "CWE-22", "path_traversal": "CWE-22",
    "cmdi": "CWE-78", "command_injection": "CWE-78",
    "csrf": "CWE-352",
    "ssrf": "CWE-918", "ssrf_basic": "CWE-918",
    "xxe": "CWE-611",
    "deserialization": "CWE-502", "insecure_deserialization": "CWE-502",
    "auth_bypass": "CWE-287",
    "idor": "CWE-639",
    "cors": "CWE-942", "cors_misconfig": "CWE-942",
    "open_redirect": "CWE-601",
    "ssti": "CWE-94",
    "file_upload": "CWE-434",
    "default_creds": "CWE-798",
    "info_disclosure": "CWE-200",
    "race_condition": "CWE-362",
    "business_logic": "CWE-840",
    "oauth_bypass": "CWE-287",
    "websocket_hijack": "CWE-1385",
    "graphql_introspection": "CWE-200",
    "prompt_injection": "CWE-77",
}

# HackerOne weakness IDs (subset of most common)
H1_WEAKNESS_IDS = {
    "CWE-79": 60,     # XSS
    "CWE-89": 67,     # SQLi
    "CWE-22": 19,     # Path Traversal
    "CWE-78": 58,     # OS Command Injection
    "CWE-352": 16,    # CSRF
    "CWE-918": 68,    # SSRF
    "CWE-611": 86,    # XXE
    "CWE-502": 52,    # Deserialization
    "CWE-287": 27,    # Auth Bypass
    "CWE-639": 55,    # IDOR
    "CWE-942": 16,    # CORS
    "CWE-601": 53,    # Open Redirect
    "CWE-94": 70,     # Code Injection
    "CWE-434": 39,    # Unrestricted Upload
    "CWE-798": 32,    # Hardcoded Creds
    "CWE-200": 18,    # Info Disclosure
    "CWE-362": 29,    # Race Condition
}

SEVERITY_TO_RATING = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "low": "low",
    "info": "none",
}


class AutoSubmitPipeline:
    """Automated finding -> report -> submission pipeline.

    Takes validated findings, generates HackerOne-format reports,
    and queues them for submission (with human approval gate).

    Supports platforms: hackerone, bugcrowd, intigriti, yogosha.
    """

    def __init__(self, platform: str = "hackerone",
                 min_confidence: float = 0.5,
                 require_approval: bool = True):
        self.platform = platform.lower()
        self.min_confidence = min_confidence
        self.require_approval = require_approval
        self._tracker_path = SUBMISSIONS_DIR / "submission_tracker.json"
        self._tracker = self._load_tracker()

    def _load_tracker(self) -> dict:
        if self._tracker_path.exists():
            try:
                return json.loads(self._tracker_path.read_text())
            except (json.JSONDecodeError, OSError):
                pass
        return {"submissions": [], "pending": [], "rejected": []}

    def _save_tracker(self):
        self._tracker_path.write_text(json.dumps(self._tracker, indent=2, default=str))

    async def process_findings(self, findings: List[dict], program: str,
                               scope: Optional[dict] = None) -> List[dict]:
        """Process findings into submission-ready reports.

        Args:
            findings: List of finding dicts from ViperCore.
            program: Bug bounty program handle/slug.
            scope: Optional scope dict for asset validation.

        Returns:
            List of report dicts ready for submission.
        """
        reports = []
        for finding in findings:
            confidence = finding.get("confidence", 0)
            if isinstance(confidence, str):
                try:
                    confidence = float(confidence.strip("%")) / 100
                except ValueError:
                    confidence = 0.0

            if confidence < self.min_confidence:
                logger.info("Skipping low-confidence finding: %s (%.0f%%)",
                            finding.get("vuln_type", "unknown"), confidence * 100)
                continue

            # Skip if already submitted
            finding_hash = self._finding_hash(finding)
            if self._is_duplicate(finding_hash):
                logger.info("Skipping duplicate: %s", finding_hash[:12])
                continue

            # Validate against scope if provided
            if scope and not self._in_scope(finding, scope):
                logger.warning("Finding URL not in scope, skipping: %s",
                               finding.get("url", ""))
                continue

            report = self._generate_report(finding, program)
            report["_finding_hash"] = finding_hash
            report["_finding"] = finding
            reports.append(report)

        # Queue for approval
        for report in reports:
            self._tracker["pending"].append({
                "hash": report["_finding_hash"],
                "program": program,
                "title": report["title"],
                "severity": report["severity_rating"],
                "created_at": datetime.now().isoformat(),
                "status": "pending_approval" if self.require_approval else "ready",
            })
        self._save_tracker()

        logger.info("Processed %d/%d findings into reports for %s",
                     len(reports), len(findings), program)
        return reports

    def _generate_report(self, finding: dict, program: str) -> dict:
        """Generate platform-format report from finding."""
        vuln_type = finding.get("vuln_type", finding.get("attack", "unknown"))
        url = finding.get("url", finding.get("target_url", ""))
        severity = finding.get("severity", "medium").lower()

        if self.platform == "hackerone":
            return self._generate_h1_report(finding, program, vuln_type, url, severity)
        elif self.platform == "bugcrowd":
            return self._generate_bugcrowd_report(finding, program, vuln_type, url, severity)
        else:
            return self._generate_h1_report(finding, program, vuln_type, url, severity)

    def _generate_h1_report(self, finding: dict, program: str,
                            vuln_type: str, url: str, severity: str) -> dict:
        """Generate HackerOne-format report."""
        cwe = self._map_cwe(vuln_type)
        weakness_id = H1_WEAKNESS_IDS.get(cwe, 18)  # Default to info disclosure

        description = self._format_description(finding)
        impact = self._format_impact(finding)

        title_vuln = self._human_readable_vuln(vuln_type)
        # Extract domain from URL for title
        domain = ""
        if url:
            try:
                from urllib.parse import urlparse
                domain = urlparse(url).hostname or url
            except Exception:
                domain = url[:50]

        return {
            "title": f"{title_vuln} on {domain}",
            "vulnerability_information": description,
            "impact": impact,
            "severity_rating": SEVERITY_TO_RATING.get(severity, "medium"),
            "weakness_id": weakness_id,
            "structured_scope": url,
            "platform": "hackerone",
            "program": program,
            "cwe": cwe,
        }

    def _generate_bugcrowd_report(self, finding: dict, program: str,
                                  vuln_type: str, url: str, severity: str) -> dict:
        """Generate Bugcrowd-format report."""
        cwe = self._map_cwe(vuln_type)
        description = self._format_description(finding)
        impact = self._format_impact(finding)
        title_vuln = self._human_readable_vuln(vuln_type)
        domain = ""
        if url:
            try:
                from urllib.parse import urlparse
                domain = urlparse(url).hostname or url
            except Exception:
                domain = url[:50]

        return {
            "title": f"{title_vuln} on {domain}",
            "description": description,
            "impact": impact,
            "severity": severity,
            "vrt": self._map_bugcrowd_vrt(vuln_type),
            "url": url,
            "platform": "bugcrowd",
            "program": program,
            "cwe": cwe,
        }

    def _format_description(self, finding: dict) -> str:
        """Generate markdown description with PoC steps."""
        vuln_type = finding.get("vuln_type", finding.get("attack", "unknown"))
        url = finding.get("url", "")
        evidence = finding.get("evidence", finding.get("response_snippet", ""))
        payload = finding.get("payload", "")
        method = finding.get("method", "GET")
        param = finding.get("param", finding.get("parameter", ""))
        headers = finding.get("headers", {})
        cvss = finding.get("cvss", "")
        confidence = finding.get("confidence", 0)

        title_vuln = self._human_readable_vuln(vuln_type)
        cwe = self._map_cwe(vuln_type)

        lines = [
            f"## Summary\n",
            f"A **{title_vuln}** vulnerability was identified at the following endpoint.\n",
            f"- **Vulnerability Type:** {title_vuln} ({cwe})",
            f"- **Affected URL:** `{url}`",
        ]
        if param:
            lines.append(f"- **Parameter:** `{param}`")
        if cvss:
            lines.append(f"- **CVSS Score:** {cvss}")
        lines.append(f"- **Confidence:** {confidence:.0%}" if isinstance(confidence, float)
                      else f"- **Confidence:** {confidence}")

        lines.append(f"\n## Steps to Reproduce\n")
        step = 1

        if method and url:
            lines.append(f"{step}. Send the following {method} request to the target endpoint:\n")
            step += 1
            curl_parts = [f"curl -X {method}"]
            if headers:
                for k, v in headers.items():
                    curl_parts.append(f'  -H "{k}: {v}"')
            if payload and method in ("POST", "PUT", "PATCH"):
                curl_parts.append(f"  -d '{payload}'")
                curl_parts.append(f"  '{url}'")
            else:
                target_url = url
                if payload and "?" in url:
                    target_url = url  # Payload already in URL
                elif payload:
                    target_url = f"{url}?{param}={payload}" if param else url
                curl_parts.append(f"  '{target_url}'")
            lines.append("```bash")
            lines.append(" \\\n".join(curl_parts))
            lines.append("```\n")

        if payload:
            lines.append(f"{step}. The injected payload:\n")
            step += 1
            lines.append(f"```")
            lines.append(payload)
            lines.append("```\n")

        if evidence:
            lines.append(f"{step}. Observe the following in the response:\n")
            step += 1
            evidence_str = evidence if isinstance(evidence, str) else json.dumps(evidence, indent=2)
            # Truncate long evidence
            if len(evidence_str) > 1000:
                evidence_str = evidence_str[:1000] + "\n... (truncated)"
            lines.append("```")
            lines.append(evidence_str)
            lines.append("```\n")

        return "\n".join(lines)

    def _format_impact(self, finding: dict) -> str:
        """Generate impact statement from finding metadata."""
        vuln_type = finding.get("vuln_type", finding.get("attack", "unknown")).lower()
        severity = finding.get("severity", "medium").lower()

        impact_templates = {
            "xss": "An attacker can execute arbitrary JavaScript in a victim's browser session, "
                   "potentially stealing session cookies, performing actions on behalf of the user, "
                   "or redirecting them to malicious sites.",
            "sqli": "An attacker can extract, modify, or delete data from the backend database. "
                    "Depending on the database configuration, this could lead to full server compromise.",
            "ssrf": "An attacker can make the server-side application send requests to internal services, "
                    "potentially accessing sensitive internal APIs, metadata endpoints, or cloud credentials.",
            "idor": "An attacker can access or modify resources belonging to other users by manipulating "
                    "object references, leading to unauthorized data access or modification.",
            "auth_bypass": "An attacker can bypass authentication mechanisms, gaining unauthorized access "
                          "to protected functionality and user data.",
            "cors": "A malicious website can read sensitive data from the application's API responses "
                    "in a cross-origin context, bypassing the Same-Origin Policy.",
            "csrf": "An attacker can force authenticated users to perform unintended actions "
                    "by crafting malicious requests that the victim's browser sends automatically.",
            "cmdi": "An attacker can execute arbitrary operating system commands on the server, "
                    "potentially leading to full system compromise.",
            "lfi": "An attacker can read arbitrary files from the server, potentially accessing "
                   "configuration files, source code, or sensitive credentials.",
            "ssti": "An attacker can inject template directives that execute on the server, "
                    "potentially leading to remote code execution.",
            "open_redirect": "An attacker can redirect users to malicious sites using a trusted domain, "
                            "facilitating phishing or credential theft.",
            "race_condition": "An attacker can exploit timing windows to perform unauthorized actions "
                             "such as double-spending, coupon reuse, or privilege escalation.",
            "business_logic": "An attacker can abuse business logic flaws to perform unauthorized operations "
                             "such as price manipulation, workflow bypass, or privilege escalation.",
        }

        # Find matching template
        impact = ""
        for key, template in impact_templates.items():
            if key in vuln_type:
                impact = template
                break

        if not impact:
            if severity == "critical":
                impact = ("This vulnerability could allow an attacker to compromise the application's "
                         "security, potentially leading to unauthorized access to sensitive data or systems.")
            elif severity == "high":
                impact = ("This vulnerability could allow an attacker to access sensitive data or "
                         "perform unauthorized actions within the application.")
            elif severity == "medium":
                impact = ("This vulnerability could be leveraged by an attacker to gain additional "
                         "information about the application or perform limited unauthorized actions.")
            else:
                impact = ("This issue provides information that could assist an attacker in identifying "
                         "further attack vectors against the application.")

        bounty_est = finding.get("estimated_bounty", "")
        if bounty_est:
            impact += f"\n\n**Estimated Bounty Range:** {bounty_est}"

        return impact

    def _map_cwe(self, vuln_type: str) -> str:
        """Map vuln_type string to CWE ID."""
        vt = vuln_type.lower().strip()
        # Direct match
        if vt in VULN_CWE_MAP:
            return VULN_CWE_MAP[vt]
        # Partial match
        for key, cwe in VULN_CWE_MAP.items():
            if key in vt or vt in key:
                return cwe
        return "CWE-200"  # Default: information exposure

    def _map_bugcrowd_vrt(self, vuln_type: str) -> str:
        """Map vuln_type to Bugcrowd VRT category."""
        vrt_map = {
            "xss": "cross_site_scripting_xss.reflected",
            "xss_stored": "cross_site_scripting_xss.stored",
            "sqli": "server_side_injection.sql_injection",
            "ssrf": "server_side_injection.ssrf",
            "idor": "broken_access_control.idor",
            "auth_bypass": "broken_authentication.auth_bypass",
            "csrf": "cross_site_request_forgery",
            "cors": "server_security_misconfiguration.cors",
            "open_redirect": "unvalidated_redirects_and_forwards.open_redirect",
            "ssti": "server_side_injection.ssti",
            "lfi": "server_side_injection.file_inclusion.local",
            "cmdi": "server_side_injection.command_injection",
        }
        vt = vuln_type.lower()
        for key, vrt in vrt_map.items():
            if key in vt:
                return vrt
        return "other"

    def _human_readable_vuln(self, vuln_type: str) -> str:
        """Convert internal vuln_type to human-readable name."""
        readable = {
            "xss": "Cross-Site Scripting (XSS)",
            "xss_reflected": "Reflected Cross-Site Scripting (XSS)",
            "xss_stored": "Stored Cross-Site Scripting (XSS)",
            "xss_dom": "DOM-Based Cross-Site Scripting (XSS)",
            "sqli": "SQL Injection",
            "sqli_error": "Error-Based SQL Injection",
            "sqli_union": "Union-Based SQL Injection",
            "sqli_blind": "Blind SQL Injection",
            "ssrf": "Server-Side Request Forgery (SSRF)",
            "idor": "Insecure Direct Object Reference (IDOR)",
            "auth_bypass": "Authentication Bypass",
            "cors": "CORS Misconfiguration",
            "cors_misconfig": "CORS Misconfiguration with Wildcard Origin",
            "csrf": "Cross-Site Request Forgery (CSRF)",
            "lfi": "Local File Inclusion (LFI)",
            "path_traversal": "Path Traversal",
            "cmdi": "OS Command Injection",
            "command_injection": "OS Command Injection",
            "ssti": "Server-Side Template Injection (SSTI)",
            "xxe": "XML External Entity Injection (XXE)",
            "open_redirect": "Open Redirect",
            "file_upload": "Unrestricted File Upload",
            "deserialization": "Insecure Deserialization",
            "default_creds": "Default/Hardcoded Credentials",
            "info_disclosure": "Information Disclosure",
            "race_condition": "Race Condition",
            "business_logic": "Business Logic Flaw",
            "oauth_bypass": "OAuth Authentication Bypass",
            "websocket_hijack": "WebSocket Hijacking",
            "graphql_introspection": "GraphQL Introspection Enabled",
            "prompt_injection": "Prompt Injection",
        }
        vt = vuln_type.lower().strip()
        if vt in readable:
            return readable[vt]
        for key, name in readable.items():
            if key in vt:
                return name
        # Fallback: title-case the vuln_type
        return vuln_type.replace("_", " ").title()

    def _finding_hash(self, finding: dict) -> str:
        """Generate a deterministic hash for deduplication."""
        import hashlib
        key_parts = [
            finding.get("vuln_type", finding.get("attack", "")),
            finding.get("url", finding.get("target_url", "")),
            finding.get("param", finding.get("parameter", "")),
            finding.get("payload", ""),
        ]
        raw = "|".join(str(p) for p in key_parts)
        return hashlib.sha256(raw.encode()).hexdigest()

    def _is_duplicate(self, finding_hash: str) -> bool:
        """Check if finding was already submitted or pending."""
        for entry in self._tracker.get("submissions", []):
            if entry.get("hash") == finding_hash:
                return True
        for entry in self._tracker.get("pending", []):
            if entry.get("hash") == finding_hash:
                return True
        return False

    def _in_scope(self, finding: dict, scope: dict) -> bool:
        """Validate finding URL is within provided scope."""
        url = finding.get("url", finding.get("target_url", ""))
        if not url:
            return False
        try:
            from urllib.parse import urlparse
            parsed = urlparse(url)
            hostname = parsed.hostname or ""
        except Exception:
            return False

        in_scope_domains = scope.get("in_scope", [])
        if isinstance(in_scope_domains, list):
            for asset in in_scope_domains:
                domain = asset.get("asset_identifier", asset) if isinstance(asset, dict) else str(asset)
                if domain.startswith("*."):
                    if hostname.endswith(domain[1:]) or hostname == domain[2:]:
                        return True
                elif hostname == domain:
                    return True
        return False

    def approve_submission(self, finding_hash: str) -> bool:
        """Approve a pending submission for send."""
        for entry in self._tracker["pending"]:
            if entry.get("hash") == finding_hash:
                entry["status"] = "approved"
                entry["approved_at"] = datetime.now().isoformat()
                self._save_tracker()
                return True
        return False

    def reject_submission(self, finding_hash: str, reason: str = "") -> bool:
        """Reject a pending submission."""
        for i, entry in enumerate(self._tracker["pending"]):
            if entry.get("hash") == finding_hash:
                entry["status"] = "rejected"
                entry["rejected_at"] = datetime.now().isoformat()
                entry["reason"] = reason
                self._tracker["rejected"].append(self._tracker["pending"].pop(i))
                self._save_tracker()
                return True
        return False

    def mark_submitted(self, finding_hash: str, report_url: str = "") -> bool:
        """Mark a submission as sent."""
        for i, entry in enumerate(self._tracker["pending"]):
            if entry.get("hash") == finding_hash:
                entry["status"] = "submitted"
                entry["submitted_at"] = datetime.now().isoformat()
                entry["report_url"] = report_url
                self._tracker["submissions"].append(self._tracker["pending"].pop(i))
                self._save_tracker()
                return True
        return False

    def get_pending(self) -> List[dict]:
        """Get all pending submissions awaiting approval."""
        return [e for e in self._tracker.get("pending", [])
                if e.get("status") in ("pending_approval", "ready", "approved")]

    def save_report_to_disk(self, report: dict) -> Path:
        """Save a generated report as markdown to disk."""
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        slug = re.sub(r'[^a-z0-9]+', '-', report.get("title", "report").lower())[:60]
        filename = f"{ts}_{slug}.md"
        path = REPORTS_DIR / filename

        lines = [
            f"# {report.get('title', 'Vulnerability Report')}",
            f"\n**Platform:** {report.get('platform', 'hackerone')}",
            f"**Program:** {report.get('program', '')}",
            f"**Severity:** {report.get('severity_rating', report.get('severity', ''))}",
            f"**CWE:** {report.get('cwe', '')}",
            f"\n---\n",
            report.get("vulnerability_information", report.get("description", "")),
            f"\n---\n",
            f"## Impact\n",
            report.get("impact", ""),
        ]

        path.write_text("\n".join(lines), encoding="utf-8")
        logger.info("Report saved: %s", path)
        return path
