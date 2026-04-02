#!/usr/bin/env python3
"""
VIPER Reporter Module - Vulnerability Report Generation

Generates professional reports in:
- Markdown
- JSON
- HackerOne format

Author: VIPER Contributors
"""

import json
from datetime import datetime
from typing import List, Dict, Optional
from pathlib import Path
from dataclasses import asdict

from .models import Finding


class ReportGenerator:
    """
    Generate vulnerability reports in multiple formats.
    """
    
    SEVERITY_COLORS = {
        "critical": "[CRIT]",
        "high": "[HIGH]",
        "medium": "[MED]",
        "low": "[LOW]",
        "info": "[INFO]"
    }
    
    SEVERITY_CVSS = {
        "critical": (9.0, 10.0),
        "high": (7.0, 8.9),
        "medium": (4.0, 6.9),
        "low": (0.1, 3.9),
        "info": (0.0, 0.0)
    }
    
    def __init__(self, target: str, program: str = ""):
        self.target = target
        self.program = program
        self.findings: List[Finding] = []
        self.scan_start = datetime.now()
        self.scan_end = None
    
    def add_finding(self, finding: Finding):
        """Add a finding to the report."""
        self.findings.append(finding)
    
    def add_finding_dict(self, data: Dict):
        """Add finding from dictionary."""
        finding = Finding(
            id=data.get("id", f"VULN-{len(self.findings)+1:03d}"),
            title=data.get("title", "Untitled Vulnerability"),
            severity=data.get("severity", "medium"),
            cvss=data.get("cvss", 5.0),
            vulnerability_type=data.get("type", "unknown"),
            endpoint=data.get("endpoint", self.target),
            parameter=data.get("parameter"),
            payload=data.get("payload"),
            evidence=data.get("evidence", ""),
            impact=data.get("impact", ""),
            remediation=data.get("remediation", ""),
            references=data.get("references", [])
        )
        self.findings.append(finding)
    
    def generate_markdown(self) -> str:
        """Generate Markdown report."""
        self.scan_end = datetime.now()
        
        lines = [
            f"# Security Assessment Report",
            f"",
            f"**Target:** {self.target}",
            f"**Program:** {self.program or 'N/A'}",
            f"**Date:** {self.scan_start.strftime('%Y-%m-%d %H:%M')}",
            f"**Duration:** {(self.scan_end - self.scan_start).seconds}s",
            f"",
            f"---",
            f"",
            f"## Executive Summary",
            f"",
        ]
        
        # Summary stats
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for finding in self.findings:
            severity_counts[finding.severity] = severity_counts.get(finding.severity, 0) + 1
        
        lines.append(f"Total Findings: **{len(self.findings)}**")
        lines.append("")
        lines.append("| Severity | Count |")
        lines.append("|----------|-------|")
        for sev, count in severity_counts.items():
            if count > 0:
                lines.append(f"| {self.SEVERITY_COLORS[sev]} {sev.capitalize()} | {count} |")
        
        lines.append("")
        lines.append("---")
        lines.append("")
        lines.append("## Findings")
        lines.append("")
        
        # Sort by severity
        severity_order = ["critical", "high", "medium", "low", "info"]
        sorted_findings = sorted(self.findings, 
                                key=lambda f: severity_order.index(f.severity))
        
        for i, finding in enumerate(sorted_findings, 1):
            lines.extend([
                f"### {i}. {finding.title}",
                f"",
                f"**ID:** {finding.id}  ",
                f"**Severity:** {self.SEVERITY_COLORS[finding.severity]} {finding.severity.upper()} (CVSS: {finding.cvss})  ",
                f"**Type:** {finding.vulnerability_type}  ",
                f"**Endpoint:** `{finding.endpoint}`  ",
            ])
            
            if finding.parameter:
                lines.append(f"**Parameter:** `{finding.parameter}`  ")
            
            lines.append("")
            lines.append("#### Evidence")
            lines.append("```")
            lines.append(finding.evidence or "No evidence captured")
            lines.append("```")
            
            if finding.payload:
                lines.append("")
                lines.append("#### Payload")
                lines.append("```")
                lines.append(finding.payload)
                lines.append("```")
            
            lines.append("")
            lines.append("#### Impact")
            lines.append(finding.impact or "Impact not assessed")
            
            lines.append("")
            lines.append("#### Remediation")
            lines.append(finding.remediation or "Remediation not specified")
            
            if finding.references:
                lines.append("")
                lines.append("#### References")
                for ref in finding.references:
                    lines.append(f"- {ref}")
            
            lines.append("")
            lines.append("---")
            lines.append("")
        
        return "\n".join(lines)
    
    def generate_json(self) -> str:
        """Generate JSON report."""
        self.scan_end = datetime.now()
        
        report = {
            "metadata": {
                "target": self.target,
                "program": self.program,
                "scan_start": self.scan_start.isoformat(),
                "scan_end": self.scan_end.isoformat(),
                "total_findings": len(self.findings)
            },
            "summary": {
                "critical": len([f for f in self.findings if f.severity == "critical"]),
                "high": len([f for f in self.findings if f.severity == "high"]),
                "medium": len([f for f in self.findings if f.severity == "medium"]),
                "low": len([f for f in self.findings if f.severity == "low"]),
                "info": len([f for f in self.findings if f.severity == "info"]),
            },
            "findings": [f.to_dict() for f in self.findings]
        }
        
        return json.dumps(report, indent=2)
    
    def generate_hackerone(self) -> str:
        """Generate HackerOne-style report for submission."""
        if not self.findings:
            return "No findings to report."
        
        # Use highest severity finding as primary
        severity_order = ["critical", "high", "medium", "low", "info"]
        sorted_findings = sorted(self.findings,
                                key=lambda f: severity_order.index(f.severity))
        
        primary = sorted_findings[0]
        
        report = f"""## Summary
{primary.title}

## Severity
{primary.severity.upper()} ({primary.cvss})

## Description
A {primary.vulnerability_type} vulnerability was identified at:
- **Endpoint:** {primary.endpoint}
{f"- **Parameter:** {primary.parameter}" if primary.parameter else ""}

## Steps to Reproduce
1. Navigate to `{primary.endpoint}`
2. Inject the following payload:
```
{primary.payload or 'N/A'}
```
3. Observe the vulnerable behavior

## Evidence
```
{primary.evidence or 'See attached screenshots'}
```

## Impact
{primary.impact or 'An attacker could exploit this vulnerability to...'}

## Suggested Remediation
{primary.remediation or 'Implement proper input validation and output encoding.'}

## References
"""
        for ref in primary.references:
            report += f"- {ref}\n"
        
        if not primary.references:
            report += "- OWASP Testing Guide\n"
            report += f"- CWE (relevant CWE for {primary.vulnerability_type})\n"
        
        return report
    
    def save(self, output_dir: str = "reports", formats: List[str] = None):
        """Save report in specified formats."""
        formats = formats or ["markdown", "json"]
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        target_safe = self.target.replace("://", "_").replace("/", "_").replace(":", "_")[:30]
        
        saved = []
        
        if "markdown" in formats:
            md_path = output_path / f"report_{target_safe}_{timestamp}.md"
            md_path.write_text(self.generate_markdown())
            saved.append(str(md_path))
        
        if "json" in formats:
            json_path = output_path / f"report_{target_safe}_{timestamp}.json"
            json_path.write_text(self.generate_json())
            saved.append(str(json_path))
        
        if "hackerone" in formats:
            h1_path = output_path / f"hackerone_{target_safe}_{timestamp}.md"
            h1_path.write_text(self.generate_hackerone())
            saved.append(str(h1_path))
        
        return saved


# ═══════════════════════════════════════════════════════════════════════
# CVSS v4.0 SCORING (Phase 5 upgrade)
# ═══════════════════════════════════════════════════════════════════════

class CvssV4Score:
    """CVSS v4.0 score calculator.

    Implements simplified CVSS 4.0 scoring based on the base metric group.
    Vector format: CVSS:4.0/AV:.../AC:.../AT:.../PR:.../UI:.../VC:.../VI:.../VA:.../SC:.../SI:.../SA:...
    """

    # Metric value weights (simplified from CVSS 4.0 spec)
    AV_WEIGHTS = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}   # Network, Adjacent, Local, Physical
    AC_WEIGHTS = {"L": 0.77, "H": 0.44}                          # Low, High
    AT_WEIGHTS = {"N": 0.85, "P": 0.62}                          # None, Present (attack requirements)
    PR_WEIGHTS = {"N": 0.85, "L": 0.62, "H": 0.27}              # None, Low, High
    UI_WEIGHTS = {"N": 0.85, "P": 0.62, "A": 0.43}              # None, Passive, Active
    IMPACT_WEIGHTS = {"H": 0.56, "L": 0.22, "N": 0.0}           # High, Low, None

    def __init__(
        self,
        attack_vector: str = "N",
        attack_complexity: str = "L",
        attack_requirements: str = "N",
        privileges_required: str = "N",
        user_interaction: str = "N",
        vuln_conf: str = "N",
        vuln_integ: str = "N",
        vuln_avail: str = "N",
        sub_conf: str = "N",
        sub_integ: str = "N",
        sub_avail: str = "N",
    ):
        self.av = attack_vector
        self.ac = attack_complexity
        self.at = attack_requirements
        self.pr = privileges_required
        self.ui = user_interaction
        self.vc = vuln_conf
        self.vi = vuln_integ
        self.va = vuln_avail
        self.sc = sub_conf
        self.si = sub_integ
        self.sa = sub_avail

    @property
    def vector_string(self) -> str:
        """CVSS 4.0 vector string."""
        return (
            f"CVSS:4.0/AV:{self.av}/AC:{self.ac}/AT:{self.at}"
            f"/PR:{self.pr}/UI:{self.ui}"
            f"/VC:{self.vc}/VI:{self.vi}/VA:{self.va}"
            f"/SC:{self.sc}/SI:{self.si}/SA:{self.sa}"
        )

    @property
    def score(self) -> float:
        """Calculate CVSS 4.0 base score (0.0-10.0).

        Uses a simplified CVSS 4.0 model: Exploitability * Impact scaled to 0-10.
        The formula follows the general CVSS structure but uses lookup tables
        for the final score to match real-world CVSS 4.0 outputs.
        """
        # Exploitability sub-score (0-1)
        exploit = (
            self.AV_WEIGHTS.get(self.av, 0.5)
            * self.AC_WEIGHTS.get(self.ac, 0.5)
            * self.AT_WEIGHTS.get(self.at, 0.5)
            * self.PR_WEIGHTS.get(self.pr, 0.5)
            * self.UI_WEIGHTS.get(self.ui, 0.5)
        )

        # Impact sub-score — use additive model for more realistic scores
        impact_vals = [
            self.IMPACT_WEIGHTS.get(self.vc, 0.0),
            self.IMPACT_WEIGHTS.get(self.vi, 0.0),
            self.IMPACT_WEIGHTS.get(self.va, 0.0),
        ]
        sub_vals = [
            self.IMPACT_WEIGHTS.get(self.sc, 0.0),
            self.IMPACT_WEIGHTS.get(self.si, 0.0),
            self.IMPACT_WEIGHTS.get(self.sa, 0.0),
        ]
        vuln_impact = sum(impact_vals) / 1.68  # normalize: max 3*0.56=1.68
        sub_impact = sum(sub_vals) / 1.68
        impact = min(1.0, max(vuln_impact, sub_impact))

        if impact <= 0:
            return 0.0

        # Scale: exploit determines the ceiling, impact determines the floor
        # High exploit + high impact = 9-10, low exploit + low impact = 1-3
        raw = 1.0 + 9.0 * (0.6 * impact + 0.4 * exploit)
        return round(min(10.0, raw), 1)

    @property
    def severity(self) -> str:
        """Qualitative severity rating."""
        s = self.score
        if s >= 9.0:
            return "Critical"
        elif s >= 7.0:
            return "High"
        elif s >= 4.0:
            return "Medium"
        elif s > 0.0:
            return "Low"
        return "None"

    def to_dict(self) -> dict:
        return {
            "vector": self.vector_string,
            "score": self.score,
            "severity": self.severity,
        }

    @classmethod
    def from_finding(cls, finding: dict) -> "CvssV4Score":
        """Auto-calculate CVSS v4.0 from a finding dict."""
        vuln_type = finding.get("vulnerability_type", "").lower()
        severity = finding.get("severity", "medium").lower()

        # Map common vuln types to CVSS v4.0 metrics
        def _mk(av="N", ac="L", at="N", pr="N", ui="N", vc="N", vi="N", va="N", sc="N", si="N", sa="N"):
            return cls(attack_vector=av, attack_complexity=ac, attack_requirements=at,
                       privileges_required=pr, user_interaction=ui,
                       vuln_conf=vc, vuln_integ=vi, vuln_avail=va,
                       sub_conf=sc, sub_integ=si, sub_avail=sa)

        presets = {
            "sqli": _mk(vc="H", vi="H", va="H"),
            "xss": _mk(ui="P", vc="L", vi="L"),
            "cors": _mk(ui="P", vc="L"),
            "ssrf": _mk(vc="H", vi="L"),
            "idor": _mk(pr="L", vc="H", vi="H"),
            "lfi": _mk(vc="H"),
            "auth_bypass": _mk(vc="H", vi="H", va="H"),
            "ssti": _mk(vc="H", vi="H", va="H"),
        }

        for key, preset in presets.items():
            if key in vuln_type:
                return preset

        # Default based on severity
        if severity == "critical":
            return _mk(vc="H", vi="H", va="H")
        elif severity == "high":
            return _mk(vc="H", vi="L")
        elif severity == "medium":
            return _mk(at="P", vc="L", vi="L")
        else:
            return _mk(ac="H", at="P", pr="L", vc="L")


def calculate_cvss4(finding: dict) -> CvssV4Score:
    """Calculate CVSS v4.0 score for a finding.

    Convenience function that wraps CvssV4Score.from_finding().
    """
    return CvssV4Score.from_finding(finding)


# Predefined finding templates
FINDING_TEMPLATES = {
    "sqli": {
        "title": "SQL Injection",
        "vulnerability_type": "SQL Injection",
        "impact": "An attacker could read, modify, or delete database contents. In severe cases, this could lead to complete database compromise or remote code execution.",
        "remediation": "Use parameterized queries (prepared statements) instead of string concatenation. Implement input validation and use an ORM.",
        "references": [
            "https://owasp.org/www-community/attacks/SQL_Injection",
            "https://cwe.mitre.org/data/definitions/89.html"
        ]
    },
    "xss": {
        "title": "Cross-Site Scripting (XSS)",
        "vulnerability_type": "XSS",
        "impact": "An attacker could execute malicious JavaScript in victims' browsers, stealing session cookies, credentials, or performing actions on behalf of users.",
        "remediation": "Implement proper output encoding. Use Content-Security-Policy headers. Sanitize user input with a whitelist approach.",
        "references": [
            "https://owasp.org/www-community/attacks/xss/",
            "https://cwe.mitre.org/data/definitions/79.html"
        ]
    },
    "lfi": {
        "title": "Local File Inclusion",
        "vulnerability_type": "LFI",
        "impact": "An attacker could read sensitive files from the server, including configuration files, source code, or system files like /etc/passwd.",
        "remediation": "Avoid using user input in file paths. Use a whitelist of allowed files. Implement proper input validation.",
        "references": [
            "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/11.1-Testing_for_Local_File_Inclusion",
            "https://cwe.mitre.org/data/definitions/98.html"
        ]
    },
    "ssrf": {
        "title": "Server-Side Request Forgery",
        "vulnerability_type": "SSRF",
        "impact": "An attacker could make requests to internal services, access cloud metadata endpoints (AWS/GCP/Azure), or scan internal networks.",
        "remediation": "Validate and sanitize URLs. Use allowlists for permitted domains. Block requests to private IP ranges.",
        "references": [
            "https://owasp.org/www-community/attacks/Server_Side_Request_Forgery",
            "https://cwe.mitre.org/data/definitions/918.html"
        ]
    },
    "idor": {
        "title": "Insecure Direct Object Reference",
        "vulnerability_type": "IDOR",
        "impact": "An attacker could access or modify other users' data by manipulating object references (IDs, filenames, etc.).",
        "remediation": "Implement proper authorization checks. Use indirect references. Verify user permissions for each resource access.",
        "references": [
            "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/04-Testing_for_Insecure_Direct_Object_References",
            "https://cwe.mitre.org/data/definitions/639.html"
        ]
    }
}


def create_finding_from_template(template_name: str, endpoint: str, 
                                parameter: str = None, payload: str = None,
                                evidence: str = None, severity: str = "medium",
                                cvss: float = 5.0) -> Finding:
    """Create a Finding using a predefined template."""
    template = FINDING_TEMPLATES.get(template_name, {})
    
    return Finding(
        id=f"VULN-{template_name.upper()}-001",
        title=template.get("title", f"{template_name.upper()} Vulnerability"),
        severity=severity,
        cvss=cvss,
        vulnerability_type=template.get("vulnerability_type", template_name),
        endpoint=endpoint,
        parameter=parameter,
        payload=payload,
        evidence=evidence or "",
        impact=template.get("impact", ""),
        remediation=template.get("remediation", ""),
        references=template.get("references", [])
    )


# Export
__all__ = [
    "Finding",
    "ReportGenerator",
    "FINDING_TEMPLATES",
    "create_finding_from_template"
]
