"""Compliance Mapper — maps findings to security standards (PCI-DSS, OWASP, HIPAA, SOC2, NIST)."""

from typing import Dict, List, Optional

# CWE → compliance standard mappings
CWE_COMPLIANCE = {
    "CWE-79": {  # XSS
        "owasp": "A03:2021 Injection",
        "pci_dss": "6.5.7 Cross-site scripting",
        "nist": "SI-10 Information Input Validation",
        "hipaa": "164.312(a)(1) Access Control",
    },
    "CWE-89": {  # SQL Injection
        "owasp": "A03:2021 Injection",
        "pci_dss": "6.5.1 SQL Injection",
        "nist": "SI-10 Information Input Validation",
        "hipaa": "164.312(a)(1) Access Control",
    },
    "CWE-22": {  # Path Traversal
        "owasp": "A01:2021 Broken Access Control",
        "pci_dss": "6.5.8 Improper Access Control",
        "nist": "AC-3 Access Enforcement",
    },
    "CWE-78": {  # OS Command Injection
        "owasp": "A03:2021 Injection",
        "pci_dss": "6.5.1 Injection Flaws",
        "nist": "SI-10 Information Input Validation",
    },
    "CWE-352": {  # CSRF
        "owasp": "A01:2021 Broken Access Control",
        "pci_dss": "6.5.9 Cross-site request forgery",
        "nist": "SC-23 Session Authenticity",
    },
    "CWE-918": {  # SSRF
        "owasp": "A10:2021 Server-Side Request Forgery",
        "pci_dss": "6.5.8 Improper Access Control",
        "nist": "AC-4 Information Flow Enforcement",
    },
    "CWE-611": {  # XXE
        "owasp": "A05:2021 Security Misconfiguration",
        "pci_dss": "6.5.1 Injection Flaws",
        "nist": "SI-10 Information Input Validation",
    },
    "CWE-502": {  # Deserialization
        "owasp": "A08:2021 Software and Data Integrity Failures",
        "pci_dss": "6.5.1 Injection Flaws",
        "nist": "SI-10 Information Input Validation",
    },
    "CWE-287": {  # Improper Authentication
        "owasp": "A07:2021 Identification and Authentication Failures",
        "pci_dss": "8.1 User Identification",
        "nist": "IA-2 Identification and Authentication",
        "hipaa": "164.312(d) Person or Entity Authentication",
        "soc2": "CC6.1 Logical Access Security",
    },
    "CWE-306": {  # Missing Authentication
        "owasp": "A07:2021 Identification and Authentication Failures",
        "pci_dss": "8.1 User Identification",
        "nist": "IA-2 Identification and Authentication",
    },
    "CWE-434": {  # Unrestricted Upload
        "owasp": "A04:2021 Insecure Design",
        "pci_dss": "6.5.8 Improper Access Control",
        "nist": "SI-10 Information Input Validation",
    },
    "CWE-94": {  # Code Injection
        "owasp": "A03:2021 Injection",
        "pci_dss": "6.5.1 Injection Flaws",
        "nist": "SI-10 Information Input Validation",
    },
    "CWE-1021": {  # Clickjacking
        "owasp": "A04:2021 Insecure Design",
        "pci_dss": "6.5.7 Cross-site scripting",
        "nist": "SC-18 Mobile Code",
    },
    "CWE-200": {  # Information Exposure
        "owasp": "A01:2021 Broken Access Control",
        "pci_dss": "6.5.8 Improper Access Control",
        "nist": "AC-3 Access Enforcement",
        "hipaa": "164.312(a)(1) Access Control",
        "soc2": "CC6.1 Logical Access Security",
    },
    "CWE-311": {  # Missing Encryption
        "owasp": "A02:2021 Cryptographic Failures",
        "pci_dss": "4.1 Strong Cryptography",
        "nist": "SC-8 Transmission Confidentiality",
        "hipaa": "164.312(e)(1) Transmission Security",
        "soc2": "CC6.7 Encryption in Transit",
    },
    "CWE-798": {  # Hardcoded Credentials
        "owasp": "A07:2021 Identification and Authentication Failures",
        "pci_dss": "2.1 Default Passwords",
        "nist": "IA-5 Authenticator Management",
    },
}

# Vuln type → CWE mapping
VULN_TO_CWE = {
    "xss": "CWE-79", "xss_reflected": "CWE-79", "xss_stored": "CWE-79",
    "sqli": "CWE-89", "sqli_error": "CWE-89", "sqli_union": "CWE-89", "sqli_blind": "CWE-89",
    "lfi": "CWE-22", "lfi_basic": "CWE-22", "lfi_wrapper": "CWE-22", "path_traversal": "CWE-22",
    "cmdi": "CWE-78", "cmdi_basic": "CWE-78", "command_injection": "CWE-78",
    "csrf": "CWE-352",
    "ssrf": "CWE-918", "ssrf_basic": "CWE-918",
    "xxe": "CWE-611", "xxe_basic": "CWE-611",
    "deserialization": "CWE-502", "insecure_deserialization": "CWE-502",
    "auth_bypass": "CWE-287", "auth_bypass_cookie": "CWE-287", "auth_bypass_header": "CWE-287",
    "default_creds": "CWE-798",
    "file_upload": "CWE-434",
    "ssti": "CWE-94", "ssti_basic": "CWE-94",
    "cors": "CWE-200", "cors_check": "CWE-200", "cors_misconfig": "CWE-200",
    "info_disclosure": "CWE-200",
    "secret_exposure": "CWE-798",
}


def enrich_finding(finding: Dict) -> Dict:
    """Add compliance data to a finding dict. Returns enriched copy."""
    enriched = dict(finding)
    vuln_type = finding.get("type", finding.get("vuln_type", "")).lower()

    cwe = finding.get("cwe") or VULN_TO_CWE.get(vuln_type)
    if cwe:
        compliance = CWE_COMPLIANCE.get(cwe, {})
        if compliance:
            enriched["compliance"] = compliance
            enriched["cwe"] = cwe
    return enriched


def format_compliance_section(findings: List[Dict]) -> str:
    """Format compliance info for report output."""
    standards_hit = {}  # standard -> set of findings

    for f in findings:
        enriched = enrich_finding(f)
        compliance = enriched.get("compliance", {})
        for standard, ref in compliance.items():
            standards_hit.setdefault(standard, set()).add(ref)

    if not standards_hit:
        return "No compliance mappings available for current findings."

    lines = ["## Compliance Impact\n"]
    standard_names = {
        "owasp": "OWASP Top 10 (2021)",
        "pci_dss": "PCI DSS v4.0",
        "nist": "NIST SP 800-53",
        "hipaa": "HIPAA Security Rule",
        "soc2": "SOC 2 Trust Services Criteria",
    }
    for std, refs in sorted(standards_hit.items()):
        name = standard_names.get(std, std.upper())
        lines.append(f"### {name}")
        for ref in sorted(refs):
            lines.append(f"- {ref}")
        lines.append("")

    return "\n".join(lines)
