#!/usr/bin/env python3
"""
VIPER MITRE ATT&CK Mapper — Maps CWE IDs to CAPEC, ATT&CK techniques, and kill chain phases.

Provides enrichment for findings with MITRE ATT&CK context including:
  - CWE → CAPEC attack pattern mapping
  - CWE → ATT&CK technique/tactic mapping
  - Kill chain phase classification
  - Attack narrative generation
"""

from typing import Dict, List, Optional


# ---------------------------------------------------------------------------
# CWE → CAPEC → ATT&CK mapping table (30+ entries)
# ---------------------------------------------------------------------------

CWE_TO_ATTACK: Dict[str, Dict] = {
    # -- Injection family --
    "CWE-79": {
        "capec": ["CAPEC-86", "CAPEC-198"],
        "technique": "T1059.007",
        "tactic": "Execution",
        "name": "Cross-Site Scripting",
        "description": "Injection of malicious scripts into web pages viewed by other users",
    },
    "CWE-89": {
        "capec": ["CAPEC-66", "CAPEC-7"],
        "technique": "T1190",
        "tactic": "Initial Access",
        "name": "SQL Injection",
        "description": "Insertion of SQL commands into input fields to manipulate database queries",
    },
    "CWE-78": {
        "capec": ["CAPEC-88"],
        "technique": "T1059",
        "tactic": "Execution",
        "name": "OS Command Injection",
        "description": "Execution of arbitrary OS commands through vulnerable application inputs",
    },
    "CWE-94": {
        "capec": ["CAPEC-242", "CAPEC-35"],
        "technique": "T1059",
        "tactic": "Execution",
        "name": "Code Injection",
        "description": "Injection of code that is interpreted/executed by the application",
    },
    "CWE-90": {
        "capec": ["CAPEC-136"],
        "technique": "T1190",
        "tactic": "Initial Access",
        "name": "LDAP Injection",
        "description": "Manipulation of LDAP queries through crafted input",
    },
    "CWE-643": {
        "capec": ["CAPEC-83"],
        "technique": "T1190",
        "tactic": "Initial Access",
        "name": "XPath Injection",
        "description": "Injection of XPath queries to extract data from XML stores",
    },
    "CWE-943": {
        "capec": ["CAPEC-676"],
        "technique": "T1190",
        "tactic": "Initial Access",
        "name": "NoSQL Injection",
        "description": "Manipulation of NoSQL database queries through crafted input",
    },
    "CWE-113": {
        "capec": ["CAPEC-105"],
        "technique": "T1557",
        "tactic": "Collection",
        "name": "HTTP Response Splitting",
        "description": "Injection of CRLF characters to split HTTP responses",
    },
    "CWE-93": {
        "capec": ["CAPEC-105"],
        "technique": "T1557",
        "tactic": "Collection",
        "name": "CRLF Injection",
        "description": "Injection of carriage return/line feed characters into HTTP headers",
    },
    "CWE-1321": {
        "capec": ["CAPEC-242"],
        "technique": "T1059.007",
        "tactic": "Execution",
        "name": "Prototype Pollution",
        "description": "Modification of JavaScript object prototypes to alter application behavior",
    },

    # -- Access Control family --
    "CWE-22": {
        "capec": ["CAPEC-126"],
        "technique": "T1083",
        "tactic": "Discovery",
        "name": "Path Traversal",
        "description": "Accessing files outside the intended directory via path manipulation",
    },
    "CWE-98": {
        "capec": ["CAPEC-193"],
        "technique": "T1105",
        "tactic": "Command and Control",
        "name": "Remote File Inclusion",
        "description": "Including remote files to execute arbitrary code on the server",
    },
    "CWE-639": {
        "capec": ["CAPEC-58"],
        "technique": "T1078",
        "tactic": "Privilege Escalation",
        "name": "Insecure Direct Object Reference",
        "description": "Accessing objects by manipulating references without authorization checks",
    },
    "CWE-601": {
        "capec": ["CAPEC-194"],
        "technique": "T1566.002",
        "tactic": "Initial Access",
        "name": "Open Redirect",
        "description": "Redirecting users to malicious sites through manipulated URL parameters",
    },
    "CWE-548": {
        "capec": ["CAPEC-127"],
        "technique": "T1083",
        "tactic": "Discovery",
        "name": "Directory Listing",
        "description": "Exposure of directory contents due to misconfigured web server",
    },
    "CWE-284": {
        "capec": ["CAPEC-233"],
        "technique": "T1584.001",
        "tactic": "Resource Development",
        "name": "Improper Access Control",
        "description": "Failure to properly restrict access to resources",
    },

    # -- SSRF --
    "CWE-918": {
        "capec": ["CAPEC-664"],
        "technique": "T1190",
        "tactic": "Initial Access",
        "name": "Server-Side Request Forgery",
        "description": "Forcing the server to make requests to unintended locations",
    },

    # -- Authentication --
    "CWE-287": {
        "capec": ["CAPEC-114"],
        "technique": "T1078",
        "tactic": "Initial Access",
        "name": "Improper Authentication",
        "description": "Bypassing authentication mechanisms to gain unauthorized access",
    },
    "CWE-521": {
        "capec": ["CAPEC-49", "CAPEC-55"],
        "technique": "T1110",
        "tactic": "Credential Access",
        "name": "Weak Password Requirements",
        "description": "Insufficient password complexity enabling brute-force attacks",
    },
    "CWE-384": {
        "capec": ["CAPEC-61"],
        "technique": "T1563",
        "tactic": "Lateral Movement",
        "name": "Session Fixation",
        "description": "Forcing a user session to a known value for session hijacking",
    },
    "CWE-352": {
        "capec": ["CAPEC-62"],
        "technique": "T1185",
        "tactic": "Collection",
        "name": "Cross-Site Request Forgery",
        "description": "Tricking authenticated users into executing unintended actions",
    },

    # -- Cryptographic --
    "CWE-327": {
        "capec": ["CAPEC-20"],
        "technique": "T1600",
        "tactic": "Defense Evasion",
        "name": "Use of Broken Crypto Algorithm",
        "description": "Using weak or broken cryptographic algorithms that can be defeated",
    },
    "CWE-311": {
        "capec": ["CAPEC-157"],
        "technique": "T1040",
        "tactic": "Credential Access",
        "name": "Missing Encryption of Sensitive Data",
        "description": "Transmitting or storing sensitive data without encryption",
    },
    "CWE-798": {
        "capec": ["CAPEC-191"],
        "technique": "T1552.001",
        "tactic": "Credential Access",
        "name": "Hard-coded Credentials",
        "description": "Credentials embedded in source code or configuration files",
    },

    # -- Misconfiguration --
    "CWE-942": {
        "capec": ["CAPEC-111"],
        "technique": "T1189",
        "tactic": "Initial Access",
        "name": "Overly Permissive CORS Policy",
        "description": "CORS misconfiguration allowing unauthorized cross-origin access",
    },
    "CWE-16": {
        "capec": ["CAPEC-75"],
        "technique": "T1574",
        "tactic": "Persistence",
        "name": "Configuration Weakness",
        "description": "Security weaknesses arising from system misconfiguration",
    },
    "CWE-693": {
        "capec": ["CAPEC-554"],
        "technique": "T1562",
        "tactic": "Defense Evasion",
        "name": "Protection Mechanism Failure",
        "description": "Missing or ineffective security headers or protection mechanisms",
    },
    "CWE-215": {
        "capec": ["CAPEC-170"],
        "technique": "T1592",
        "tactic": "Reconnaissance",
        "name": "Information Exposure Through Debug",
        "description": "Leaking sensitive information through debug endpoints or error pages",
    },
    "CWE-1021": {
        "capec": ["CAPEC-103"],
        "technique": "T1189",
        "tactic": "Initial Access",
        "name": "Clickjacking",
        "description": "Tricking users into clicking hidden UI elements via frame overlay",
    },

    # -- Deserialization / XXE --
    "CWE-502": {
        "capec": ["CAPEC-586"],
        "technique": "T1059",
        "tactic": "Execution",
        "name": "Deserialization of Untrusted Data",
        "description": "Executing arbitrary code through malicious serialized objects",
    },
    "CWE-611": {
        "capec": ["CAPEC-221"],
        "technique": "T1059",
        "tactic": "Execution",
        "name": "XML External Entity",
        "description": "Processing external XML entities to read files or perform SSRF",
    },

    # -- File Upload --
    "CWE-434": {
        "capec": ["CAPEC-1"],
        "technique": "T1105",
        "tactic": "Command and Control",
        "name": "Unrestricted File Upload",
        "description": "Uploading malicious files to achieve remote code execution",
    },

    # -- Information Disclosure --
    "CWE-200": {
        "capec": ["CAPEC-118"],
        "technique": "T1592",
        "tactic": "Reconnaissance",
        "name": "Information Exposure",
        "description": "Unintended disclosure of sensitive information to unauthorized actors",
    },
    "CWE-209": {
        "capec": ["CAPEC-54"],
        "technique": "T1592",
        "tactic": "Reconnaissance",
        "name": "Error Message Information Exposure",
        "description": "Revealing sensitive information through verbose error messages",
    },

    # -- Design Flaws --
    "CWE-840": {
        "capec": ["CAPEC-207"],
        "technique": "T1190",
        "tactic": "Initial Access",
        "name": "Business Logic Errors",
        "description": "Exploiting flaws in application business logic",
    },
    "CWE-362": {
        "capec": ["CAPEC-26"],
        "technique": "T1068",
        "tactic": "Privilege Escalation",
        "name": "Race Condition",
        "description": "Exploiting timing windows in concurrent operations",
    },

    # -- Components --
    "CWE-1104": {
        "capec": ["CAPEC-310"],
        "technique": "T1195.002",
        "tactic": "Initial Access",
        "name": "Unmaintained Third-Party Components",
        "description": "Using outdated components with known vulnerabilities",
    },
    "CWE-1035": {
        "capec": ["CAPEC-310"],
        "technique": "T1195.002",
        "tactic": "Initial Access",
        "name": "Known Vulnerability in Third-Party Software",
        "description": "Exploiting published CVEs in third-party dependencies",
    },

    # -- HTTP Smuggling --
    "CWE-444": {
        "capec": ["CAPEC-33"],
        "technique": "T1557",
        "tactic": "Collection",
        "name": "HTTP Request Smuggling",
        "description": "Exploiting discrepancies in HTTP request parsing between servers",
    },
}


# ---------------------------------------------------------------------------
# Kill chain phases
# ---------------------------------------------------------------------------

KILL_CHAIN_PHASES: Dict[str, List[str]] = {
    "reconnaissance": [
        "subdomain_enum", "port_scan", "tech_fingerprint",
        "whois", "dns_enum", "shodan_search", "google_dork",
    ],
    "weaponization": [
        "payload_generation", "exploit_selection", "wordlist_generation",
        "fuzzer_setup", "encoding",
    ],
    "delivery": [
        "sqli", "xss", "ssti", "lfi", "cmdi", "xxe", "ssrf",
        "nosql_injection", "ldap_injection", "xpath_injection",
        "crlf", "header_injection",
    ],
    "exploitation": [
        "rce", "auth_bypass", "idor", "deserialization",
        "file_upload", "prototype_pollution", "race_condition",
        "request_smuggling", "cache_poisoning",
    ],
    "installation": [
        "webshell", "backdoor", "persistence",
    ],
    "command_and_control": [
        "reverse_shell", "bind_shell", "c2_beacon",
    ],
    "actions_on_objectives": [
        "data_exfil", "privilege_escalation", "lateral_movement",
        "credential_dump", "ransomware",
    ],
}

# Reverse index: attack_type → phase
_ATTACK_TO_PHASE: Dict[str, str] = {}
for _phase, _attacks in KILL_CHAIN_PHASES.items():
    for _attack in _attacks:
        _ATTACK_TO_PHASE[_attack] = _phase


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def get_mitre_mapping(cwe_id: str) -> Optional[Dict]:
    """Return CAPEC/ATT&CK mapping for a CWE ID, or None if unmapped.

    Args:
        cwe_id: CWE identifier (e.g. "CWE-79" or "79")

    Returns:
        Dict with capec, technique, tactic, name, description keys or None
    """
    if not cwe_id:
        return None
    # Normalize: accept "79" or "CWE-79"
    normalized = cwe_id if cwe_id.startswith("CWE-") else f"CWE-{cwe_id}"
    return CWE_TO_ATTACK.get(normalized)


def enrich_finding_mitre(finding: Dict) -> Dict:
    """Add MITRE ATT&CK enrichment to a finding dict (in-place and returned).

    Reads the CWE from finding['compliance']['cwe_id'] or finding['cwe'],
    looks up the ATT&CK mapping, and adds a 'mitre_attack' sub-dict.
    Also adds kill_chain_phase based on vuln_type/attack type.
    """
    # Extract CWE ID from finding
    cwe_id = None
    compliance = finding.get("compliance", {})
    if compliance:
        cwe_id = compliance.get("cwe_id")
    if not cwe_id:
        cwe_id = finding.get("cwe", "")

    mapping = get_mitre_mapping(cwe_id)
    if mapping:
        finding["mitre_attack"] = {
            "technique_id": mapping["technique"],
            "technique_name": mapping["name"],
            "tactic": mapping["tactic"],
            "capec_ids": mapping["capec"],
            "description": mapping["description"],
        }

    # Add kill chain phase
    vuln_type = (
        finding.get("vuln_type")
        or finding.get("attack")
        or finding.get("type")
        or ""
    ).lower()
    phase = get_kill_chain_phase(vuln_type)
    if phase:
        finding.setdefault("mitre_attack", {})["kill_chain_phase"] = phase

    return finding


def get_kill_chain_phase(attack_type: str) -> Optional[str]:
    """Return the kill chain phase for a given attack type, or None."""
    return _ATTACK_TO_PHASE.get(attack_type.lower()) if attack_type else None


def get_attack_narrative(findings: List[Dict]) -> str:
    """Generate an ATT&CK narrative summary from a list of enriched findings.

    Builds a textual attack narrative describing the tactics and techniques
    observed, organized by kill chain phase.
    """
    if not findings:
        return "No findings to generate narrative from."

    # Collect unique techniques by tactic
    by_tactic: Dict[str, List[Dict]] = {}
    for f in findings:
        mitre = f.get("mitre_attack")
        if not mitre:
            enriched = enrich_finding_mitre(f)
            mitre = enriched.get("mitre_attack")
        if not mitre or "technique_id" not in mitre:
            continue
        tactic = mitre.get("tactic", "Unknown")
        by_tactic.setdefault(tactic, []).append(mitre)

    if not by_tactic:
        return "No findings could be mapped to MITRE ATT&CK techniques."

    # Build narrative
    tactic_order = [
        "Reconnaissance", "Resource Development", "Initial Access",
        "Execution", "Persistence", "Privilege Escalation",
        "Defense Evasion", "Credential Access", "Discovery",
        "Lateral Movement", "Collection", "Command and Control",
        "Exfiltration", "Impact",
    ]

    lines = ["# MITRE ATT&CK Narrative\n"]
    total_techniques = set()

    for tactic in tactic_order:
        entries = by_tactic.get(tactic)
        if not entries:
            continue

        lines.append(f"\n## {tactic}\n")
        seen = set()
        for entry in entries:
            tid = entry["technique_id"]
            if tid in seen:
                continue
            seen.add(tid)
            total_techniques.add(tid)
            name = entry.get("technique_name", "Unknown")
            desc = entry.get("description", "")
            lines.append(f"- **{tid}** ({name}): {desc}")

    # Handle any tactics not in the standard order
    for tactic, entries in by_tactic.items():
        if tactic in tactic_order:
            continue
        lines.append(f"\n## {tactic}\n")
        seen = set()
        for entry in entries:
            tid = entry["technique_id"]
            if tid in seen:
                continue
            seen.add(tid)
            total_techniques.add(tid)
            name = entry.get("technique_name", "Unknown")
            desc = entry.get("description", "")
            lines.append(f"- **{tid}** ({name}): {desc}")

    lines.insert(1, f"**{len(total_techniques)} unique techniques** across "
                    f"**{len(by_tactic)} tactics** identified.\n")

    return "\n".join(lines)


class MitreMapper:
    """Wrapper class for MITRE ATT&CK mapping functions."""

    @staticmethod
    def map(cwe_id: str):
        return get_mitre_mapping(cwe_id)

    @staticmethod
    def enrich(finding: dict):
        return enrich_finding_mitre(finding)

    @staticmethod
    def kill_chain_phase(attack_type: str):
        return get_kill_chain_phase(attack_type)

    @staticmethod
    def narrative(findings: list):
        return get_attack_narrative(findings)

    @staticmethod
    def tactic_coverage(findings: list):
        return get_tactic_coverage(findings)


def get_tactic_coverage(findings: List[Dict]) -> Dict[str, int]:
    """Return a dict of tactic → count of findings mapped to that tactic."""
    coverage: Dict[str, int] = {}
    for f in findings:
        mitre = f.get("mitre_attack")
        if not mitre:
            enriched = enrich_finding_mitre(f)
            mitre = enriched.get("mitre_attack")
        if mitre and "tactic" in mitre:
            tactic = mitre["tactic"]
            coverage[tactic] = coverage.get(tactic, 0) + 1
    return coverage
