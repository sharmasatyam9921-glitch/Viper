#!/usr/bin/env python3
"""
VIPER 5.0 — Attack Chain Escalation Engine

Detects combinations of low/medium-severity findings that, when chained
together, constitute a higher-severity attack path. Produces escalated
findings with full chain documentation suitable for bug bounty reports.

Example chains:
  CORS misconfiguration + CSRF → Account Takeover (Critical)
  SSRF + Internal API discovery → Data Exfiltration (Critical)
  LFI + Log Poisoning → Remote Code Execution (Critical)
  Open Redirect + OAuth misconfiguration → Token Theft (High)
  IDOR + PII Exposure → Mass Data Breach (Critical)
"""

import logging
import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional, Set, Tuple

logger = logging.getLogger("viper.chain_escalator")


@dataclass
class EscalatedChain:
    """A chain of vulnerabilities that escalates to a higher severity."""

    chain_name: str
    escalated_severity: str
    escalated_impact: str
    component_findings: List[Dict[str, Any]]
    matched_requirements: List[str]
    cvss_bump: float = 0.0
    report_narrative: str = ""
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())

    def to_dict(self) -> Dict[str, Any]:
        return {
            "chain_name": self.chain_name,
            "severity": self.escalated_severity,
            "impact": self.escalated_impact,
            "component_findings": self.component_findings,
            "matched_requirements": self.matched_requirements,
            "cvss_bump": self.cvss_bump,
            "report_narrative": self.report_narrative,
            "timestamp": self.timestamp,
        }

    def to_finding(self) -> Dict[str, Any]:
        """Convert this chain to a finding dict compatible with VIPER's pipeline."""
        component_urls = list({
            f.get("url", "") for f in self.component_findings if f.get("url")
        })
        component_types = list({
            f.get("vuln_type", f.get("attack", "unknown"))
            for f in self.component_findings
        })
        return {
            "type": "attack_chain",
            "vuln_type": f"chain_{self.chain_name}",
            "attack": f"chain_{self.chain_name}",
            "severity": self.escalated_severity,
            "confidence": 0.70,
            "url": component_urls[0] if component_urls else "",
            "details": self.report_narrative or self.escalated_impact,
            "impact": self.escalated_impact,
            "chain_name": self.chain_name,
            "chain_components": component_types,
            "chain_urls": component_urls,
            "source": "chain_escalator",
            "validated": False,  # chains need manual validation
        }


# ═══════════════════════════════════════════════════════════════
# Chain Definitions
# ═══════════════════════════════════════════════════════════════

# Each chain specifies:
#   requires: list of alternative requirement sets (any set matching = chain found)
#   escalated_severity: the resulting severity
#   escalated_impact: human-readable impact description
#   narrative_template: template for the report narrative
#   cvss_bump: how much to increase CVSS score above the max component score

CHAINS: Dict[str, Dict[str, Any]] = {
    "account_takeover_cors": {
        "requires": [["cors", "csrf"]],
        "escalated_severity": "critical",
        "escalated_impact": (
            "Full account takeover: CORS misconfiguration allows a malicious site "
            "to read cross-origin responses, and missing CSRF protection allows "
            "state-changing actions, enabling complete account compromise."
        ),
        "narrative_template": (
            "An attacker can chain the CORS misconfiguration on {urls} with the "
            "CSRF vulnerability to perform authenticated actions on behalf of the "
            "victim. The CORS issue allows reading sensitive data cross-origin, "
            "while the CSRF flaw enables state-changing operations without tokens."
        ),
        "cvss_bump": 2.5,
    },
    "account_takeover_xss": {
        "requires": [["xss", "csrf"], ["xss", "session"]],
        "escalated_severity": "critical",
        "escalated_impact": (
            "Account takeover via XSS: Cross-site scripting enables session "
            "hijacking or CSRF bypass, leading to full account compromise."
        ),
        "narrative_template": (
            "The XSS vulnerability at {urls} can be exploited to steal session "
            "tokens or bypass CSRF protections, enabling full account takeover."
        ),
        "cvss_bump": 2.0,
    },
    "data_exfiltration_ssrf": {
        "requires": [["ssrf", "internal"], ["ssrf", "api"], ["ssrf", "cloud"]],
        "escalated_severity": "critical",
        "escalated_impact": (
            "Internal data exfiltration: SSRF allows reaching internal services "
            "or cloud metadata endpoints, enabling extraction of secrets, "
            "credentials, and internal data."
        ),
        "narrative_template": (
            "The SSRF vulnerability at {urls} can be chained with internal "
            "service access to exfiltrate sensitive data including cloud "
            "credentials, internal API responses, and configuration secrets."
        ),
        "cvss_bump": 3.0,
    },
    "rce_via_lfi": {
        "requires": [
            ["lfi", "log_poison"],
            ["lfi", "file_upload"],
            ["lfi", "log"],
        ],
        "escalated_severity": "critical",
        "escalated_impact": (
            "Remote code execution via LFI chain: Local file inclusion combined "
            "with log poisoning or file upload enables arbitrary code execution "
            "on the server."
        ),
        "narrative_template": (
            "The LFI vulnerability at {urls} can be escalated to RCE by "
            "injecting code into log files or uploaded files, then including "
            "them via the LFI endpoint."
        ),
        "cvss_bump": 3.5,
    },
    "rce_via_ssti": {
        "requires": [["ssti", "template"], ["ssti"]],
        "escalated_severity": "critical",
        "escalated_impact": (
            "Remote code execution via server-side template injection: SSTI "
            "allows arbitrary code execution through template engine payloads."
        ),
        "narrative_template": (
            "The SSTI vulnerability at {urls} enables direct remote code "
            "execution through template engine payload injection."
        ),
        "cvss_bump": 2.0,
    },
    "token_theft_redirect": {
        "requires": [
            ["open_redirect", "oauth"],
            ["redirect", "oauth"],
            ["open_redirect", "sso"],
        ],
        "escalated_severity": "high",
        "escalated_impact": (
            "OAuth token theft: Open redirect in the OAuth flow allows an "
            "attacker to steal authorization codes or tokens by redirecting "
            "the callback to an attacker-controlled domain."
        ),
        "narrative_template": (
            "The open redirect at {urls} can be exploited during the OAuth "
            "flow to redirect authorization codes or tokens to an attacker-"
            "controlled domain, enabling account compromise."
        ),
        "cvss_bump": 2.0,
    },
    "mass_data_breach": {
        "requires": [
            ["idor", "pii"],
            ["idor", "personal"],
            ["idor", "user_data"],
            ["bola", "pii"],
        ],
        "escalated_severity": "critical",
        "escalated_impact": (
            "Mass user data breach: IDOR/BOLA vulnerability combined with PII "
            "exposure allows an attacker to enumerate and exfiltrate personal "
            "data of all users in the system."
        ),
        "narrative_template": (
            "The IDOR vulnerability at {urls} exposes PII that can be "
            "enumerated across all user accounts, constituting a mass data "
            "breach affecting potentially all users of the platform."
        ),
        "cvss_bump": 2.5,
    },
    "privilege_escalation": {
        "requires": [
            ["idor", "admin"],
            ["auth_bypass", "admin"],
            ["broken_access", "role"],
        ],
        "escalated_severity": "critical",
        "escalated_impact": (
            "Privilege escalation to admin: Access control flaws allow a "
            "regular user to gain administrative privileges."
        ),
        "narrative_template": (
            "The access control vulnerability at {urls} allows escalation "
            "from a regular user role to administrative access, enabling "
            "full control over the application."
        ),
        "cvss_bump": 3.0,
    },
    "sqli_data_dump": {
        "requires": [["sqli", "database"], ["sql_injection", "data"]],
        "escalated_severity": "critical",
        "escalated_impact": (
            "Database data dump via SQL injection: Confirmed SQL injection "
            "combined with database access enables extraction of entire "
            "database contents including credentials and user data."
        ),
        "narrative_template": (
            "The SQL injection at {urls} provides direct database access, "
            "enabling extraction of all stored data including user credentials, "
            "personal information, and application secrets."
        ),
        "cvss_bump": 2.0,
    },
    "stored_xss_to_admin": {
        "requires": [["stored_xss", "admin"], ["persistent_xss", "admin"]],
        "escalated_severity": "critical",
        "escalated_impact": (
            "Admin account takeover via stored XSS: Persistent cross-site "
            "scripting that executes in admin context enables administrative "
            "account compromise."
        ),
        "narrative_template": (
            "The stored XSS at {urls} executes in the admin panel context, "
            "enabling theft of admin session tokens and full admin account "
            "takeover."
        ),
        "cvss_bump": 2.5,
    },
    "subdomain_takeover": {
        "requires": [
            ["dangling_dns", "cname"],
            ["subdomain_takeover"],
        ],
        "escalated_severity": "high",
        "escalated_impact": (
            "Subdomain takeover: Dangling DNS records point to unclaimed "
            "services, allowing an attacker to claim the subdomain and serve "
            "malicious content or steal cookies."
        ),
        "narrative_template": (
            "The dangling DNS records for {urls} can be claimed by an attacker "
            "to serve phishing pages, steal cookies, or bypass CSP policies."
        ),
        "cvss_bump": 1.5,
    },
}

# Type aliases used for fuzzy matching
TYPE_ALIASES: Dict[str, List[str]] = {
    "cors": ["cors", "cors_misconfig", "cors_misconfiguration", "cross_origin"],
    "csrf": ["csrf", "cross_site_request_forgery", "missing_csrf", "csrf_token"],
    "xss": ["xss", "cross_site_scripting", "reflected_xss", "xss_reflected"],
    "stored_xss": ["stored_xss", "persistent_xss", "xss_stored"],
    "ssrf": ["ssrf", "server_side_request_forgery"],
    "lfi": ["lfi", "local_file_inclusion", "path_traversal", "directory_traversal"],
    "ssti": ["ssti", "server_side_template_injection", "template_injection"],
    "idor": ["idor", "insecure_direct_object_reference", "bola", "broken_object_level"],
    "bola": ["bola", "broken_object_level", "idor"],
    "sqli": ["sqli", "sql_injection", "sqli_error", "blind_sqli"],
    "sql_injection": ["sql_injection", "sqli", "sqli_error"],
    "open_redirect": ["open_redirect", "redirect", "url_redirect", "unvalidated_redirect"],
    "redirect": ["redirect", "open_redirect", "url_redirect"],
    "oauth": ["oauth", "oauth_misconfig", "oauth2", "oidc"],
    "sso": ["sso", "single_sign_on", "saml"],
    "session": ["session", "session_fixation", "session_hijack", "cookie"],
    "internal": ["internal", "internal_api", "internal_service", "metadata"],
    "api": ["api", "api_exposure", "api_key", "internal_api"],
    "cloud": ["cloud", "metadata", "aws", "gcp", "azure", "cloud_metadata"],
    "log_poison": ["log_poison", "log_poisoning", "log_injection"],
    "log": ["log", "log_file", "log_exposure", "access_log"],
    "file_upload": ["file_upload", "upload", "unrestricted_upload"],
    "pii": ["pii", "personal_data", "pii_exposure", "pii_leak", "data_exposure"],
    "personal": ["personal", "personal_data", "user_data"],
    "user_data": ["user_data", "personal_data", "data_leak"],
    "admin": ["admin", "admin_panel", "admin_access", "administrative"],
    "auth_bypass": ["auth_bypass", "authentication_bypass", "broken_auth"],
    "broken_access": ["broken_access", "broken_access_control", "bac"],
    "role": ["role", "role_escalation", "privilege_escalation"],
    "database": ["database", "db_access", "data_dump", "data_leak"],
    "data": ["data", "data_exposure", "information_disclosure"],
    "template": ["template", "template_engine", "jinja2", "twig"],
    "dangling_dns": ["dangling_dns", "dns_misconfiguration", "cname_dangling"],
    "cname": ["cname", "cname_takeover", "dns_cname"],
    "subdomain_takeover": ["subdomain_takeover", "sub_takeover"],
}


class ChainEscalator:
    """Chain low-severity findings into high-severity attack paths.

    Analyzes a list of findings, detects combinable vulnerability pairs,
    and produces escalated chain findings with full impact documentation.
    """

    def __init__(self, chains: Optional[Dict[str, Dict]] = None):
        self.chains = chains or CHAINS
        self._alias_cache: Dict[str, Set[str]] = {}

    def analyze(self, findings: List[Dict[str, Any]]) -> List[EscalatedChain]:
        """Find chainable vulnerabilities and create escalated findings.

        Args:
            findings: List of VIPER finding dicts (must have vuln_type or attack key).

        Returns:
            List of EscalatedChain objects representing discovered chains.
        """
        if not findings:
            return []

        # Build a set of normalized vulnerability type tokens from all findings
        vuln_tokens: Set[str] = set()
        vuln_to_findings: Dict[str, List[Dict]] = {}

        for f in findings:
            raw_type = (
                f.get("vuln_type", "") or f.get("attack", "") or f.get("type", "")
            )
            tokens = self._extract_tokens(raw_type)
            # Also extract from details/impact text for richer matching
            details = str(f.get("details", "")) + " " + str(f.get("impact", ""))
            tokens.update(self._extract_tokens(details))

            vuln_tokens.update(tokens)
            for token in tokens:
                vuln_to_findings.setdefault(token, []).append(f)

        chains_found: List[EscalatedChain] = []
        used_chain_names: Set[str] = set()

        for chain_name, chain_def in self.chains.items():
            if chain_name in used_chain_names:
                continue

            for required_set in chain_def["requires"]:
                if self._requirements_met(required_set, vuln_tokens):
                    # Gather component findings
                    components = self._gather_components(required_set, vuln_to_findings)
                    if not components:
                        continue

                    # Build narrative
                    urls = ", ".join(
                        list({c.get("url", "?") for c in components})[:5]
                    )
                    narrative = chain_def.get("narrative_template", "").format(
                        urls=urls
                    )

                    chain = EscalatedChain(
                        chain_name=chain_name,
                        escalated_severity=chain_def["escalated_severity"],
                        escalated_impact=chain_def["escalated_impact"],
                        component_findings=components,
                        matched_requirements=required_set,
                        cvss_bump=chain_def.get("cvss_bump", 0.0),
                        report_narrative=narrative,
                    )
                    chains_found.append(chain)
                    used_chain_names.add(chain_name)
                    break  # Only match first requirement set per chain

        if chains_found:
            logger.info(
                "Chain escalation found %d chains: %s",
                len(chains_found),
                ", ".join(c.chain_name for c in chains_found),
            )

        return chains_found

    def analyze_as_findings(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Convenience method: analyze and return escalated finding dicts.

        Returns a list of finding dicts ready to append to the main findings list.
        """
        chains = self.analyze(findings)
        return [c.to_finding() for c in chains]

    def _extract_tokens(self, text: str) -> Set[str]:
        """Extract normalized tokens from a vulnerability type or description string."""
        if not text:
            return set()
        # Normalize: lowercase, split on non-alphanum
        tokens = set(re.split(r"[^a-z0-9]+", text.lower()))
        tokens.discard("")

        # Expand through aliases
        expanded: Set[str] = set(tokens)
        for token in tokens:
            for alias_key, alias_vals in TYPE_ALIASES.items():
                if token in alias_vals or token == alias_key:
                    expanded.add(alias_key)
                    expanded.update(alias_vals)

        return expanded

    def _requirements_met(
        self, required: List[str], available: Set[str]
    ) -> bool:
        """Check if all requirements in a set are met by available tokens."""
        for req in required:
            # Check if the requirement matches any available token (including aliases)
            req_aliases = self._get_aliases(req)
            if not req_aliases & available:
                return False
        return True

    def _get_aliases(self, key: str) -> Set[str]:
        """Get all aliases for a vulnerability type key."""
        if key in self._alias_cache:
            return self._alias_cache[key]

        aliases = {key}
        if key in TYPE_ALIASES:
            aliases.update(TYPE_ALIASES[key])
        # Reverse lookup
        for alias_key, alias_vals in TYPE_ALIASES.items():
            if key in alias_vals:
                aliases.add(alias_key)
                aliases.update(alias_vals)

        self._alias_cache[key] = aliases
        return aliases

    def _gather_components(
        self,
        required: List[str],
        vuln_to_findings: Dict[str, List[Dict]],
    ) -> List[Dict[str, Any]]:
        """Gather component findings that satisfy the requirement set."""
        components: List[Dict] = []
        seen_ids: Set[int] = set()

        for req in required:
            req_aliases = self._get_aliases(req)
            for alias in req_aliases:
                for f in vuln_to_findings.get(alias, []):
                    fid = id(f)
                    if fid not in seen_ids:
                        components.append(f)
                        seen_ids.add(fid)

        return components
