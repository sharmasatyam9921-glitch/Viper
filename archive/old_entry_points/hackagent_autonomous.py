#!/usr/bin/env python3
"""
HACKAGENT - Red Team Offensive Agent
Continuous penetration testing and vulnerability discovery
"""

import json
import logging

logger = logging.getLogger("viper.hackagent_autonomous")
import time
import requests
import re
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional
from urllib.parse import urljoin

# Paths
WORKSPACE = Path(".")
STATE_FILE = WORKSPACE / "skills/hackagent/hackagent_state.json"
REPORTS_DIR = WORKSPACE / "skills/hackagent/reports"
SENTINEL_STATE = WORKSPACE / "skills/security-agent/sentinel_state.json"

class HackAgentAutonomous:
    """Red Team autonomous offensive agent"""
    
    def __init__(self):
        self.state = self.load_state()
        self.findings = []
        self.requests_made = 0
        
        # Attack payloads
        self.sqli_payloads = [
            "'", "''", "' OR '1'='1", "' OR 1=1--", 
            "admin'--", "1' AND '1'='1", "' UNION SELECT NULL--"
        ]
        
        self.xss_payloads = [
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "<svg onload=alert(1)>",
            "javascript:alert(1)",
            "'><script>alert(1)</script>"
        ]
        
        self.paths_to_check = [
            "/", "/admin", "/admin/", "/api", "/api/",
            "/debug", "/debug/", "/config", "/config/",
            "/.env", "/.git/config", "/robots.txt",
            "/backup", "/test", "/dev", "/staging",
            "/_dash-layout", "/_dash-dependencies",
            "/swagger", "/api-docs", "/graphql",
            "/actuator", "/actuator/health", "/metrics"
        ]
        
        self.security_headers = [
            "X-Frame-Options",
            "X-Content-Type-Options", 
            "Content-Security-Policy",
            "Strict-Transport-Security",
            "X-XSS-Protection"
        ]
    
    def load_state(self) -> dict:
        if STATE_FILE.exists():
            return json.loads(STATE_FILE.read_text())
        return {
            "last_scan": None,
            "targets_scanned": [],
            "vulns_found": [],
            "techniques_used": [],
            "success_rate": {}
        }
    
    def save_state(self):
        STATE_FILE.write_text(json.dumps(self.state, indent=2, default=str))
    
    def log(self, msg: str, level: str = "INFO"):
        timestamp = datetime.now().strftime("%H:%M:%S")
        print(f"[{timestamp}] [{level}] {msg}")
    
    def finding(self, vuln_type: str, severity: str, location: str, 
                payload: str = "", details: str = ""):
        """Record a vulnerability finding"""
        f = {
            "type": vuln_type,
            "severity": severity,
            "location": location,
            "payload": payload,
            "details": details,
            "time": datetime.now().isoformat()
        }
        self.findings.append(f)
        self.log(f"VULN: {vuln_type} ({severity}) at {location}", "VULN")
        
        # Track for learning
        if vuln_type not in self.state["vulns_found"]:
            self.state["vulns_found"].append(vuln_type)
    
    def request(self, method: str, url: str, **kwargs) -> Optional[requests.Response]:
        """Make HTTP request"""
        self.requests_made += 1
        kwargs.setdefault('timeout', 10)
        kwargs.setdefault('verify', False)
        kwargs.setdefault('allow_redirects', False)
        
        try:
            if method.upper() == "GET":
                return requests.get(url, **kwargs)
            elif method.upper() == "POST":
                return requests.post(url, **kwargs)
        except Exception as e:
            return None
    
    # ==================== SCANNING ====================
    
    def scan_headers(self, url: str) -> List[str]:
        """Check for missing security headers"""
        r = self.request("GET", url)
        if not r:
            return []
        
        missing = []
        for header in self.security_headers:
            if header not in r.headers:
                missing.append(header)
        
        if missing:
            self.finding(
                "Missing Security Headers",
                "low",
                url,
                "",
                f"Missing: {', '.join(missing)}"
            )
        
        return missing
    
    def scan_endpoints(self, base_url: str) -> List[str]:
        """Discover accessible endpoints"""
        found = []
        
        for path in self.paths_to_check:
            url = urljoin(base_url, path)
            r = self.request("GET", url)
            
            if r and r.status_code == 200:
                found.append(path)
                self.log(f"Found: {path} ({len(r.content)} bytes)", "FOUND")
                
                # Check for sensitive endpoints
                if path in ["/.env", "/.git/config", "/config/"]:
                    self.finding(
                        "Sensitive File Exposure",
                        "high",
                        url,
                        "",
                        f"Sensitive endpoint accessible: {path}"
                    )
                elif path in ["/debug", "/debug/", "/actuator"]:
                    self.finding(
                        "Debug Endpoint Exposed",
                        "medium",
                        url,
                        "",
                        "Debug/monitoring endpoint accessible"
                    )
        
        return found
    
    def scan_sqli(self, url: str, param: str = "id") -> bool:
        """Test for SQL injection"""
        for payload in self.sqli_payloads[:3]:  # Quick test
            test_url = f"{url}?{param}={payload}"
            r = self.request("GET", test_url)
            
            if r:
                body = r.text.lower()
                # Look for SQL error indicators
                sql_errors = ["sql", "mysql", "sqlite", "postgres", "syntax error",
                            "query failed", "unclosed quotation"]
                
                if any(err in body for err in sql_errors):
                    self.finding(
                        "SQL Injection",
                        "critical",
                        url,
                        payload,
                        "SQL error in response indicates injection vulnerability"
                    )
                    return True
        
        return False
    
    def scan_xss(self, url: str, param: str = "q") -> bool:
        """Test for reflected XSS"""
        for payload in self.xss_payloads[:3]:  # Quick test
            test_url = f"{url}?{param}={payload}"
            r = self.request("GET", test_url)
            
            if r and payload in r.text:
                self.finding(
                    "Reflected XSS",
                    "high",
                    url,
                    payload,
                    "Payload reflected without encoding"
                )
                return True
        
        return False
    
    def scan_idor(self, url: str) -> bool:
        """Test for IDOR by manipulating IDs"""
        # Try numeric IDs
        for test_id in [1, 2, 999, 0, -1]:
            test_url = f"{url}/{test_id}"
            r = self.request("GET", test_url)
            
            if r and r.status_code == 200 and len(r.content) > 50:
                # Check if we get different data for different IDs
                self.log(f"IDOR test: {test_url} returned {r.status_code}", "SCAN")
        
        return False
    
    def scan_debug_mode(self, url: str) -> bool:
        """Check if debug mode is enabled"""
        debug_endpoints = [
            "/_dash-debug-menu",
            "/debug/",
            "/__debug__/",
            "/actuator/env",
            "/trace"
        ]
        
        for endpoint in debug_endpoints:
            r = self.request("GET", urljoin(url, endpoint))
            if r and r.status_code == 200:
                self.finding(
                    "Debug Mode Enabled",
                    "medium",
                    urljoin(url, endpoint),
                    "",
                    "Debug endpoint accessible - may leak sensitive info"
                )
                return True
        
        return False
    
    def fingerprint(self, url: str) -> dict:
        """Identify target technology stack"""
        r = self.request("GET", url)
        if not r:
            return {}
        
        info = {
            "server": r.headers.get("Server", "Hidden"),
            "powered_by": r.headers.get("X-Powered-By", "Unknown"),
            "frameworks": []
        }
        
        body = r.text.lower()
        
        # Detect frameworks
        if "_dash" in body or "dash" in r.headers.get("Server", "").lower():
            info["frameworks"].append("Plotly Dash")
        if "react" in body:
            info["frameworks"].append("React")
        if "angular" in body:
            info["frameworks"].append("Angular")
        if "vue" in body:
            info["frameworks"].append("Vue.js")
        if "django" in body or "csrfmiddlewaretoken" in body:
            info["frameworks"].append("Django")
        if "laravel" in body:
            info["frameworks"].append("Laravel")
        
        return info
    
    # ==================== LEARNING ====================
    
    def learn_from_sentinel(self):
        """Learn from Sentinel's detections"""
        if not SENTINEL_STATE.exists():
            return
        
        try:
            sentinel = json.loads(SENTINEL_STATE.read_text())
            
            # Learn what Sentinel is monitoring
            if "file_baselines" in sentinel:
                critical_paths = list(sentinel["file_baselines"].keys())
                self.log(f"Sentinel monitors {len(critical_paths)} files", "LEARN")
            
            # Adapt based on defcon level
            if sentinel.get("defcon_history"):
                recent = sentinel["defcon_history"][-1]
                self.log(f"Sentinel DEFCON: {recent.get('level', 5)}", "INTEL")
        except Exception as e:  # noqa: BLE001
            pass
    
    def report_to_sentinel(self):
        """Share findings with Sentinel for patching"""
        if not self.findings:
            return
        
        report = {
            "from": "hackagent",
            "timestamp": datetime.now().isoformat(),
            "findings": self.findings,
            "recommendations": []
        }
        
        for f in self.findings:
            if f["type"] == "Missing Security Headers":
                report["recommendations"].append({
                    "action": "add_headers",
                    "target": f["location"]
                })
            elif f["type"] == "Debug Mode Enabled":
                report["recommendations"].append({
                    "action": "disable_debug",
                    "target": f["location"]
                })
        
        report_path = REPORTS_DIR / f"for_sentinel_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        report_path.write_text(json.dumps(report, indent=2))
        self.log(f"Report sent to Sentinel: {report_path.name}", "REPORT")
    
    # ==================== MAIN ====================
    
    def full_scan(self, target: str) -> dict:
        """Run comprehensive security scan"""
        self.log(f"Starting full scan on {target}", "SCAN")
        self.findings = []
        self.requests_made = 0
        start_time = datetime.now()
        
        results = {
            "target": target,
            "timestamp": start_time.isoformat(),
            "fingerprint": {},
            "endpoints": [],
            "findings": []
        }
        
        # Phase 1: Fingerprint
        self.log("Phase 1: Fingerprinting...", "PHASE")
        results["fingerprint"] = self.fingerprint(target)
        self.log(f"Server: {results['fingerprint'].get('server')}", "INFO")
        
        # Phase 2: Headers
        self.log("Phase 2: Security headers...", "PHASE")
        self.scan_headers(target)
        
        # Phase 3: Endpoints
        self.log("Phase 3: Endpoint discovery...", "PHASE")
        results["endpoints"] = self.scan_endpoints(target)
        
        # Phase 4: Debug mode
        self.log("Phase 4: Debug mode check...", "PHASE")
        self.scan_debug_mode(target)
        
        # Phase 5: Injection tests (careful!)
        self.log("Phase 5: Injection tests...", "PHASE")
        # Only test on known safe endpoints
        # self.scan_sqli(target + "/api/search")
        # self.scan_xss(target + "/search")
        
        # Results
        results["findings"] = self.findings
        results["stats"] = {
            "requests": self.requests_made,
            "endpoints_found": len(results["endpoints"]),
            "vulns_found": len(self.findings),
            "duration_seconds": (datetime.now() - start_time).total_seconds()
        }
        
        # Update state
        self.state["last_scan"] = results["timestamp"]
        if target not in self.state["targets_scanned"]:
            self.state["targets_scanned"].append(target)
        self.save_state()
        
        # Save report
        report_path = REPORTS_DIR / f"scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        REPORTS_DIR.mkdir(exist_ok=True)
        report_path.write_text(json.dumps(results, indent=2))
        
        # Share with Sentinel
        self.report_to_sentinel()
        
        return results


def main():
    print("=" * 60)
    print("HACKAGENT - Red Team Offensive Agent")
    print("=" * 60)
    
    agent = HackAgentAutonomous()
    
    # Learn from Sentinel first
    agent.learn_from_sentinel()
    
    # Scan our own infrastructure
    targets = [
        "http://localhost:8889",  # HackAgent Dashboard
        "http://localhost:8899",  # Trading Dashboard
        "http://localhost:1999",  # framework Gateway
    ]
    
    for target in targets:
        print(f"\n{'='*60}")
        print(f"TARGET: {target}")
        print("=" * 60)
        
        results = agent.full_scan(target)
        
        print(f"\nResults:")
        print(f"  Requests: {results['stats']['requests']}")
        print(f"  Endpoints: {results['stats']['endpoints_found']}")
        print(f"  Vulnerabilities: {results['stats']['vulns_found']}")
        
        if results['findings']:
            print("\nFindings:")
            for f in results['findings']:
                print(f"  [{f['severity'].upper()}] {f['type']}")


if __name__ == "__main__":
    main()


