#!/usr/bin/env python3
"""
HackAgent Reconnaissance Module
Passive and active recon for authorized bug bounty targets.

ETHICAL USE ONLY - Only run against authorized targets in scope!
"""

import subprocess
import json
import re
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Optional
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("HackAgent.Recon")


class ReconModule:
    """Reconnaissance tools for bug bounty hunting."""
    
    def __init__(self, output_dir: Path):
        self.output_dir = output_dir
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.results = {
            "target": None,
            "timestamp": None,
            "subdomains": [],
            "urls": [],
            "technologies": [],
            "ports": [],
            "findings": []
        }
    
    def set_target(self, domain: str):
        """Set the target domain."""
        self.results["target"] = domain
        self.results["timestamp"] = datetime.now().isoformat()
        logger.info(f"Target set: {domain}")
    
    # =========================================================================
    # PASSIVE RECON (No direct contact with target)
    # =========================================================================
    
    def subdomain_enum_passive(self, domain: str) -> List[str]:
        """
        Passive subdomain enumeration using multiple sources.
        Does NOT contact target directly.
        """
        subdomains = set()
        
        # Method 1: crt.sh (Certificate Transparency logs)
        try:
            import requests
            url = f"https://crt.sh/?q=%.{domain}&output=json"
            response = requests.get(url, timeout=30)
            if response.ok:
                data = response.json()
                for entry in data:
                    name = entry.get("name_value", "")
                    for sub in name.split("\n"):
                        sub = sub.strip().lower()
                        if sub.endswith(domain):
                            subdomains.add(sub)
        except Exception as e:
            logger.warning(f"crt.sh failed: {e}")
        
        # Method 2: Common subdomains wordlist
        common_subs = [
            "www", "mail", "api", "dev", "staging", "test", "admin",
            "portal", "app", "m", "mobile", "cdn", "static", "assets",
            "blog", "shop", "store", "secure", "login", "auth",
            "dashboard", "panel", "cpanel", "webmail", "ftp", "vpn"
        ]
        for sub in common_subs:
            subdomains.add(f"{sub}.{domain}")
        
        self.results["subdomains"] = list(subdomains)
        logger.info(f"Found {len(subdomains)} subdomains (passive)")
        return list(subdomains)
    
    def wayback_urls(self, domain: str) -> List[str]:
        """
        Get historical URLs from Wayback Machine.
        Passive - no contact with target.
        """
        urls = []
        try:
            import requests
            url = f"https://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=json&fl=original&collapse=urlkey"
            response = requests.get(url, timeout=60)
            if response.ok:
                data = response.json()
                for entry in data[1:]:  # Skip header row
                    urls.append(entry[0])
        except Exception as e:
            logger.warning(f"Wayback failed: {e}")
        
        # Dedupe and filter
        urls = list(set(urls))
        self.results["urls"] = urls[:1000]  # Limit
        logger.info(f"Found {len(urls)} historical URLs")
        return urls
    
    def google_dorks(self, domain: str) -> List[str]:
        """
        Generate Google dork queries for manual search.
        Does NOT execute searches automatically.
        """
        dorks = [
            f'site:{domain} ext:php',
            f'site:{domain} ext:asp',
            f'site:{domain} ext:aspx',
            f'site:{domain} ext:jsp',
            f'site:{domain} ext:sql',
            f'site:{domain} ext:log',
            f'site:{domain} ext:bak',
            f'site:{domain} ext:conf',
            f'site:{domain} ext:env',
            f'site:{domain} inurl:admin',
            f'site:{domain} inurl:login',
            f'site:{domain} inurl:api',
            f'site:{domain} intitle:"index of"',
            f'site:{domain} filetype:pdf',
            f'site:{domain} "password"',
            f'site:{domain} "username" "password"',
            f'site:{domain} inurl:wp-content',
            f'site:{domain} inurl:wp-admin',
        ]
        logger.info(f"Generated {len(dorks)} Google dorks")
        return dorks
    
    # =========================================================================
    # ACTIVE RECON (Contacts target - ONLY use with authorization!)
    # =========================================================================
    
    def check_http_headers(self, url: str) -> Dict:
        """
        Check security headers of a URL.
        ACTIVE - contacts target.
        """
        import requests
        
        headers_to_check = [
            "Strict-Transport-Security",
            "Content-Security-Policy",
            "X-Frame-Options",
            "X-Content-Type-Options",
            "X-XSS-Protection",
            "Referrer-Policy",
            "Permissions-Policy"
        ]
        
        result = {
            "url": url,
            "present": [],
            "missing": [],
            "server": None,
            "technology": []
        }
        
        try:
            response = requests.get(url, timeout=10, allow_redirects=True)
            
            # Check security headers
            for header in headers_to_check:
                if header in response.headers:
                    result["present"].append({header: response.headers[header]})
                else:
                    result["missing"].append(header)
            
            # Server info
            result["server"] = response.headers.get("Server")
            result["technology"].append(response.headers.get("X-Powered-By"))
            
        except Exception as e:
            logger.error(f"Header check failed: {e}")
        
        return result
    
    def directory_bruteforce(self, url: str, wordlist: List[str] = None) -> List[str]:
        """
        Check for common directories.
        ACTIVE - contacts target. Use with rate limiting!
        """
        import requests
        import time
        
        if wordlist is None:
            wordlist = [
                "admin", "administrator", "login", "wp-admin", "wp-login.php",
                "dashboard", "panel", "api", "api/v1", "api/v2",
                "backup", "backups", "db", "database", "sql",
                "config", "configuration", "settings",
                "uploads", "upload", "files", "images",
                "test", "testing", "dev", "development", "staging",
                ".git", ".env", ".htaccess", "robots.txt", "sitemap.xml",
                "phpinfo.php", "info.php", "server-status",
                "wp-content", "wp-includes",
                "swagger", "swagger-ui", "api-docs", "graphql",
                "console", "shell", "cmd", "debug"
            ]
        
        found = []
        base_url = url.rstrip("/")
        
        for path in wordlist:
            try:
                full_url = f"{base_url}/{path}"
                response = requests.get(full_url, timeout=5, allow_redirects=False)
                
                if response.status_code in [200, 301, 302, 403]:
                    finding = {
                        "url": full_url,
                        "status": response.status_code,
                        "size": len(response.content)
                    }
                    found.append(finding)
                    logger.info(f"Found: {full_url} [{response.status_code}]")
                
                time.sleep(0.5)  # Rate limiting - be gentle!
                
            except Exception:
                continue
        
        self.results["findings"].extend(found)
        return found
    
    # =========================================================================
    # REPORTING
    # =========================================================================
    
    def generate_report(self) -> str:
        """Generate markdown report of findings."""
        report = f"""# Reconnaissance Report

## Target: {self.results['target']}
**Generated:** {self.results['timestamp']}

## Subdomains Found ({len(self.results['subdomains'])})
"""
        for sub in self.results['subdomains'][:50]:
            report += f"- {sub}\n"
        
        if len(self.results['subdomains']) > 50:
            report += f"- ... and {len(self.results['subdomains']) - 50} more\n"
        
        report += f"""
## Historical URLs ({len(self.results['urls'])})
"""
        for url in self.results['urls'][:20]:
            report += f"- {url}\n"
        
        report += f"""
## Findings ({len(self.results['findings'])})
"""
        for finding in self.results['findings']:
            report += f"- **{finding.get('url')}** [{finding.get('status')}]\n"
        
        return report
    
    def save_results(self, filename: str = None):
        """Save results to JSON."""
        if filename is None:
            filename = f"recon_{self.results['target']}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        
        output_path = self.output_dir / filename
        with open(output_path, 'w') as f:
            json.dump(self.results, f, indent=2)
        
        logger.info(f"Results saved to {output_path}")
        return output_path


def main():
    """Example usage - ONLY run on authorized targets!"""
    print("=" * 60)
    print("HackAgent Recon Module")
    print("=" * 60)
    print("\n⚠️  ETHICAL USE ONLY!")
    print("Only run against authorized bug bounty targets.")
    print("\nExample usage:")
    print("""
    from recon import ReconModule
    
    recon = ReconModule(Path("./output"))
    recon.set_target("example.com")  # Replace with authorized target
    
    # Passive recon (safe)
    subs = recon.subdomain_enum_passive("example.com")
    urls = recon.wayback_urls("example.com")
    dorks = recon.google_dorks("example.com")
    
    # Active recon (requires authorization!)
    # headers = recon.check_http_headers("https://example.com")
    # dirs = recon.directory_bruteforce("https://example.com")
    
    # Generate report
    report = recon.generate_report()
    recon.save_results()
    """)


if __name__ == "__main__":
    main()
