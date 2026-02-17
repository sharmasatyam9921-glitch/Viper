#!/usr/bin/env python3
"""Quick Red vs Blue scan"""
import requests
from datetime import datetime

print("=" * 60)
print("VIPER vs SENTINEL - Security Scan")
print("=" * 60)

targets = [
    ("http://localhost:8889", "HackAgent Dashboard"),
    ("http://localhost:8899", "Trading Dashboard"),
    ("http://localhost:1999", "framework Gateway")
]

headers_check = ["X-Frame-Options", "X-Content-Type-Options", "Content-Security-Policy"]
all_findings = []

for url, name in targets:
    print(f"\n[TARGET] {name}")
    print(f"         {url}")
    print("-" * 40)
    
    try:
        r = requests.get(url, timeout=5)
        print(f"  Status: {r.status_code}")
        server = r.headers.get("Server", "Hidden")
        print(f"  Server: {server}")
        
        # Check headers
        missing = [h for h in headers_check if h not in r.headers]
        if missing:
            print(f"  [LOW] Missing {len(missing)} security headers")
            all_findings.append(("LOW", "Missing Headers", name))
        else:
            print(f"  [OK] All security headers present")
        
        # Check debug mode (only if content indicates actual debug)
        try:
            d = requests.get(url + "/_dash-debug-menu", timeout=3)
            # Dash returns 200 for most paths, check content length for real debug
            if d.status_code == 200 and len(d.content) > 200 and "debug" in d.text.lower():
                print(f"  [MEDIUM] Debug mode ENABLED!")
                all_findings.append(("MEDIUM", "Debug Mode", name))
        except:
            pass
        
        # Check sensitive endpoints (verify actual sensitive content, not just 200)
        sensitive = ["/.env", "/config/", "/admin/"]
        for ep in sensitive:
            try:
                s = requests.get(url + ep, timeout=3)
                # Dash/SPA apps return 200 with HTML for everything - check for REAL sensitive content
                if s.status_code == 200:
                    content = s.text
                    # Skip if it's just returning the main HTML page
                    if "<!DOCTYPE html>" in content or "<html" in content:
                        continue  # It's just the SPA, not real sensitive data
                    
                    content_lower = content.lower()
                    is_sensitive = any([
                        "password=" in content_lower,
                        "secret=" in content_lower,
                        "config_key=" in content_lower,
                        "private_key" in content_lower,
                    ])
                    if is_sensitive:
                        print(f"  [HIGH] Sensitive data exposed: {ep}")
                        all_findings.append(("HIGH", f"Exposed {ep}", name))
            except:
                pass
                
    except Exception as e:
        print(f"  Error: {e}")

print("\n" + "=" * 60)
print("SUMMARY")
print("=" * 60)

critical = len([f for f in all_findings if f[0] == "CRITICAL"])
high = len([f for f in all_findings if f[0] == "HIGH"])
medium = len([f for f in all_findings if f[0] == "MEDIUM"])
low = len([f for f in all_findings if f[0] == "LOW"])

print(f"Total Findings: {len(all_findings)}")
print(f"  CRITICAL: {critical}")
print(f"  HIGH:     {high}")
print(f"  MEDIUM:   {medium}")
print(f"  LOW:      {low}")

if all_findings:
    print("\nAll Findings:")
    for sev, vuln, target in all_findings:
        print(f"  [{sev}] {vuln} @ {target}")

print("\n" + "=" * 60)
print("REMEDIATION NEEDED")
print("=" * 60)
print("1. Add security headers to all services")
print("2. Disable debug mode in production")
print("3. Restrict sensitive endpoints")

