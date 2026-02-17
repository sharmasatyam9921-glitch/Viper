#!/usr/bin/env python3
"""Full demo of HackerMind thinking process."""

import sys
sys.path.insert(0, '.\\skills\\hackagent\\core')

from hacker_mind import HackerMind, AttackPhase

print("=" * 70)
print("HACKERMIND - THINKING LIKE A HACKER")
print("=" * 70)

# Create mind with target
mind = HackerMind(
    target="https://vulnerable-app.example.com",
    scope={
        "in_scope": ["*.example.com", "api.example.com"],
        "out_of_scope": ["admin.example.com"]
    }
)

print("\n[PHASE 1: RECONNAISSANCE]")
print("-" * 50)

# Simulate discovery from recon
mind.observe("endpoint", "/api/v1/users/{id}", "directory_brute")
mind.observe("endpoint", "/api/v1/search?query=", "directory_brute")
mind.observe("endpoint", "/api/v1/upload", "directory_brute")
mind.observe("endpoint", "/api/v1/export", "directory_brute")
mind.observe("endpoint", "/admin/login", "directory_brute")
mind.observe("endpoint", "/graphql", "directory_brute")
mind.observe("endpoint", "/api/v1/password-reset", "directory_brute")
mind.observe("endpoint", "/api/v1/users/me", "directory_brute")
mind.observe("endpoint", "/debug/info", "directory_brute")
mind.observe("endpoint", "/api/v1/orders/{id}", "directory_brute")

# Tech stack discovery
mind.observe("technology", "PHP/7.4.21", "X-Powered-By")
mind.observe("technology", "nginx/1.18.0", "Server")
mind.observe("technology", "Laravel", "Cookie names")

# Error discovered
mind.observe("error", "SQLSTATE[42000]: Syntax error near '", "/api/v1/search")

print(f"Endpoints discovered: {len(mind.endpoints_discovered)}")
print(f"Tech stack: {mind.technology_stack}")
print(f"Errors found: {mind.error_patterns}")

# Think about what we found
decision = mind.think("Initial recon complete")
print(f"\nDecision: {decision}")

print("\n[PHASE 2: ENUMERATION]")
print("-" * 50)

# Advance phase
mind.phase = AttackPhase.ENUMERATION
decision = mind.think("Analyzing attack surface")
print(f"Decision: {decision}")

print("\n[HYPOTHESES GENERATED]")
print("-" * 50)

for h in mind.hypotheses:
    print(f"\n{'='*50}")
    print(f"[{h.confidence:.0%} confidence] {h.description}")
    print(f"Category: {h.vulnerability_class}")
    print(f"Status: {h.status}")
    print(f"Test plan:")
    for step in h.test_plan[:3]:
        print(f"  - {step}")

print("\n[PHASE 3: VULNERABILITY ANALYSIS]")
print("-" * 50)

mind.phase = AttackPhase.VULNERABILITY_ANALYSIS
decision = mind.think("Testing hypotheses")
print(f"Decision: {decision}")

if mind.current_hypothesis:
    print(f"\nTesting: {mind.current_hypothesis.description}")

print("\n[SIMULATING HTTP RESPONSE ANALYSIS]")
print("-" * 50)

# Simulate analyzing a response
mind.process_response(
    url="https://vulnerable-app.example.com/api/v1/search?query=test",
    status=500,
    headers={
        "Server": "nginx/1.18.0",
        "X-Powered-By": "PHP/7.4.21",
        "CF-RAY": "abc123"  # Cloudflare
    },
    body="""
    <html>
    <h1>Error</h1>
    <p>SQLSTATE[42000]: Syntax error or access violation: 1064 
    You have an error in your SQL syntax near 'test''</p>
    <pre>Stack trace: #0 /var/www/app/Search.php(45)</pre>
    </html>
    """
)

print(f"WAF detected: {mind.waf_detected}")
print(f"New observations: {len(mind.observations)}")

# Check for interesting observations
interesting = [o for o in mind.observations if o.category == "interesting" or o.category == "error"]
print(f"\nInteresting findings:")
for o in interesting:
    print(f"  [{o.confidence:.0%}] {o.detail}")

print("\n[PAYLOAD GENERATION]")
print("-" * 50)

# Generate smart payloads
sqli_payloads = mind.generate_payload("sqli", {})
print("SQL Injection payloads (adapted to MySQL + Cloudflare):")
for p in sqli_payloads[:5]:
    print(f"  {p}")

print("\n[WAF BYPASS STRATEGIES]")
print("-" * 50)
bypasses = mind.adapt_to_waf()
for b in bypasses:
    print(f"  - {b}")

print("\n[ATTACK CHAINS]")
print("-" * 50)

# Simulate confirmed findings
mind.hypotheses[0].status = "confirmed" if mind.hypotheses else None
mind.hypotheses[1].status = "confirmed" if len(mind.hypotheses) > 1 else None

chains = mind._find_attack_chains([h for h in mind.hypotheses if h.status == "confirmed"])
if chains:
    for chain in chains:
        print(f"\nChain: {chain.name}")
        print(f"Impact: {chain.total_impact}")
        for step in chain.steps:
            print(f"  → {step['action']}")
else:
    print("No attack chains identified yet (need more confirmed vulns)")

print("\n[FINAL STATUS]")
print("-" * 50)
status = mind.get_status()
for k, v in status.items():
    print(f"  {k}: {v}")

print("\n[THINKING LOG]")
print("-" * 50)
print(mind.explain_thinking())

print("\n" + "=" * 70)
print("HackerMind is ready for real targets!")
print("=" * 70)
