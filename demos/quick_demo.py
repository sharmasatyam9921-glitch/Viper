#!/usr/bin/env python3
"""Quick HackAgent Demo"""

import asyncio
import sys
sys.stdout.reconfigure(encoding='utf-8')
sys.path.insert(0, '.\\skills\\hackagent')

from tools.http_client import HackerHTTPClient
from tools.payload_mutator import PayloadMutator
from core.exploit_db import ExploitDB, seed_default_exploits

print('=' * 60)
print('HACKAGENT LIVE DEMONSTRATION')
print('=' * 60)

# 1. Exploit DB
print('\n[EXPLOIT DATABASE]')
db = ExploitDB()
if not db.exploits:
    seed_default_exploits(db)
print(f'Loaded {len(db.exploits)} exploits\n')

for e in list(db.exploits.values())[:4]:
    print(f'  [{e.severity.upper()}] {e.name}')
    print(f'       Type: {e.exploit_type} | Bounty: {e.bounty_range}')
    if e.payloads:
        print(f'       Payload: {e.payloads[0][:40]}...')
    print()

# 2. Payload Mutations
print('[WAF BYPASS MUTATIONS]')
mutator = PayloadMutator()

payloads = [
    ("SQLi", "' OR 1=1--"),
    ("XSS", "<script>alert(1)</script>"),
]

for name, payload in payloads:
    print(f'\n{name}: {payload}')
    for m in mutator.mutate_all(payload)[:4]:
        print(f'  → [{m.mutation_type.value}] {m.mutated[:50]}')

# 3. HTTP Recon
print('\n\n[LIVE HTTP RECONNAISSANCE]')
print('Target: httpbin.org (legal test target)')

async def recon():
    async with HackerHTTPClient(requests_per_second=5.0) as client:
        # Main request
        r = await client.get('https://httpbin.org/get')
        print(f'\nStatus: {r.status} | Time: {r.elapsed_ms:.0f}ms')
        print(f'WAF Detected: {r.waf_detected or "None"}')
        
        # Headers
        print('\nServer Headers:')
        for h in ['Server', 'Content-Type', 'Access-Control-Allow-Origin']:
            if h in r.headers:
                print(f'  {h}: {r.headers[h]}')
        
        # Endpoint enumeration
        print('\nEndpoint Scan:')
        paths = [
            '/robots.txt',
            '/admin', 
            '/.git/config',
            '/.env',
            '/api',
            '/graphql',
        ]
        
        for p in paths:
            r = await client.get(f'https://httpbin.org{p}')
            if r.status == 200:
                status = '✓ ACCESSIBLE'
            elif r.status == 404:
                status = '✗ Not found'
            elif r.status == 403:
                status = '⚠ Forbidden (exists!)'
            else:
                status = f'? Status {r.status}'
            print(f'  {p}: {status}')
        
        print(f'\nStats: {client.get_stats()}')

asyncio.run(recon())

print('\n' + '=' * 60)
print('HACKAGENT CAPABILITIES:')
print('=' * 60)
print('''
  ✓ Cognitive reasoning (HackerMind)
  ✓ Exploit database with 8+ patterns
  ✓ Payload mutation for WAF bypass
  ✓ Async HTTP with rate limiting
  ✓ WAF detection (Cloudflare, Akamai, AWS, etc.)
  ✓ User-agent rotation
  ✓ Attack chain construction
  
Ready for bug bounty hunting! 🎯🔥
''')
