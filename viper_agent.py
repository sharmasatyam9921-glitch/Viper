#!/usr/bin/env python3
"""
VIPER Agent - Fully Autonomous Adaptive Hacker

Combines:
- ViperMind: Hacker reasoning (observe → hypothesize → test → adapt)
- ViperBrain: Q-learning for attack optimization
- Self-training on practice targets

VIPER thinks. VIPER adapts. VIPER learns. VIPER hunts.
"""

import asyncio
import aiohttp
import json
import os
import re
import urllib.parse
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple

# Import VIPER components
from viper_mind import ViperMind
from viper_brain import ViperBrain

os.environ["PATH"] = r"C:\Users\sharm\go\bin;" + os.environ.get("PATH", "")

HACKAGENT_DIR = Path(__file__).parent
LOGS_DIR = HACKAGENT_DIR / "logs"
REPORTS_DIR = HACKAGENT_DIR / "reports"
LOGS_DIR.mkdir(exist_ok=True)
REPORTS_DIR.mkdir(exist_ok=True)


class ViperAgent:
    """
    VIPER's autonomous hunting agent.
    
    Uses Mind for reasoning, Brain for optimization.
    Learns from every engagement.
    """
    
    def __init__(self):
        self.mind = ViperMind()
        self.brain = ViperBrain()
        self.session: Optional[aiohttp.ClientSession] = None
        self.current_target = ""
        self.findings: List[Dict] = []
        self.log_file = LOGS_DIR / f"viper_agent_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
        
    def log(self, msg: str, level: str = "INFO"):
        timestamp = datetime.now().strftime('%H:%M:%S')
        line = f"[{timestamp}] [{level}] {msg}"
        print(line)
        with open(self.log_file, 'a', encoding='utf-8') as f:
            f.write(line + '\n')
    
    async def request(self, url: str, method: str = "GET", 
                      data: dict = None, headers: dict = None,
                      cookies: dict = None) -> Tuple[int, str, Dict]:
        """Make HTTP request"""
        try:
            kwargs = {
                'timeout': aiohttp.ClientTimeout(total=15),
                'ssl': False
            }
            if data:
                kwargs['data'] = data
            if headers:
                kwargs['headers'] = headers
            if cookies:
                kwargs['cookies'] = cookies
                
            async with self.session.request(method, url, **kwargs) as resp:
                body = await resp.text()
                return resp.status, body, dict(resp.headers)
        except Exception as e:
            return 0, str(e), {}
    
    async def execute_test(self, base_url: str, test: Dict, context: Dict) -> Tuple[int, str]:
        """Execute a test designed by the Mind"""
        test_spec = test.get('test', {})
        
        # Handle different test types
        if 'payload' in test_spec:
            payload = test_spec['payload']
            
            # Find injection point
            if 'type' in test_spec:
                test_type = test_spec['type']
                
                if test_type == 'cookie':
                    # Cookie manipulation
                    return await self.request(base_url, cookies=payload)
                
                elif test_type == 'header':
                    # Header injection
                    return await self.request(base_url, headers=payload)
                
                elif test_type == 'param':
                    # Parameter injection
                    parsed = urllib.parse.urlparse(base_url)
                    params = urllib.parse.parse_qs(parsed.query)
                    
                    # Inject into first param or add new
                    if params:
                        first_param = list(params.keys())[0]
                        new_query = f"{first_param}={urllib.parse.quote(str(payload))}"
                    else:
                        new_query = f"input={urllib.parse.quote(str(payload))}"
                    
                    test_url = urllib.parse.urlunparse(parsed._replace(query=new_query))
                    status, body, _ = await self.request(test_url)
                    return status, body
            
            else:
                # Default: inject payload into URL params
                parsed = urllib.parse.urlparse(base_url)
                params = urllib.parse.parse_qs(parsed.query)
                
                if params:
                    first_param = list(params.keys())[0]
                    new_query = f"{first_param}={urllib.parse.quote(str(payload))}"
                    test_url = urllib.parse.urlunparse(parsed._replace(query=new_query))
                else:
                    # Try common param names
                    test_url = f"{base_url}{'&' if '?' in base_url else '?'}page={urllib.parse.quote(str(payload))}"
                
                status, body, _ = await self.request(test_url)
                return status, body
        
        elif 'path' in test_spec:
            # Path-based test
            path = test_spec['path']
            test_url = base_url.rstrip('/') + path
            status, body, _ = await self.request(test_url)
            return status, body
        
        elif 'method' in test_spec:
            # Method + path test (API)
            method = test_spec['method']
            path = test_spec.get('path', '')
            test_url = base_url.rstrip('/') + path
            
            if test_spec.get('payload'):
                status, body, _ = await self.request(
                    test_url, method=method, 
                    data=test_spec['payload'],
                    headers={'Content-Type': 'application/json'}
                )
            else:
                status, body, _ = await self.request(test_url, method=method)
            return status, body
        
        elif 'file' in test_spec:
            # File upload test (simplified)
            self.log("File upload test - would need multipart form", "DEBUG")
            return 0, ""
        
        return 0, ""
    
    async def hunt(self, target_url: str, max_steps: int = 30) -> Dict:
        """
        Autonomous hunt using Mind + Brain.
        
        The Mind reasons about what to try.
        The Brain optimizes the approach.
        Both learn from results.
        """
        self.current_target = target_url
        self.findings = []
        
        self.log(f"=== Hunting: {target_url} ===")
        self.log(f"Mind state: {len(self.mind.confirmed)} confirmed vulns")
        self.log(f"Brain state: {self.brain.get_stats()['patterns_known']} patterns")
        
        # Initial recon
        status, body, headers = await self.request(target_url)
        if status == 0:
            self.log(f"Failed to connect: {body}", "ERROR")
            return {'success': False, 'error': 'Connection failed'}
        
        context = {
            'url': target_url,
            'content': body,
            'headers': headers,
            'status': status,
            'access_level': 0,
            'vulns_found': []
        }
        
        self.log(f"Target responded: {status}, {len(body)} bytes")
        self.log(f"Server: {headers.get('Server', 'Unknown')}")
        
        for step in range(max_steps):
            # Mind reasons about what to try
            reasoning = self.mind.reason(context)
            
            self.log(f"[Step {step+1}] {reasoning['reason']}")
            
            if reasoning['action'] == 'enumerate':
                # Generic enumeration - use Brain patterns
                attack = self.brain.choose_action(context)
                self.log(f"  Brain suggests: {attack}")
                
                # Execute Brain's suggestion
                pattern = self.brain.attack_patterns.get(attack, {})
                if pattern:
                    for payload in pattern.payloads[:2]:
                        test_url = target_url.rstrip('/') + payload if payload.startswith('/') else f"{target_url}?test={urllib.parse.quote(payload)}"
                        status, body, _ = await self.request(test_url)
                        
                        for marker in pattern.success_markers:
                            if marker.lower() in body.lower():
                                self.log(f"  [!] Found: {attack} ({marker})", "VULN")
                                self.findings.append({
                                    'type': attack,
                                    'url': test_url,
                                    'marker': marker
                                })
                                context['vulns_found'].append(attack)
                                break
            
            elif reasoning['action'] == 'test':
                # Mind has a specific test
                test = reasoning.get('test', {})
                
                if test:
                    self.log(f"  Testing: {reasoning['pattern']}")
                    
                    status, body, *_ = await self.execute_test(target_url, test, context)
                    
                    # Evaluate result
                    success, conf_delta, confirmed = self.mind.evaluate_result(test, body, status)
                    
                    if success:
                        self.log(f"  [!] Confirmed: {confirmed}", "VULN")
                        self.findings.append({
                            'type': reasoning['pattern'],
                            'confirmed': confirmed,
                            'confidence': reasoning['confidence'] + conf_delta
                        })
                        context['vulns_found'].extend(confirmed)
                        
                        # Adapt strategy
                        pivots = self.mind.adapt_strategy(confirmed)
                        if pivots:
                            self.log(f"  Pivots available: {', '.join(pivots[:2])}")
                        
                        # Think ahead
                        for vuln in confirmed:
                            chain = self.mind.think_ahead(vuln)
                            if chain:
                                self.log(f"  Attack chain: {' -> '.join(chain[:2])}")
                    else:
                        self.log(f"  Test negative")
            
            # Update context
            context['content'] = body if 'body' in dir() else context['content']
            
            # Check if we've achieved significant access
            if any(v in context['vulns_found'] for v in ['rce', 'command_injection', 'webshell']):
                context['access_level'] = 3
                self.log("[+] Shell access achieved!", "SUCCESS")
                break
            
            # Avoid getting stuck - if no progress in 5 steps, try different approach
            if step > 0 and step % 5 == 0 and not self.findings:
                self.log("  No progress, trying different vectors...")
                # Force exploration
                self.mind.hypotheses = []
        
        # Generate report
        report = self.generate_report(target_url, context)
        
        # Save states
        self.mind.save_state()
        self.brain.save()
        
        return {
            'success': len(self.findings) > 0,
            'findings': self.findings,
            'access_level': context['access_level'],
            'report': report
        }
    
    def generate_report(self, target: str, context: Dict) -> str:
        """Generate hunt report"""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        
        report = f"""# VIPER Hunt Report
## Target: {target}
## Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

---

## Summary

- Findings: {len(self.findings)}
- Access Level: {context['access_level']}
- Vulnerabilities: {', '.join(context['vulns_found']) or 'None confirmed'}

---

## Reasoning Log

{self.mind.explain_reasoning()}

---

## Findings

"""
        for i, finding in enumerate(self.findings, 1):
            report += f"""
### {i}. {finding.get('type', 'Unknown')}
- Confirmed: {finding.get('confirmed', finding.get('marker', 'N/A'))}
- URL: {finding.get('url', 'N/A')}
- Confidence: {finding.get('confidence', 0):.0%}
"""
        
        report += f"""

---

## Attack Surface

{json.dumps(self.mind.get_attack_surface(), indent=2)}

---

*Generated by VIPER Agent*
"""
        
        # Save report
        report_file = REPORTS_DIR / f"viper_hunt_{timestamp}.md"
        report_file.write_text(report, encoding='utf-8')
        self.log(f"Report saved: {report_file}")
        
        return report
    
    async def train(self, targets: List[str], cycles: int = 1):
        """Train on practice targets"""
        self.log("=== VIPER Training Mode ===")
        self.log(f"Targets: {len(targets)}")
        self.log(f"Cycles: {cycles}")
        
        # Learn from Natas first
        self.brain.learn_from_natas()
        
        async with aiohttp.ClientSession() as self.session:
            for cycle in range(cycles):
                self.log(f"\n--- Cycle {cycle + 1}/{cycles} ---")
                
                for target in targets:
                    result = await self.hunt(target)
                    
                    if result['success']:
                        self.log(f"[+] {len(result['findings'])} findings", "SUCCESS")
                    else:
                        self.log(f"[-] No findings")
                    
                    await asyncio.sleep(1)
        
        # Print final stats
        self.log("\n=== Training Complete ===")
        self.log(f"Mind: {self.mind.get_attack_surface()}")
        self.log(f"Brain: {self.brain.get_stats()}")


async def main():
    import sys
    
    agent = ViperAgent()
    
    if len(sys.argv) < 2:
        print("VIPER Agent - Autonomous Adaptive Hacker")
        print()
        print("Usage:")
        print("  python viper_agent.py <target_url>      # Hunt single target")
        print("  python viper_agent.py --train           # Train on local lab")
        print("  python viper_agent.py --natas           # Train on Natas")
        return
    
    if sys.argv[1] == '--train':
        # Train on local Metasploitable
        targets = [
            'http://192.168.56.1:8080',
            'http://192.168.56.1:8080/dvwa/',
            'http://192.168.56.1:8080/mutillidae/',
        ]
        await agent.train(targets, cycles=1)
    
    elif sys.argv[1] == '--natas':
        # Train on Natas (already have progress)
        agent.brain.learn_from_natas()
        print(f"Learned from Natas: {agent.brain.get_stats()}")
    
    else:
        # Hunt provided target
        target = sys.argv[1]
        async with aiohttp.ClientSession() as agent.session:
            result = await agent.hunt(target)
            
            if result['success']:
                print(f"\n[+] Hunt successful: {len(result['findings'])} findings")
            else:
                print(f"\n[-] No vulnerabilities confirmed")


if __name__ == "__main__":
    asyncio.run(main())
