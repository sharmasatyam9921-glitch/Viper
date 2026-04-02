#!/usr/bin/env python3
"""
VIPER Recon Engine - Comprehensive reconnaissance orchestrator

Features:
- Subdomain enumeration (amass, subfinder, or Python fallback)
- Port scanning (nmap or Python socket fallback)  
- Technology fingerprinting (httpx or Python httpx library)
- DNS enumeration (dnspython)
"""

import asyncio
import logging

logger = logging.getLogger("viper.recon_engine")
import json
import os
import random
import re
import socket
import string
import struct
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple
from dataclasses import dataclass, field

import aiohttp

try:
    import whois as python_whois
    WHOIS_AVAILABLE = True
except ImportError:
    WHOIS_AVAILABLE = False

try:
    import dns.resolver
    import dns.zone
    import dns.query
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False

HACKAGENT_DIR = Path(__file__).parent.parent
RECON_OUTPUT_DIR = HACKAGENT_DIR / "data" / "recon"
RECON_OUTPUT_DIR.mkdir(parents=True, exist_ok=True)


@dataclass
class ReconResult:
    """Results from reconnaissance"""
    target: str
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())

    # Subdomain enumeration
    subdomains: Set[str] = field(default_factory=set)

    # Port scanning
    open_ports: Dict[str, List[int]] = field(default_factory=dict)  # host -> [ports]

    # Technology fingerprinting
    technologies: Dict[str, Dict] = field(default_factory=dict)  # url -> tech_info

    # DNS records
    dns_records: Dict[str, List[str]] = field(default_factory=dict)  # record_type -> [values]

    # Live hosts
    live_hosts: Set[str] = field(default_factory=set)

    # WHOIS information
    whois_info: Dict = field(default_factory=dict)

    # Shodan data (ports, vulns, hostnames)
    shodan_data: Dict = field(default_factory=dict)

    # URLScan results (urls, technologies, IPs)
    urlscan_data: Dict = field(default_factory=dict)

    # Wappalyzer-style deep tech fingerprinting
    wappalyzer_techs: List[Dict] = field(default_factory=list)

    # GAU / Wayback Machine URLs
    archived_urls: Set[str] = field(default_factory=set)

    # Extended recon fields
    banners: Dict[str, Dict] = field(default_factory=dict)  # host -> {port: {service, version, banner}}
    api_endpoints: List[Dict] = field(default_factory=list)  # [{path, status_code, content_type, size}]
    wildcard_filtered: bool = False  # Whether wildcard filtering was applied

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "timestamp": self.timestamp,
            "subdomains": list(self.subdomains),
            "open_ports": self.open_ports,
            "technologies": self.technologies,
            "dns_records": self.dns_records,
            "live_hosts": list(self.live_hosts),
            "whois_info": self.whois_info,
            "shodan_data": self.shodan_data,
            "urlscan_data": self.urlscan_data,
            "wappalyzer_techs": self.wappalyzer_techs,
            "archived_urls": list(self.archived_urls),
            "banners": self.banners,
            "api_endpoints": self.api_endpoints,
            "wildcard_filtered": self.wildcard_filtered,
        }
    
    def save(self, filename: str = None):
        if not filename:
            safe_target = re.sub(r'[^\w\-_.]', '_', self.target)
            filename = f"recon_{safe_target}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        
        filepath = RECON_OUTPUT_DIR / filename
        filepath.write_text(json.dumps(self.to_dict(), indent=2))
        return filepath


class ReconEngine:
    """
    Orchestrates comprehensive reconnaissance.
    
    Uses external tools if available, falls back to Python implementations.
    """
    
    def __init__(self, verbose: bool = True, tool_manager=None):
        self.verbose = verbose
        self.session: Optional[aiohttp.ClientSession] = None
        self.tool_manager = tool_manager
        if tool_manager:
            self.tools = {name: tool_manager.check_tool(name)
                          for name in ['amass', 'subfinder', 'httpx', 'nmap', 'nuclei', 'knockpy', 'naabu']}
            self.log(f"Tools (via ToolManager): {[t for t, v in self.tools.items() if v]}")
        else:
            self._check_tools()

    def log(self, msg: str, level: str = "INFO"):
        if self.verbose:
            timestamp = datetime.now().strftime('%H:%M:%S')
            print(f"[{timestamp}] [RECON] [{level}] {msg}")

    def _check_tools(self):
        """Check which external tools are available"""
        self.tools = {}
        tools_to_check = ['amass', 'subfinder', 'httpx', 'nmap', 'nuclei', 'knockpy', 'naabu']

        for tool in tools_to_check:
            try:
                result = subprocess.run(
                    ['where' if sys.platform == 'win32' else 'which', tool],
                    capture_output=True,
                    text=True
                )
                self.tools[tool] = result.returncode == 0
            except Exception as e:  # noqa: BLE001
                self.tools[tool] = False

        self.log(f"Available tools: {[t for t, v in self.tools.items() if v]}")
        self.log(f"Missing tools: {[t for t, v in self.tools.items() if not v]}")
    
    async def full_recon(self, target: str, 
                         subdomain_enum: bool = True,
                         port_scan: bool = True,
                         tech_fingerprint: bool = True,
                         dns_enum: bool = True) -> ReconResult:
        """
        Run full reconnaissance on target.
        
        Args:
            target: Domain or IP to scan
            subdomain_enum: Enumerate subdomains
            port_scan: Scan for open ports
            tech_fingerprint: Identify technologies
            dns_enum: Enumerate DNS records
        """
        result = ReconResult(target=target)
        
        self.log(f"Starting full recon on: {target}")
        
        async with aiohttp.ClientSession(
            connector=aiohttp.TCPConnector(ssl=False),
            timeout=aiohttp.ClientTimeout(total=30)
        ) as self.session:
            
            # 1. DNS Enumeration
            if dns_enum:
                self.log("Phase 1: DNS Enumeration")
                result.dns_records = await self.enumerate_dns(target)
            
            # 2. Subdomain Enumeration
            if subdomain_enum:
                self.log("Phase 2: Subdomain Enumeration")
                result.subdomains = await self.enumerate_subdomains(target)
                result.subdomains.add(target)  # Include main domain

                # 2b. DNS brute-force (Knockpy-style)
                self.log("Phase 2b: DNS Brute-force (Knockpy-style)")
                brute_subs = await self._run_dns_bruteforce(target)
                result.subdomains.update(brute_subs)

                # 2c. Wildcard filtering (Puredns-style)
                self.log("Phase 2c: Wildcard DNS Filtering")
                pre_count = len(result.subdomains)
                result.subdomains = self._filter_wildcards(target, result.subdomains)
                if len(result.subdomains) < pre_count:
                    result.wildcard_filtered = True
            else:
                result.subdomains = {target}

            # 3. Find live hosts
            self.log("Phase 3: Probing Live Hosts")
            result.live_hosts = await self.probe_live_hosts(result.subdomains)
            
            # 4. Port Scanning
            if port_scan and result.live_hosts:
                self.log("Phase 4: Port Scanning")
                result.open_ports = await self.scan_ports(result.live_hosts)
            
            # 4b. Naabu-style fast port scan + banner grabbing on live hosts
            if result.live_hosts:
                self.log("Phase 4b: Naabu Fast Port Scan + Banner Grabbing")
                for host in result.live_hosts:
                    naabu_ports = await self._run_naabu_scan(host)
                    if naabu_ports:
                        # Merge with existing port scan results
                        existing = set(result.open_ports.get(host, []))
                        existing.update(naabu_ports)
                        result.open_ports[host] = sorted(existing)
                    # Banner grab on all known open ports for this host
                    all_ports = result.open_ports.get(host, [])
                    if all_ports:
                        host_banners = await self._grab_banners(host, all_ports)
                        if host_banners:
                            result.banners[host] = {
                                str(p): v for p, v in host_banners.items()
                            }

            # 5. Technology Fingerprinting
            if tech_fingerprint and result.live_hosts:
                self.log("Phase 5: Technology Fingerprinting")
                result.technologies = await self.fingerprint_technologies(result.live_hosts)

            # 5b. API Brute-force (Kiterunner-style) on live hosts
            if result.live_hosts:
                self.log("Phase 5b: API Brute-force (Kiterunner-style)")
                for host in result.live_hosts:
                    # Determine best URL scheme from open ports
                    host_ports = result.open_ports.get(host, [])
                    if 443 in host_ports or 8443 in host_ports:
                        base_url = f"https://{host}"
                    else:
                        base_url = f"http://{host}"
                    api_results = await self._run_api_bruteforce(base_url)
                    if api_results:
                        result.api_endpoints.extend(api_results)

            # 6. Advanced Recon Sources (parallel)
            self.log("Phase 6: Advanced Recon Sources (parallel)")
            await self._run_advanced_recon(target, result)

        # Save results
        saved_path = result.save()
        self.log(f"Recon complete. Results saved to: {saved_path}")
        
        return result
    
    async def enumerate_dns(self, domain: str) -> Dict[str, List[str]]:
        """Enumerate DNS records"""
        records = {}
        record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA']
        
        if not DNS_AVAILABLE:
            self.log("dnspython not available, skipping DNS enumeration", "WARN")
            return records
        
        resolver = dns.resolver.Resolver()
        resolver.timeout = 5
        resolver.lifetime = 10
        
        for rtype in record_types:
            try:
                answers = resolver.resolve(domain, rtype)
                records[rtype] = [str(r) for r in answers]
                self.log(f"  {rtype}: {len(records[rtype])} records")
            except dns.resolver.NoAnswer:
                pass
            except dns.resolver.NXDOMAIN:
                self.log(f"Domain {domain} does not exist", "WARN")
                break
            except Exception as e:
                pass
        
        # Try zone transfer (usually blocked but worth trying)
        try:
            ns_records = resolver.resolve(domain, 'NS')
            for ns in ns_records:
                try:
                    zone = dns.zone.from_xfr(dns.query.xfr(str(ns), domain, timeout=5))
                    records['ZONE_TRANSFER'] = [str(n) for n in zone.nodes.keys()]
                    self.log(f"[!] Zone transfer successful from {ns}!", "VULN")
                    break
                except Exception as e:  # noqa: BLE001
                    pass
        except Exception as e:  # noqa: BLE001
            pass
        
        return records
    
    async def enumerate_subdomains(self, domain: str, parallel: bool = True) -> Set[str]:
        """
        Enumerate subdomains using all available sources.

        Runs all discovery tools in parallel via asyncio.gather() for speed.
        Falls back to sequential execution if parallel mode fails.

        Sources: subfinder, amass, crt.sh, HackerTarget, Python brute-force
        """
        subdomains = set()

        # Build list of coroutines for all available sources
        tasks = []
        task_names = []

        if self.tools.get('subfinder'):
            tasks.append(self._run_subfinder(domain))
            task_names.append("subfinder")

        if self.tools.get('amass'):
            tasks.append(self._run_amass(domain))
            task_names.append("amass")

        # Passive OSINT sources (always available)
        tasks.append(self._query_crtsh(domain))
        task_names.append("crt.sh")

        tasks.append(self._query_hackertarget(domain))
        task_names.append("hackertarget")

        # Python DNS brute-force (always available)
        tasks.append(self._python_subdomain_enum(domain))
        task_names.append("python-brute")

        if parallel:
            self.log(f"  Running {len(tasks)} sources in parallel: {', '.join(task_names)}")
            try:
                results = await asyncio.gather(*tasks, return_exceptions=True)
                for name, result in zip(task_names, results):
                    if isinstance(result, Exception):
                        self.log(f"  {name} failed: {result}", "WARN")
                    elif isinstance(result, set):
                        self.log(f"  {name}: {len(result)} subdomains")
                        subdomains.update(result)
            except Exception as e:
                self.log(f"  Parallel execution failed ({e}), falling back to sequential", "WARN")
                subdomains = await self.enumerate_subdomains(domain, parallel=False)
                return subdomains
        else:
            self.log(f"  Running {len(tasks)} sources sequentially (fallback mode)")
            for name, coro in zip(task_names, tasks):
                try:
                    result = await coro
                    if isinstance(result, set):
                        self.log(f"  {name}: {len(result)} subdomains")
                        subdomains.update(result)
                except Exception as e:
                    self.log(f"  {name} failed: {e}", "WARN")

        # Remove empty strings, error messages (contain spaces), and invalid hostnames
        subdomains = {s for s in subdomains if s and ' ' not in s and len(s) < 253 and '.' in s}
        self.log(f"  Total unique subdomains found: {len(subdomains)}")
        return subdomains
    
    async def _run_subfinder(self, domain: str) -> Set[str]:
        """Run subfinder"""
        try:
            proc = await asyncio.create_subprocess_exec(
                'subfinder', '-d', domain, '-silent',
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=120)
            return set(stdout.decode().strip().split('\n'))
        except Exception as e:  # noqa: BLE001
            return set()
    
    async def _run_amass(self, domain: str) -> Set[str]:
        """Run amass enum"""
        try:
            proc = await asyncio.create_subprocess_exec(
                'amass', 'enum', '-passive', '-d', domain,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=300)
            return set(stdout.decode().strip().split('\n'))
        except Exception as e:  # noqa: BLE001
            return set()

    async def _query_crtsh(self, domain: str) -> Set[str]:
        """Query crt.sh Certificate Transparency logs for subdomains"""
        subdomains = set()
        url = f"https://crt.sh/?q=%25.{domain}&output=json"
        try:
            async with aiohttp.ClientSession(
                connector=aiohttp.TCPConnector(ssl=False),
                timeout=aiohttp.ClientTimeout(total=30)
            ) as session:
                async with session.get(url) as resp:
                    if resp.status == 200:
                        data = await resp.json(content_type=None)
                        for entry in data:
                            name = entry.get("name_value", "")
                            for sub in name.split("\n"):
                                sub = sub.strip().lower()
                                if sub.endswith(f".{domain}") or sub == domain:
                                    # Skip wildcards
                                    if not sub.startswith("*"):
                                        subdomains.add(sub)
        except Exception as e:
            self.log(f"  crt.sh query error: {e}", "WARN")
        return subdomains

    async def _query_hackertarget(self, domain: str) -> Set[str]:
        """Query HackerTarget API for subdomains"""
        subdomains = set()
        url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
        try:
            async with aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=20)
            ) as session:
                async with session.get(url) as resp:
                    if resp.status == 200:
                        text = await resp.text()
                        if "error" not in text.lower() and "API count" not in text:
                            for line in text.strip().split("\n"):
                                parts = line.split(",")
                                if parts and parts[0].strip():
                                    sub = parts[0].strip().lower()
                                    if sub.endswith(f".{domain}") or sub == domain:
                                        subdomains.add(sub)
        except Exception as e:
            self.log(f"  HackerTarget query error: {e}", "WARN")
        return subdomains

    async def _python_subdomain_enum(self, domain: str) -> Set[str]:
        """Python-based subdomain enumeration using common prefixes and DNS"""
        subdomains = set()
        
        # Common subdomain prefixes
        prefixes = [
            'www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'ns1', 'ns2',
            'ns', 'dns', 'dns1', 'dns2', 'mx', 'mx1', 'mx2', 'smtp', 'imap', 'blog',
            'app', 'api', 'dev', 'stage', 'staging', 'test', 'testing', 'demo',
            'admin', 'panel', 'portal', 'secure', 'vpn', 'remote', 'login', 'auth',
            'shop', 'store', 'mobile', 'm', 'beta', 'alpha', 'new', 'old', 'legacy',
            'cdn', 'static', 'assets', 'media', 'images', 'img', 'video', 'files',
            'backup', 'bak', 'db', 'database', 'sql', 'mysql', 'postgres', 'redis',
            'web', 'www1', 'www2', 'web1', 'web2', 'server', 'server1', 'server2',
            'git', 'gitlab', 'github', 'jenkins', 'ci', 'cd', 'docker', 'k8s',
            'support', 'help', 'helpdesk', 'ticket', 'crm', 'erp', 'hr', 'finance',
            'news', 'forum', 'community', 'social', 'chat', 'slack', 'teams'
        ]
        
        if not DNS_AVAILABLE:
            return subdomains
        
        resolver = dns.resolver.Resolver()
        resolver.timeout = 2
        resolver.lifetime = 4
        
        async def check_subdomain(prefix: str) -> Optional[str]:
            subdomain = f"{prefix}.{domain}"
            try:
                await asyncio.get_event_loop().run_in_executor(
                    None, 
                    lambda: resolver.resolve(subdomain, 'A')
                )
                return subdomain
            except Exception as e:  # noqa: BLE001
                return None
        
        # Check in batches
        batch_size = 20
        for i in range(0, len(prefixes), batch_size):
            batch = prefixes[i:i+batch_size]
            tasks = [check_subdomain(p) for p in batch]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            for result in results:
                if isinstance(result, str):
                    subdomains.add(result)
        
        return subdomains
    
    async def probe_live_hosts(self, hosts: Set[str]) -> Set[str]:
        """Check which hosts are alive"""
        live = set()
        
        async def check_host(host: str) -> Optional[str]:
            for scheme in ['https', 'http']:
                url = f"{scheme}://{host}"
                try:
                    async with self.session.head(url, allow_redirects=True) as resp:
                        if resp.status < 500:
                            return host
                except Exception as e:  # noqa: BLE001
                    pass
            return None
        
        # Check in batches
        batch_size = 20
        hosts_list = list(hosts)
        for i in range(0, len(hosts_list), batch_size):
            batch = hosts_list[i:i+batch_size]
            tasks = [check_host(h) for h in batch]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            for result in results:
                if isinstance(result, str):
                    live.add(result)
        
        self.log(f"  Live hosts: {len(live)}/{len(hosts)}")
        return live
    
    async def scan_ports(self, hosts: Set[str], 
                         ports: List[int] = None) -> Dict[str, List[int]]:
        """Scan ports on hosts"""
        if ports is None:
            # Common web/service ports
            ports = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445,
                     993, 995, 1723, 3306, 3389, 5432, 5900, 6379, 8000, 8080, 
                     8443, 8888, 9000, 9200, 27017]
        
        results = {}
        
        # Use nmap if available
        if self.tools.get('nmap'):
            self.log("  Using nmap...")
            for host in hosts:
                open_ports = await self._run_nmap(host, ports)
                if open_ports:
                    results[host] = open_ports
        else:
            # Python fallback
            self.log("  Using Python socket scanner...")
            for host in hosts:
                open_ports = await self._python_port_scan(host, ports)
                if open_ports:
                    results[host] = open_ports
        
        return results
    
    async def _run_nmap(self, host: str, ports: List[int]) -> List[int]:
        """Run nmap scan"""
        try:
            port_str = ','.join(map(str, ports))
            proc = await asyncio.create_subprocess_exec(
                'nmap', '-Pn', '-sT', '-p', port_str, '-oG', '-', host,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=120)
            
            # Parse grepable output
            open_ports = []
            for line in stdout.decode().split('\n'):
                if '/open/' in line:
                    # Extract port numbers
                    port_matches = re.findall(r'(\d+)/open', line)
                    open_ports.extend([int(p) for p in port_matches])
            
            return open_ports
        except Exception as e:  # noqa: BLE001
            return []
    
    async def _python_port_scan(self, host: str, ports: List[int]) -> List[int]:
        """Python socket-based port scan"""
        open_ports = []
        
        async def check_port(port: int) -> Optional[int]:
            try:
                # Resolve hostname first
                try:
                    ip = socket.gethostbyname(host)
                except Exception as e:  # noqa: BLE001
                    ip = host
                
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(ip, port),
                    timeout=2
                )
                writer.close()
                await writer.wait_closed()
                return port
            except Exception as e:  # noqa: BLE001
                return None
        
        # Check in batches
        batch_size = 50
        for i in range(0, len(ports), batch_size):
            batch = ports[i:i+batch_size]
            tasks = [check_port(p) for p in batch]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            for result in results:
                if isinstance(result, int):
                    open_ports.append(result)
        
        if open_ports:
            self.log(f"  {host}: {open_ports}")
        
        return sorted(open_ports)
    
    async def fingerprint_technologies(self, hosts: Set[str]) -> Dict[str, Dict]:
        """Fingerprint technologies on hosts"""
        results = {}
        
        # Use httpx CLI if available
        if self.tools.get('httpx'):
            self.log("  Using httpx CLI...")
            for host in hosts:
                tech = await self._run_httpx(host)
                if tech:
                    results[host] = tech
        else:
            # Python fingerprinting
            self.log("  Using Python fingerprinting...")
            for host in hosts:
                tech = await self._python_fingerprint(host)
                if tech:
                    results[host] = tech
        
        return results
    
    async def _run_httpx(self, host: str) -> Optional[Dict]:
        """Run httpx for fingerprinting"""
        try:
            proc = await asyncio.create_subprocess_exec(
                'httpx', '-u', host, '-json', '-tech-detect', '-status-code',
                '-title', '-server', '-silent',
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=30)
            
            if stdout:
                return json.loads(stdout.decode().strip())
        except Exception as e:  # noqa: BLE001
            pass
        return None
    
    async def _python_fingerprint(self, host: str) -> Optional[Dict]:
        """Python-based technology fingerprinting"""
        tech_info = {
            "technologies": [],
            "headers": {},
            "title": None,
            "status_code": None
        }
        
        for scheme in ['https', 'http']:
            url = f"{scheme}://{host}"
            try:
                async with self.session.get(url, allow_redirects=True) as resp:
                    tech_info["status_code"] = resp.status
                    tech_info["headers"] = dict(resp.headers)
                    
                    body = await resp.text()
                    
                    # Extract title
                    title_match = re.search(r'<title>([^<]+)</title>', body, re.I)
                    if title_match:
                        tech_info["title"] = title_match.group(1).strip()
                    
                    # Technology detection
                    techs = []
                    
                    # Server header
                    server = resp.headers.get('Server', '')
                    if server:
                        techs.append(f"Server:{server}")
                    
                    # Powered-by
                    powered = resp.headers.get('X-Powered-By', '')
                    if powered:
                        techs.append(powered)
                    
                    # Framework detection from body
                    patterns = {
                        "WordPress": [r'wp-content', r'wp-includes'],
                        "Drupal": [r'Drupal', r'sites/default/files'],
                        "Joomla": [r'/media/jui/', r'joomla'],
                        "Laravel": [r'laravel_session', r'XSRF-TOKEN'],
                        "Django": [r'csrfmiddlewaretoken', r'django'],
                        "Rails": [r'csrf-token', r'rails'],
                        "React": [r'react', r'_reactRoot'],
                        "Vue.js": [r'vue', r'v-if', r'v-for'],
                        "Angular": [r'ng-', r'angular'],
                        "jQuery": [r'jquery'],
                        "Bootstrap": [r'bootstrap'],
                        "PHP": [r'\.php', r'PHPSESSID'],
                        "ASP.NET": [r'__VIEWSTATE', r'aspnet'],
                        "Java": [r'JSESSIONID', r'\.jsp'],
                        "Nginx": [r'nginx'],
                        "Apache": [r'apache'],
                        "IIS": [r'IIS', r'ASP\.NET'],
                    }
                    
                    combined = f"{body} {json.dumps(dict(resp.headers))}"
                    for tech, pats in patterns.items():
                        for pat in pats:
                            if re.search(pat, combined, re.I):
                                techs.append(tech)
                                break
                    
                    tech_info["technologies"] = list(set(techs))
                    return tech_info
                    
            except Exception as e:  # noqa: BLE001
                continue
        
        return None


    # -------------------------------------------------------------------
    # Advanced Recon Capabilities
    # -------------------------------------------------------------------

    # Top 100 ports for Naabu-style scanning
    TOP_100_PORTS = [
        21, 22, 23, 25, 53, 80, 81, 88, 110, 111, 113, 119, 135, 139, 143,
        161, 179, 194, 389, 443, 445, 465, 514, 515, 548, 554, 587, 631, 636,
        646, 993, 995, 1025, 1026, 1027, 1028, 1029, 1110, 1433, 1521, 1720,
        1723, 1755, 2000, 2001, 2049, 2121, 2717, 3000, 3128, 3306, 3389,
        3986, 4899, 5000, 5009, 5051, 5060, 5101, 5190, 5357, 5432, 5631,
        5666, 5800, 5900, 5901, 6000, 6001, 6379, 6646, 7070, 8000, 8008,
        8080, 8081, 8443, 8888, 9000, 9090, 9100, 9200, 9443, 9999, 10000,
        11211, 13722, 15000, 17988, 20000, 27017, 27018, 28017, 32768, 33434,
        43594, 49152, 49153, 49154,
    ]

    # Common API paths for Kiterunner-style brute-force
    COMMON_API_PATHS = [
        "/api", "/api/v1", "/api/v2", "/api/v3", "/api/v4",
        "/graphql", "/graphiql", "/playground",
        "/swagger.json", "/swagger-ui.html", "/swagger-ui/", "/swagger/",
        "/openapi.json", "/openapi.yaml", "/api-docs", "/api-docs.json",
        "/api/docs", "/api/health", "/api/status", "/api/version", "/api/info",
        "/api/users", "/api/admin", "/api/config", "/api/settings",
        "/api/auth/login", "/api/auth/register", "/api/auth/token",
        "/api/auth/refresh", "/api/auth/logout",
        "/api/search", "/api/upload", "/api/download", "/api/export",
        "/api/v1/users", "/api/v1/users/me", "/api/v1/admin",
        "/api/v2/users", "/api/v2/health",
        "/rest", "/rest/api", "/rest/api/2", "/rest/api/latest",
        "/json", "/xml", "/ws", "/websocket", "/wss",
        "/actuator", "/actuator/health", "/actuator/env", "/actuator/beans",
        "/actuator/configprops", "/actuator/mappings", "/actuator/metrics",
        "/actuator/info", "/actuator/loggers", "/actuator/heapdump",
        "/actuator/threaddump", "/actuator/scheduledtasks",
        "/debug", "/debug/vars", "/debug/pprof",
        "/trace", "/metrics", "/info", "/env",
        "/.well-known/openid-configuration", "/.well-known/security.txt",
        "/.well-known/jwks.json", "/.well-known/assetlinks.json",
        "/wp-json", "/wp-json/wp/v2/users", "/wp-json/wp/v2/posts",
        "/jsonapi", "/jsonapi/node/article",
        "/v1", "/v2", "/v3",
        "/healthz", "/readyz", "/livez",
        "/server-status", "/server-info",
        "/_cat/indices", "/_cluster/health", "/_nodes",
        "/console", "/admin/console",
        "/elmah.axd", "/trace.axd",
        "/robots.txt", "/sitemap.xml",
        "/cgi-bin/", "/phpmyadmin/", "/adminer.php",
        "/.env", "/.git/config", "/.git/HEAD",
        "/config.json", "/config.yaml", "/config.yml",
        "/api/internal", "/api/private", "/api/debug",
        "/token", "/oauth/token", "/oauth/authorize",
        "/login", "/register", "/signup", "/signin",
        "/dashboard", "/panel", "/admin", "/admin/api",
        "/manage", "/management",
        "/prometheus", "/prometheus/metrics",
        "/api/graphql", "/gql", "/query",
        "/socket.io/", "/sockjs/",
        "/feeds", "/rss", "/atom.xml",
        "/api/test", "/api/ping", "/api/echo",
        "/status.json", "/health.json", "/version.json",
    ]

    async def _run_dns_bruteforce(self, domain: str) -> Set[str]:
        """
        Knockpy-style DNS brute-force subdomain enumeration.
        Uses wordlist + async DNS resolution with concurrency limit.
        Falls back to knockpy subprocess if available.
        """
        discovered = set()

        # Try external knockpy first
        if self.tools.get('knockpy'):
            self.log("  DNS brute-force: using knockpy")
            try:
                proc = await asyncio.create_subprocess_exec(
                    'knockpy', domain, '-w',
                    str(HACKAGENT_DIR / 'wordlists' / 'subdomains-top1million-5000.txt'),
                    '--no-http', '--json',
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.DEVNULL
                )
                stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=300)
                try:
                    data = json.loads(stdout.decode())
                    for entry in data if isinstance(data, list) else data.values():
                        if isinstance(entry, dict) and entry.get('domain'):
                            discovered.add(entry['domain'])
                        elif isinstance(entry, str):
                            discovered.add(entry)
                except (json.JSONDecodeError, AttributeError):
                    # Parse line-based output
                    for line in stdout.decode().splitlines():
                        line = line.strip()
                        if line and '.' in line and not line.startswith(('#', '[')):
                            discovered.add(line)
                if discovered:
                    self.log(f"  knockpy found {len(discovered)} subdomains")
                    return discovered
            except Exception as e:
                self.log(f"  knockpy failed: {e}, using Python fallback", "WARN")

        # Python DNS brute-force fallback
        wordlist_path = HACKAGENT_DIR / 'wordlists' / 'subdomains-top1million-5000.txt'
        if not wordlist_path.exists():
            self.log(f"  Wordlist not found: {wordlist_path}", "WARN")
            return discovered

        words = wordlist_path.read_text(errors='ignore').splitlines()
        words = [w.strip() for w in words if w.strip() and not w.startswith('#')]
        self.log(f"  DNS brute-force: {len(words)} words against {domain}")

        sem = asyncio.Semaphore(50)
        loop = asyncio.get_event_loop()

        async def resolve_sub(word: str):
            fqdn = f"{word}.{domain}"
            async with sem:
                try:
                    await loop.run_in_executor(
                        None, socket.getaddrinfo, fqdn, None
                    )
                    return fqdn
                except (socket.gaierror, OSError):
                    return None

        tasks = [resolve_sub(w) for w in words]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for r in results:
            if isinstance(r, str):
                discovered.add(r)

        self.log(f"  DNS brute-force found {len(discovered)} subdomains")
        return discovered

    def _filter_wildcards(self, domain: str, subdomains: Set[str]) -> Set[str]:
        """
        Puredns-style wildcard DNS filtering.
        Detects wildcard DNS and removes subdomains that resolve to the wildcard IP.
        """
        # Generate a random non-existent subdomain to test for wildcard
        rand_prefix = ''.join(random.choices(string.ascii_lowercase + string.digits, k=16))
        wildcard_host = f"{rand_prefix}.{domain}"

        try:
            wildcard_ips = {
                addr[4][0]
                for addr in socket.getaddrinfo(wildcard_host, None)
            }
        except (socket.gaierror, OSError):
            # No wildcard — domain doesn't resolve random subdomains
            self.log("  No wildcard DNS detected, skipping filter")
            return subdomains

        self.log(f"  Wildcard DNS detected! IPs: {wildcard_ips}")

        filtered = set()
        for sub in subdomains:
            try:
                sub_ips = {
                    addr[4][0]
                    for addr in socket.getaddrinfo(sub, None)
                }
                if not sub_ips.issubset(wildcard_ips):
                    filtered.add(sub)
            except (socket.gaierror, OSError):
                # Can't resolve — skip it
                pass

        removed = len(subdomains) - len(filtered)
        self.log(f"  Wildcard filter: removed {removed} subdomains, kept {len(filtered)}")
        return filtered

    async def _run_naabu_scan(self, host: str) -> List[int]:
        """
        Naabu-style fast port scanning.
        Uses naabu binary if available, otherwise enhanced Python scanner.
        """
        # Try naabu binary first
        if self.tools.get('naabu'):
            self.log(f"  Naabu scan on {host}: using naabu binary")
            try:
                proc = await asyncio.create_subprocess_exec(
                    'naabu', '-host', host, '-top-ports', '100', '-silent', '-json',
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.DEVNULL
                )
                stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=120)
                open_ports = []
                for line in stdout.decode().splitlines():
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        entry = json.loads(line)
                        if 'port' in entry:
                            open_ports.append(int(entry['port']))
                    except json.JSONDecodeError:
                        # Plain port number output
                        m = re.search(r'(\d+)', line)
                        if m:
                            open_ports.append(int(m.group(1)))
                return sorted(set(open_ports))
            except Exception as e:
                self.log(f"  naabu failed: {e}, using Python fallback", "WARN")

        # Enhanced Python scanner — top 100 ports, batches of 50, 3s timeout
        self.log(f"  Naabu scan on {host}: Python scanner ({len(self.TOP_100_PORTS)} ports)")
        open_ports = []
        sem = asyncio.Semaphore(50)

        async def check_port(port: int) -> Optional[int]:
            async with sem:
                # Try CONNECT scan (works without raw sockets)
                try:
                    ip = socket.gethostbyname(host)
                except (socket.gaierror, OSError):
                    ip = host
                try:
                    reader, writer = await asyncio.wait_for(
                        asyncio.open_connection(ip, port),
                        timeout=3
                    )
                    writer.close()
                    await writer.wait_closed()
                    return port
                except Exception as e:  # noqa: BLE001
                    return None

        tasks = [check_port(p) for p in self.TOP_100_PORTS]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for r in results:
            if isinstance(r, int):
                open_ports.append(r)

        open_ports = sorted(open_ports)
        if open_ports:
            self.log(f"  {host}: {len(open_ports)} open ports: {open_ports}")
        return open_ports

    async def _grab_banners(self, host: str, open_ports: List[int]) -> Dict[int, Dict]:
        """
        Banner grabbing with protocol-specific probes.
        Returns {port: {service, version, banner}}.
        """
        banners = {}

        async def grab_one(port: int) -> Tuple[int, Optional[Dict]]:
            try:
                ip = socket.gethostbyname(host)
            except (socket.gaierror, OSError):
                ip = host

            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(ip, port),
                    timeout=3
                )
            except Exception as e:  # noqa: BLE001
                return (port, None)

            info = {"service": "unknown", "version": "", "banner": ""}

            try:
                if port == 22:
                    # SSH — server sends banner immediately
                    data = await asyncio.wait_for(reader.read(1024), timeout=3)
                    banner = data.decode(errors='replace').strip()
                    info["banner"] = banner
                    info["service"] = "ssh"
                    m = re.search(r'SSH-[\d.]+-(\S+)', banner)
                    if m:
                        info["version"] = m.group(1)

                elif port == 21:
                    # FTP — read 220 welcome
                    data = await asyncio.wait_for(reader.read(1024), timeout=3)
                    banner = data.decode(errors='replace').strip()
                    info["banner"] = banner
                    info["service"] = "ftp"
                    m = re.search(r'220[- ](.+)', banner)
                    if m:
                        info["version"] = m.group(1).strip()

                elif port == 25:
                    # SMTP — read 220, send EHLO
                    data = await asyncio.wait_for(reader.read(1024), timeout=3)
                    banner = data.decode(errors='replace').strip()
                    info["service"] = "smtp"
                    info["banner"] = banner
                    writer.write(b"EHLO probe.local\r\n")
                    await writer.drain()
                    ehlo_data = await asyncio.wait_for(reader.read(1024), timeout=3)
                    info["banner"] += "\n" + ehlo_data.decode(errors='replace').strip()
                    m = re.search(r'220[- ](\S+)', banner)
                    if m:
                        info["version"] = m.group(1)

                elif port in (80, 443, 8080, 8443, 8888, 8000, 8008, 9090):
                    # HTTP — send HEAD request
                    scheme = "https" if port in (443, 8443) else "http"
                    req = (
                        f"HEAD / HTTP/1.1\r\n"
                        f"Host: {host}\r\n"
                        f"Connection: close\r\n\r\n"
                    )
                    writer.write(req.encode())
                    await writer.drain()
                    data = await asyncio.wait_for(reader.read(4096), timeout=3)
                    banner = data.decode(errors='replace')
                    info["banner"] = banner[:512]
                    info["service"] = "http"
                    m = re.search(r'[Ss]erver:\s*(.+)', banner)
                    if m:
                        info["version"] = m.group(1).strip()

                elif port == 3306:
                    # MySQL — read initial handshake, extract version
                    data = await asyncio.wait_for(reader.read(1024), timeout=3)
                    info["service"] = "mysql"
                    if len(data) > 5:
                        # MySQL greeting: skip 4-byte header, 1-byte protocol,
                        # then null-terminated version string
                        try:
                            version_end = data.index(b'\x00', 5)
                            info["version"] = data[5:version_end].decode(errors='replace')
                            info["banner"] = f"MySQL {info['version']}"
                        except (ValueError, IndexError):
                            info["banner"] = data[:64].decode(errors='replace')
                    else:
                        info["banner"] = data.decode(errors='replace')

                elif port == 6379:
                    # Redis — send INFO server
                    writer.write(b"INFO server\r\n")
                    await writer.drain()
                    data = await asyncio.wait_for(reader.read(4096), timeout=3)
                    banner = data.decode(errors='replace')
                    info["service"] = "redis"
                    info["banner"] = banner[:512]
                    m = re.search(r'redis_version:(\S+)', banner)
                    if m:
                        info["version"] = m.group(1)

                else:
                    # Generic — try to read whatever the server sends
                    try:
                        data = await asyncio.wait_for(reader.read(1024), timeout=3)
                        info["banner"] = data.decode(errors='replace').strip()[:256]
                    except asyncio.TimeoutError:
                        pass

            except asyncio.TimeoutError:
                pass
            except Exception as e:
                info["banner"] = f"error: {e}"
            finally:
                try:
                    writer.close()
                    await writer.wait_closed()
                except Exception as e:  # noqa: BLE001
                    pass

            return (port, info if info["banner"] or info["version"] else None)

        tasks = [grab_one(p) for p in open_ports]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for r in results:
            if isinstance(r, tuple) and r[1] is not None:
                banners[r[0]] = r[1]

        self.log(f"  Banners grabbed on {host}: {len(banners)} services identified")
        return banners

    async def _run_api_bruteforce(self, base_url: str) -> List[Dict]:
        """
        Kiterunner-style API endpoint brute-force.
        Sends GET to common API paths, records non-404 / non-redirect-to-homepage responses.
        """
        base_url = base_url.rstrip('/')
        found = []
        sem = asyncio.Semaphore(20)

        async def probe_path(session: aiohttp.ClientSession, path: str) -> Optional[Dict]:
            url = f"{base_url}{path}"
            async with sem:
                try:
                    async with session.get(
                        url,
                        timeout=aiohttp.ClientTimeout(total=2),
                        allow_redirects=False,
                        ssl=False
                    ) as resp:
                        status = resp.status

                        # Skip 404s
                        if status == 404:
                            return None

                        # Skip redirects to homepage (301/302 to /)
                        if status in (301, 302, 303, 307, 308):
                            location = resp.headers.get('Location', '')
                            # Redirect to root or main page — not interesting
                            if location in ('/', f'{base_url}/', base_url, ''):
                                return None

                        content_type = resp.headers.get('Content-Type', '')
                        body = await resp.read()
                        return {
                            "path": path,
                            "status_code": status,
                            "content_type": content_type.split(';')[0].strip(),
                            "size": len(body),
                        }
                except Exception as e:  # noqa: BLE001
                    return None

        self.log(f"  API brute-force: {len(self.COMMON_API_PATHS)} paths against {base_url}")

        async with aiohttp.ClientSession(
            connector=aiohttp.TCPConnector(ssl=False, limit=30),
            headers={"User-Agent": "Mozilla/5.0 (compatible; VIPER/2.0)"}
        ) as session:
            tasks = [probe_path(session, p) for p in self.COMMON_API_PATHS]
            results = await asyncio.gather(*tasks, return_exceptions=True)

        for r in results:
            if isinstance(r, dict):
                found.append(r)

        self.log(f"  API brute-force: {len(found)} endpoints found")
        return found

    # -------------------------------------------------------------------
    # Advanced Recon Sources
    # -------------------------------------------------------------------

    async def _run_advanced_recon(self, target: str, result: ReconResult):
        """Run all advanced recon sources in parallel."""
        tasks = {
            "whois": self._run_whois(target),
            "shodan": self._run_shodan(target),
            "urlscan": self._run_urlscan(target),
            "gau": self._run_gau(target),
        }

        # Wappalyzer needs HTML — grab from first live host
        first_host = next(iter(result.live_hosts), target)
        tasks["wappalyzer"] = self._run_wappalyzer_on_host(first_host)

        task_names = list(tasks.keys())
        coros = list(tasks.values())

        self.log(f"  Running {len(coros)} advanced sources in parallel: {', '.join(task_names)}")
        results = await asyncio.gather(*coros, return_exceptions=True)

        for name, res in zip(task_names, results):
            if isinstance(res, Exception):
                self.log(f"  {name} failed: {res}", "WARN")
                continue
            if name == "whois" and isinstance(res, dict):
                result.whois_info = res
                self.log(f"  whois: registrar={res.get('registrar', 'N/A')}")
            elif name == "shodan" and isinstance(res, dict):
                result.shodan_data = res
                self.log(f"  shodan: {len(res.get('ports', []))} ports, "
                         f"{len(res.get('vulns', []))} vulns")
            elif name == "urlscan" and isinstance(res, dict):
                result.urlscan_data = res
                # Merge any new subdomains
                for sub in res.get("subdomains", []):
                    result.subdomains.add(sub)
                self.log(f"  urlscan: {len(res.get('urls', []))} urls, "
                         f"{len(res.get('subdomains', []))} subdomains")
            elif name == "wappalyzer" and isinstance(res, list):
                result.wappalyzer_techs = res
                self.log(f"  wappalyzer: {len(res)} technologies detected")
            elif name == "gau" and isinstance(res, set):
                result.archived_urls = res
                self.log(f"  gau: {len(res)} archived URLs")

    async def _run_whois(self, domain: str) -> Dict:
        """WHOIS lookup via python-whois library."""
        if not WHOIS_AVAILABLE:
            self.log("  python-whois not available, skipping WHOIS", "WARN")
            return {}

        loop = asyncio.get_event_loop()
        try:
            w = await loop.run_in_executor(None, python_whois.whois, domain)
            info = {}
            for key in ("registrar", "creation_date", "expiration_date",
                        "name_servers", "status", "emails", "org",
                        "registrant", "country"):
                val = getattr(w, key, None) if hasattr(w, key) else w.get(key)
                if val is not None:
                    # Dates to string
                    if hasattr(val, "isoformat"):
                        val = val.isoformat()
                    elif isinstance(val, list):
                        val = [v.isoformat() if hasattr(v, "isoformat") else str(v)
                               for v in val]
                    else:
                        val = str(val)
                    info[key] = val
            return info
        except Exception as e:
            self.log(f"  WHOIS error: {e}", "WARN")
            return {}

    async def _run_shodan(self, domain: str) -> Dict:
        """Shodan lookup — uses API if SHODAN_API_KEY set, else InternetDB free fallback."""
        api_key = os.environ.get("SHODAN_API_KEY")

        # Resolve domain to IP for Shodan
        try:
            ip = socket.gethostbyname(domain)
        except socket.gaierror:
            return {}

        if api_key:
            return await self._shodan_api(ip, api_key)
        return await self._shodan_internetdb(ip)

    async def _shodan_api(self, ip: str, api_key: str) -> Dict:
        """Shodan paid API lookup."""
        url = f"https://api.shodan.io/shodan/host/{ip}?key={api_key}"
        try:
            async with aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=15)
            ) as session:
                async with session.get(url) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        return {
                            "ip": ip,
                            "ports": data.get("ports", []),
                            "vulns": data.get("vulns", []),
                            "hostnames": data.get("hostnames", []),
                            "os": data.get("os"),
                            "tags": data.get("tags", []),
                            "org": data.get("org"),
                            "isp": data.get("isp"),
                        }
        except Exception as e:
            self.log(f"  Shodan API error: {e}", "WARN")
        return {}

    async def _shodan_internetdb(self, ip: str) -> Dict:
        """Shodan InternetDB free fallback (no API key needed)."""
        url = f"https://internetdb.shodan.io/{ip}"
        try:
            async with aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=10)
            ) as session:
                async with session.get(url) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        return {
                            "ip": ip,
                            "ports": data.get("ports", []),
                            "vulns": data.get("vulns", []),
                            "hostnames": data.get("hostnames", []),
                            "cpes": data.get("cpes", []),
                            "tags": data.get("tags", []),
                            "source": "internetdb",
                        }
        except Exception as e:
            self.log(f"  InternetDB error: {e}", "WARN")
        return {}

    async def _run_urlscan(self, domain: str) -> Dict:
        """URLScan.io passive lookup (no auth needed)."""
        url = f"https://urlscan.io/api/v1/search/?q=domain:{domain}&size=100"
        try:
            async with aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=15)
            ) as session:
                async with session.get(url) as resp:
                    if resp.status != 200:
                        return {}
                    data = await resp.json()

            results = data.get("results", [])
            subdomains = set()
            ips = set()
            urls = set()
            technologies = set()

            for entry in results:
                page = entry.get("page", {})
                task = entry.get("task", {})

                page_domain = page.get("domain", "")
                if page_domain and (page_domain.endswith(f".{domain}")
                                    or page_domain == domain):
                    subdomains.add(page_domain)

                page_ip = page.get("ip", "")
                if page_ip:
                    ips.add(page_ip)

                page_url = task.get("url", "")
                if page_url:
                    urls.add(page_url)

                server = page.get("server", "")
                if server:
                    technologies.add(server)

            return {
                "subdomains": list(subdomains),
                "ips": list(ips),
                "urls": list(urls),
                "technologies": list(technologies),
            }
        except Exception as e:
            self.log(f"  URLScan error: {e}", "WARN")
            return {}

    async def _run_wappalyzer_on_host(self, host: str) -> List[Dict]:
        """Fetch a host's page and run Wappalyzer-style fingerprinting."""
        for scheme in ("https", "http"):
            url = f"{scheme}://{host}"
            try:
                async with aiohttp.ClientSession(
                    connector=aiohttp.TCPConnector(ssl=False),
                    timeout=aiohttp.ClientTimeout(total=15),
                ) as session:
                    async with session.get(url, allow_redirects=True) as resp:
                        html = await resp.text()
                        headers = dict(resp.headers)
                        return self._run_wappalyzer(url, html, headers)
            except (aiohttp.ClientError, asyncio.TimeoutError, ConnectionError) as e:
                logger.debug(f"Wappalyzer fetch failed for {url}: {e}")
                continue
            except Exception as e:
                logger.debug(f"Unexpected error during Wappalyzer fetch for {url}: {e}")
                continue
        return []

    def _run_wappalyzer(self, url: str, html: str, headers: Dict) -> List[Dict]:
        """Deep technology fingerprinting using pattern matching.

        Returns list of dicts: [{name, category, confidence, version}]
        """
        detected = []
        combined = f"{html} {json.dumps(headers)}"
        headers_lower = {k.lower(): v for k, v in headers.items()}

        for tech_name, patterns in WAPPALYZER_PATTERNS.items():
            confidence = 0
            version = None
            category = patterns.get("category", "Other")

            # Check headers
            for hdr_name, hdr_pattern in patterns.get("headers", {}).items():
                hdr_val = headers_lower.get(hdr_name.lower(), "")
                if hdr_val:
                    m = re.search(hdr_pattern, hdr_val, re.I)
                    if m:
                        confidence += 80
                        if m.lastindex:
                            version = m.group(1)

            # Check body patterns
            for body_pat in patterns.get("body", []):
                m = re.search(body_pat, html, re.I)
                if m:
                    confidence += 60
                    if m.lastindex and not version:
                        version = m.group(1)

            # Check meta tags
            for meta_pat in patterns.get("meta", []):
                m = re.search(meta_pat, html, re.I)
                if m:
                    confidence += 70
                    if m.lastindex and not version:
                        version = m.group(1)

            # Check script/link sources
            for src_pat in patterns.get("scripts", []):
                m = re.search(src_pat, html, re.I)
                if m:
                    confidence += 50
                    if m.lastindex and not version:
                        version = m.group(1)

            # Check cookies
            for cookie_name in patterns.get("cookies", []):
                set_cookie = headers_lower.get("set-cookie", "")
                if cookie_name.lower() in set_cookie.lower():
                    confidence += 70

            if confidence > 0:
                detected.append({
                    "name": tech_name,
                    "category": category,
                    "confidence": min(confidence, 100),
                    "version": version,
                })

        # Sort by confidence
        detected.sort(key=lambda x: x["confidence"], reverse=True)
        return detected

    async def _run_gau(self, domain: str) -> Set[str]:
        """Query Wayback Machine CDX API for archived URLs."""
        urls = set()
        cdx_url = (
            f"http://web.archive.org/cdx/search/cdx"
            f"?url=*.{domain}&output=json&fl=original"
            f"&collapse=urlkey&limit=500"
        )
        try:
            async with aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=30)
            ) as session:
                async with session.get(cdx_url) as resp:
                    if resp.status != 200:
                        return urls
                    data = await resp.json(content_type=None)

            # First row is the header ["original"]
            for row in data[1:] if len(data) > 1 else []:
                if row and isinstance(row, list) and row[0]:
                    urls.add(row[0])
        except Exception as e:
            self.log(f"  GAU/Wayback error: {e}", "WARN")
        return urls


# ---------------------------------------------------------------------------
# Wappalyzer-style pattern database (50+ technologies)
# ---------------------------------------------------------------------------

WAPPALYZER_PATTERNS: Dict[str, Dict] = {
    # Web Servers
    "Nginx": {
        "category": "Web Server",
        "headers": {"server": r"nginx(?:/([0-9.]+))?"},
        "body": [],
    },
    "Apache": {
        "category": "Web Server",
        "headers": {"server": r"Apache(?:/([0-9.]+))?"},
        "body": [],
    },
    "IIS": {
        "category": "Web Server",
        "headers": {"server": r"Microsoft-IIS(?:/([0-9.]+))?"},
        "body": [],
    },
    "LiteSpeed": {
        "category": "Web Server",
        "headers": {"server": r"LiteSpeed"},
        "body": [],
    },
    "Caddy": {
        "category": "Web Server",
        "headers": {"server": r"Caddy"},
        "body": [],
    },

    # Programming Languages
    "PHP": {
        "category": "Language",
        "headers": {"x-powered-by": r"PHP(?:/([0-9.]+))?"},
        "body": [r'\.php[\s"\'>?]'],
        "cookies": ["PHPSESSID"],
    },
    "ASP.NET": {
        "category": "Language",
        "headers": {"x-powered-by": r"ASP\.NET", "x-aspnet-version": r"([0-9.]+)"},
        "body": [r'__VIEWSTATE', r'__EVENTVALIDATION'],
        "cookies": ["ASP.NET_SessionId"],
    },
    "Java": {
        "category": "Language",
        "headers": {},
        "body": [r'\.jsp[\s"\'>?]', r'\.jsf[\s"\'>?]'],
        "cookies": ["JSESSIONID"],
    },
    "Python": {
        "category": "Language",
        "headers": {"x-powered-by": r"Python(?:/([0-9.]+))?"},
        "body": [],
    },
    "Ruby": {
        "category": "Language",
        "headers": {"x-powered-by": r"Phusion Passenger"},
        "body": [],
    },
    "Node.js": {
        "category": "Language",
        "headers": {"x-powered-by": r"Express"},
        "body": [],
    },

    # CMS
    "WordPress": {
        "category": "CMS",
        "headers": {},
        "body": [r'wp-content/', r'wp-includes/', r'wp-json/'],
        "meta": [r'<meta\s+name="generator"\s+content="WordPress\s*([0-9.]*)"'],
        "scripts": [r'wp-includes/js/'],
    },
    "Drupal": {
        "category": "CMS",
        "headers": {"x-drupal-cache": r".*", "x-generator": r"Drupal\s*([0-9.]*)"},
        "body": [r'sites/default/files', r'Drupal\.settings'],
        "meta": [r'<meta\s+name="generator"\s+content="Drupal\s*([0-9.]*)"'],
    },
    "Joomla": {
        "category": "CMS",
        "headers": {},
        "body": [r'/media/jui/', r'joomla'],
        "meta": [r'<meta\s+name="generator"\s+content="Joomla!\s*([0-9.]*)"'],
    },
    "Shopify": {
        "category": "CMS",
        "headers": {"x-shopify-stage": r".*"},
        "body": [r'cdn\.shopify\.com', r'Shopify\.theme'],
    },
    "Squarespace": {
        "category": "CMS",
        "headers": {},
        "body": [r'squarespace\.com', r'static\.squarespace\.com'],
        "meta": [r'<meta\s+name="generator"\s+content="Squarespace"'],
    },
    "Wix": {
        "category": "CMS",
        "headers": {},
        "body": [r'wix\.com', r'static\.wixstatic\.com'],
    },
    "Ghost": {
        "category": "CMS",
        "headers": {},
        "body": [r'ghost/'],
        "meta": [r'<meta\s+name="generator"\s+content="Ghost\s*([0-9.]*)"'],
    },

    # Frameworks
    "Laravel": {
        "category": "Framework",
        "headers": {},
        "body": [],
        "cookies": ["laravel_session", "XSRF-TOKEN"],
    },
    "Django": {
        "category": "Framework",
        "headers": {},
        "body": [r'csrfmiddlewaretoken', r'__admin_media_prefix__'],
        "cookies": ["csrftoken", "django_language"],
    },
    "Rails": {
        "category": "Framework",
        "headers": {"x-powered-by": r"Phusion Passenger"},
        "body": [r'csrf-token', r'data-turbolinks'],
        "cookies": ["_rails_"],
    },
    "Spring": {
        "category": "Framework",
        "headers": {},
        "body": [r'org\.springframework'],
        "cookies": ["JSESSIONID"],
    },
    "Flask": {
        "category": "Framework",
        "headers": {"server": r"Werkzeug(?:/([0-9.]+))?"},
        "body": [],
    },
    "FastAPI": {
        "category": "Framework",
        "headers": {},
        "body": [r'/docs', r'/openapi\.json'],
    },
    "Next.js": {
        "category": "Framework",
        "headers": {"x-powered-by": r"Next\.js"},
        "body": [r'_next/static', r'__NEXT_DATA__'],
    },
    "Nuxt.js": {
        "category": "Framework",
        "headers": {},
        "body": [r'_nuxt/', r'__NUXT__'],
    },

    # JavaScript Libraries
    "React": {
        "category": "JS Framework",
        "headers": {},
        "body": [r'react\.production\.min\.js', r'_reactRoot', r'data-reactroot'],
    },
    "Vue.js": {
        "category": "JS Framework",
        "headers": {},
        "body": [r'vue(?:\.min)?\.js', r'v-if=', r'v-for=', r':class='],
    },
    "Angular": {
        "category": "JS Framework",
        "headers": {},
        "body": [r'ng-app=', r'ng-controller=', r'angular(?:\.min)?\.js'],
    },
    "jQuery": {
        "category": "JS Library",
        "headers": {},
        "scripts": [r'jquery(?:\.min)?\.js(?:\?ver=([0-9.]+))?'],
        "body": [],
    },
    "Bootstrap": {
        "category": "CSS Framework",
        "headers": {},
        "scripts": [r'bootstrap(?:\.min)?\.(?:js|css)'],
        "body": [r'class="[^"]*\bcontainer\b[^"]*".*class="[^"]*\brow\b'],
    },
    "Tailwind CSS": {
        "category": "CSS Framework",
        "headers": {},
        "body": [r'class="[^"]*\b(?:flex|grid|bg-|text-|p-|m-)\b'],
    },

    # CDN / Infrastructure
    "Cloudflare": {
        "category": "CDN",
        "headers": {"server": r"cloudflare", "cf-ray": r".*"},
        "body": [],
        "cookies": ["__cflb", "__cfuid"],
    },
    "AWS CloudFront": {
        "category": "CDN",
        "headers": {"x-amz-cf-id": r".*", "via": r"CloudFront"},
        "body": [],
    },
    "Akamai": {
        "category": "CDN",
        "headers": {"x-akamai-transformed": r".*"},
        "body": [],
    },
    "Fastly": {
        "category": "CDN",
        "headers": {"x-served-by": r"cache-", "via": r"varnish"},
        "body": [],
    },
    "Varnish": {
        "category": "Cache",
        "headers": {"via": r"varnish", "x-varnish": r".*"},
        "body": [],
    },

    # Security
    "ModSecurity": {
        "category": "WAF",
        "headers": {"server": r"mod_security|ModSecurity(?:/([0-9.]+))?"},
        "body": [],
    },
    "Sucuri": {
        "category": "WAF",
        "headers": {"x-sucuri-id": r".*", "server": r"Sucuri"},
        "body": [],
    },
    "Imperva": {
        "category": "WAF",
        "headers": {},
        "body": [],
        "cookies": ["visid_incap_", "incap_ses_"],
    },

    # Analytics / Marketing
    "Google Analytics": {
        "category": "Analytics",
        "headers": {},
        "body": [r'google-analytics\.com/analytics\.js', r'gtag\(', r'UA-\d+-\d+'],
    },
    "Google Tag Manager": {
        "category": "Analytics",
        "headers": {},
        "body": [r'googletagmanager\.com/gtm\.js', r'GTM-[A-Z0-9]+'],
    },
    "Hotjar": {
        "category": "Analytics",
        "headers": {},
        "body": [r'static\.hotjar\.com'],
    },

    # Miscellaneous
    "GraphQL": {
        "category": "API",
        "headers": {},
        "body": [r'/graphql', r'graphql-ws', r'__schema'],
    },
    "Swagger/OpenAPI": {
        "category": "API",
        "headers": {},
        "body": [r'swagger-ui', r'openapi', r'/api-docs'],
    },
    "Elasticsearch": {
        "category": "Database",
        "headers": {},
        "body": [r'"cluster_name"', r'"tagline"\s*:\s*"You Know, for Search"'],
    },
    "Redis": {
        "category": "Database",
        "headers": {},
        "body": [],
    },
    "MongoDB": {
        "category": "Database",
        "headers": {},
        "body": [r'mongodb://'],
    },
    "Firebase": {
        "category": "Backend",
        "headers": {},
        "body": [r'firebaseapp\.com', r'firebase\.js', r'firebaseio\.com'],
    },
    "Webpack": {
        "category": "Build Tool",
        "headers": {},
        "body": [r'webpackJsonp', r'webpack-'],
    },
    "Vercel": {
        "category": "Hosting",
        "headers": {"x-vercel-id": r".*", "server": r"Vercel"},
        "body": [],
    },
    "Netlify": {
        "category": "Hosting",
        "headers": {"server": r"Netlify", "x-nf-request-id": r".*"},
        "body": [],
    },
    "Heroku": {
        "category": "Hosting",
        "headers": {"via": r"heroku"},
        "body": [],
    },
}


async def main():
    """CLI interface"""
    import sys
    
    if len(sys.argv) < 2:
        print("VIPER Recon Engine")
        print()
        print("Usage:")
        print("  python recon_engine.py <domain>         # Full recon")
        print("  python recon_engine.py <domain> --quick # Quick recon (no subdomain enum)")
        print("  python recon_engine.py --check          # Check available tools")
        return
    
    if sys.argv[1] == '--check':
        engine = ReconEngine()
        return
    
    target = sys.argv[1]
    quick = '--quick' in sys.argv
    
    engine = ReconEngine()
    result = await engine.full_recon(
        target,
        subdomain_enum=not quick,
        port_scan=True,
        tech_fingerprint=True,
        dns_enum=True
    )
    
    print(f"\n=== Recon Results for {target} ===")
    print(f"Subdomains: {len(result.subdomains)}")
    print(f"Live hosts: {len(result.live_hosts)}")
    print(f"Open ports: {sum(len(p) for p in result.open_ports.values())}")
    print(f"DNS records: {len(result.dns_records)}")


if __name__ == "__main__":
    asyncio.run(main())
