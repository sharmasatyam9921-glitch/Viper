#!/usr/bin/env python3
"""
VIPER 4.0 Tool Registry

Single source of truth for tool metadata used by dynamic prompt builders.
Dict insertion order defines tool priority (first = highest).

VIPER's pure-Python tool ecosystem.
"""

TOOL_DESCRIPTIONS = {
    "web_search": (
        "**web_search** (Passive OSINT -- external research)\n"
        "   - Search the internet for CVE details, exploit PoCs, advisories, version-specific vulns\n"
        "   - Use for context not available locally"
    ),
    "graph_query": (
        "**graph_query** (Knowledge Graph -- start here)\n"
        "   - Query the VIPER knowledge graph for recon data, findings, and relationships\n"
        "   - Nodes: Domains, Subdomains, IPs, Ports, Services, URLs, Technologies,\n"
        "     Vulnerabilities, CVEs, CWEs, Endpoints, Parameters, Certificates, Headers\n"
        "   - Always check graph data before making network requests"
    ),
    "nuclei_scan": (
        "**nuclei_scan** (CVE verification & exploitation)\n"
        "   - 8000+ YAML templates -- verify and exploit CVEs in one step\n"
        "   - Examples: -u URL -id CVE-2021-41773 -jsonl | -u URL -tags cve,rce -severity critical -jsonl"
    ),
    "curl_request": (
        "**curl_request** (HTTP requests)\n"
        "   - Make HTTP requests for reachability checks, headers, status codes\n"
        "   - Key flags: --path-as-is (path traversal), --data-urlencode (encoding),\n"
        "     -X POST -d (POST body), -H (headers), -b (cookies)"
    ),
    "port_scan": (
        "**port_scan** (Fast port scanning)\n"
        "   - Verify open ports or scan targets not yet in graph\n"
        "   - Example: -host 10.0.0.5 -p 80,443,8080 -json"
    ),
    "nmap_scan": (
        "**nmap_scan** (Deep network scanning)\n"
        "   - Version detection (-sV), OS fingerprint (-O), NSE scripts (-sC/--script)\n"
        "   - Slower than port_scan but far more detailed"
    ),
    "shell_exec": (
        "**shell_exec** (Shell command execution)\n"
        "   - Execute shell commands on the attack platform\n"
        "   - Full toolset: netcat, socat, msfvenom, searchsploit, sqlmap,\n"
        "     john, smbclient, sshpass, wget, gcc, perl, hping3, slowhttptest\n"
        "   - Python libs: requests, beautifulsoup4, pycryptodome, paramiko, impacket, pwntools\n"
        "   - For multi-line scripts use code_exec instead (avoids shell escaping)"
    ),
    "code_exec": (
        "**code_exec** (Code execution -- no shell escaping)\n"
        "   - Write and run code files with appropriate interpreter\n"
        "   - Languages: python (default), bash, ruby, perl, c, cpp\n"
        "   - Python libs available: requests, beautifulsoup4, pycryptodome, paramiko, impacket\n"
        "   - Use for multi-line exploit scripts"
    ),
    "hydra_attack": (
        "**hydra_attack** (THC Hydra -- brute force)\n"
        "   - 50+ protocols: ssh, ftp, rdp, smb, vnc, mysql, mssql, postgres, redis, http-post-form\n"
        "   - Key flags: -l/-L user(s), -p/-P pass(es), -C combo file,\n"
        "     -e nsr (null/login-as-pass/reverse), -t threads, -f stop on first hit\n"
        "   - Syntax: [flags] protocol://target[:port]"
    ),
    "metasploit": (
        "**metasploit** (Exploitation framework)\n"
        "   - Persistent msfconsole -- module context and sessions survive between calls\n"
        "   - Chain commands with semicolons (;). Do NOT use && or ||\n"
        "   - Search modules: search CVE-XXXX or search type:exploit platform:linux"
    ),
    "sqlmap_scan": (
        "**sqlmap_scan** (SQL injection automation)\n"
        "   - Automated SQL injection detection and exploitation\n"
        "   - Syntax: -u URL --forms --batch --level 3 --risk 2"
    ),
    "shodan_lookup": (
        "**shodan_lookup** (Internet-wide OSINT)\n"
        "   - Search exposed IPs, get host details, reverse DNS\n"
        "   - Actions: search, host, dns_reverse, dns_domain, count"
    ),
    "google_dork": (
        "**google_dork** (Passive OSINT via Google)\n"
        "   - Google advanced search -- no packets to target\n"
        "   - Operators: site:, inurl:, intitle:, filetype:, intext:, ext:"
    ),
}


def get_tool_description(tool_name: str) -> str:
    """Get the description for a specific tool."""
    return TOOL_DESCRIPTIONS.get(tool_name, f"**{tool_name}** (No description available)")


def get_all_tool_descriptions(tool_names: list = None) -> str:
    """Get formatted descriptions for a list of tools (or all tools if None)."""
    if tool_names is None:
        tool_names = list(TOOL_DESCRIPTIONS.keys())

    parts = []
    for name in tool_names:
        if name in TOOL_DESCRIPTIONS:
            parts.append(f"- {TOOL_DESCRIPTIONS[name]}")

    return "\n".join(parts)


def get_tools_for_phase(phase: str) -> list:
    """Get recommended tools for a given phase.

    Returns list of tool names appropriate for the phase.
    """
    _PHASE_TOOLS = {
        "informational": [
            "graph_query", "web_search", "shodan_lookup", "google_dork",
            "port_scan", "nmap_scan", "nuclei_scan", "curl_request", "shell_exec",
        ],
        "exploitation": [
            "graph_query", "web_search", "curl_request", "nuclei_scan",
            "nmap_scan", "shell_exec", "code_exec", "hydra_attack",
            "metasploit", "sqlmap_scan",
        ],
        "post_exploitation": [
            "graph_query", "web_search", "curl_request", "nmap_scan",
            "shell_exec", "code_exec", "metasploit",
        ],
    }
    return _PHASE_TOOLS.get(phase, list(TOOL_DESCRIPTIONS.keys()))
