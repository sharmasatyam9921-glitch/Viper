"""Recon-phase swarm workers.

Each module in this package registers one worker with the parent
`core.swarm_workers` registry. Importing this package pulls them all in.

Workers:
    subdomain        — passive subdomain enumeration (crt.sh + subfinder)
    port_scan        — TCP/UDP port scan via existing `tools/nmap_scanner.py` or naabu
    wappalyzer       — technology fingerprinting on HTTP responses
    shodan           — Shodan InternetDB lookup (no API key required)
    crtsh            — certificate-transparency lookups (HTTPS to crt.sh)
    github_secrets   — org-wide GitHub secret hunting (existing recon module)
    wayback          — Wayback Machine URL mining (existing module)
    dns              — DNS record enumeration (A, AAAA, MX, TXT, NS, CAA)

A worker is just a coroutine ``async def run(agent: SwarmAgent) -> List[dict]``
that yields finding dicts. The dicts follow this shape (all keys optional):

    {
        "type": "subdomain",
        "title": "example.com",
        "url": "https://example.com",
        "severity": "info",
        "evidence": "...",
        "confidence": 0.9,
    }
"""

from __future__ import annotations

# Import each worker module so it self-registers.
from . import (  # noqa: F401
    crtsh,
    dns,
    endpoints,
    github_secrets,
    openapi,
    port_scan,
    shodan,
    subdomain,
    wappalyzer,
    wayback,
)

__all__ = [
    "crtsh", "dns", "endpoints", "github_secrets", "openapi", "port_scan",
    "shodan", "subdomain", "wappalyzer", "wayback",
]
