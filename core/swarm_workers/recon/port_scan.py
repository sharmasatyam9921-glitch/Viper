"""Port-scan worker — TCP connect scan on the top ~50 ports.

Wraps `recon.recon_engine.ReconEngine._python_port_scan` if available;
otherwise does its own asyncio TCP probe (no external deps).

Output:
    {"type": "open_port", "title": "443/tcp", "asset": "example.com",
     "url": "https://example.com:443", "severity": "info",
     "evidence": "TCP connect succeeded"}
"""

from __future__ import annotations

import asyncio
import logging
from typing import List
from urllib.parse import urlparse

from core.swarm_engine import SwarmAgent
from core.swarm_workers import register_worker

logger = logging.getLogger("viper.swarm_workers.recon.port_scan")

TECHNIQUE = "port_scan"

# Common targeted ports (cheap, covers >95% of bug-bounty surface).
# Includes ports commonly used by self-hosted dev/CTF targets.
DEFAULT_PORTS = [
    21, 22, 23, 25, 53, 80, 81, 88, 110, 111, 135, 139, 143, 161, 389, 443,
    445, 465, 587, 636, 993, 995, 1433, 1521, 2049, 2375, 2376, 3000, 3306,
    3389, 4444, 4567, 5000, 5001, 5432, 5601, 5672, 5900, 5985, 5986, 6379,
    7000, 7001, 7474, 8000, 8001, 8008, 8080, 8081, 8088, 8443, 8888, 9000,
    9001, 9090, 9100, 9200, 9300, 9418, 9999, 10000, 11211, 27017,
]


def _host(target: str) -> str:
    t = target.strip().lower()
    if "://" in t:
        return urlparse(t).hostname or ""
    return t.split(":", 1)[0]


async def _probe(host: str, port: int, timeout: float = 1.5) -> bool:
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=timeout,
        )
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        return True
    except (OSError, asyncio.TimeoutError):
        return False


async def run(agent: SwarmAgent) -> List[dict]:
    host = _host(agent.target)
    if not host:
        return []

    ports = (agent.payload or {}).get("ports") or DEFAULT_PORTS
    # Cap parallelism — too many concurrent SYNs trip IDS
    sem = asyncio.Semaphore(50)

    async def check(p: int) -> tuple[int, bool]:
        async with sem:
            return p, await _probe(host, p)

    results = await asyncio.gather(*(check(p) for p in ports))
    open_ports = [p for p, ok in results if ok]

    return [
        {
            "type": "open_port",
            "title": f"{p}/tcp",
            "asset": host,
            "port": p,
            "url": f"http{'s' if p in (443, 8443, 9443) else ''}://{host}:{p}"
                   if p in (80, 443, 8080, 8081, 8443, 8888, 9000, 9090, 3000, 9200)
                   else "",
            "severity": "info",
            "evidence": "TCP connect succeeded",
        }
        for p in open_ports
    ]


register_worker("recon", TECHNIQUE, run)
