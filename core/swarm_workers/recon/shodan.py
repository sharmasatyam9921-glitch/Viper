"""Shodan InternetDB worker — no API key required.

Uses the free `internetdb.shodan.io/<ip>` endpoint to fetch open ports
+ known CVEs for an IP. If target is a hostname, resolves it first.

Output:
    {"type": "shodan_intel", "title": "CVE-2021-44228", "asset": "1.2.3.4",
     "severity": "high", "evidence": "shodan reports this CVE on the host"}
"""

from __future__ import annotations

import asyncio
import json
import logging
import socket
from typing import List
from urllib.parse import urlparse

from core import tool_gateway as gateway
from core.swarm_engine import SwarmAgent
from core.swarm_workers import register_worker

logger = logging.getLogger("viper.swarm_workers.recon.shodan")

TECHNIQUE = "shodan"


def _resolve(target: str) -> list[str]:
    t = target.strip()
    if "://" in t:
        t = urlparse(t).hostname or ""
    t = t.split(":", 1)[0]
    try:
        # Single A-record fetch is enough for swarm work
        infos = socket.getaddrinfo(t, None, socket.AF_INET)
        return sorted({i[4][0] for i in infos})
    except Exception:
        return []


async def _internetdb(ip: str, *, timeout: float = 8.0) -> dict:
    # Shodan InternetDB is third-party OSINT infrastructure, not the target
    # → is_infra=True (exempt from the target scope check, still rate-limited).
    resp = await gateway.http(
        "GET", f"https://internetdb.shodan.io/{ip}",
        is_infra=True, timeout=timeout,
        headers={"User-Agent": "viper-swarm/1.0"},
    )
    if resp is None:  # scope-denied or network error
        return {}
    try:
        return json.loads(resp.body)
    except Exception as e:  # noqa: BLE001
        logger.debug("internetdb miss for %s: %s", ip, e)
        return {}


async def run(agent: SwarmAgent) -> List[dict]:
    ips = await asyncio.to_thread(_resolve, agent.target)
    if not ips:
        return []

    findings: list[dict] = []
    for ip in ips:
        data = await _internetdb(ip, timeout=min(agent.timeout_s, 8.0))
        if not data:
            continue
        for cve in data.get("vulns", []) or []:
            findings.append({
                "type": "shodan_cve",
                "title": cve,
                "asset": ip,
                "severity": "high",
                "evidence": f"shodan internetdb reports {cve} on {ip}",
                "cve": cve,
            })
        for port in data.get("ports", []) or []:
            findings.append({
                "type": "shodan_port",
                "title": f"{port}/tcp",
                "asset": ip,
                "port": port,
                "severity": "info",
                "evidence": "shodan internetdb",
            })
        for tag in data.get("tags", []) or []:
            findings.append({
                "type": "shodan_tag",
                "title": tag,
                "asset": ip,
                "severity": "info",
                "evidence": f"shodan tag: {tag}",
            })
    return findings


register_worker("recon", TECHNIQUE, run)
