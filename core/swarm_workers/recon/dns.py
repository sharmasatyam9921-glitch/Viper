"""DNS record enumeration worker.

Queries A, AAAA, MX, TXT, NS, CNAME, SOA, CAA for the target. Uses
stdlib `socket.getaddrinfo` for A/AAAA and `dns.resolver` (dnspython)
for the rest if installed. Falls back to skipping unsupported types.
"""

from __future__ import annotations

import asyncio
import logging
import socket
from typing import List
from urllib.parse import urlparse

from core.swarm_engine import SwarmAgent
from core.swarm_workers import register_worker

logger = logging.getLogger("viper.swarm_workers.recon.dns")

TECHNIQUE = "dns"


def _domain(target: str) -> str:
    t = target.strip().lower()
    if "://" in t:
        t = urlparse(t).netloc
    return t.split(":", 1)[0].rstrip(".")


def _resolve_basic(domain: str) -> tuple[list[str], list[str]]:
    """A + AAAA via getaddrinfo. Returns (ipv4, ipv6)."""
    ipv4: set[str] = set()
    ipv6: set[str] = set()
    try:
        for info in socket.getaddrinfo(domain, None):
            family, _, _, _, sockaddr = info
            ip = sockaddr[0]
            if family == socket.AF_INET:
                ipv4.add(ip)
            elif family == socket.AF_INET6:
                ipv6.add(ip)
    except Exception:
        pass
    return sorted(ipv4), sorted(ipv6)


def _dnspython_records(domain: str) -> dict[str, list[str]]:
    """Try dnspython for MX/TXT/NS/CNAME/SOA/CAA. Empty if not installed."""
    try:
        import dns.resolver  # type: ignore
    except Exception:
        return {}
    out: dict[str, list[str]] = {}
    for rtype in ("MX", "TXT", "NS", "CNAME", "SOA", "CAA"):
        try:
            answers = dns.resolver.resolve(domain, rtype, lifetime=4.0)
            out[rtype] = [str(r) for r in answers]
        except Exception:
            continue
    return out


async def run(agent: SwarmAgent) -> List[dict]:
    domain = _domain(agent.target)
    if not domain:
        return []

    ipv4, ipv6 = await asyncio.to_thread(_resolve_basic, domain)
    extra = await asyncio.to_thread(_dnspython_records, domain)

    findings: list[dict] = []
    for ip in ipv4:
        findings.append({
            "type": "dns_a", "title": ip, "asset": domain,
            "severity": "info", "evidence": "DNS A record",
        })
    for ip in ipv6:
        findings.append({
            "type": "dns_aaaa", "title": ip, "asset": domain,
            "severity": "info", "evidence": "DNS AAAA record",
        })
    for rtype, values in extra.items():
        for v in values:
            findings.append({
                "type": f"dns_{rtype.lower()}",
                "title": v, "asset": domain,
                "severity": "info", "evidence": f"DNS {rtype} record",
            })
    return findings


register_worker("recon", TECHNIQUE, run)
