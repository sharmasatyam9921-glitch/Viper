"""Wayback Machine URL mining worker.

Pulls historical URLs from web.archive.org for the target. Useful for
finding forgotten endpoints, parameters, and exposed admin paths.
"""

from __future__ import annotations

import ipaddress
import json
import logging
import urllib.parse
from typing import List
from urllib.parse import urlparse

from core import tool_gateway as gateway
from core.swarm_engine import SwarmAgent
from core.swarm_workers import register_worker

logger = logging.getLogger("viper.swarm_workers.recon.wayback")

TECHNIQUE = "wayback"


def _domain(target: str) -> str:
    t = target.strip().lower()
    if "://" in t:
        t = urlparse(t).netloc
    return t.split(":", 1)[0].rstrip(".")


def _is_public_host(host: str) -> bool:
    """Public web archives index the internet, so querying them for a
    loopback/private/intranet target returns only internet-wide noise
    (everyone's archived '127.0.0.1' URLs). Treat those as non-public."""
    h = host.strip().lower()
    if h in ("", "localhost"):
        return False
    try:
        return ipaddress.ip_address(h).is_global  # private/loopback -> False
    except ValueError:
        # Hostname, not an IP. Single-label or *.local/.internal = intranet.
        return "." in h and not h.endswith((".local", ".internal", ".localhost"))


async def _wayback_urls(domain: str, *, limit: int = 500, timeout: float = 15.0) -> list[str]:
    """Hit the CDX API. Returns deduplicated URLs."""
    url = (
        f"https://web.archive.org/cdx/search/cdx?"
        f"url={urllib.parse.quote(f'*.{domain}/*')}"
        f"&output=json&fl=original&collapse=urlkey&limit={limit}"
    )
    # web.archive.org is third-party OSINT infrastructure, not the target.
    resp = await gateway.http(
        "GET", url, is_infra=True, timeout=timeout,
        headers={"User-Agent": "viper-swarm/1.0"},
    )
    if resp is None:  # scope-denied or network error
        return []
    try:
        data = json.loads(resp.body)
    except Exception as e:  # noqa: BLE001
        logger.debug("wayback CDX parse failed for %s: %s", domain, e)
        return []
    if not data or len(data) < 2:
        return []
    # First row is column headers
    return sorted({row[0] for row in data[1:] if row})


_INTERESTING = (
    "/admin", "/login", "/api", "/swagger", "/openapi", "/.git",
    "/.env", "/backup", "/dump", "/console", "/internal", "/debug",
    "/setup", "/install", "/phpinfo", "/test", "/old",
)


async def run(agent: SwarmAgent) -> List[dict]:
    domain = _domain(agent.target)
    if not domain or not _is_public_host(domain):
        # Loopback/private/intranet target → the archive only has noise.
        return []

    urls = await _wayback_urls(
        domain, limit=500, timeout=min(agent.timeout_s, 20.0),
    )

    # Only surface the genuinely interesting historical paths (forgotten admin
    # / api / .git / backup endpoints) as findings. Emitting all 500 raw URLs
    # floods the findings stream AND turns each into a vuln-probe asset, which
    # starves the actual app-logic testing. Cap to keep the signal tight.
    findings: list[dict] = []
    for u in urls:
        if not any(seg in u.lower() for seg in _INTERESTING):
            continue
        findings.append({
            "type": "historical_url",
            "title": u,
            "url": u,
            "severity": "low",
            "evidence": "wayback machine archive (interesting path)",
        })
        if len(findings) >= 100:
            break
    return findings


register_worker("recon", TECHNIQUE, run)
