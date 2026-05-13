"""Wayback Machine URL mining worker.

Pulls historical URLs from web.archive.org for the target. Useful for
finding forgotten endpoints, parameters, and exposed admin paths.
"""

from __future__ import annotations

import asyncio
import json
import logging
import urllib.parse
import urllib.request
from typing import List
from urllib.parse import urlparse

from core.swarm_engine import SwarmAgent
from core.swarm_workers import register_worker

logger = logging.getLogger("viper.swarm_workers.recon.wayback")

TECHNIQUE = "wayback"


def _domain(target: str) -> str:
    t = target.strip().lower()
    if "://" in t:
        t = urlparse(t).netloc
    return t.split(":", 1)[0].rstrip(".")


def _wayback_urls(domain: str, *, limit: int = 500, timeout: float = 15.0) -> list[str]:
    """Hit the CDX API. Returns deduplicated URLs."""
    url = (
        f"https://web.archive.org/cdx/search/cdx?"
        f"url={urllib.parse.quote(f'*.{domain}/*')}"
        f"&output=json&fl=original&collapse=urlkey&limit={limit}"
    )
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "viper-swarm/1.0"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            data = json.loads(r.read().decode("utf-8", errors="replace"))
    except Exception as e:  # noqa: BLE001
        logger.debug("wayback CDX query failed for %s: %s", domain, e)
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
    if not domain:
        return []

    urls = await asyncio.to_thread(
        _wayback_urls, domain, limit=500, timeout=min(agent.timeout_s, 20.0),
    )

    findings: list[dict] = []
    for u in urls[:500]:
        # Highlight obviously interesting paths with higher severity
        is_interesting = any(seg in u.lower() for seg in _INTERESTING)
        findings.append({
            "type": "historical_url",
            "title": u,
            "url": u,
            "severity": "low" if is_interesting else "info",
            "evidence": "wayback machine archive",
        })
    return findings


register_worker("recon", TECHNIQUE, run)
