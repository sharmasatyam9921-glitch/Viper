"""Certificate-transparency lookup (crt.sh).

Lighter-weight than `subdomain.py` — only crt.sh, no subfinder/amass.
Useful when you want fast results or when subfinder isn't installed.
"""

from __future__ import annotations

import asyncio
import logging
from typing import List
from urllib.parse import urlparse

from core.swarm_engine import SwarmAgent
from core.swarm_workers import register_worker
from core.swarm_workers.recon.subdomain import _crtsh_query

logger = logging.getLogger("viper.swarm_workers.recon.crtsh")

TECHNIQUE = "crtsh"


def _domain(target: str) -> str:
    t = target.strip().lower()
    if "://" in t:
        t = urlparse(t).netloc
    return t.split(":", 1)[0].rstrip(".")


async def run(agent: SwarmAgent) -> List[dict]:
    domain = _domain(agent.target)
    if not domain:
        return []

    subs = await _crtsh_query(domain, timeout=min(agent.timeout_s, 20.0))

    payload = agent.payload or {}
    scope = payload.get("scope_reasoner")
    if scope is not None:
        subs = {s for s in subs if scope.decide(s).allowed}

    return [
        {
            "type": "subdomain",
            "title": s,
            "url": f"https://{s}",
            "severity": "info",
            "evidence": "crt.sh certificate transparency",
            "asset": s,
        }
        for s in sorted(subs)
    ]


register_worker("recon", TECHNIQUE, run)
