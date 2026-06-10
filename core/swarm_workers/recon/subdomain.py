"""Subdomain enumeration worker.

Tries the existing `recon.recon_engine.ReconEngine.enumerate_subdomains`
(which fans out subfinder + amass + crt.sh + hackertarget internally).
If unavailable, falls back to a quick python crt.sh query.

Output finding shape:
    {"type": "subdomain", "title": "api.example.com",
     "url": "https://api.example.com", "severity": "info",
     "evidence": "found via <source>"}
"""

from __future__ import annotations

import json
import logging
import urllib.parse
from typing import List
from urllib.parse import urlparse

from core import tool_gateway as gateway
from core.swarm_engine import SwarmAgent
from core.swarm_workers import register_worker

logger = logging.getLogger("viper.swarm_workers.recon.subdomain")

TECHNIQUE = "subdomain"


def _domain_from_target(target: str) -> str:
    t = target.strip().lower()
    if "://" in t:
        t = urlparse(t).netloc
    return t.split(":", 1)[0].rstrip(".")


async def _crtsh_query(domain: str, *, timeout: float = 15.0) -> set[str]:
    """Cheap HTTPS query to crt.sh — works without API keys."""
    url = f"https://crt.sh/?q=%25.{urllib.parse.quote(domain)}&output=json"
    # crt.sh is third-party OSINT infrastructure, not the target → is_infra=True.
    resp = await gateway.http(
        "GET", url, is_infra=True, timeout=timeout,
        headers={"User-Agent": "viper-swarm/1.0"},
    )
    if resp is None:  # scope-denied or network error
        return set()
    try:
        rows = json.loads(resp.body)
    except Exception as e:  # noqa: BLE001
        logger.debug("crt.sh query failed for %s: %s", domain, e)
        return set()
    out: set[str] = set()
    for row in rows:
        name = (row.get("name_value") or "").strip().lower()
        for line in name.split("\n"):
            line = line.strip(" \t.")
            if not line or "*" in line:
                continue
            if line.endswith(domain):
                out.add(line)
    return out


async def run(agent: SwarmAgent) -> List[dict]:
    domain = _domain_from_target(agent.target)
    if not domain:
        return []

    payload = agent.payload or {}
    scope = payload.get("scope_reasoner")

    found: set[str] = set()

    # Path A — try the existing ReconEngine (will use subfinder/amass if installed)
    try:
        from recon.recon_engine import ReconEngine
        eng = ReconEngine(verbose=False)
        subs = await eng.enumerate_subdomains(domain, parallel=True)
        for s in subs:
            s = s.strip().lower().rstrip(".")
            if s.endswith(domain):
                found.add(s)
    except Exception as e:  # noqa: BLE001
        logger.debug("ReconEngine.enumerate_subdomains failed: %s", e)

    # Path B — direct crt.sh fallback (always cheap)
    if not found:
        found = await _crtsh_query(domain, timeout=min(agent.timeout_s, 20.0))

    # Filter to in-scope, if a scope reasoner was provided
    if scope is not None:
        try:
            found = {s for s in found if scope.decide(s).allowed}
        except Exception:
            pass

    return [
        {
            "type": "subdomain",
            "title": s,
            "url": f"https://{s}",
            "severity": "info",
            "evidence": f"discovered via {TECHNIQUE}",
            "asset": s,
        }
        for s in sorted(found)
    ]


register_worker("recon", TECHNIQUE, run)
