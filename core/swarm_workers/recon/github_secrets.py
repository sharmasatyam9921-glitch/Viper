"""GitHub-secrets worker.

Looks for the target's org/keyword across public GitHub for committed
credentials. Wraps the existing `recon.github_hunt` /
`recon.github_secrets` modules when available; otherwise no-op
(returns []) — this worker only does useful work when a GH_TOKEN is set.
"""

from __future__ import annotations

import asyncio
import logging
import os
from typing import List
from urllib.parse import urlparse

from core.swarm_engine import SwarmAgent
from core.swarm_workers import register_worker

logger = logging.getLogger("viper.swarm_workers.recon.github_secrets")

TECHNIQUE = "github_secrets"


def _keyword(target: str) -> str:
    """Derive a search keyword from the target domain (e.g. 'example' for
    'example.com')."""
    t = target.strip().lower()
    if "://" in t:
        t = urlparse(t).netloc
    t = t.split(":", 1)[0].split(".", 1)[0]
    return t.strip()


async def run(agent: SwarmAgent) -> List[dict]:
    keyword = _keyword(agent.target)
    if not keyword:
        return []

    if not os.environ.get("GH_TOKEN") and not os.environ.get("GITHUB_TOKEN"):
        # Without a token GitHub heavily rate-limits — skip rather than spam.
        return []

    try:
        from recon.github_hunt import run_github_hunt_async  # type: ignore
        results = await asyncio.wait_for(
            run_github_hunt_async(org_or_keyword=keyword),
            timeout=min(agent.timeout_s, 30.0),
        )
    except Exception as e:  # noqa: BLE001
        logger.debug("github_hunt unavailable: %s", e)
        return []

    findings: list[dict] = []
    for hit in (results or [])[:50]:
        findings.append({
            "type": "github_secret",
            "title": hit.get("name") or hit.get("file") or "leaked secret",
            "severity": hit.get("severity", "medium"),
            "evidence": hit.get("snippet") or hit.get("url") or "",
            "url": hit.get("url"),
        })
    return findings


register_worker("recon", TECHNIQUE, run)
