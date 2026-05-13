"""Active Directory enumeration recommendation worker.

Detects AD-indicator findings (LDAP port open, Kerberos, SMB) and
suggests the operator drop the existing `pentest.ad_enum` orchestrator.
"""

from __future__ import annotations

import logging
from typing import List

from core.swarm_engine import SwarmAgent
from core.swarm_workers import register_worker

logger = logging.getLogger("viper.swarm_workers.post.ad_enum")

TECHNIQUE = "ad_enum"

_AD_PORTS = {88, 389, 445, 464, 636, 3268, 3269, 9389}


async def run(agent: SwarmAgent) -> List[dict]:
    findings = (agent.payload or {}).get("findings") or []
    ad_hosts: set[str] = set()
    for f in findings:
        if f.get("type") == "open_port":
            try:
                port = int(f.get("port") or 0)
            except (TypeError, ValueError):
                continue
            if port in _AD_PORTS:
                host = f.get("asset")
                if host:
                    ad_hosts.add(host)
    if not ad_hosts:
        return []
    return [
        {
            "type": "post_recommend",
            "vuln_type": f"ad_enum_recommend:{h}",
            "title": f"AD environment detected on {h}",
            "severity": "medium",
            "url": h,
            "evidence": (
                f"AD-typical ports open on {h}. Run pentest.ad_enum.enumerate_ad() "
                "to fingerprint domain, find ASREP-roastable users, and check "
                "SMB signing."
            ),
            "next_action": f"pentest.ad_enum.enumerate_ad('{h}')",
        }
        for h in sorted(ad_hosts)
    ]


register_worker("post", TECHNIQUE, run)
