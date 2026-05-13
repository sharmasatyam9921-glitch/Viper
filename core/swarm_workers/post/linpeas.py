"""Linux privesc worker (post-foothold).

Wraps the existing `agents.post_exploit.PostExploitAgent` analyzers
(`analyze_linux_foothold` etc.). Stub-mode: returns empty findings if
no foothold context is available — the coordinator gates this worker
behind approval, so this code path only runs when the operator has
explicitly authorized it.
"""

from __future__ import annotations

import logging
from typing import List

from core.swarm_engine import SwarmAgent
from core.swarm_workers import register_worker

logger = logging.getLogger("viper.swarm_workers.post.linpeas")

TECHNIQUE = "linpeas"


async def run(agent: SwarmAgent) -> List[dict]:
    """Stub — real linpeas deployment lives in tools/linpeas_runner.py
    and requires an SSH session set up by the operator. Here we just
    surface a finding telling the operator how to escalate further."""
    payload = agent.payload or {}
    findings = payload.get("findings") or []
    foothold = next((f for f in findings if f.get("foothold")), None)
    if not foothold:
        return []

    return [{
        "type": "post_recommend",
        "vuln_type": "linux_privesc_recommend",
        "title": "Linux privesc enumeration recommended",
        "severity": "info",
        "url": foothold.get("url"),
        "evidence": (
            "Foothold confirmed at "
            f"{foothold.get('url')}. Drop linpeas via the existing "
            "tools/linpeas_runner.py to enumerate sudo/SUID/cap/kernel."
        ),
        "next_action": "tools.linpeas_runner.run_via_ssh(host, user, password)",
    }]


register_worker("post", TECHNIQUE, run)
