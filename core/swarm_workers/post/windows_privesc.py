"""Windows privesc recommendation worker (post-foothold).

Stub that wraps the operator's existing tooling — winPEAS auto-deploy
needs a session set up by the operator. We surface the next-step
finding so the dashboard shows what's possible.
"""

from __future__ import annotations

import logging
from typing import List

from core.swarm_engine import SwarmAgent
from core.swarm_workers import register_worker

logger = logging.getLogger("viper.swarm_workers.post.windows_privesc")

TECHNIQUE = "windows_privesc"


async def run(agent: SwarmAgent) -> List[dict]:
    findings = (agent.payload or {}).get("findings") or []
    win_foothold = next(
        (f for f in findings if f.get("foothold") and "windows" in (
            (f.get("evidence", "") + f.get("title", "")).lower()
        )), None,
    )
    if not win_foothold:
        return []
    return [{
        "type": "post_recommend",
        "vuln_type": "windows_privesc_recommend",
        "title": "Windows privesc enumeration recommended",
        "severity": "info",
        "url": win_foothold.get("url"),
        "evidence": (
            f"Windows foothold at {win_foothold.get('url')}. "
            "Deploy winPEAS via tools/winpeas_runner.py."
        ),
        "next_action": "tools.winpeas_runner.run_via_smb / winrm",
    }]


register_worker("post", TECHNIQUE, run)
