"""GTFOBins / SUID-binary escalation suggestion worker.

Cross-references `pentest.gtfobins_db` against any `sudo_binary` or
`suid_binary` findings already in scope, and emits the cheapest
escalation one-liner per known binary.
"""

from __future__ import annotations

import logging
from typing import List

from core.swarm_engine import SwarmAgent
from core.swarm_workers import register_worker

logger = logging.getLogger("viper.swarm_workers.post.gtfobins")

TECHNIQUE = "gtfobins"


async def run(agent: SwarmAgent) -> List[dict]:
    findings = (agent.payload or {}).get("findings") or []
    sudo_binaries: list[str] = []
    suid_binaries: list[str] = []
    for f in findings:
        t = (f.get("type") or "").lower()
        if t == "sudo_binary":
            sudo_binaries.append(f.get("binary") or f.get("title") or "")
        elif t == "suid_binary":
            suid_binaries.append(f.get("binary") or f.get("title") or "")
    if not (sudo_binaries or suid_binaries):
        return []

    try:
        from pentest import gtfobins_db
    except Exception as e:  # noqa: BLE001
        logger.debug("gtfobins_db unavailable: %s", e)
        return []

    out: list[dict] = []
    for binary in set(sudo_binaries):
        vectors = gtfobins_db.lookup(binary)
        if "sudo" in vectors:
            out.append({
                "type": "post_recommend",
                "vuln_type": f"gtfobins_sudo:{binary}",
                "title": f"GTFOBins sudo escalation: {binary}",
                "severity": "high",
                "evidence": vectors["sudo"],
                "next_action": f"Run: {vectors['sudo']}",
            })
    for binary in set(suid_binaries):
        if binary in gtfobins_db.known_safe_suids():
            continue
        vectors = gtfobins_db.lookup(binary)
        if "suid" in vectors:
            out.append({
                "type": "post_recommend",
                "vuln_type": f"gtfobins_suid:{binary}",
                "title": f"GTFOBins SUID escalation: {binary}",
                "severity": "high",
                "evidence": vectors["suid"],
                "next_action": f"Run: {vectors['suid']}",
            })
    return out


register_worker("post", TECHNIQUE, run)
