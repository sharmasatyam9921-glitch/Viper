"""Two-account BOLA / IDOR worker (specialist, opt-in).

Wraps core.specialist.bola_engine into the swarm. It is SELF-GATED: it does
nothing unless an operator supplies two authenticated identities via
``agent.payload["bola"]`` — because cross-user authorization testing requires
two accounts you control (the bug-bounty norm), it is never an unattended scan.

Config shape (agent.payload["bola"]):
    {
      "owner_headers":    {"Cookie": "session=A..."},   # victim identity A
      "owner_markers":    ["alice@victim.io", "1001"],  # A's private identifiers
      "attacker_headers": {"Cookie": "session=B..."},   # second identity B
    }

The coordinator dispatches this per discovered object URL (id-bearing asset);
for each, it checks whether identity B can read identity A's private data.
Read-only (GET).
"""

from __future__ import annotations

import logging
from typing import List

from core.swarm_engine import SwarmAgent
from core.swarm_workers import register_worker

from ._http import fetch, normalize_target_url

logger = logging.getLogger("viper.swarm_workers.vuln.bola_multi")

TECHNIQUE = "bola_multi"


async def run(agent: SwarmAgent) -> List[dict]:
    cfg = (agent.payload or {}).get("bola")
    # Opt-in only: no two-session config -> do nothing.
    if not isinstance(cfg, dict) or not cfg.get("owner_headers") \
            or not cfg.get("attacker_headers") or not cfg.get("owner_markers"):
        return []

    url = normalize_target_url(agent.target)
    if not url:
        return []

    from core.specialist.bola_engine import Session, find_bola

    owner = Session(cfg.get("owner_name", "A"),
                    cfg["owner_headers"], cfg["owner_markers"])
    attacker = Session(cfg.get("attacker_name", "B"),
                       cfg["attacker_headers"],
                       cfg.get("attacker_markers", []))
    timeout = min(agent.timeout_s, 10.0)

    async def _fetch(method, u, *, headers=None, timeout=timeout):
        return await fetch(method, u, headers=headers, timeout=timeout)

    return await find_bola(owner, attacker, [url], fetch=_fetch,
                           timeout=timeout,
                           unauth_control=cfg.get("unauth_control", True))


register_worker("vuln", TECHNIQUE, run)
