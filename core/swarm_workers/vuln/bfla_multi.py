"""Two-account Broken Function-Level Authorization (BFLA) worker (opt-in).

Wraps core.specialist.bfla_engine into the swarm. SELF-GATED: does nothing unless
an operator supplies two identities via ``agent.payload["bfla"]`` — a privileged
one and a low-privilege one — because confirming role bypass needs two accounts
you control (the bug-bounty norm).

Config shape (agent.payload["bfla"]):
    {
      "privileged_headers": {"Cookie": "session=ADMIN..."},   # high-priv identity
      "low_headers":        {"Cookie": "session=USER..."},    # low-priv identity
      "candidate_urls":     ["https://t/api/admin/users", ...] (optional; else the
                            agent target is tested),
      "admin_only":         true,   # only flag admin-shaped paths (default)
    }

Read-only (GET). The privileged role's reachable URLs (e.g. from a SessionContext
reachability matrix) make the best candidate list.
"""
from __future__ import annotations

import logging
from typing import List

from core.swarm_engine import SwarmAgent
from core.swarm_workers import register_worker

from ._http import fetch, normalize_target_url

logger = logging.getLogger("viper.swarm_workers.vuln.bfla_multi")

TECHNIQUE = "bfla_multi"


async def run(agent: SwarmAgent) -> List[dict]:
    cfg = (agent.payload or {}).get("bfla")
    if not isinstance(cfg, dict) or not cfg.get("privileged_headers") \
            or not cfg.get("low_headers"):
        return []

    candidates = cfg.get("candidate_urls")
    if not candidates:
        url = normalize_target_url(agent.target)
        candidates = [url] if url else []
    if not candidates:
        return []

    from core.specialist.bfla_engine import Identity, find_bfla

    privileged = Identity(cfg.get("privileged_name", "admin"),
                          cfg["privileged_headers"])
    low_priv = Identity(cfg.get("low_name", "user"), cfg["low_headers"])
    timeout = min(agent.timeout_s, 10.0)

    async def _fetch(method, u, *, headers=None, timeout=timeout):
        # use_session_auth=False: this worker fully specifies each identity
        # (admin / low-priv / anonymous); the global session must not leak in.
        return await fetch(method, u, headers=headers, timeout=timeout,
                           use_session_auth=False)

    return await find_bfla(privileged, low_priv, candidates, fetch=_fetch,
                           timeout=timeout,
                           admin_only=cfg.get("admin_only", True),
                           unauth_control=cfg.get("unauth_control", True))


register_worker("vuln", TECHNIQUE, run)
