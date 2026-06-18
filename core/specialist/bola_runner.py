"""Focused two-account BOLA/IDOR runner (Burp/temp-account driven).

Ties the pieces together: two identities' session headers + a list of identity
A's object URLs (typically imported from Burp via :mod:`burp_import`, or captured
from temp accounts) -> :func:`core.specialist.bola_engine.find_bola`, optionally
routed through an intercepting proxy (Burp) so the operator can watch every
request.

Strictly read-only (GET replays). Each identity's headers are sent verbatim with
the global session-auth merge disabled, so identity A's session can never leak
into identity B's or the anonymous control probe.
"""

from __future__ import annotations

import logging
from typing import List, Optional

from .bola_engine import Session, find_bola

logger = logging.getLogger("viper.specialist.bola_runner")


async def run_bola(
    *,
    owner_headers: dict,
    owner_markers: List[str],
    attacker_headers: dict,
    candidate_urls: List[str],
    attacker_markers: Optional[List[str]] = None,
    proxy: Optional[str] = None,
    unauth_control: bool = True,
    timeout: float = 10.0,
    owner_name: str = "A",
    attacker_name: str = "B",
) -> List[dict]:
    """Replay identity A's object URLs as identity B and confirm cross-user reads.

    owner_headers / attacker_headers : each identity's auth headers (Cookie/Bearer).
    owner_markers   : strings unique to A's PRIVATE data (email, user-id, ...).
    candidate_urls  : A's observed object URLs (use burp_import.object_urls()).
    proxy           : optional 'http://127.0.0.1:8080' to route via Burp/ZAP.

    Returns confirmed-BOLA finding dicts (low-FP, read-only).
    """
    from core.swarm_workers.vuln._http import fetch, set_proxy, get_proxy

    owner = Session(owner_name, dict(owner_headers or {}), list(owner_markers or []))
    attacker = Session(attacker_name, dict(attacker_headers or {}),
                       list(attacker_markers or []))

    async def _fetch(method, u, *, headers=None, timeout=timeout):
        # use_session_auth=False: identities are fully specified here; the global
        # hunt session must not contaminate the attacker / anonymous probes.
        return await fetch(method, u, headers=headers, timeout=timeout,
                           use_session_auth=False)

    prev = None
    if proxy:
        prev = get_proxy()
        set_proxy(proxy)
        logger.info("BOLA runner routing through proxy %s", proxy)
    try:
        return await find_bola(
            owner, attacker, candidate_urls, fetch=_fetch,
            timeout=timeout, unauth_control=unauth_control,
        )
    finally:
        if proxy:
            set_proxy(prev)
