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
from typing import Iterable, List, Optional
from urllib.parse import urlsplit

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
    allowed_hosts: Optional[Iterable[str]] = None,
) -> List[dict]:
    """Replay identity A's object URLs as identity B and confirm cross-user reads.

    owner_headers / attacker_headers : each identity's auth headers (Cookie/Bearer).
    owner_markers   : strings unique to A's PRIVATE data (email, user-id, ...).
    candidate_urls  : A's observed object URLs (use burp_import.object_urls()).
    proxy           : optional 'http://127.0.0.1:8080' to route via Burp/ZAP.
    allowed_hosts   : if given, replays are RESTRICTED to these netlocs. Candidate
                      URLs on any other host are dropped, and a fail-closed scope
                      guard is installed for the run — so the operator's session
                      is never replayed to a third-party host that happened to be
                      in an imported capture (analytics/CDN/OAuth/etc.). Strongly
                      recommended whenever candidate_urls come from a Burp import.

    Returns confirmed-BOLA finding dicts (low-FP, read-only).
    """
    from core.swarm_workers.vuln._http import (
        fetch, get_proxy, get_scope_guard, set_proxy, set_scope_guard,
    )

    # Compare by HOSTNAME (port-agnostic, and resolves the true host past any
    # "user@host" userinfo) so a legit :443 URL isn't dropped and a
    # "target@evil.com" spoof can't pass.
    allow = {h.lower() for h in allowed_hosts} if allowed_hosts is not None else None
    if allow is not None:
        kept = [u for u in candidate_urls
                if (urlsplit(u).hostname or "").lower() in allow]
        dropped = len(candidate_urls) - len(kept)
        if dropped:
            logger.warning(
                "BOLA: dropped %d candidate URL(s) outside the allowed host(s) %s "
                "— not replaying your session to a third-party host", dropped,
                sorted(allow))
        candidate_urls = kept

    owner = Session(owner_name, dict(owner_headers or {}), list(owner_markers or []))
    attacker = Session(attacker_name, dict(attacker_headers or {}),
                       list(attacker_markers or []))

    async def _fetch(method, u, *, headers=None, timeout=timeout):
        # use_session_auth=False: identities are fully specified here; the global
        # hunt session must not contaminate the attacker / anonymous probes.
        return await fetch(method, u, headers=headers, timeout=timeout,
                           use_session_auth=False)

    prev_proxy = get_proxy() if proxy else None
    prev_guard = get_scope_guard() if allow is not None else None
    if proxy:
        set_proxy(proxy)
        logger.info("BOLA runner routing through proxy %s", proxy)
    if allow is not None:
        def _guard(u, _allow=allow, _prev=prev_guard):
            try:
                if (urlsplit(u).hostname or "").lower() not in _allow:
                    return False
                return _prev(u) if _prev else True
            except Exception:  # noqa: BLE001 — fail closed on any guard error
                return False
        set_scope_guard(_guard)
    try:
        return await find_bola(
            owner, attacker, candidate_urls, fetch=_fetch,
            timeout=timeout, unauth_control=unauth_control,
        )
    finally:
        if proxy:
            set_proxy(prev_proxy)
        if allow is not None:
            set_scope_guard(prev_guard)
