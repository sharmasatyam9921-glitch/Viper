"""Authenticated per-role crawl — feed the confirmed workers the surface that only
appears when you are logged in.

The recon workers crawl ANONYMOUSLY, so admin panels, user dashboards, and authed
APIs — exactly the endpoints the two-account BOLA/BFLA engine and the injection
workers most want — never enter the attack surface. When the operator has supplied
authenticated identities (SessionContext roles, e.g. the two accounts already given
for BOLA), this does a shallow crawl of the target once PER ROLE and:

  * records each (role, url) -> status into the SessionContext reachability matrix,
    which the BOLA/BFLA engine consumes to find cross-user access (an object one role
    can read that another cannot), and
  * returns the same-host endpoints reachable by at least one role, plus their query
    parameter names, to feed forward as vuln targets / injection params.

Strictly read-only GETs with OPERATOR-supplied sessions — VIPER never creates an
account, and this produces discovery data only, so it never touches the validation
gate. Bounded per role so an authenticated sweep can't run away.
"""
from __future__ import annotations

import logging
import re
from typing import List, Set, Tuple
from urllib.parse import parse_qs, urljoin, urlsplit

from core.swarm_workers.vuln._http import fetch as _default_fetch, normalize_target_url

logger = logging.getLogger("viper.authenticated_crawl")

_HREF_RE = re.compile(r'(?:href|src|action)\s*=\s*["\']([^"\'#\s]+)["\']', re.I)
_SKIP_SCHEMES = ("javascript:", "mailto:", "tel:", "data:", "blob:")


def _same_host_links(body: str, base_url: str, netloc: str, cap: int) -> List[str]:
    """Same-host href/src/action URLs from a page body (deduped, fragment-stripped)."""
    out: List[str] = []
    seen: Set[str] = set()
    for m in _HREF_RE.finditer(body or ""):
        raw = m.group(1).strip()
        if not raw or raw.lower().startswith(_SKIP_SCHEMES):
            continue
        if raw.startswith(("http://", "https://")):
            full = raw
        elif raw.startswith("//"):
            full = "https:" + raw
        else:
            full = urljoin(base_url, raw)
        full = full.split("#", 1)[0]
        p = urlsplit(full)
        if p.netloc and p.netloc != netloc:
            continue          # cross-host links are recon leads, not authed targets
        if full and full not in seen:
            seen.add(full)
            out.append(full)
        if len(out) >= cap:
            break
    return out


def _query_params(url: str) -> List[str]:
    return list(parse_qs(urlsplit(url).query).keys())


async def crawl_roles(
    session_context,
    base_url: str,
    *,
    fetch=None,
    max_urls_per_role: int = 30,
    timeout: float = 8.0,
) -> Tuple[List[str], Set[str]]:
    """Crawl `base_url` once per SessionContext role, recording reachability and
    returning (endpoints reachable by >=1 role, query-parameter names). No-op (returns
    ([], set())) when there are no roles or no base URL."""
    fetch = fetch or _default_fetch
    roles = list(session_context.roles) if session_context else []
    base = normalize_target_url(base_url)
    if not roles or not base:
        return [], set()
    netloc = urlsplit(base).netloc
    # An endpoint is "surfaced" if ANY role reaches it with a 2xx/3xx — a numeric max
    # would let one role's 403 (403 > 200) hide another role's success. Insertion-
    # ordered dict preserves discovery order.
    reachable: dict = {}
    params: Set[str] = set()

    def _note(url: str, status: int) -> None:
        if 200 <= status < 400:
            reachable.setdefault(url, True)

    for role in roles:
        r = session_context.get_role(role)
        headers = dict(getattr(r, "headers", {}) or {})
        try:
            resp = await fetch("GET", base, headers=headers, timeout=timeout,
                               use_session_auth=False)
        except Exception as e:  # noqa: BLE001 — one role's failure can't sink the crawl
            logger.debug("authed crawl base fetch failed for role %s: %s", role, e)
            continue
        base_status = getattr(resp, "status", 0) if resp else 0
        session_context.record(role, "GET", base, base_status)
        _note(base, base_status)
        body = getattr(resp, "body", "") if resp else ""
        for link in _same_host_links(body, base, netloc, max_urls_per_role):
            try:
                lr = await fetch("GET", link, headers=headers, timeout=timeout,
                                 use_session_auth=False)
            except Exception as e:  # noqa: BLE001
                logger.debug("authed crawl link fetch failed (%s): %s", link, e)
                continue
            st = getattr(lr, "status", 0) if lr else 0
            session_context.record(role, "GET", link, st)
            _note(link, st)
            params.update(_query_params(link))

    endpoints = list(reachable.keys())
    logger.info("authed crawl: %d roles, %d reachable endpoints, %d params",
                len(roles), len(endpoints), len(params))
    return endpoints, params
