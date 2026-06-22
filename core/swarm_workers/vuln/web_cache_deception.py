"""Web Cache Deception (WCD) worker — opt-in, two-identity confirmed.

WCD tricks a CDN/cache into storing an authenticated page under a static-looking
URL, so an unauthenticated attacker can then fetch the victim's private data from
the cache. The reliable, FP-averse proof is differential and needs two identities
you control:

  1. As the VICTIM (session), request a sensitive path with a static-file suffix
     (``/account/x.css``). If it returns the victim's private data (a marker) AND
     the response is cacheable, the cache may now hold it.
  2. As ANONYMOUS (no session), request the SAME URL. If anon receives the
     victim's private marker, the cache served authenticated data to an
     unauthenticated request — confirmed WCD.

Self-gated: does nothing unless ``agent.payload["wcd"]`` supplies the victim
session headers and identity markers (strings unique to the victim's private
data). Read-only GET. For authorized testing with accounts you control.
"""
from __future__ import annotations

import logging
import re
import secrets
from typing import List, Optional
from urllib.parse import urlsplit, urlunsplit

from core.swarm_engine import SwarmAgent
from core.swarm_workers import register_worker

from ._http import HttpResp, fetch, normalize_target_url

logger = logging.getLogger("viper.swarm_workers.vuln.web_cache_deception")

TECHNIQUE = "web_cache_deception"

_DEFAULT_PATHS = ["/account", "/profile", "/settings", "/dashboard", "/me",
                  "/api/me", "/user", "/api/account"]
# Static-suffix / path-confusion variants ({p}=path, {r}=random token).
_VARIANTS = ["{p}/{r}.css", "{p}/{r}.js", "{p}%2f{r}.css", "{p}/%2e%2e/{r}.css",
             "{p};{r}.css"]
_NO_CACHE = re.compile(r"\b(no-store|private)\b", re.I)
_CACHE_OK = re.compile(r"\b(public|max-age|s-maxage)\b", re.I)
_CACHE_HDRS = ("x-cache", "cf-cache-status", "age", "x-cache-status",
               "x-served-by", "x-cache-hits")


def _origin(url: str) -> str:
    p = urlsplit(url)
    return urlunsplit((p.scheme, p.netloc, "", "", ""))


def _markers_in(body: str, markers: List[str]) -> List[str]:
    low = (body or "").lower()
    return [m for m in markers if m.lower() in low]


def _cacheable(resp: Optional[HttpResp]) -> bool:
    if resp is None:
        return False
    h = resp.headers or {}
    cc = h.get("cache-control", "")
    if _NO_CACHE.search(cc):
        return False
    if _CACHE_OK.search(cc):
        return True
    return any(k in h for k in _CACHE_HDRS)


async def run(agent: SwarmAgent) -> List[dict]:
    cfg = (agent.payload or {}).get("wcd")
    if not isinstance(cfg, dict) or not cfg.get("headers") or not cfg.get("markers"):
        return []
    base = _origin(normalize_target_url(agent.target))
    if not base:
        return []
    headers = cfg["headers"]
    markers = [m.strip() for m in cfg["markers"] if isinstance(m, str) and len(m.strip()) >= 3]
    if not markers:
        return []
    paths = cfg.get("paths") or _DEFAULT_PATHS
    timeout = min(agent.timeout_s, 10.0)

    for path in paths[:8]:
        for tmpl in _VARIANTS:
            token = secrets.token_hex(4)
            wcd_url = base + tmpl.format(p=path, r=token)
            # 1. victim primes the cache (own session, NOT the global session).
            authed = await fetch("GET", wcd_url, headers=headers, timeout=timeout,
                                 use_session_auth=False)
            if authed is None or not (200 <= authed.status < 300):
                continue
            leaked = _markers_in(authed.body, markers)
            if not leaked or not _cacheable(authed):
                continue
            # 2. attacker (anonymous) fetches the same URL — does the cache leak it?
            anon = await fetch("GET", wcd_url, headers={}, timeout=timeout,
                               use_session_auth=False)
            if anon is None or not (200 <= anon.status < 300):
                continue
            if _markers_in(anon.body, leaked):
                return [{
                    "type": "web_cache_deception",
                    "vuln_type": f"web_cache_deception:{path}",
                    "title": f"Web Cache Deception at {path}",
                    "severity": "high",
                    "url": wcd_url,
                    "cwe": "CWE-525",
                    "confidence": 0.9,
                    "cache_confirmed": True,
                    "evidence": (
                        f"A static-suffixed URL of {path} returned the victim's "
                        f"private marker(s) {leaked!r} with a cacheable response; an "
                        f"UNAUTHENTICATED request to the same URL then received the "
                        f"same private data from cache — web cache deception."),
                    "poc_request": f"GET {wcd_url}  (no session) returns the victim's data",
                }]
    return []


register_worker("vuln", TECHNIQUE, run)
