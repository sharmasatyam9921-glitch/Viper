"""Web-cache-poisoning RISK detector (CWE-444/CWE-524) — safe, lead-only.

Actually POISONING a cache serves attacker content to OTHER users — destructive, out
of scope. So this uses the standard SAFE research methodology: every probe carries a
unique CACHE-BUSTER query parameter, so any cached response is keyed to a URL only WE
requested and is never served to a real user, and the injected value is a BENIGN fake
hostname marker (never an XSS/redirect payload). It reports the RISK — an unkeyed
request header reflected into a CACHEABLE response — as a lead; a human then confirms
real impact in a controlled way.

FP-averse: a lead requires BOTH that the response is cacheable (Cache-Control
public/max-age, or a cache-status header, and no per-user Set-Cookie) AND that the
benign header marker is reflected back — reflection alone (already covered by the
host-header worker) or cacheability alone is not enough.
"""
from __future__ import annotations

import logging
import re
import secrets
from typing import List, Tuple

from core.swarm_engine import SwarmAgent
from core.swarm_workers import register_worker

from ._http import add_query, fetch, normalize_target_url

logger = logging.getLogger("viper.swarm_workers.vuln.cache_poisoning")

TECHNIQUE = "cache_poisoning"

# Commonly-unkeyed request headers a front-end reflects into links / Location / body.
_UNKEYED_HEADERS = ["X-Forwarded-Host", "X-Forwarded-Scheme", "X-Host",
                    "X-Forwarded-Server"]
# Response headers that reveal a shared cache sits in front of the origin.
_CACHE_STATUS_HEADERS = ("x-cache", "cf-cache-status", "age", "x-cache-hits",
                         "x-served-by", "cache-status", "x-varnish")
_MAX_AGE = re.compile(r"max-age\s*=\s*(\d+)")


def _headers_lower(resp) -> dict:
    return {str(k).lower(): str(v) for k, v in (resp.headers or {}).items()}


def _cacheability(h: dict) -> Tuple[bool, str]:
    """Is the response shared-cacheable? Returns (cacheable, why)."""
    if "set-cookie" in h:                 # a per-user cookie => not shared-cacheable
        return False, ""
    cc = h.get("cache-control", "").lower()
    if "no-store" in cc or "private" in cc:
        return False, ""
    signals: List[str] = []
    if "public" in cc:
        signals.append("Cache-Control: public")
    m = _MAX_AGE.search(cc)
    if m and int(m.group(1)) > 0 and "no-cache" not in cc:
        signals.append(f"max-age={m.group(1)}")
    for ch in _CACHE_STATUS_HEADERS:
        if ch in h:
            signals.append(f"{ch}={h[ch]}")
    return bool(signals), "; ".join(signals[:3])


def _reflected(resp, h: dict, marker: str) -> bool:
    if marker in (resp.body or ""):
        return True
    return any(marker in v for v in h.values())


def _lead(url: str, header: str, why: str) -> dict:
    return {
        "type": "web_cache_poisoning",
        "vuln_type": f"web_cache_poisoning:{header.lower()}",
        "title": f"Web-cache-poisoning risk via unkeyed {header}",
        "severity": "medium",
        "url": url,
        "cwe": "CWE-524",
        "confidence": 0.45,
        "evidence": (f"the unkeyed request header {header} was reflected into a "
                     f"CACHEABLE response ({why}); probed with a cache buster + a "
                     "benign marker so no shared cache entry was poisoned"),
        "needs_manual_verification": True,
    }


async def run(agent: SwarmAgent) -> List[dict]:
    url = normalize_target_url(agent.target)
    if not url:
        return []
    timeout = min(agent.timeout_s, 8.0)
    findings: List[dict] = []
    for header in _UNKEYED_HEADERS:
        token = secrets.token_hex(6)
        marker = f"vppcp{token}.example"          # benign fake host — never a payload
        probe_url = add_query(url, "vppcb", token)  # unique cache buster keys it to us
        r = await fetch("GET", probe_url, headers={header: marker}, timeout=timeout,
                        follow_redirects=False)
        if not r:
            continue
        h = _headers_lower(r)
        cacheable, why = _cacheability(h)
        if cacheable and _reflected(r, h, marker):
            findings.append(_lead(url, header, why))
            break   # one confirmed unkeyed-header risk is enough
    return findings


register_worker("vuln", TECHNIQUE, run)
