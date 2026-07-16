"""Endpoint-discovery worker.

Fetches the target's index page and pulls out:
  - `<a href="...">` links
  - `<form action="...">` actions (form parameters become candidates)
  - `<script src="...">` JS bundles (a follow-up worker could mine these,
    but here we just record the URL)
  - href/src/action URLs from inline strings in JS

Emits one `endpoint` finding per discovered URL. Vuln workers consume
these as assets, so /users?id=1 and /search?q=hi get probed individually.

Light fallback when `recon.web_crawler.WebCrawler` isn't usable.
"""

from __future__ import annotations

import logging
import re
from typing import List
from urllib.parse import urljoin, urlsplit

from core.swarm_engine import SwarmAgent
from core.swarm_workers import register_worker

from ..vuln._http import fetch, normalize_target_url

logger = logging.getLogger("viper.swarm_workers.recon.endpoints")

TECHNIQUE = "endpoints"

_HREF_RE = re.compile(r'(?:href|src|action)\s*=\s*["\']([^"\'#\s]+)["\']', re.I)
_INTERESTING_SUFFIX = (
    "/login", "/admin", "/api", "/users", "/user", "/search", "/redirect",
    "/template", "/view", "/file", "/upload", "/download", "/debug",
    "/.env", "/.git", "/config", "/swagger", "/openapi",
)


def _classify_severity(path: str) -> str:
    low = path.lower()
    for marker in _INTERESTING_SUFFIX:
        if marker in low:
            return "low"  # interesting paths get nudged up so they're surfaced
    return "info"


# Asset extensions we still record as endpoints but never CRAWL for more links.
_ASSET_EXT = (".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
              ".woff", ".woff2", ".ttf", ".eot", ".pdf", ".zip", ".mp4", ".webp")
_MAX_PAGES = 16        # total pages fetched during the crawl
_MAX_DEPTH = 2         # index (0) -> its links (1) -> their links (2)
_MAX_ENDPOINTS = 60    # total endpoints emitted


def _crawlable(path: str) -> bool:
    return not path.lower().endswith(_ASSET_EXT)


async def run(agent: SwarmAgent) -> List[dict]:
    url = normalize_target_url(agent.target)
    if not url:
        return []
    timeout = min(agent.timeout_s, 8.0)
    parts = urlsplit(url)

    # Bounded, same-host, depth-2 BFS — a real hacker doesn't conclude a target off one
    # index page. Read-only GETs; the shared fetch path rate-limits, and same-host + the
    # downstream scope reasoner keep it in bounds.
    seen: set[str] = set()          # endpoint URLs already emitted
    visited: set[str] = set()       # pages already fetched
    findings: list[dict] = []
    queue: list[tuple[str, int]] = [(url, 0)]

    while queue and len(visited) < _MAX_PAGES and len(seen) < _MAX_ENDPOINTS:
        page_url, depth = queue.pop(0)
        if page_url in visited:
            continue
        visited.add(page_url)
        # Don't auto-follow redirects during the crawl: a same-host 3xx off-host would
        # otherwise fetch + parse off-host content. Treat a same-host Location as just
        # another discovered link (re-filtered below); off-host Locations are dropped.
        resp = await fetch("GET", page_url, timeout=timeout, follow_redirects=False)
        if not resp:
            continue
        status = getattr(resp, "status", 0) or 0
        if 300 <= status < 400:
            loc = (resp.headers or {}).get("location") or (resp.headers or {}).get("Location")
            if loc:
                nxt = urljoin(page_url, loc)
                np = urlsplit(nxt)
                if (not np.netloc or np.netloc == parts.netloc) and nxt not in seen:
                    seen.add(nxt)
                    findings.append({
                        "type": "endpoint",
                        "vuln_type": f"endpoint:{nxt}",
                        "title": nxt,
                        "asset": parts.netloc,
                        "url": nxt,
                        "severity": _classify_severity(np.path),
                        "evidence": f"redirect target ({status}) from {page_url}",
                    })
                    if nxt not in visited:
                        queue.append((nxt, depth))   # a redirect isn't a hop deeper
            continue
        if not resp.body:
            continue
        body = resp.body[:512 * 1024]
        # Feed-forward: harvest object IDs (numeric in an id-context, or UUIDs) seen on
        # this page into the cross-worker pool so IDOR/BOLA can replay them elsewhere.
        try:
            from core.payload_library import add_object_refs
            add_object_refs(body)
        except Exception:  # noqa: BLE001
            pass

        for m in _HREF_RE.finditer(body):
            raw = m.group(1).strip()
            if not raw or raw.startswith(("javascript:", "mailto:", "tel:", "data:")):
                continue
            if raw.startswith(("http://", "https://")):
                full = raw
            elif raw.startswith("//"):
                full = parts.scheme + ":" + raw
            else:
                full = urljoin(page_url, raw)

            f_parts = urlsplit(full)
            # Same-host only (cross-origin links are recon leads, not vuln targets).
            if f_parts.netloc and f_parts.netloc != parts.netloc:
                continue
            if full in seen:
                continue
            seen.add(full)
            findings.append({
                "type": "endpoint",
                "vuln_type": f"endpoint:{full}",
                "title": full,
                "asset": parts.netloc,
                "url": full,
                "severity": _classify_severity(f_parts.path),
                "evidence": f"discovered by depth-{depth} crawl of {page_url}",
            })
            # Enqueue same-host HTML pages for a deeper pass (assets aren't crawled).
            if (depth + 1 <= _MAX_DEPTH and full not in visited
                    and _crawlable(f_parts.path)):
                queue.append((full, depth + 1))
            if len(seen) >= _MAX_ENDPOINTS:
                break

    return findings


register_worker("recon", TECHNIQUE, run)
