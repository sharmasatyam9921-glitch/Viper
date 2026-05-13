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


async def run(agent: SwarmAgent) -> List[dict]:
    url = normalize_target_url(agent.target)
    if not url:
        return []
    timeout = min(agent.timeout_s, 8.0)
    resp = await fetch("GET", url, timeout=timeout)
    if not resp or not resp.body:
        return []

    body = resp.body[:512 * 1024]  # cap parsed body
    parts = urlsplit(url)
    base = f"{parts.scheme}://{parts.netloc}"

    seen: set[str] = set()
    findings: list[dict] = []
    for m in _HREF_RE.finditer(body):
        raw = m.group(1).strip()
        if not raw or raw.startswith(("javascript:", "mailto:", "tel:", "data:")):
            continue
        # Normalize → absolute URL
        if raw.startswith(("http://", "https://")):
            full = raw
        elif raw.startswith("//"):
            full = parts.scheme + ":" + raw
        else:
            full = urljoin(url, raw)

        # Only keep same-host endpoints (cross-origin links are recon
        # leads, not vuln targets, and the scope reasoner is the gate
        # downstream anyway)
        f_parts = urlsplit(full)
        if f_parts.netloc and f_parts.netloc != parts.netloc:
            continue
        if full in seen:
            continue
        seen.add(full)
        if len(seen) > 50:  # cap fan-out
            break

        findings.append({
            "type": "endpoint",
            "vuln_type": f"endpoint:{full}",
            "title": full,
            "asset": parts.netloc,
            "url": full,
            "severity": _classify_severity(f_parts.path),
            "evidence": "discovered in HTML/JS of index page",
        })

    return findings


register_worker("recon", TECHNIQUE, run)
