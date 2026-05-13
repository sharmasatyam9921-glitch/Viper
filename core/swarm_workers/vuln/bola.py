"""BOLA (Broken Object-Level Authorization) probe.

BOLA is the API-layer cousin of IDOR — REST endpoints like
`/api/users/<id>` that accept any ID without enforcing ownership.

Strategy:
  1. Discover candidate API endpoints from the response of a baseline
     GET (look for `/api/...` or `/v1/...` URLs in HTML/JS).
  2. For endpoints whose path ends in an ID-shaped segment, try the
     adjacent ID (no auth).
  3. If both responses are 2xx with distinct bodies, flag as candidate.

Honest limit: confirmed BOLA needs two real accounts; this worker
surfaces structural candidates for operator review.
"""

from __future__ import annotations

import logging
import re
from typing import List
from urllib.parse import urlsplit

from core.swarm_engine import SwarmAgent
from core.swarm_workers import register_worker

from ._http import fetch, normalize_target_url

logger = logging.getLogger("viper.swarm_workers.vuln.bola")

TECHNIQUE = "bola"

_API_URL_RE = re.compile(
    r'["\'`](/(?:api|v\d+|rest)/[a-zA-Z0-9_/.-]+?/(\d{1,9}|[0-9a-f-]{8,40}))["\'`]'
)
_NUMERIC_RE = re.compile(r"^\d{1,9}$")
_UUID_LIKE = re.compile(r"^[0-9a-f]{8,40}(?:-[0-9a-f]{4,12}){0,4}$", re.I)


def _adjacent_id(seg: str) -> str | None:
    if _NUMERIC_RE.match(seg):
        try:
            return str(int(seg) + 1)
        except ValueError:
            return None
    if _UUID_LIKE.match(seg):
        new_last = format((int(seg[-1], 16) + 1) % 16, "x")
        return seg[:-1] + new_last
    return None


async def _baseline_extract(url: str, timeout: float) -> set[tuple[str, str]]:
    """Return (api_path, id_segment) tuples observed in the baseline page."""
    out: set[tuple[str, str]] = set()
    resp = await fetch("GET", url, timeout=timeout)
    if not resp or not resp.body:
        return out
    for m in _API_URL_RE.finditer(resp.body[:256 * 1024]):
        out.add((m.group(1), m.group(2)))
    return out


async def run(agent: SwarmAgent) -> List[dict]:
    base = normalize_target_url(agent.target)
    if not base:
        return []
    timeout = min(agent.timeout_s, 8.0)

    parts = urlsplit(base)
    host = f"{parts.scheme}://{parts.netloc}"

    candidates = await _baseline_extract(base, timeout)
    if not candidates:
        return []

    findings: list[dict] = []
    seen: set[str] = set()
    for path, id_seg in list(candidates)[:10]:
        if path in seen:
            continue
        seen.add(path)
        adj = _adjacent_id(id_seg)
        if not adj or adj == id_seg:
            continue
        url_a = host + path
        url_b = host + path.replace(f"/{id_seg}", f"/{adj}", 1)
        ra = await fetch("GET", url_a, timeout=timeout)
        rb = await fetch("GET", url_b, timeout=timeout)
        if not (ra and rb):
            continue
        if ra.ok and rb.ok and ra.body != rb.body and ra.body and rb.body:
            findings.append({
                "type": "bola_candidate",
                "vuln_type": f"bola:{path}",
                "title": f"BOLA candidate on {path}",
                "severity": "medium",
                "url": url_b,
                "parameter": "id",
                "payload": adj,
                "cwe": "CWE-639",
                "confidence": 0.55,
                "evidence": (
                    f"Both {id_seg} ({ra.status}, {len(ra.body)}B) and "
                    f"{adj} ({rb.status}, {len(rb.body)}B) returned distinct "
                    "content without authentication — manual verification needed."
                ),
            })
    return findings


register_worker("vuln", TECHNIQUE, run)
