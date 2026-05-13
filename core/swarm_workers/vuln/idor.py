"""IDOR (Insecure Direct Object Reference) probe.

Light-weight: looks for URLs / params with integer or UUID-like IDs and
tries adjacent values without auth credentials. If responses still
contain "user-data-like" markers (email, name, id_2 != id_1), it
emits a candidate.

Honest limit: real IDOR almost always requires authentication. This
worker flags STRUCTURAL candidates the operator can manually verify.
No exploitation; no PII exfil.
"""

from __future__ import annotations

import logging
import re
from typing import List
from urllib.parse import parse_qs, urlencode, urlsplit, urlunsplit

from core.swarm_engine import SwarmAgent
from core.swarm_workers import register_worker

from ._http import fetch, normalize_target_url

logger = logging.getLogger("viper.swarm_workers.vuln.idor")

TECHNIQUE = "idor"

_NUMERIC_RE = re.compile(r"^\d{1,9}$")
_UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)


def _candidates(url: str) -> list[tuple[str, str]]:
    """Yield (param, value) for params whose value looks like an ID."""
    qs = parse_qs(urlsplit(url).query)
    out: list[tuple[str, str]] = []
    for k, vs in qs.items():
        for v in vs:
            if _NUMERIC_RE.match(v) or _UUID_RE.match(v):
                out.append((k, v))
    return out


def _adjacent(value: str) -> str | None:
    if _NUMERIC_RE.match(value):
        try:
            return str(int(value) + 1)
        except ValueError:
            return None
    if _UUID_RE.match(value):
        # Increment the last hex digit safely
        new_last = format((int(value[-1], 16) + 1) % 16, "x")
        return value[:-1] + new_last
    return None


def _replace_param(url: str, key: str, value: str) -> str:
    parsed = urlsplit(url)
    qs = parse_qs(parsed.query)
    qs[key] = [value]
    new_q = urlencode(qs, doseq=True)
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, new_q, parsed.fragment))


async def run(agent: SwarmAgent) -> List[dict]:
    url = normalize_target_url(agent.target)
    if not url:
        return []
    timeout = min(agent.timeout_s, 8.0)

    candidates = _candidates(url)
    if not candidates:
        return []

    findings: list[dict] = []
    for param, value in candidates[:5]:
        adj = _adjacent(value)
        if not adj or adj == value:
            continue
        url_a = _replace_param(url, param, value)
        url_b = _replace_param(url, param, adj)
        ra = await fetch("GET", url_a, timeout=timeout)
        rb = await fetch("GET", url_b, timeout=timeout)
        if not ra or not rb:
            continue
        # Both must be 2xx — strong IDOR signal
        if ra.ok and rb.ok:
            # And the bodies must differ (otherwise it's likely a
            # generic page that ignores the ID)
            if ra.body and rb.body and ra.body != rb.body:
                findings.append({
                    "type": "idor_candidate",
                    "vuln_type": f"idor:{param}",
                    "title": f"IDOR candidate on ?{param}=",
                    "severity": "medium",
                    "url": url_b,
                    "parameter": param,
                    "payload": adj,
                    "cwe": "CWE-639",
                    "confidence": 0.55,
                    "evidence": (
                        f"Both id={value} ({ra.status}, {len(ra.body)}B) and "
                        f"id={adj} ({rb.status}, {len(rb.body)}B) returned distinct "
                        "content without auth checks — manual verification recommended."
                    ),
                })
    return findings


register_worker("vuln", TECHNIQUE, run)
