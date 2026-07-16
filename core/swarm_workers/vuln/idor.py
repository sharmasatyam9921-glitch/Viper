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

    # Feed-forward: object IDs harvested elsewhere this hunt (leaked in a response,
    # a REST path, a UUID) become extra test values here — "harvest an ID here, replay
    # it there", the classic IDOR-enumeration move. Only SAME-SHAPE refs (numeric vs
    # UUID) different from the current value; read-only GET, still anonymous, still a
    # lead (0.55) for manual review. Empty pool -> identical to the adjacent-only behavior.
    try:
        from core.payload_library import get_object_refs
        pool = get_object_refs()
    except Exception:  # noqa: BLE001
        pool = []

    findings: list[dict] = []
    for param, value in candidates[:5]:
        is_uuid = bool(_UUID_RE.match(value))
        alternates: list[str] = []
        adj = _adjacent(value)
        if adj and adj != value:
            alternates.append(adj)
        for ref in pool:
            if ref == value or ref in alternates:
                continue
            if bool(_UUID_RE.match(ref)) == is_uuid and (is_uuid or _NUMERIC_RE.match(ref)):
                alternates.append(ref)
        alternates = alternates[:4]          # adjacent + up to 3 replayed pool ids
        if not alternates:
            continue

        url_a = _replace_param(url, param, value)
        # use_session_auth=False: the evidence asserts "without auth checks", so these
        # probes must be genuinely anonymous — not carry the hunt's global identity-A
        # session (which would make the claim false and turn two distinct logged-in
        # responses into a spurious candidate).
        ra = await fetch("GET", url_a, timeout=timeout, use_session_auth=False)
        if not ra or not ra.ok or not ra.body:
            continue
        for alt in alternates:
            url_b = _replace_param(url, param, alt)
            rb = await fetch("GET", url_b, timeout=timeout, use_session_auth=False)
            if not rb or not rb.ok or not rb.body:
                continue
            # Bodies must differ (else the endpoint ignores the ID — a generic page).
            if ra.body != rb.body:
                replayed = alt != adj
                findings.append({
                    "type": "idor_candidate",
                    "vuln_type": f"idor:{param}",
                    "title": f"IDOR candidate on ?{param}=",
                    "severity": "medium",
                    "url": url_b,
                    "parameter": param,
                    "payload": alt,
                    "cwe": "CWE-639",
                    "confidence": 0.55,
                    "evidence": (
                        f"Both id={value} ({ra.status}, {len(ra.body)}B) and "
                        f"id={alt} ({rb.status}, {len(rb.body)}B) returned distinct "
                        "content without auth checks"
                        + (" (id replayed from another response this hunt)"
                           if replayed else "")
                        + " — manual verification recommended."
                    ),
                })
                break                        # one candidate per param is enough
    return findings


register_worker("vuln", TECHNIQUE, run)
