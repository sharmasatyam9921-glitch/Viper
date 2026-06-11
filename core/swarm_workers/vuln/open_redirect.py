"""Open redirect probe (CWE-601).

For each common redirect parameter (``next``, ``url``, ``redirect``, ...) we
set the value to a clearly attacker-controlled URL and request with redirects
DISABLED. A target is vulnerable if it bounces us to the attacker host via:

  - a ``Location`` response header (the classic case),
  - an HTML ``<meta http-equiv="refresh" ...>`` tag, or
  - a JavaScript ``location``/``location.href`` assignment.

Two payload shapes are tried per parameter: an absolute attacker URL and the
scheme-relative ``//host`` form (often bypasses naive ``http://`` blocklists).

Non-destructive: GET only, benign off-host URL, no data mutation.
"""

from __future__ import annotations

import logging
import re
from typing import List, Optional
from urllib.parse import urlsplit

from core.swarm_engine import SwarmAgent
from core.swarm_workers import register_worker

from ._http import HttpResp, add_query, fetch, normalize_target_url

logger = logging.getLogger("viper.swarm_workers.vuln.open_redirect")

TECHNIQUE = "open_redirect"

# Common redirect parameter names.
REDIRECT_PARAMS = (
    "next", "url", "redirect", "return", "returnUrl", "returnTo",
    "dest", "destination", "continue", "r", "u", "goto", "out", "link",
)

# Attacker-controlled destination. The host is what we look for in the response.
_ATTACKER_HOST = "evil-redirect.example"
_ATTACKER_ABS = f"https://{_ATTACKER_HOST}/x"
_ATTACKER_REL = f"//{_ATTACKER_HOST}"

# meta-refresh: <meta http-equiv="refresh" content="0;url=https://evil...">
_META_RE = re.compile(
    r"""<meta[^>]+http-equiv\s*=\s*['"]?refresh['"]?[^>]+content\s*=\s*"""
    r"""['"][^'"]*url\s*=\s*([^'";> ]+)""",
    re.IGNORECASE,
)
# JS redirect: location = "..." / location.href = "..." / location.replace("...")
_JS_RE = re.compile(
    r"""(?:location(?:\.href)?\s*=|location\.(?:replace|assign)\s*\(\s*)"""
    r"""\s*['"]([^'"]+)['"]""",
    re.IGNORECASE,
)


def _host_of(value: str) -> str:
    """Best-effort host extraction, tolerant of scheme-relative URLs."""
    v = (value or "").strip()
    if v.startswith("//"):
        v = "http:" + v
    try:
        return urlsplit(v).netloc.lower()
    except Exception:  # noqa: BLE001
        return ""


def _points_to_attacker(value: str) -> bool:
    """True if `value` (a redirect target) resolves to the attacker host."""
    if not value:
        return False
    return _host_of(value) == _ATTACKER_HOST


def _detect(resp: HttpResp) -> Optional[tuple[str, str]]:
    """Return (channel, evidence_value) if the response redirects to attacker."""
    # 1) Location header (only meaningful on a 3xx, but check regardless of
    #    code since some apps emit Location on 200 too).
    loc = (resp.headers.get("location") or "").strip()
    if loc and _points_to_attacker(loc):
        return ("location_header", loc)

    body = resp.body or ""
    # 2) HTML meta-refresh
    m = _META_RE.search(body)
    if m and _points_to_attacker(m.group(1)):
        return ("meta_refresh", m.group(1).strip())

    # 3) JS location assignment
    j = _JS_RE.search(body)
    if j and _points_to_attacker(j.group(1)):
        return ("js_location", j.group(1).strip())

    return None


async def run(agent: SwarmAgent) -> List[dict]:
    url = normalize_target_url(agent.target)
    if not url:
        return []
    timeout = min(agent.timeout_s, 10.0)
    findings: list[dict] = []
    seen_params: set[str] = set()

    for param in REDIRECT_PARAMS:
        for payload in (_ATTACKER_ABS, _ATTACKER_REL):
            test_url = add_query(url, param, payload)
            resp = await fetch(
                "GET", test_url, timeout=timeout, follow_redirects=False,
            )
            if not resp:
                continue
            hit = _detect(resp)
            if not hit:
                continue
            channel, evidence_val = hit
            if param in seen_params:
                break  # one finding per parameter is enough
            seen_params.add(param)
            findings.append({
                "type": "open_redirect",
                "vuln_type": f"open_redirect:{param}",
                "title": f"Open redirect via '{param}' parameter ({channel})",
                "severity": "medium",
                "url": test_url,
                "cwe": "CWE-601",
                "confidence": 0.9 if channel == "location_header" else 0.75,
                "evidence": (
                    f"{param}={payload} -> {channel} redirects to "
                    f"{_ATTACKER_HOST} ({evidence_val})"
                ),
                "payload": payload,
                "parameter": param,
            })
            break  # stop trying payloads for this param

    return findings


register_worker("vuln", TECHNIQUE, run)
