"""Reflected-XSS probe (non-destructive).

Sends a uniquely-marked benign payload to each parameter and checks if
the marker appears unencoded in the response. Does NOT execute JS — the
marker is constructed so a real XSS would echo it back verbatim.
"""

from __future__ import annotations

import logging
import secrets
from typing import List
from urllib.parse import parse_qs, urlsplit

from core.swarm_engine import SwarmAgent
from core.swarm_workers import register_worker

from ._http import add_query, fetch, normalize_target_url

logger = logging.getLogger("viper.swarm_workers.vuln.xss_probe")

TECHNIQUE = "xss_probe"
_DEFAULT_PARAMS = ["q", "search", "name", "user", "comment", "id", "page", "msg"]

# Reflected XSS requires the marker to land in a context a browser parses as
# markup. An echoed value in application/json, text/plain, text/csv,
# application/javascript, etc. is NOT XSS — the browser renders it as inert
# data, never as HTML. Only these content types (or an empty/missing type,
# which a browser may content-sniff into HTML) can yield reflected XSS.
_HTML_CTYPES = {
    "text/html",
    "application/xhtml+xml",
    "image/svg+xml",
    "application/xml",
    "text/xml",
    "",
}


def _html_context(resp) -> bool:
    """True if the response would be parsed as markup by a browser.

    Gates the whole probe: a non-HTML content type means any reflection is a
    benign data echo, not XSS — UNLESS the server omits the type AND does not
    forbid sniffing (then a browser may sniff it into HTML). When nosniff is
    set, an empty content-type is treated as non-HTML and rejected.
    """
    ctype = (resp.headers.get("content-type") or "").split(";")[0].strip().lower()
    if ctype not in _HTML_CTYPES:
        return False
    if ctype == "":
        # No declared type: only sniffable into HTML when nosniff is absent.
        nosniff = (resp.headers.get("x-content-type-options") or "").strip().lower()
        if nosniff == "nosniff":
            return False
    return True


async def _probe_param(url: str, param: str, timeout: float) -> List[dict]:
    marker = "v" + secrets.token_hex(4) + "z"
    # The payload is benign HTML — it never executes. If it shows up
    # unencoded in the response, reflection is confirmed and a real
    # `<script>` payload would have worked too.
    payload = f'<{marker}>"\'><svg/onload=1>'
    test_url = add_query(url, param, payload)
    resp = await fetch("GET", test_url, timeout=timeout, follow_redirects=False)
    if not resp or not resp.body:
        return []
    # Content-type gate: reflection is only XSS in an HTML/XML/SVG (or
    # sniffable) context. JSON/plain/csv/js echoes are inert data, not XSS.
    if not _html_context(resp):
        return []
    body = resp.body
    findings: list[dict] = []
    # Tier 1: full payload echoed (most credible)
    if payload in body:
        findings.append({
            "type": "xss_reflected",
            "vuln_type": f"xss:{param}",
            "title": f"Reflected XSS in ?{param}=",
            "severity": "high",
            "url": test_url,
            "parameter": param,
            "payload": payload,
            "cwe": "CWE-79",
            "confidence": 0.9,
            "evidence": "full HTML payload reflected unencoded in response",
        })
    elif f"<{marker}>" in body:
        # Tier 2: marker tag reflected → angle brackets pass through
        findings.append({
            "type": "xss_reflected",
            "vuln_type": f"xss_tag:{param}",
            "title": f"Reflected angle-bracket marker ?{param}=",
            "severity": "medium",
            "url": test_url,
            "parameter": param,
            "payload": payload,
            "cwe": "CWE-79",
            "confidence": 0.7,
            "evidence": f"marker tag <{marker}> reflected; full payload was filtered",
        })
    elif marker in body:
        # Tier 3: bare marker reflected but tags were stripped
        findings.append({
            "type": "xss_reflection",
            "vuln_type": f"xss_text:{param}",
            "title": f"Parameter ?{param}= reflected unencoded",
            "severity": "low",
            "url": test_url,
            "parameter": param,
            "payload": marker,
            "cwe": "CWE-79",
            "confidence": 0.5,
            "evidence": "marker reflected as text; HTML tags filtered",
        })
    return findings


async def run(agent: SwarmAgent) -> List[dict]:
    url = normalize_target_url(agent.target)
    if not url:
        return []
    timeout = min(agent.timeout_s, 8.0)
    qs = parse_qs(urlsplit(url).query)
    params = list(qs.keys()) if qs else list(_DEFAULT_PARAMS)
    params = params[:5]

    findings: list[dict] = []
    for p in params:
        try:
            findings.extend(await _probe_param(url, p, timeout))
        except Exception as e:  # noqa: BLE001
            logger.debug("xss probe %s?%s failed: %s", url, p, e)
    return findings


register_worker("vuln", TECHNIQUE, run)
