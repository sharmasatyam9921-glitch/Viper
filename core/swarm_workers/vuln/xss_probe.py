"""Reflected-XSS probe (non-destructive).

Sends a uniquely-marked benign payload to each parameter and checks if
the marker appears unencoded in the response. Does NOT execute JS — the
marker is constructed so a real XSS would echo it back verbatim.
"""

from __future__ import annotations

import asyncio
import logging
import re
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

# XML-family content types (plus the sniffable-empty case) where '<'/'>' inside
# a CDATA section or a comment is inert character data, NOT markup. A reflection
# that survives ONLY in such an inert region is not XSS, so we strip those
# regions before substring-matching. Search/data feeds (Atom/RSS/OpenSearch/SRU)
# routinely wrap user input in CDATA, which is exactly this case.
_XML_FAMILY_CTYPES = {
    "application/xml",
    "text/xml",
    "image/svg+xml",
    "application/xhtml+xml",
    "",
}

# <![CDATA[ ... ]]> — minimal match so adjacent sections aren't merged.
_CDATA_RE = re.compile(r"<!\[CDATA\[.*?\]\]>", re.DOTALL)
# <!-- ... --> XML/HTML comments — also inert.
_COMMENT_RE = re.compile(r"<!--.*?-->", re.DOTALL)


def _content_type(resp) -> str:
    return (resp.headers.get("content-type") or "").split(";")[0].strip().lower()


def _strip_inert_regions(body: str, ctype: str) -> str:
    """For XML-family responses, remove CDATA sections and comments.

    Inside <![CDATA[...]]> or <!-- ... -->, angle brackets are character data,
    not markup — a payload reflected only there cannot execute. Stripping them
    before matching prevents a HIGH-severity false positive on XML search feeds
    that echo the query verbatim inside CDATA. Non-XML responses are returned
    unchanged (HTML comments can still host markup-adjacent injection, and the
    existing content-type gate already handles those credibly)."""
    if ctype not in _XML_FAMILY_CTYPES:
        return body
    body = _CDATA_RE.sub("", body)
    body = _COMMENT_RE.sub("", body)
    return body


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
    if resp is None:
        return []
    _waf = ""
    # If a WAF blocked the raw payload, try to slip a mutated variant past it and
    # re-run the SAME reflection differential on the bypassed response. This runs
    # ONLY on a block (the happy path is unchanged), and the differential is not
    # relaxed — a total block emits nothing (never a fabricated success).
    from core.waf_bypass import is_blocked as _looks_blocked
    if _looks_blocked(resp):
        from ._bypass import adaptive_fetch

        def _build(variant: str) -> str:
            return add_query(url, param, variant)

        res = await adaptive_fetch("GET", _build, payload, timeout=timeout,
                                   follow_redirects=False)
        if res.blocked or res.response is None:
            return []
        if res.bypassed:
            resp = res.response
            test_url = _build(res.payload)
            _waf = f" (WAF-bypassed via {res.label})"
    if not resp.body:
        return []
    # Content-type gate: reflection is only XSS in an HTML/XML/SVG (or
    # sniffable) context. JSON/plain/csv/js echoes are inert data, not XSS.
    if not _html_context(resp):
        return []
    # Strip inert regions (CDATA + comments) from XML-family responses: a
    # reflection that survives only inside <![CDATA[...]]> or <!-- ... --> is
    # character data, not markup, and cannot execute. This kills the XML
    # search-feed false positive without weakening live-markup detection.
    body = _strip_inert_regions(resp.body, _content_type(resp))
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
            "evidence": "full HTML payload reflected unencoded in response" + _waf,
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
            "evidence": f"marker tag <{marker}> reflected; full payload was filtered" + _waf,
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
            "evidence": "marker reflected as text; HTML tags filtered" + _waf,
        })
    return findings


async def run(agent: SwarmAgent) -> List[dict]:
    url = normalize_target_url(agent.target)
    if not url:
        return []
    timeout = min(agent.timeout_s, 8.0)
    qs = parse_qs(urlsplit(url).query)
    params = list(qs.keys()) if qs else list(_DEFAULT_PARAMS)
    # Append crawler-discovered param names (empty unless a hunt populated them),
    # so a URL like /reflect?x=1 still probes the app's real 'q'/'search'/etc.
    from core.payload_library import get_discovered_params
    disc = get_discovered_params()
    if disc:
        # URL's own params + the worker defaults FIRST (highest signal), then the
        # broader discovered/seeded set. Cap is generous so crawl/form-discovered
        # params are never crowded out by seeded access-control param names.
        params = list(dict.fromkeys(params + list(_DEFAULT_PARAMS) + disc))[:32]
    else:
        params = params[:5]

    # Each param's probe is fully self-contained (its own unique marker, its own
    # request/differential), so they run concurrently (bounded) for speed without
    # affecting each other's verdict. Order is preserved by asyncio.gather.
    _sem = asyncio.Semaphore(6)

    async def _one(p: str) -> List[dict]:
        async with _sem:
            try:
                return await _probe_param(url, p, timeout)
            except Exception as e:  # noqa: BLE001
                logger.debug("xss probe %s?%s failed: %s", url, p, e)
                return []
    groups = await asyncio.gather(*[_one(p) for p in params])
    return [f for g in groups for f in g]


register_worker("vuln", TECHNIQUE, run)
