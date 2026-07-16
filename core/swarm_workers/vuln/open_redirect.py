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

# A js_location match is only a redirect if the assignment runs at page LOAD —
# not inside a user-gesture handler (addEventListener("click",...)/onclick).
# (Code that is merely displayed/disabled inside an inert region — HTML
# comments, <code>/<pre>/<template>/<noscript>/<textarea>, non-JS <script type>
# — is removed up front by _INERT_RE in _detect, so it never reaches this gate.)
# The round-1 audit FP was a safe interstitial that reflected the URL into a
# click handler. We look at the context immediately BEFORE the assignment for
# handler/gesture markers; if any is present the assignment is gated behind
# interaction and is NOT an open redirect.
_JS_GESTURE_RE = re.compile(
    r"""addeventlistener\s*\(\s*['"](?:click|mousedown|mouseup|submit|"""
    r"""touchstart|touchend|keydown|keyup|keypress|change|focus|blur)['"]"""
    r"""|on(?:click|mousedown|mouseup|submit|touchstart|touchend|keydown|"""
    r"""keyup|keypress|change|focus|blur)\s*=""",
    re.IGNORECASE,
)
# How many characters of preceding context to inspect for a gesture marker.
_JS_CONTEXT_WINDOW = 200

# Inert regions whose contents a browser NEVER executes: HTML comments, and the
# text content of <pre>/<code>/<template>/<noscript>/<textarea> and non-JS
# <script type=...> blocks (JSON, templates). Redirect-looking code inside any
# of these is documentation, disabled legacy code, or data — not a real
# redirect. We strip them from the body BEFORE running _META_RE / _JS_RE so
# commented-out or quoted redirect code is never treated as evidence. The
# Location-header channel reads only headers and is unaffected.
_INERT_RE = re.compile(
    r"<!--.*?-->"
    r"|<(pre|code|template|noscript|textarea)\b[^>]*>.*?</\1>"
    r"|<script[^>]*type\s*=\s*['\"]?"
    r"(?:text/(?:plain|template)|application/json|application/ld\+json)"
    r"['\"]?[^>]*>.*?</script>",
    re.IGNORECASE | re.DOTALL,
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


def _js_assignment_is_load_time(body: str, match: "re.Match[str]") -> bool:
    """True if a `location = "..."` match runs at page load, not on a gesture.

    A browser only follows a `location.href = ...` automatically when it
    executes as the script loads. If the assignment sits inside a click/submit
    handler (``addEventListener("click", ...)`` / ``onclick=``) the user must
    interact first — that is a SAFE interstitial pattern, not an open redirect.
    We inspect the preceding context for a gesture marker; if one is present the
    assignment is gated behind interaction and is not redirect evidence.

    Note: `body` here is already the inert-stripped scan body, so matches inside
    HTML comments or inert containers (<code>/<pre>/<template>/<noscript>/
    <textarea>/non-JS <script type>) never reach this function.
    """
    start = match.start()
    ctx = body[max(0, start - _JS_CONTEXT_WINDOW):start]
    return _JS_GESTURE_RE.search(ctx) is None


def detect_redirect_to(resp: HttpResp, host: str) -> Optional[tuple[str, str]]:
    """Return (channel, evidence_value) if `resp` actually REDIRECTS to `host`.

    Host-parametrized so the same detection logic serves two callers: the worker
    (which passes the fixed ``_ATTACKER_HOST``) and the validation gate (which
    passes a FRESH random host the server has never seen, so a hardcoded/echoed
    constant can't be mistaken for a parameter-driven redirect). A finding
    requires a REAL redirect to `host` — not a mere reflection in the body — so
    each channel is gated on redirect behavior: a 3xx Location, an auto-firing
    meta-refresh, or a load-time JS assignment (never a click-handler reflection).
    """
    host = (host or "").lower()
    if not host:
        return None
    # 1) Location header — only honor it on a real redirect status (3xx). A
    #    200/4xx response carrying a Location is not a redirect the browser
    #    follows, so a reflected/echoed Location on a 200 is not evidence.
    if 300 <= resp.status < 400:
        loc = (resp.headers.get("location") or "").strip()
        if loc and _host_of(loc) == host:
            return ("location_header", loc)

    body = resp.body or ""
    # Strip inert regions (HTML comments, <pre>/<code>/<template>/<noscript>/
    # <textarea>, non-JS <script type>) once, up front. Redirect code inside
    # these never executes, so the meta and JS channels must scan the stripped
    # body — otherwise disabled/legacy code (e.g. a commented-out
    # `location.href = ...`) or quoted samples read as live redirect evidence.
    scan_body = _INERT_RE.sub(" ", body)

    # 2) HTML meta-refresh — the browser follows this automatically (no user
    #    interaction), so a matching directive to `host` is a real redirect.
    m = _META_RE.search(scan_body)
    if m and _host_of(m.group(1)) == host:
        return ("meta_refresh", m.group(1).strip())

    # 3) JS location assignment — only when it executes at LOAD time. Reject
    #    assignments gated behind a user gesture (click/submit handlers): those
    #    are the safe-interstitial pattern that drove the audit false positive.
    for j in _JS_RE.finditer(scan_body):
        if _host_of(j.group(1)) != host:
            continue
        if _js_assignment_is_load_time(scan_body, j):
            return ("js_location", j.group(1).strip())

    return None


def _detect(resp: HttpResp) -> Optional[tuple[str, str]]:
    """Worker-side detection: does the response redirect to ``_ATTACKER_HOST``?"""
    return detect_redirect_to(resp, _ATTACKER_HOST)


async def run(agent: SwarmAgent) -> List[dict]:
    url = normalize_target_url(agent.target)
    if not url:
        return []
    timeout = min(agent.timeout_s, 10.0)
    findings: list[dict] = []
    seen_params: set[str] = set()

    # Test the parameters actually present on the discovered URL FIRST (a real
    # endpoint like /redirect?to= names its own redirect param), then the common
    # defaults. Without this, an injected param is added but the live one is
    # never exercised.
    from urllib.parse import parse_qsl, urlsplit
    existing = [k for k, _ in parse_qsl(urlsplit(url).query, keep_blank_values=True)]
    # Also probe recon-discovered params whose name looks redirect-ish (a real app's
    # own ?returnTo=/ ?next= that isn't in the static list). The gate re-injects a fresh
    # attacker host and requires it to be the actual redirect target, so a non-redirect
    # param probed here can never confirm — this only widens coverage, never precision.
    _redirish = ("redirect", "redir", "return", "returnurl", "next", "goto", "dest",
                 "destination", "continue", "forward", "callback", "url", "target", "rurl")
    disc: list[str] = []
    try:
        from core.payload_library import get_discovered_params
        disc = [p for p in get_discovered_params()
                if any(tok in p.lower() for tok in _redirish)]
    except Exception:  # noqa: BLE001
        disc = []
    # Cap total fan-out per URL for parity with cmdi ([:24]) / ssrf ([:5]) — bounded
    # even on a recon-heavy target; the gate still re-confirms each with a fresh host.
    params = list(dict.fromkeys([*existing, *disc, *REDIRECT_PARAMS]))[:24]

    for param in params:
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
