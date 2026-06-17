"""CSRF / missing anti-CSRF protection probe (detection only).

This worker is strictly READ-ONLY. It never submits a state-changing
request. It fetches the base page, parses any HTML <form> elements, and
flags:

  - A state-changing form (method=POST) that carries NO recognised
    anti-CSRF token field AND whose session cookie (from Set-Cookie on the
    base response) lacks SameSite=Lax/Strict. Missing SameSite means the
    browser will attach the cookie on a cross-site POST, so the form is
    forgeable.
  - A JSON API POST endpoint that accepts a "simple" cross-site
    Content-Type (text/plain) without requiring a CSRF token/header. This
    is probed with a benign, non-mutating GET-only baseline plus an
    OPTIONS preflight check — we do NOT POST real data.

Recognised token field names: csrf, csrf_token, _token,
authenticity_token, xsrf, __requestverificationtoken (case-insensitive).

CWE-352. vuln_type always contains "csrf".
"""

from __future__ import annotations

import logging
import re
from html.parser import HTMLParser
from typing import List, Optional
from urllib.parse import urljoin, urlsplit

from core.swarm_engine import SwarmAgent
from core.swarm_workers import register_worker

from ._http import HttpResp, fetch, normalize_target_url

logger = logging.getLogger("viper.swarm_workers.vuln.csrf")

TECHNIQUE = "csrf"

# Anti-CSRF token field / header name fragments (lowercased, substring match).
_TOKEN_NAMES = (
    "csrf",
    "csrf_token",
    "_token",
    "authenticity_token",
    "xsrf",
    "__requestverificationtoken",
)

# Headers that, if present, indicate a token-style anti-CSRF defence.
_TOKEN_HEADER_HINTS = ("x-csrf-token", "x-xsrf-token", "csrf-token", "x-requested-with")


def _has_token_name(name: str) -> bool:
    n = (name or "").lower()
    return any(tok in n for tok in _TOKEN_NAMES)


class _FormParser(HTMLParser):
    """Collect <form> elements with their method, action and input names."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.forms: list[dict] = []
        self._cur: Optional[dict] = None

    def handle_starttag(self, tag: str, attrs: list) -> None:
        a = {k.lower(): (v or "") for k, v in attrs}
        if tag == "form":
            self._cur = {
                "method": a.get("method", "get").strip().lower(),
                "action": a.get("action", "").strip(),
                "inputs": [],
            }
            self.forms.append(self._cur)
        elif tag in ("input", "button", "textarea", "select") and self._cur is not None:
            name = a.get("name", "")
            if name:
                self._cur["inputs"].append(name)

    def handle_endtag(self, tag: str) -> None:
        if tag == "form":
            self._cur = None


def _parse_forms(body: str) -> list[dict]:
    p = _FormParser()
    try:
        p.feed(body or "")
    except Exception as e:  # noqa: BLE001 — malformed HTML must not raise
        logger.debug("form parse error: %s", e)
    return p.forms


def _session_cookie_lacks_samesite(set_cookie: str) -> Optional[str]:
    """Return the session cookie name if a session-ish cookie lacks
    SameSite=Lax/Strict, else None.

    `set_cookie` is the raw (possibly comma-joined) Set-Cookie header value.
    We split conservatively on newlines / cookie boundaries and inspect each
    cookie individually.
    """
    if not set_cookie:
        return None
    # urllib joins multiple Set-Cookie headers with ", ". Split on commas that
    # precede a "name=" pair (avoids splitting inside Expires=...,GMT dates).
    parts = re.split(r",(?=\s*[A-Za-z0-9_\-]+=)", set_cookie)
    for raw in parts:
        cookie = raw.strip()
        if not cookie or "=" not in cookie:
            continue
        attrs = [seg.strip() for seg in cookie.split(";")]
        name = attrs[0].split("=", 1)[0].strip().lower()
        # Heuristic: only care about session/auth cookies.
        if not any(k in name for k in ("session", "sess", "auth", "sid", "token", "login")):
            continue
        samesite = ""
        for seg in attrs[1:]:
            if seg.lower().startswith("samesite"):
                samesite = seg.split("=", 1)[-1].strip().lower() if "=" in seg else ""
                break
        if samesite not in ("lax", "strict"):
            return attrs[0].split("=", 1)[0].strip()
    return None


async def run(agent: SwarmAgent) -> List[dict]:
    url = normalize_target_url(agent.target)
    if not url:
        return []
    timeout = min(agent.timeout_s, 10.0)
    findings: list[dict] = []

    # --- Base page (read-only GET) -----------------------------------------
    # use_session_auth=False: the CSRF finding keys on the Set-Cookie the server
    # mints for a fresh/anonymous visitor (a SameSite-less SESSION cookie). With
    # the hunt's global session merged in, an already-authenticated request gets
    # no Set-Cookie and the finding is silently suppressed (false negative).
    resp = await fetch("GET", url, timeout=timeout, use_session_auth=False)
    if not resp:
        return findings

    set_cookie = resp.headers.get("set-cookie", "") or ""
    weak_session_cookie = _session_cookie_lacks_samesite(set_cookie)

    # --- Test 1: HTML forms missing CSRF token + weak SameSite -------------
    seen_actions: set[str] = set()
    for form in _parse_forms(resp.body):
        if form["method"] != "post":
            continue  # only state-changing forms
        if any(_has_token_name(n) for n in form["inputs"]):
            continue  # token present → defended
        action = form["action"]
        form_url = urljoin(resp.final_url or url, action) if action else (resp.final_url or url)
        if form_url in seen_actions:
            continue
        seen_actions.add(form_url)

        # Only flag when the browser would actually attach the session cookie
        # cross-site, i.e. the session cookie lacks SameSite=Lax/Strict.
        if weak_session_cookie:
            findings.append({
                "type": "csrf",
                "vuln_type": "csrf_missing_token",
                "title": "CSRF: state-changing POST form lacks anti-CSRF token (cookie lacks SameSite)",
                "severity": "medium",
                "url": form_url,
                "cwe": "CWE-352",
                "confidence": 0.7,
                "evidence": (
                    f"POST form action={action or '(self)'} has no anti-CSRF token field; "
                    f"session cookie '{weak_session_cookie}' has no SameSite=Lax/Strict"
                ),
                "parameter": ",".join(form["inputs"][:8]) or None,
            })

    # --- Test 2: JSON API POST accepts cross-site Content-Type, no token ----
    # We do NOT POST. We use an OPTIONS preflight to learn whether the
    # endpoint advertises a CSRF token requirement or restricts content types.
    api_target = _guess_api_endpoint(resp, url)
    if api_target:
        opt = await fetch(
            "OPTIONS",
            api_target,
            headers={
                "Origin": "https://csrf-probe.example",
                "Access-Control-Request-Method": "POST",
                "Access-Control-Request-Headers": "content-type",
            },
            timeout=timeout,
        )
        if opt is not None:
            allow_headers = (opt.headers.get("access-control-allow-headers") or "").lower()
            allow_methods = (opt.headers.get("access-control-allow-methods") or "").lower()
            requires_token = any(h in allow_headers for h in _TOKEN_HEADER_HINTS)
            # A POST-capable JSON endpoint that does NOT require any CSRF
            # token/header, and which would accept a simple cross-site
            # Content-Type, is forgeable.
            if "post" in allow_methods and not requires_token:
                findings.append({
                    "type": "csrf",
                    "vuln_type": "csrf_json_api",
                    "title": "CSRF: JSON API POST endpoint accepts cross-site request without CSRF token/header",
                    "severity": "low",
                    "url": api_target,
                    "cwe": "CWE-352",
                    "confidence": 0.5,
                    "evidence": (
                        f"OPTIONS preflight: Allow-Methods='{allow_methods}', "
                        f"Allow-Headers='{allow_headers or '(none)'}' — no CSRF token/header required"
                    ),
                })

    return findings


def _guess_api_endpoint(resp: HttpResp, base_url: str) -> Optional[str]:
    """Find a plausible JSON API POST endpoint referenced by the base page.

    Read-only: derives a candidate URL from <form action> targeting an /api/
    path, or from an action/href that looks like a JSON API. Returns None if
    nothing credible is found (keeps FP low — we only preflight real paths).
    """
    body = resp.body or ""
    base = resp.final_url or base_url
    # Look for /api/... paths in form actions or fetch() calls in inline JS.
    candidates = re.findall(r"""['"]((?:https?://[^'"\s]+)?/[^'"\s]*?\bapi/[^'"\s]{1,80})['"]""", body)
    for c in candidates:
        cand = urljoin(base, c)
        # Same-origin only — never preflight off-origin hosts.
        if urlsplit(cand).netloc == urlsplit(base).netloc:
            return cand
    return None


register_worker("vuln", TECHNIQUE, run)