"""Clickjacking exposure probe (CWE-1021, detection only).

This worker is strictly READ-ONLY: it issues a single benign GET and
inspects the response headers. The page is reported FRAMEABLE only when
BOTH framing defences are absent / permissive:

  - X-Frame-Options is absent or set to a non-restrictive value
    (i.e. NOT DENY and NOT SAMEORIGIN), AND
  - Content-Security-Policy lacks a restrictive frame-ancestors directive
    (i.e. no `frame-ancestors 'none'` / `'self'` / explicit allow-list).

If X-Frame-Options is DENY/SAMEORIGIN, OR CSP carries a restrictive
frame-ancestors directive, the page is protected and NO finding is
emitted. The three corresponding FP guards are:

  - protected-by-XFO
  - protected-by-CSP-frame-ancestors
  - protected-by-SameSite-cookie

The SameSite guard mirrors the header guards: when the response sets a
session/auth cookie carrying SameSite=Strict (or Lax), a cross-site
iframe sends NO session cookie, so the framed page renders unauthenticated
and no state-changing action can be triggered through the overlay. A
clickjacking finding on such a page is a false positive, so it is
suppressed.

Severity is held at LOW: a missing X-Frame-Options header on its own is
low-impact without a sensitive, state-changing action on the page. The
evidence note makes that caveat explicit so triage can confirm a
clickjacking-worthy target action before escalating.

vuln_type always contains "clickjacking". CWE-1021.
"""

from __future__ import annotations

import logging
from typing import List, Optional

from core.swarm_engine import SwarmAgent
from core.swarm_workers import register_worker

from ._http import fetch, normalize_target_url

logger = logging.getLogger("viper.swarm_workers.vuln.clickjacking")

TECHNIQUE = "clickjacking"


def _xfo_protects(xfo: str) -> bool:
    """True if X-Frame-Options carries a restrictive value (DENY/SAMEORIGIN).

    A permissive ALLOW-FROM (deprecated, widely unsupported) or any
    unrecognised / empty value does NOT protect.
    """
    v = (xfo or "").strip().lower()
    if not v:
        return False
    # Header may be duplicated/comma-joined by upstream proxies; treat each
    # token independently. Only DENY / SAMEORIGIN are honoured by browsers.
    tokens = [t.strip() for t in v.replace(",", " ").split()]
    return "deny" in tokens or "sameorigin" in tokens


def _csp_frame_ancestors_value(csp: str) -> Optional[str]:
    """Return the `frame-ancestors` source-list (lowercased) if present, else None.

    `csp` is the raw Content-Security-Policy header value (possibly several
    policies comma-joined). Per spec, when multiple policies are present the
    most restrictive wins, so a frame-ancestors directive in ANY policy is
    enforced — we return the first one we find.
    """
    if not csp:
        return None
    # Multiple policies are comma-separated; directives within a policy are
    # semicolon-separated.
    for policy in csp.split(","):
        for directive in policy.split(";"):
            directive = directive.strip()
            if not directive:
                continue
            parts = directive.split(None, 1)
            if parts[0].lower() == "frame-ancestors":
                return (parts[1] if len(parts) > 1 else "").strip().lower()
    return None


def _csp_protects(csp: str) -> bool:
    """True if CSP carries a restrictive frame-ancestors directive.

    A present `frame-ancestors` directive is restrictive UNLESS its source
    list is wildcard-permissive (`*` or `http:`/`https:` scheme-only, which
    allow any origin to frame). `'none'`, `'self'`, and explicit host
    allow-lists all protect.
    """
    value = _csp_frame_ancestors_value(csp)
    if value is None:
        return False  # directive absent → no framing protection from CSP
    sources = value.split()
    if not sources:
        return False  # `frame-ancestors` with empty list == 'none' (restrictive)
    # Permissive wildcards that defeat the directive.
    permissive = {"*", "http:", "https:", "http://*", "https://*"}
    if all(s in permissive for s in sources):
        return False
    return True


# Cookie names that indicate an authenticated/session context. A cross-site
# iframe only fails to carry SUCH cookies — a SameSite guard on a non-session
# cookie (e.g. a CSRF or locale cookie) does not neutralise clickjacking, so we
# require the protected cookie to look session-bearing before suppressing.
_SESSION_COOKIE_HINTS = (
    "session", "sess", "sid", "auth", "token", "jwt", "login",
    "csrftoken", "remember", "secure",
)


def _samesite_session_cookie_present(set_cookie: str) -> bool:
    """True if any Set-Cookie sets a SESSION-LIKE cookie with SameSite=Strict|Lax.

    `set_cookie` is the raw (possibly multi-cookie comma-joined) Set-Cookie
    header value. Each cookie is `name=value; Attr; Attr=val; ...`. A cookie is
    a clickjacking mitigation only when BOTH hold:

      - its name looks session/auth-bearing (so a cross-site frame loses the
        session and cannot drive a state-changing action), AND
      - it carries SameSite=Strict or SameSite=Lax (Lax already blocks the
        cookie on cross-site sub-resource/iframe loads).

    SameSite=None (or absent → browser-default, increasingly Lax but explicitly
    cross-site when None) does NOT protect.
    """
    if not set_cookie:
        return False
    # Splitting multiple cookies on comma is ambiguous (Expires dates contain
    # commas), but we only inspect the cookie NAME (before the first '=') and
    # the SameSite attribute, both comma-free, so a coarse split is safe enough.
    # Inspect the whole header per-cookie by splitting on the cookie boundary
    # heuristically: a new cookie starts after "; " is unlikely — cookies are
    # joined with ", ". We scan the raw string for any session-name token that
    # is followed (within its own cookie) by a SameSite=Strict/Lax attribute.
    raw = set_cookie
    # Normalise: split into candidate cookie segments. urllib joins duplicate
    # Set-Cookie headers with ", "; within one cookie attributes use "; ".
    # Re-join then re-split on ", " that precedes a `name=` token.
    segments = [seg.strip() for seg in raw.split(",") if seg.strip()]
    # Re-merge segments that are actually Expires continuations (a date like
    # "Wed" / "09 Jun 2027 ...") — those start with a weekday or digit and have
    # no '=' before the first ';'.
    cookies: list[str] = []
    for seg in segments:
        head = seg.split(";", 1)[0]
        if "=" in head and not head.strip().lower().startswith(
            ("mon", "tue", "wed", "thu", "fri", "sat", "sun")
        ):
            cookies.append(seg)
        elif cookies:
            cookies[-1] = cookies[-1] + ", " + seg
        else:
            cookies.append(seg)

    for cookie in cookies:
        attrs = [a.strip() for a in cookie.split(";")]
        if not attrs:
            continue
        name = attrs[0].split("=", 1)[0].strip().lower()
        if not name:
            continue
        if not any(hint in name for hint in _SESSION_COOKIE_HINTS):
            continue
        samesite = ""
        for a in attrs[1:]:
            if a.lower().startswith("samesite"):
                _, _, val = a.partition("=")
                samesite = val.strip().lower()
                break
        if samesite in ("strict", "lax"):
            return True
    return False


async def run(agent: SwarmAgent) -> List[dict]:
    url = normalize_target_url(agent.target)
    if not url:
        return []
    timeout = min(agent.timeout_s, 10.0)
    findings: list[dict] = []

    resp = await fetch("GET", url, timeout=timeout)
    if not resp:
        return findings

    xfo = (resp.headers.get("x-frame-options") or "").strip()
    csp = (resp.headers.get("content-security-policy") or "").strip()
    set_cookie = (resp.headers.get("set-cookie") or "").strip()

    # FP guard 1: protected-by-XFO
    if _xfo_protects(xfo):
        logger.debug("clickjacking: protected-by-XFO (%r) — no finding", xfo)
        return findings

    # FP guard 2: protected-by-CSP-frame-ancestors
    if _csp_protects(csp):
        logger.debug("clickjacking: protected-by-CSP-frame-ancestors — no finding")
        return findings

    # FP guard 3: protected-by-SameSite-cookie
    # If the page establishes its session/auth via a SameSite=Strict|Lax cookie,
    # a cross-site iframe carries NO session, so the framed page is
    # unauthenticated and no state-changing action can be reached through the
    # clickjacking overlay. Suppress the finding.
    if _samesite_session_cookie_present(set_cookie):
        logger.debug(
            "clickjacking: protected-by-SameSite-cookie — no finding")
        return findings

    # FRAMEABLE: both defences absent/permissive.
    fa = _csp_frame_ancestors_value(csp)
    csp_note = (
        f"CSP frame-ancestors='{fa}' is permissive"
        if fa is not None
        else "CSP has no frame-ancestors directive"
    )
    findings.append({
        "type": "clickjacking",
        "vuln_type": "clickjacking_frameable",
        "title": "Clickjacking: page can be framed (no X-Frame-Options / CSP frame-ancestors)",
        "severity": "low",
        "url": resp.final_url or url,
        "cwe": "CWE-1021",
        "confidence": 0.6,
        "evidence": (
            f"X-Frame-Options={xfo or '(absent)'}; {csp_note}. "
            "Page is FRAMEABLE — both framing defences absent/permissive. "
            "Impact is LOW unless the page hosts a sensitive, state-changing "
            "action (e.g. fund transfer, settings change, one-click purchase) "
            "that an attacker can trick a victim into triggering via an "
            "overlaid transparent iframe."
        ),
    })

    return findings


register_worker("vuln", TECHNIQUE, run)
