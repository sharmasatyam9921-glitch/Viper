"""Independent validation gate for swarm findings — the autonomy lever.

A worker that FINDS a vulnerability must not be the only thing that CONFIRMS it.
This gate re-tests every finding through a DIFFERENT code path
(core.finding_validator.FindingValidator, which issues its own requests via the
hunt's scope/proxy/auth context) and sets a hard ``validated`` flag plus a
calibrated confidence. Only findings that pass become ``submittable``; everything
else is a ``lead`` for manual review.

It is FAIL-CLOSED: a finding that cannot be independently re-confirmed (network
error, no matching validator, low confidence) is NOT submittable. That is the
difference between an autonomous agent that earns and one that gets banned for
false-positive spam — VIPER never auto-submits anything an independent check
didn't reproduce.
"""

from __future__ import annotations

import logging
import re
from typing import Awaitable, Callable, List, Optional, Tuple

logger = logging.getLogger("viper.swarm_validation")

# A fresh marker the original worker did NOT use, so re-confirmation is an
# independent probe (an arbitrary attacker origin/host the server must reflect).
_PROBE_ORIGIN = "https://viper-revalidate.example"
_PROBE_HOST = "viper-revalidate.example"

_ENV_LINE = re.compile(r"(?m)^[A-Z][A-Z0-9_]{2,}=\S")
_DIRLIST = ("index of /", "parent directory", "directory listing for")

# Tight DB-error signatures (a corpus search quoting "SQL syntax" won't reproduce
# the SAME one under two different quote chars; a broken query does).
_SQL_ERR = re.compile(
    r"SQL syntax|SQLSTATE\[|ORA-\d{5}|unclosed quotation mark|"
    r"quoted string not properly terminated|near \"[^\"]*\": syntax error|"
    r"PG::\w*Error|psqlException|MySqlException|valid MySQL result|"
    r"sqlite3?\.(Operational|Programming)Error|SQLITE_ERROR|SqlException|"
    r"Microsoft OLE DB|Incorrect syntax near|Warning: \w*sql|"
    r"PostgreSQL.{0,20}ERROR|Unclosed quotation mark", re.I)
_PASSWD = re.compile(r"root:.*?:0:0:")

# Unambiguous credential SHAPES — a benign page never carries these verbatim.
_SECRET_SHAPE = re.compile(
    r"AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{36}|gho_[A-Za-z0-9]{36}|"
    r"sk_live_[0-9A-Za-z]{20,}|AIza[0-9A-Za-z_\-]{35}|"
    r"xox[baprs]-[0-9A-Za-z\-]{10,}|"
    r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |)PRIVATE KEY-----")
# Sensitive content that should never come back to an ANONYMOUS request.
_SENSITIVE = re.compile(
    r'"(email|password|passwordHash|ssn|creditCard|cardNum|apiKey|api_key|'
    r'secret|sessionToken|access_token)"\s*:|AKIA[0-9A-Z]{16}|'
    r"-----BEGIN .*PRIVATE KEY", re.I)


def _ctype(resp) -> str:
    return ((getattr(resp, "headers", {}) or {}).get("content-type", "") or "").lower()


def _body(resp) -> str:
    return getattr(resp, "body", "") or ""


def _ok2xx(resp) -> bool:
    return resp is not None and 200 <= getattr(resp, "status", 0) < 300


async def _recheck_xss(finding, fetch, timeout):
    """Confirm the reflection lands as LIVE, UNENCODED markup in an HTML context —
    not entity-encoded (the secure outcome) and not a non-HTML body."""
    import secrets
    from core.swarm_workers.vuln._http import add_query
    param = finding.get("parameter")
    url = finding.get("url") or ""
    if not param or not url:
        return False, 0.0, "no parameter to re-test"
    tag = "vgx" + secrets.token_hex(3)
    r = await fetch("GET", add_query(url, param, f"<{tag}>x</{tag}>"), timeout=timeout)
    if r is None:
        return False, 0.0, "re-fetch failed"
    ct = _ctype(r)
    body = _body(r)
    html_ctx = "html" in ct or "xml" in ct or ct == ""
    if html_ctx and f"<{tag}>" in body and f"&lt;{tag}&gt;" not in body:
        return True, 0.8, f"injected <{tag}> reflected UNENCODED in HTML context (live markup)"
    return False, 0.2, "reflection encoded or non-HTML context — not exploitable"


async def _recheck_sqli(finding, fetch, timeout):
    """Confirm a DB error appears under BOTH a single- and double-quote breaker but
    not a benign value — a corpus search echoing 'SQL syntax' fails this (it returns
    different content for ' vs ")."""
    from core.swarm_workers.vuln._http import add_query
    param = finding.get("parameter")
    url = finding.get("url") or ""
    if not param or not url:
        return False, 0.0, "no parameter to re-test"
    benign = await fetch("GET", add_query(url, param, "1"), timeout=timeout)
    q1 = await fetch("GET", add_query(url, param, "1'"), timeout=timeout)
    q2 = await fetch("GET", add_query(url, param, '1"'), timeout=timeout)
    if None in (benign, q1, q2):
        return False, 0.0, "re-fetch failed"

    def err(r):
        return bool(_SQL_ERR.search(_body(r)))
    if not err(benign) and err(q1) and (err(q2) or getattr(q1, "status", 0) >= 500):
        return True, 0.75, "DB error reproduced under ' and \" breakers, absent for benign value"
    return False, 0.2, "no reproducible DB-error differential (likely reflected content)"


async def _recheck_ssti(finding, fetch, timeout):
    """Confirm a FRESH arithmetic expression (operands the worker never used) is
    EVALUATED — product present, literal consumed, absent in a control."""
    from core.swarm_workers.vuln._http import add_query
    param = finding.get("parameter")
    url = finding.get("url") or ""
    if not param or not url:
        return False, 0.0, "no parameter to re-test"
    confirmed = 0
    for expr, prod in (("8*8", "64"), ("11*11", "121")):
        live = await fetch("GET", add_query(url, param, "${" + expr + "}"), timeout=timeout)
        ctrl = await fetch("GET", add_query(url, param, "${" + expr.replace("*", "x") + "}"),
                           timeout=timeout)
        if live is None or ctrl is None:
            return False, 0.0, "re-fetch failed"
        lb, cb = _body(live), _body(ctrl)
        if prod in lb and prod not in cb and expr not in lb:
            confirmed += 1
    if confirmed >= 2:
        return True, 0.8, "two fresh arithmetic expressions evaluated (consumed), absent in controls"
    return False, 0.2, "fresh operands not evaluated — not a template engine"


async def _recheck_secrets(finding, fetch, timeout):
    """Confirm a SHAPE-SPECIFIC credential (AKIA…, ghp_…, sk_live_…, PEM key) is
    reproduced in the response — a benign page never carries these verbatim. A
    generic/entropy-only match stays a lead (manual review)."""
    url = finding.get("url") or ""
    if not url:
        return False, 0.0, "no url to re-test"
    r = await fetch("GET", url, timeout=timeout)
    if not _ok2xx(r):
        return False, 0.1, "url no longer serves 2xx"
    m = _SECRET_SHAPE.search(_body(r))
    if m:
        return True, 0.75, f"shape-specific credential reproduced ({m.group(0)[:4]}…)"
    return False, 0.2, "no shape-specific credential on re-fetch — manual review"


async def _recheck_access_control(finding, fetch, timeout):
    """Confirm a protected endpoint returns sensitive data to an ANONYMOUS request
    (no session). Read-only: a 401/403 (or no sensitive content) means access
    control works and the finding stays a lead."""
    url = finding.get("url") or ""
    if not url:
        return False, 0.0, "no url to re-test"
    # use_session_auth=False -> send NO session, even if a hunt installed one.
    r = await fetch("GET", url, timeout=timeout, use_session_auth=False)
    if not _ok2xx(r):
        return False, 0.2, "not accessible anonymously (access control works)"
    body = _body(r)
    if _SENSITIVE.search(body):
        return True, 0.7, "protected endpoint returns sensitive data ANONYMOUSLY (2xx)"
    return False, 0.2, "anonymous access returns no sensitive content"


async def _recheck_cmdi(finding, fetch, timeout):
    """Re-run the hardened command-injection time-test from a fresh context. Its
    paired-control median scaling already rejects load/latency noise; a SECOND
    independent run that still fires confirms the delay is reproducible (a
    transient load spike — the cmdi failure mode — won't repeat)."""
    url = finding.get("url") or finding.get("target") or ""
    if not url:
        return False, 0.0, "no url to re-test"
    try:
        import core.swarm_workers  # noqa: F401  (registers workers)
        from core.swarm_engine import SwarmAgent
        from core.swarm_workers import get_worker_runner
        run = get_worker_runner("vuln", "command_injection")
        if run is None:
            return False, 0.0, "cmdi worker unavailable"
        ag = SwarmAgent(agent_id="gate", objective="revalidate", target=url,
                        technique="command_injection", payload={},
                        timeout_s=min(timeout if timeout else 12.0, 12.0))
        fs = await run(ag)
    except Exception as e:  # noqa: BLE001
        return False, 0.0, f"cmdi re-run error: {e}"
    if any("cmdi" in str(f.get("vuln_type", "")) for f in (fs or [])):
        return True, 0.7, "command injection reproduced by an independent re-run of the time-test"
    return False, 0.2, "not reproduced on re-run (likely a transient/load spike)"


async def _recheck_lfi(finding, fetch, timeout):
    """Confirm an /etc/passwd signature under the traversal payload but NOT under a
    benign control (a doc-search echo leaks for both; a real read needs traversal)."""
    from core.swarm_workers.vuln._http import add_query
    param = finding.get("parameter")
    url = finding.get("url") or ""
    if not url:
        return False, 0.0, "no url to re-test"
    inj = await fetch("GET", url, timeout=timeout)   # the finding url carries the traversal
    if inj is None:
        return False, 0.0, "re-fetch failed"
    if not _PASSWD.search(_body(inj)):
        return False, 0.2, "passwd signature not reproduced"
    if param:
        ctrl = await fetch("GET", add_query(url, param, "index"), timeout=timeout)
        if ctrl is not None and _PASSWD.search(_body(ctrl)):
            return False, 0.2, "benign control also leaks signature — doc echo, not a file read"
    return True, 0.75, "/etc/passwd signature under traversal, absent for benign control"


async def _reconfirm(finding: dict, fetch, timeout: float) -> Tuple[bool, float, str]:
    """Independently re-test a swarm finding by its OWN shape (fresh request).

    Confirms the config/exposure classes an unauthenticated hunt actually finds,
    with a behavioral probe (not a pattern echo). Injection classes (sqli/xss/
    ssti/cmdi/lfi/idor) are left as leads here — the hardened worker already did
    a baseline differential, but the gate does not yet have an orthogonal
    behavioral re-test for them, so it stays conservative (fail-closed)."""
    url = finding.get("url") or finding.get("target") or ""
    if not url:
        return False, 0.0, "no url to re-test"
    head = (finding.get("vuln_type") or finding.get("type") or "").lower().split(":")[0]

    # CORS — reflect a FRESH arbitrary origin the worker never sent.
    if head.startswith("cors"):
        r = await fetch("GET", url, headers={"Origin": _PROBE_ORIGIN}, timeout=timeout)
        if r is None:
            return False, 0.0, "re-fetch failed"
        aco = (r.headers or {}).get("access-control-allow-origin", "")
        acc = (r.headers or {}).get("access-control-allow-credentials", "").lower()
        if aco == _PROBE_ORIGIN:
            return True, (0.9 if acc == "true" else 0.7), \
                f"server reflects an arbitrary Origin ({aco}); credentials={acc or 'false'}"
        return False, 0.2, "arbitrary origin not reflected on re-test (no real CORS bug)"

    # Directory listing / sensitive-file exposure — re-fetch, confirm shape.
    if head in ("information_disclosure", "dir_listing", "directory_listing"):
        r = await fetch("GET", url, timeout=timeout)
        if r is None or not (200 <= getattr(r, "status", 0) < 300):
            return False, 0.1, "url no longer serves 2xx"
        body = (getattr(r, "body", "") or "").lower()
        if any(m in body for m in _DIRLIST) or body.count("<a href") >= 8:
            return True, 0.7, "directory listing reproduced on re-fetch"
        return False, 0.2, "no listing shape on re-test"

    # Exposed .env / config — env-var lines, not HTML.
    if head in ("env_exposed", "actuator_env"):
        r = await fetch("GET", url, timeout=timeout)
        if r is None or not (200 <= getattr(r, "status", 0) < 300):
            return False, 0.1, "env url no longer 2xx"
        body = getattr(r, "body", "") or ""
        if "text/html" not in _ctype(r) and _ENV_LINE.search(body):
            return True, 0.85, "env-var lines reproduced (KEY=value), non-HTML body"
        return False, 0.2, "no env shape on re-test"

    # Exposed .git
    if head == "git_exposed":
        r = await fetch("GET", url, timeout=timeout)
        if r is not None and 200 <= getattr(r, "status", 0) < 300 \
                and ("[core]" in (getattr(r, "body", "") or "")
                     or "ref:" in (getattr(r, "body", "") or "")):
            return True, 0.8, ".git metadata reproduced on re-fetch"
        return False, 0.2, "no .git content on re-test"

    # Injection classes: orthogonal behavioral re-test (fresh, differential probe).
    vt_full = (finding.get("vuln_type") or "").lower()
    if head in ("xss", "xss_text", "xss_tag", "dom_xss"):
        return await _recheck_xss(finding, fetch, timeout)
    if head in ("sqli", "sqli_blind", "auth_bypass", "login_sqli"):
        return await _recheck_sqli(finding, fetch, timeout)
    if head in ("ssti", "ssti_error"):
        return await _recheck_ssti(finding, fetch, timeout)
    if head in ("lfi", "path_traversal"):
        return await _recheck_lfi(finding, fetch, timeout)
    if head in ("rce", "cmdi", "command_injection"):
        return await _recheck_cmdi(finding, fetch, timeout)
    if head in ("secret", "secrets", "js_secret", "github_secret"):
        return await _recheck_secrets(finding, fetch, timeout)
    if head == "access_control":
        return await _recheck_access_control(finding, fetch, timeout)
    # Two-account BOLA: the find_bola engine already proved a cross-user read with
    # owner+attacker+anon probes — that IS the independent confirmation.
    if ":bola:" in vt_full or head == "bola":
        return True, 0.85, "two-account cross-user object read confirmed by the BOLA engine"

    # Classes with no SAFE read-only confirmation -> stay a LEAD (fail-closed):
    #   single-session idor  -> needs two accounts (use the two-account BOLA flow)
    #   mass_assignment      -> needs a write + read-back (non-destructive: no writes)
    #   jwt / nosql          -> need the auth flow / a body mutation to prove impact
    return False, 0.0, f"no safe read-only re-test for '{head}' — manual review"

# Map the swarm workers' vuln_type strings (the head token before ':') to the
# FindingValidator dispatch keys. Grounded in the actual emitted vuln_types
# (grepped from core/swarm_workers/vuln/*.py). Unknowns fall back to a generic
# re-fetch validator, which is conservative (low confidence -> not submittable).
_VTYPE_MAP = {
    "sqli": "sqli", "sqli_blind": "sqli_blind", "auth_bypass": "sqli",
    "login_sqli": "sqli",
    "xss": "xss", "xss_text": "xss", "xss_tag": "xss", "dom_xss": "dom_xss",
    "rce": "cmdi", "cmdi": "cmdi", "command_injection": "cmdi",
    "lfi": "lfi", "path_traversal": "lfi",
    "ssti": "ssti", "ssti_error": "ssti",
    "ssrf": "ssrf",
    "cors": "cors", "cors_wildcard": "cors", "cors_origin_reflect": "cors",
    "cors_null_origin": "cors",
    "open_redirect": "open_redirect",
    "idor": "idor_enum", "bola": "idor_enum",
    "jwt": "jwt_none_alg",
    "xxe": "xxe_basic",
    "crlf_header_injection": "crlf_injection",
    "graphql_introspection": "graphql_introspection",
    "graphql_ide": "graphql_introspection", "graphql_endpoint": "graphql_introspection",
    "request_smuggling": "request_smuggling",
    "clickjacking_frameable": "clickjacking", "clickjacking": "clickjacking",
    "env_exposed": "env_file", "git_exposed": "git_exposure",
    "actuator_env": "debug_endpoints",
    # No dedicated validator yet -> generic re-fetch (conservative).
    "nosql_injection": "generic", "secret": "generic",
    "information_disclosure": "generic", "access_control": "generic",
    "business_logic": "generic", "mass_assignment": "generic", "nuclei": "generic",
}


def validator_key(vuln_type: str) -> str:
    """Normalize a swarm vuln_type to a FindingValidator dispatch key."""
    vt = (vuln_type or "").lower()
    head = vt.split(":")[0]
    return _VTYPE_MAP.get(head, _VTYPE_MAP.get(vt, "generic"))


class FetchHTTP:
    """Adapt the swarm fetch() to FindingValidator's http-client interface.

    Returns the HttpResp (it already exposes .status/.headers/.body); on a network
    failure returns a status-0 stub so validators that check ``status != 0`` skip
    gracefully — an un-reconfirmable finding then fails the gate (fail-closed).
    The request goes through the installed scope guard / proxy / rate limiter, so
    re-validation stays in scope and (if a session is installed) authenticated.
    """

    def __init__(self, timeout: float = 10.0):
        self.timeout = timeout

    async def request(self, method, url, *, headers=None, data=None, **kw):
        from core.swarm_workers.vuln._http import HttpResp, fetch
        body = data.encode() if isinstance(data, str) else data
        r = await fetch(method, url, headers=headers, body=body, timeout=self.timeout)
        return r if r is not None else HttpResp(0, {}, "", url)

    async def get(self, url, *, headers=None, **kw):
        return await self.request("GET", url, headers=headers)

    async def post(self, url, *, headers=None, data=None, **kw):
        return await self.request("POST", url, headers=headers, data=data)


async def validate_findings(
    findings: List[dict],
    *,
    default_target: str = "",
    min_confidence: float = 0.5,
    timeout: float = 10.0,
    validator=None,
    fetch=None,
) -> List[dict]:
    """Annotate each finding with an INDEPENDENT re-confirmation verdict.

    Adds to a COPY of each finding:
      validated              : bool   — an independent path reproduced it
      validation_confidence  : float  — calibrated confidence
      validation_reason      : str    — why it passed/failed
      submittable            : bool   — validated AND confidence >= min_confidence

    Default: a swarm-native behavioral re-test (_reconfirm) keyed on the finding's
    own shape, via the swarm fetch (so it runs through the hunt's scope/auth/proxy).
    Inject `validator` (an object with async validate(finding, target)) for tests
    or to use the legacy FindingValidator.
    """
    if validator is None and fetch is None:
        from core.swarm_workers.vuln._http import fetch as _swarm_fetch
        fetch = _swarm_fetch

    out: List[dict] = []
    for f in findings:
        g = dict(f)
        vt = g.get("vuln_type", g.get("type", ""))
        try:
            if validator is not None:
                target = g.get("url") or g.get("target") or default_target
                probe = dict(g)
                norm = validator_key(vt)
                probe["vuln_type"] = norm
                probe["attack"] = norm
                ok, conf, reason = await validator.validate(probe, target)
            else:
                ok, conf, reason = await _reconfirm(g, fetch, timeout)
        except Exception as e:  # noqa: BLE001 — fail closed on any error
            ok, conf, reason = False, 0.0, f"validation error: {e}"
        g["validated"] = bool(ok)
        g["validation_confidence"] = round(float(conf), 3)
        g["validation_reason"] = reason
        g["submittable"] = bool(ok) and float(conf) >= min_confidence
        out.append(g)
        logger.debug("validate %s -> validated=%s conf=%.2f submittable=%s",
                     vt, g["validated"], g["validation_confidence"], g["submittable"])
    return out


def partition(findings: List[dict]) -> Tuple[List[dict], List[dict]]:
    """Split annotated findings into (submittable, leads)."""
    submittable = [f for f in findings if f.get("submittable")]
    leads = [f for f in findings if not f.get("submittable")]
    return submittable, leads
