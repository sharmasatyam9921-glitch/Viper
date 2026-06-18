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


def _ctype(resp) -> str:
    return ((getattr(resp, "headers", {}) or {}).get("content-type", "") or "").lower()


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

    # Injection / auth classes: no orthogonal behavioral re-test yet -> lead.
    return False, 0.0, f"no independent re-test for '{head}' yet — manual review"

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
