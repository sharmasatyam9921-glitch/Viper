"""401/403 access-control bypass probe (vuln phase, non-destructive).

Many endpoints are "protected" by a front proxy / WAF rule that only checks the
literal request path, the method, or a trusted client header — and that check is
trivially sidestepped. This probe first GETs the target. ONLY if the base URL
answers 401 or 403 does it retry with a battery of benign bypass mutations and
flags a finding when any mutation flips the gate to a 2xx carrying a DIFFERENT,
larger (i.e. real) body than the forbidden baseline.

Mutation families (all read-only GETs unless a method swap is the test itself):
  * PATH    — append "/", "/.", "//", "/..;/", "%2e", "%2f", trailing "%20",
              and a case-flipped path.
  * HEADER  — X-Original-URL / X-Rewrite-URL (proxy path override),
              X-Forwarded-For / X-Custom-IP-Authorization / X-Originating-IP
              = 127.0.0.1 (trusted-IP spoof), X-Forwarded-Host.
  * METHOD  — POST / HEAD / OPTIONS against the same URL.

Detection only — the unlocked content is never used. A bypass is reported only
when the response is 2xx AND its body materially differs from (and is larger
than) the 401/403 baseline body, which keeps generic error pages and sites that
simply 200 everything from producing false positives.
"""

from __future__ import annotations

import logging
from typing import List, Optional
from urllib.parse import urlsplit

from core.swarm_engine import SwarmAgent
from core.swarm_workers import register_worker

from ._http import HttpResp, fetch, normalize_target_url

logger = logging.getLogger("viper.swarm_workers.vuln.path_bypass")

TECHNIQUE = "path_bypass"

# Trailing-suffix path mutations (appended to the original path).
_PATH_SUFFIXES = ["/", "/.", "//", "/..;/", "%2e", "%2f", "%20"]

# Headers that proxies / apps sometimes trust to override the path or the
# apparent client identity. Each entry is a single header dict to merge in.
_HEADER_MUTATIONS = [
    ("X-Original-URL", "__PATH__"),
    ("X-Rewrite-URL", "__PATH__"),
    ("X-Forwarded-For", "127.0.0.1"),
    ("X-Forwarded-Host", "127.0.0.1"),
    ("X-Custom-IP-Authorization", "127.0.0.1"),
    ("X-Originating-IP", "127.0.0.1"),
]

# Alternate methods that sometimes skip an access-control rule keyed on GET.
_METHOD_SWAPS = ["POST", "HEAD", "OPTIONS"]


def _is_2xx(resp: Optional[HttpResp]) -> bool:
    return bool(resp and 200 <= resp.status < 300)


def _is_real_unlock(resp: Optional[HttpResp], baseline_body: str) -> bool:
    """True if `resp` is a 2xx whose body is a DIFFERENT, larger real body.

    Guards against (a) gates that 2xx everything and (b) error pages echoed at
    200 — the unlocked body must be strictly longer than and not equal to the
    forbidden baseline.
    """
    if not _is_2xx(resp):
        return False
    body = resp.body or ""
    if body == baseline_body:
        return False
    return len(body) > len(baseline_body)


def _path_of(url: str) -> str:
    p = urlsplit(url)
    path = p.path or "/"
    if p.query:
        path += "?" + p.query
    return path


def _flip_case(path: str) -> str:
    return path.swapcase()


def _finding(url: str, kind: str, mutation: str, resp: HttpResp,
             baseline_status: int) -> dict:
    return {
        "type": "access_control_bypass",
        "vuln_type": f"access_control:{baseline_status}_bypass",
        "title": f"{baseline_status} access-control bypass via {kind} mutation",
        "severity": "high",
        "url": url,
        "cwe": "CWE-285",
        "confidence": 0.85,
        "payload": mutation,
        "evidence": (
            f"Base URL returned {baseline_status}; {kind} mutation "
            f"{mutation!r} returned {resp.status} with a larger real body "
            f"({len(resp.body or '')} bytes)"
        ),
    }


async def run(agent: SwarmAgent) -> List[dict]:
    url = normalize_target_url(agent.target)
    if not url:
        return []
    timeout = min(agent.timeout_s, 10.0)

    # Step 1: probe the base URL. Bail unless it is actually 401/403.
    # use_session_auth=False on every probe here: an ACL bypass must be
    # demonstrated from an UNAUTHORIZED position. Inheriting the hunt's global
    # identity-A session would make the base return 200 (hiding the gate) and
    # any "unlock" just the authenticated body — a fabricated bypass.
    base = await fetch("GET", url, timeout=timeout, follow_redirects=False, use_session_auth=False)
    if not base or base.status not in (401, 403):
        return []
    baseline_status = base.status
    baseline_body = base.body or ""

    findings: list[dict] = []

    def _record(kind: str, mutation: str, resp: Optional[HttpResp]) -> None:
        if _is_real_unlock(resp, baseline_body):
            findings.append(_finding(url, kind, mutation, resp, baseline_status))

    p = urlsplit(url)
    origin = f"{p.scheme}://{p.netloc}"
    orig_path = _path_of(url)

    # Step 2a: PATH suffix mutations.
    for suffix in _PATH_SUFFIXES:
        mutated = url + suffix
        resp = await fetch("GET", mutated, timeout=timeout, follow_redirects=False, use_session_auth=False)
        _record("path", suffix, resp)

    # Step 2b: case-flip the path.
    flipped = _flip_case(orig_path)
    if flipped != orig_path:
        case_url = origin + flipped
        resp = await fetch("GET", case_url, timeout=timeout, follow_redirects=False, use_session_auth=False)
        _record("path", "case-flip", resp)

    # Step 2c: HEADER mutations (path-override + trusted-IP spoof).
    for name, value in _HEADER_MUTATIONS:
        hv = orig_path if value == "__PATH__" else value
        resp = await fetch("GET", url, headers={name: hv},
                           timeout=timeout, follow_redirects=False, use_session_auth=False)
        _record("header", f"{name}: {hv}", resp)

    # Step 2d: METHOD swaps.
    for method in _METHOD_SWAPS:
        resp = await fetch(method, url, timeout=timeout, follow_redirects=False, use_session_auth=False)
        _record("method", method, resp)

    return findings


register_worker("vuln", TECHNIQUE, run)
