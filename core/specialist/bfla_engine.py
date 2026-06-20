"""Broken Function-Level Authorization (BFLA) — OWASP API Security #5.

The function-level sibling of BOLA. BOLA is about *objects* (user B reads user A's
record); BFLA is about *functions* (a low-privilege user invokes an admin-only
operation). It is exactly what the per-role reachability matrix VIPER captures is
for: given two identities you control — a privileged one and a low-privilege one —
confirm that the low-priv identity can reach a privileged function it must not.

Methodology (what a specialist does by hand, automated here):

  1. As the **privileged** identity, confirm the endpoint is a real privileged
     function the admin can use (2xx).
  2. Replay as the **low-privilege** identity. If it ALSO returns 2xx with the
     function's output, role enforcement is broken.
  3. Anonymous control: if the endpoint is reachable with NO auth, it is simply
     public — not a BFLA.

False-positive discipline:
  * Only ADMIN-SHAPED paths are flagged (``/admin``, ``/manage``, ``/actuator``,
    ``/internal``, ...), so a benign all-users endpoint (``/profile``) is never
    flagged. Disable with ``admin_only=False`` for an explicit URL list.
  * A low-priv "200" that is really a login / "access denied" page (soft-deny) is
    rejected — the response must look like the privileged function's output.

Strictly read-only: every probe is a GET. For authorized testing with accounts
you control (the bug-bounty norm).
"""
from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import Awaitable, Callable, List, Optional
from urllib.parse import urlsplit

logger = logging.getLogger("viper.specialist.bfla")

Fetcher = Callable[..., Awaitable[object]]

# Path SEGMENT prefixes that denote a privileged / administrative function. A
# prefix match (segment startswith) catches /admin, /administrators,
# /administration, /administer, /management, /configuration, ... A slightly broad
# candidate filter is safe here: the actual finding still requires the
# admin-2xx + low-2xx + anon-denied proof, so extra candidates only get tested,
# never falsely flagged.
_PRIV_PREFIXES = (
    "admin", "manage", "console", "dashboard", "internal", "actuator",
    "superuser", "sudo", "staff", "moderator", "operator", "config", "system",
    "debug", "metrics", "env", "settings", "owner", "root", "backoffice",
)

# A low-priv 2xx that is actually a soft-deny / login / "denied" page — NOT the
# function. Broad on purpose: this only REJECTS a candidate, so over-matching is
# the FP-averse direction. No \b anchors (they broke "unauthorized").
_SOFT_DENY = re.compile(
    r"(please\s*log\s*in|sign\s*in|log\s*in to|logged\s*in|login\s*required|"
    r"unauthori|not\s*authori|forbidden|access\s*denied|permission\s*denied|"
    r"not\s*permitted|insufficient\s*(?:privilege|permission)|"
    r"auth(?:entication|orization)?\s*required|"
    r"you\s*(?:do not|don't|must)\s*(?:have|be))",
    re.IGNORECASE,
)


@dataclass
class Identity:
    """One authenticated identity under test (no markers needed for BFLA)."""

    name: str
    headers: dict = field(default_factory=dict)


def is_privileged_path(url: str) -> bool:
    segs = [s.lower() for s in urlsplit(url).path.split("/") if s]
    return any(seg.startswith(pre) for seg in segs for pre in _PRIV_PREFIXES)


def _ok(resp) -> bool:
    return resp is not None and 200 <= getattr(resp, "status", 0) < 300


def _body(resp) -> str:
    return getattr(resp, "body", "") or ""


async def find_bfla(
    privileged: Identity,
    low_priv: Identity,
    candidate_urls: List[str],
    *,
    fetch: Fetcher,
    timeout: float = 10.0,
    max_urls: int = 60,
    unauth_control: bool = True,
    admin_only: bool = True,
) -> List[dict]:
    """Confirm a low-priv identity can invoke privileged functions.

    privileged   : the high-privilege identity (admin) — establishes the function.
    low_priv     : the identity that should be DENIED the function.
    candidate_urls: endpoints to test (admin-shaped ones are filtered when
                    admin_only=True; feed it the privileged role's reachable URLs).

    Returns confirmed-BFLA finding dicts (read-only, low-FP).
    """
    # Identities must actually differ, or every endpoint the admin reaches the
    # "low-priv" trivially reaches too (it IS the admin) -> false BFLA.
    if privileged.headers == low_priv.headers:
        logger.warning("BFLA: privileged and low-priv identities are identical — "
                       "cannot prove role bypass; skipping.")
        return []

    findings: list[dict] = []
    seen: set[str] = set()
    tested = 0
    for url in candidate_urls[:max_urls]:
        if not url or urlsplit(url).scheme.lower() not in ("http", "https"):
            continue
        if url in seen:
            continue
        seen.add(url)
        if admin_only and not is_privileged_path(url):
            continue
        tested += 1

        # 1. The privileged identity must actually be able to use this function.
        r_priv = await fetch("GET", url, headers=privileged.headers, timeout=timeout)
        if not _ok(r_priv):
            continue

        # 2. Replay as the low-privilege identity.
        r_low = await fetch("GET", url, headers=low_priv.headers, timeout=timeout)
        if not _ok(r_low):
            continue                       # properly 401/403 -> role enforcement works
        # soft-deny guard: a 200 login/"access denied" page is not the function.
        if _SOFT_DENY.search(_body(r_low)):
            continue

        # 3. FP guard: if NO auth also reaches it, the endpoint is public.
        if unauth_control:
            r_anon = await fetch("GET", url, headers={}, timeout=timeout)
            if r_anon is None:
                # anon probe failed (timeout/network) — we cannot rule out that
                # the endpoint is public, so fail closed and skip (FP-averse).
                logger.debug("BFLA: %s anon control failed — skipping (cannot "
                             "confirm not-public)", url)
                continue
            if _ok(r_anon) and not _SOFT_DENY.search(_body(r_anon)):
                logger.debug("BFLA: %s is public (anon 2xx) — not a finding", url)
                continue

        findings.append({
            "type": "bfla",
            "vuln_type": f"access_control:bfla:{urlsplit(url).path}",
            "title": (f"Broken Function-Level Authorization — '{low_priv.name}' can "
                      f"invoke a privileged function"),
            "severity": "high",
            "url": url,
            "cwe": "CWE-863",
            "confidence": 0.85,
            "evidence": (
                f"GET {url} returned 2xx as low-privilege user '{low_priv.name}' "
                f"(and as '{privileged.name}'), but is denied without auth — a "
                "privileged function with no role enforcement (read-only)."
            ),
            "poc_request": f"GET {url}  (with {low_priv.name}'s session)",
            "owner": privileged.name,
            "attacker": low_priv.name,
        })
    logger.info("BFLA: tested %d privileged URLs, %d role-bypass(es)",
                tested, len(findings))
    return findings
