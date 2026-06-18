"""Two-account BOLA / IDOR engine — the gold-standard manual methodology.

Broken Object Level Authorization (OWASP API #1, a.k.a. IDOR) is the top
real-world bug-bounty class, and it is exactly what a single-session scanner
*cannot* find: you need two authenticated identities to prove that user B can
read user A's private object.

Methodology (what a specialist does by hand, automated here):

  1. As **user A**, collect object-referencing requests — URLs carrying numeric
     or UUID identifiers (``/api/orders/5512``, ``/users/9f2c.../profile``).
  2. For each such object, confirm it is genuinely A's *private* data: A's
     response is 2xx **and** contains one of A's identity markers (A's email,
     user-id, account number — strings B has no business seeing).
  3. Replay the exact request as **user B** (a different session).
  4. **Confirm BOLA only when** B's response is 2xx **and still contains A's
     identity marker** — i.e. B is reading A's private data.

False-positive discipline (the hard part — see the Newegg cmdi lesson):

  * A marker merely being *present* is not enough; it must be A's PRIVATE
    marker leaking to B. Public objects (``/products/5``) return the same body
    to everyone and carry no A-identity marker, so they are never flagged.
  * Optional unauthenticated control: if the marker also appears with NO
    session, the data is public — not a BOLA. (Enabled by default.)
  * A broken/expired B session yields 401/403 → no 2xx → no false finding.

Strictly read-only: every probe is a GET. No object is created, modified, or
deleted. For authorized testing with accounts you control (the bug-bounty norm).
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import Awaitable, Callable, List, Optional
from urllib.parse import urlsplit

logger = logging.getLogger("viper.specialist.bola")

# A response-like object: needs .status (int) and .body (str). HttpResp fits.
# The fetcher: (method, url, headers, timeout) -> response | None.
Fetcher = Callable[..., Awaitable[object]]

# Path/query tokens that look like an object identifier.
_NUMERIC = re.compile(r"/(\d{1,12})(?=/|$|\?)")
_UUID = re.compile(
    r"/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(?=/|$|\?)",
    re.I,
)
_ID_QUERY = re.compile(r"[?&]([a-z_]*id|account|order|user|uuid|ref)=([^&]+)", re.I)


@dataclass
class Session:
    """One authenticated identity under test.

    headers: auth headers sent with every request for this identity
             (e.g. {"Cookie": "session=..."} or {"Authorization": "Bearer ..."}).
    identity_markers: strings unique to THIS user's private data — their email,
             numeric user-id, account number, API token tail. If one of these
             appears in *another* user's session response, that's a leak.
    """

    name: str
    headers: dict = field(default_factory=dict)
    identity_markers: List[str] = field(default_factory=list)

    def clean_markers(self) -> List[str]:
        return [m.strip() for m in self.identity_markers if m and len(m.strip()) >= 3]


def id_bearing_urls(urls: List[str]) -> List[str]:
    """Filter `urls` down to those referencing a concrete object id.

    These are the BOLA candidates: a numeric/UUID path segment or an id-like
    query parameter. Bare collection endpoints (``/api/orders``) are dropped.
    """
    out: list[str] = []
    seen: set[str] = set()
    for u in urls:
        if not u:
            continue
        if urlsplit(u).scheme.lower() not in ("http", "https"):
            continue  # only http(s) objects are replay targets — never file://, etc.
        if _NUMERIC.search(u) or _UUID.search(u) or _ID_QUERY.search(u):
            if u not in seen:
                seen.add(u)
                out.append(u)
    return out


def _ok(resp) -> bool:
    return resp is not None and 200 <= getattr(resp, "status", 0) < 300


def _body(resp) -> str:
    return getattr(resp, "body", "") or ""


def _markers_in(body: str, markers: List[str]) -> List[str]:
    low = body.lower()
    return [m for m in markers if m.lower() in low]


async def find_bola(
    owner: Session,
    attacker: Session,
    candidate_urls: List[str],
    *,
    fetch: Fetcher,
    timeout: float = 10.0,
    max_urls: int = 60,
    unauth_control: bool = True,
    reachability: Optional[dict] = None,
) -> List[dict]:
    """Run two-account BOLA detection.

    owner          : the victim identity (user A) whose objects we test.
    attacker       : the second identity (user B) that should NOT see A's data.
    candidate_urls : object URLs observed for the owner (use id_bearing_urls()).
    fetch          : async (method, url, *, headers, timeout) -> resp|None.
    reachability   : optional ``(role_name, url) -> status`` matrix (from a
                     SessionContext). Used ONLY to skip provably-pointless probes
                     (owner can't access her own object, or the attacker is
                     already denied). It can never turn a non-finding into a
                     finding — it only avoids wasted requests.

    Returns a list of confirmed-BOLA finding dicts (read-only, low-FP).
    """
    owner_markers = owner.clean_markers()
    if not owner_markers:
        logger.warning("BOLA: owner has no identity_markers — cannot confirm "
                       "cross-user leaks without them; skipping.")
        return []

    findings: list[dict] = []
    tested = 0
    for url in id_bearing_urls(candidate_urls)[:max_urls]:
        if reachability is not None:
            o_st = reachability.get((owner.name, url))
            a_st = reachability.get((attacker.name, url))
            if o_st is not None and not (200 <= o_st < 300):
                continue   # owner cannot reach her own object -> nothing to leak
            if a_st in (401, 403):
                continue   # attacker already denied here -> cannot be a leak
        tested += 1
        # 1. Owner must actually own private data here (2xx + owner's marker).
        r_owner = await fetch("GET", url, headers=owner.headers, timeout=timeout)
        if not _ok(r_owner):
            continue
        leaked_in_owner = _markers_in(_body(r_owner), owner_markers)
        if not leaked_in_owner:
            continue  # not the owner's private object → nothing to leak

        # 2. Replay as the attacker (different identity).
        r_att = await fetch("GET", url, headers=attacker.headers, timeout=timeout)
        if not _ok(r_att):
            continue  # proper 401/403/404 → access control working
        leaked = _markers_in(_body(r_att), leaked_in_owner)
        if not leaked:
            continue  # attacker got 2xx but NOT owner's private data → ok

        # 3. FP guard: if the marker is also visible with NO auth, it's public.
        if unauth_control:
            r_anon = await fetch("GET", url, headers={}, timeout=timeout)
            if _ok(r_anon) and _markers_in(_body(r_anon), leaked):
                logger.debug("BOLA: %s leaks marker unauthenticated — public, "
                             "not a finding", url)
                continue

        findings.append({
            "type": "bola",
            "vuln_type": f"idor:bola:{urlsplit(url).path}",
            "title": (
                f"Broken Object Level Authorization — '{attacker.name}' can read "
                f"'{owner.name}'s object"
            ),
            "severity": "high",
            "url": url,
            "cwe": "CWE-639",
            "confidence": 0.9,
            "evidence": (
                f"GET {url} as user '{attacker.name}' returned 2xx containing "
                f"user '{owner.name}'s private marker(s) {leaked!r} — cross-user "
                "object access confirmed (read-only)."
            ),
            "poc_request": f"GET {url}  (with {attacker.name}'s session)",
            "owner": owner.name,
            "attacker": attacker.name,
        })
    logger.info("BOLA: tested %d object URLs, %d cross-user leak(s)",
                tested, len(findings))
    return findings
