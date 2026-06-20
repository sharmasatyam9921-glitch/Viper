"""Turn per-role captured traffic into a SessionContext + BOLA candidates.

Given N roles, each with the traffic captured while authenticated as that role,
this populates a :class:`SessionContext` reachability matrix and computes the
*role-diff*: endpoints one identity can reach that another identity should be
tested against — the two-account BOLA seed. The output (candidate URLs +
``bola_config``) plugs straight into ``find_bola`` / the ``bola_multi`` worker.

Also ingests a HAR export (Burp / browser / the optional Playwright driver) so a
captured session from any source becomes a SessionContext. Pure functions.
"""
from __future__ import annotations

from typing import Dict, Iterable, List, Optional, Tuple
from urllib.parse import urlsplit

from core.session_context import SessionContext


def build_session_context(captures_by_role: Dict[str, dict],
                          hunt_id: str = "") -> SessionContext:
    """Build a SessionContext from per-role capture bundles.

    ``captures_by_role``: ``{role_name: {"headers": {...}, "markers": [...],
    "captures": [(method, url, status), ...]}}``
    """
    ctx = SessionContext(hunt_id=hunt_id)
    for role, bundle in captures_by_role.items():
        ctx.add_role(role, bundle.get("headers"), bundle.get("markers"))
        for cap in bundle.get("captures", []):
            method, url, status = cap
            ctx.record(role, method, url, int(status))
    return ctx


def role_diff_candidates(ctx: SessionContext, owner: str, attacker: str) -> List[str]:
    """URLs the owner can reach (2xx) — the cross-user replay set for `attacker`.

    A URL the attacker is already observed to be denied (401/403) is dropped: it
    cannot leak, so testing it is wasted traffic. A URL the attacker has not been
    observed on is KEPT (unknown — must be tested).
    """
    owner_ok = set(ctx.reachable_urls(owner, ok_only=True))
    out = []
    for url in owner_ok:
        att_status = ctx.status(attacker, url)
        if att_status in (401, 403):
            continue
        out.append(url)
    return out


def bola_plan(ctx: SessionContext, owner: str, attacker: str
              ) -> Tuple[List[str], dict]:
    """Return (candidate_urls, bola_config) ready for find_bola / bola_multi."""
    candidates = role_diff_candidates(ctx, owner, attacker)
    config = ctx.bola_config_for(owner, attacker)
    return candidates, config


def bfla_plan(ctx: SessionContext, privileged: str, low: str
              ) -> Tuple[List[str], dict]:
    """Return (candidate_urls, bfla_config) for find_bfla / bfla_multi.

    Candidates are the PRIVILEGED role's admin-shaped reachable endpoints — the
    functions a low-priv role must not reach. Reuses the role reachability matrix.
    """
    from core.specialist.bfla_engine import is_privileged_path
    p = ctx.get_role(privileged)
    lo = ctx.get_role(low)
    if p is None or lo is None:
        raise KeyError("both roles must be present for a BFLA plan")
    candidates = [u for u in ctx.reachable_urls(privileged, ok_only=True)
                  if is_privileged_path(u)]
    config = {
        "privileged_name": privileged, "privileged_headers": dict(p.headers),
        "low_name": low, "low_headers": dict(lo.headers),
        "candidate_urls": candidates,
    }
    return candidates, config


def _iter_har_entries(har: dict) -> Iterable[Tuple[str, str, int]]:
    for entry in (har.get("log", {}) or {}).get("entries", []):
        req = entry.get("request", {}) or {}
        resp = entry.get("response", {}) or {}
        method = req.get("method", "GET")
        url = req.get("url", "")
        status = int(resp.get("status", 0) or 0)
        # Only http(s) traffic enters the context — never file://, ftp://, data:,
        # etc. from a malformed or hostile HAR (defence in depth; downstream BOLA
        # already filters, but the matrix itself stays web-only).
        if url and urlsplit(url).scheme.lower() in ("http", "https"):
            yield method, url, status


def session_context_from_har(har: dict, role: str,
                             headers: Optional[dict] = None,
                             markers: Optional[List[str]] = None,
                             ctx: Optional[SessionContext] = None,
                             hunt_id: str = "") -> SessionContext:
    """Ingest one role's HAR export into a (new or existing) SessionContext.

    Call repeatedly with different `role`/`har` and the same `ctx` to fold
    multiple authenticated sessions into one multi-role context.
    """
    ctx = ctx or SessionContext(hunt_id=hunt_id)
    ctx.add_role(role, headers, markers)
    for method, url, status in _iter_har_entries(har):
        ctx.record(role, method, url, status)
    return ctx
