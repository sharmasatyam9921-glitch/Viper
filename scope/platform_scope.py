"""Multi-platform scope auto-pull (Bugcrowd, Intigriti) alongside HackerOne.

Each fetcher reads the researcher's OWN program scope via that platform's API
(the operator's own token) and normalizes it to the common attribute shape that
``scope.hackerone_scope.to_scope`` consumes:

    {asset_identifier, asset_type, eligible_for_submission, eligible_for_bounty,
     max_severity, instruction}

The normalizers are unit-tested against documented-shape fixtures. The LIVE fetch
needs the operator's API token and hits the documented endpoint; it's best-effort
against each platform's published API and degrades to a clear error if the shape
differs. Dependency-free (urllib); READ-only, touches no target.
"""
from __future__ import annotations

import json
import os
import urllib.request
from typing import List, Optional, Tuple

# ── Bugcrowd ───────────────────────────────────────────────────────────────
# https://api.bugcrowd.com  ·  Authorization: Token <token>  (JSON:API)
_BUGCROWD_BASE = "https://api.bugcrowd.com"
_BC_SKIP = {"android", "ios", "mobile", "hardware", "other", "source_code"}


def _norm_bugcrowd_target(attrs: dict) -> Optional[dict]:
    name = str(attrs.get("name") or attrs.get("uri") or "").strip()
    if not name:
        return None
    cat = str(attrs.get("category") or attrs.get("target_category") or "website").lower()
    if cat in _BC_SKIP:
        return None
    atype = "WILDCARD" if "*" in name else ("API" if cat == "api" else "URL")
    in_scope = attrs.get("in_scope")
    return {"asset_identifier": name, "asset_type": atype,
            "eligible_for_submission": True if in_scope is None else bool(in_scope),
            "eligible_for_bounty": bool(attrs.get("reward_range") or attrs.get("eligible", True)),
            "max_severity": "critical",
            "instruction": str(attrs.get("description") or "")}


def parse_bugcrowd(payload: dict) -> List[dict]:
    """Bugcrowd JSON:API: {data:[{attributes:{name,category,in_scope,...}}]}."""
    out = []
    for item in payload.get("data", []):
        attrs = item.get("attributes") if isinstance(item, dict) else None
        if isinstance(attrs, dict):
            n = _norm_bugcrowd_target(attrs)
            if n:
                out.append(n)
    return out


def fetch_bugcrowd(program: str, *, token: str, timeout: float = 20.0) -> List[dict]:
    url = f"{_BUGCROWD_BASE}/programs/{program}/targets"
    req = urllib.request.Request(url, headers={
        "Authorization": f"Token {token}", "Accept": "application/vnd.bugcrowd+json",
        "User-Agent": "VIPER-scope"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return parse_bugcrowd(json.loads(r.read().decode("utf-8", "replace")))


# ── Intigriti ──────────────────────────────────────────────────────────────
# https://api.intigriti.com/external/researcher/v1  ·  Bearer token
_INTIGRITI_BASE = "https://api.intigriti.com/external/researcher/v1"
# domain "type": numeric (1=URL,2=Wildcard,...) or string.
_INTI_TYPE = {1: "URL", 2: "WILDCARD", "url": "URL", "wildcard": "WILDCARD",
              "ip": "IP_ADDRESS", "cidr": "CIDR"}
_INTI_SKIP = {3, 4, 5, "android", "ios", "mobile", "device", "other"}


def _norm_intigriti_domain(d: dict) -> Optional[dict]:
    ep = str(d.get("endpoint") or d.get("value") or "").strip()
    if not ep:
        return None
    t = d.get("type")
    tval = t.get("value") if isinstance(t, dict) else t          # type may be nested
    if tval in _INTI_SKIP or str(tval).lower() in _INTI_SKIP:
        return None
    atype = _INTI_TYPE.get(tval) or _INTI_TYPE.get(str(tval).lower()) \
        or ("WILDCARD" if "*" in ep else "URL")
    tier = d.get("tier")
    tier_name = (tier.get("value") if isinstance(tier, dict) else tier) or ""
    in_scope = "out" not in str(tier_name).lower()
    return {"asset_identifier": ep, "asset_type": atype,
            "eligible_for_submission": in_scope, "eligible_for_bounty": in_scope,
            "max_severity": "critical", "instruction": str(d.get("description") or "")}


def parse_intigriti(payload: dict) -> List[dict]:
    """Intigriti program: {domains:[{endpoint,type,tier,...}]} (also content.domains)."""
    domains = (payload.get("domains")
               or (payload.get("content") or {}).get("domains") or [])
    out = []
    for d in domains:
        if isinstance(d, dict):
            n = _norm_intigriti_domain(d)
            if n:
                out.append(n)
    return out


def fetch_intigriti(program: str, *, token: str, timeout: float = 20.0) -> List[dict]:
    url = f"{_INTIGRITI_BASE}/programs/{program}"
    req = urllib.request.Request(url, headers={
        "Authorization": f"Bearer {token}", "Accept": "application/json",
        "User-Agent": "VIPER-scope"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return parse_intigriti(json.loads(r.read().decode("utf-8", "replace")))


# ── dispatcher + creds ──────────────────────────────────────────────────────

def platform_creds(platform: str) -> Tuple[Optional[str], Optional[str]]:
    """(username, token) for a platform from env (token-only platforms -> user None)."""
    p = platform.lower()
    if p in ("hackerone", "h1"):
        from scope.hackerone_scope import get_api_creds
        return get_api_creds()
    if p == "bugcrowd":
        return None, os.environ.get("BUGCROWD_API_TOKEN")
    if p == "intigriti":
        return None, os.environ.get("INTIGRITI_API_TOKEN")
    return None, None


def fetch_scope(platform: str, handle: str, *, username=None, token=None,
                timeout: float = 20.0) -> List[dict]:
    """Fetch + normalize a program's scope from `platform`. Raises on unknown."""
    p = platform.lower()
    if p in ("hackerone", "h1"):
        from scope.hackerone_scope import fetch_structured_scopes_api
        return fetch_structured_scopes_api(handle, username=username, token=token,
                                           timeout=timeout)
    if p == "bugcrowd":
        return fetch_bugcrowd(handle, token=token, timeout=timeout)
    if p == "intigriti":
        return fetch_intigriti(handle, token=token, timeout=timeout)
    raise ValueError(f"unsupported platform: {platform}")
