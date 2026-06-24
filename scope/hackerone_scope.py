"""Auto-pull a HackerOne program's scope so the operator only supplies a handle.

`viper.py scope pull <handle>` hits the HackerOne *Hacker API*
(`/v1/hackers/programs/<handle>/structured_scopes`, HTTP Basic auth with the
operator's own API token) and writes a scope-locked `scopes/current_scope.json`
that `guardrails`/`roe_engine` enforce — so a hunt physically cannot leave scope.
Offline fallbacks (`scope import <csv|burp.json>`) parse an exported scope CSV or a
Burp scope file when no API token is configured.

Dependency-free (urllib). The API call uses the operator's OWN credentials and only
READS their program scope — it does not touch any target. Mobile-app / source-code /
"OTHER" assets are recorded but never emitted as web-swarm targets.
"""
from __future__ import annotations

import base64
import csv
import json
import os
import re
import urllib.request
from typing import List, Optional, Tuple

_API_BASE = "https://api.hackerone.com/v1/hackers/programs"
# HackerOne asset_type -> VIPER ScopeEntry asset_type (web-targetable kinds only).
_ATYPE_MAP = {
    "WILDCARD": "wildcard", "URL": "url", "DOMAIN": "domain",
    "IP_ADDRESS": "ip", "CIDR": "cidr", "API": "api",
}


def _basic_auth(username: str, token: str) -> str:
    return "Basic " + base64.b64encode(f"{username}:{token}".encode()).decode()


def fetch_structured_scopes_api(handle: str, *, username: str, token: str,
                                timeout: float = 20.0, max_pages: int = 25) -> List[dict]:
    """Pull a program's structured scopes from the HackerOne Hacker API.
    Returns the list of `attributes` dicts. Paginated; raises on HTTP error."""
    out: List[dict] = []
    url = f"{_API_BASE}/{handle}/structured_scopes?page%5Bsize%5D=100"
    headers = {"Authorization": _basic_auth(username, token),
               "Accept": "application/json", "User-Agent": "VIPER-scope"}
    pages = 0
    while url and pages < max_pages:
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8", "replace"))
        out.extend(parse_api_payload(data))
        url = (data.get("links") or {}).get("next")
        pages += 1
    return out


def parse_api_payload(data: dict) -> List[dict]:
    """Extract `attributes` dicts from one Hacker-API structured_scopes page."""
    return [item["attributes"] for item in data.get("data", [])
            if isinstance(item, dict) and isinstance(item.get("attributes"), dict)]


def parse_csv_scopes(path: str) -> List[dict]:
    """Parse an exported HackerOne scope CSV into attribute dicts."""
    out: List[dict] = []
    with open(path, newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            ident = (row.get("identifier") or "").strip()
            if not ident:
                continue
            out.append({
                "asset_identifier": ident,
                "asset_type": (row.get("asset_type") or "").strip(),
                "eligible_for_bounty": str(row.get("eligible_for_bounty", "")).strip().lower() == "true",
                "eligible_for_submission": str(row.get("eligible_for_submission", "")).strip().lower() == "true",
                "max_severity": (row.get("max_severity") or "critical").strip() or "critical",
                "instruction": (row.get("instruction") or "").strip(),
            })
    return out


def parse_burp_excludes(path: str) -> List[str]:
    """Extract excluded hosts from a Burp Suite scope JSON (advanced mode)."""
    data = json.loads(open(path, encoding="utf-8").read())
    out: List[str] = []
    for e in data.get("target", {}).get("scope", {}).get("exclude", []):
        h = (e.get("host", "") or "").strip("^$").replace("\\.", ".").replace(".*", "*")
        if h and h not in out:
            out.append(h)
    return out


def to_scope(raw_scopes: List[dict], *, program_name: str, handle: str = "",
            extra_excludes=()) -> "object":
    """Convert raw H1 scope attributes into a BugBountyScope (in/out lists)."""
    from scope.scope_manager import BugBountyScope, ScopeEntry
    scope = BugBountyScope(
        program_name=program_name, platform="hackerone",
        program_url=f"https://hackerone.com/{handle}" if handle else "")
    seen: set = set()
    for a in raw_scopes:
        atype = (a.get("asset_identifier") and (a.get("asset_type") or "")).upper()
        ident = re.sub(r"^https?://", "", str(a.get("asset_identifier", "")).strip())
        if not ident or atype not in _ATYPE_MAP:   # skip mobile/source/OTHER assets
            continue
        key = ident.lower()
        if key in seen:
            continue
        seen.add(key)
        entry = ScopeEntry(
            target=ident, asset_type=_ATYPE_MAP[atype],
            in_scope=bool(a.get("eligible_for_submission", True)),
            eligible_for_bounty=bool(a.get("eligible_for_bounty", True)),
            max_severity=(a.get("max_severity") or "critical"),
            notes=str(a.get("instruction") or "")[:160])
        (scope.in_scope if entry.in_scope else scope.out_of_scope).append(entry)
    for h in extra_excludes:
        if h.lower() not in seen:
            seen.add(h.lower())
            scope.out_of_scope.append(ScopeEntry(
                target=h, asset_type="wildcard" if "*" in h else "url",
                in_scope=False, eligible_for_bounty=False, notes="explicit exclude"))
    return scope


def save_current_scope(scope, path: str = "scopes/current_scope.json") -> str:
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(scope.to_dict(), f, indent=2)
    return path


def get_api_creds() -> Tuple[Optional[str], Optional[str]]:
    """HackerOne API username + token from env or credentials/hackerone.json."""
    user = (os.environ.get("HACKERONE_API_USERNAME") or os.environ.get("H1_USERNAME"))
    token = (os.environ.get("HACKERONE_API_TOKEN") or os.environ.get("H1_API_TOKEN"))
    if not (user and token):
        try:
            j = json.loads(open("credentials/hackerone.json", encoding="utf-8").read())
            user = user or j.get("api_username") or j.get("username")
            token = token or j.get("api_token") or j.get("token")
        except Exception:
            pass
    return user, token
