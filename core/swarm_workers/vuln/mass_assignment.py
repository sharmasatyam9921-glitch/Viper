"""Mass-assignment / over-permissive object-binding probe (vuln phase).

Detection-leaning and strictly NON-DESTRUCTIVE. Mass assignment (CWE-915) lets
a client set object properties the server never meant to be client-controlled —
classically `isAdmin`, `role`, `balance`, `verified`. Confirming it by *writing*
those fields would mean attempting a privilege escalation, which we refuse to do.

Instead we use a read-based heuristic: if a user-facing object response (a user
record, the account profile, or a registration schema) *exposes* a privileged
field, that field is almost certainly part of the bound model and therefore a
mass-assignment candidate. Exposure of `role`/`isAdmin`/`balance`/... in a
response a normal user shouldn't see or control is the signal.

We only GET. We never send a write that escalates privileges. Findings are
flagged for human confirmation of the write path.
"""

from __future__ import annotations

import json
import logging
import re
from typing import List, Optional
from urllib.parse import urlsplit

from core.swarm_engine import SwarmAgent
from core.swarm_workers import register_worker

from ._http import HttpResp, fetch, normalize_target_url

logger = logging.getLogger("viper.swarm_workers.vuln.mass_assignment")

TECHNIQUE = "mass_assignment"

# Common object / collection / registration endpoints. Root-relative; resolved
# against the target origin so a deep asset URL still probes the API root.
_OBJECT_PATHS = [
    "/api/Users", "/api/users", "/api/user", "/api/account",
    "/api/accounts", "/api/profile", "/api/me",
    "/rest/user", "/rest/user/whoami",
    "/users", "/account", "/profile", "/register", "/api/register",
]

# Privileged fields that a user-facing object should not normally expose. Their
# presence implies the field is part of the bound model (mass-assignment risk).
_PRIVILEGED_FIELDS = [
    "role", "roles", "isadmin", "is_admin", "admin", "isstaff", "is_staff",
    "permissions", "permission", "accounttype", "account_type",
    "verified", "isverified", "is_verified", "balance", "credit", "wallet",
    "privilege", "privileges", "superuser", "is_superuser",
]

# Field tokens that, while privileged-sounding, are routinely surfaced in benign
# UIs (a self profile legitimately shows your own role label etc.). Kept out of
# the high-signal set so a single common field alone doesn't fire.
_MAX_EVIDENCE = 240


def _origin(url: str) -> str:
    p = urlsplit(url)
    return f"{p.scheme}://{p.netloc}" if p.netloc else url.rstrip("/")


def _json_objects(body: str) -> List[dict]:
    """Best-effort: return dict-shaped JSON objects found in the body.

    Handles a top-level object, a top-level list of objects, and the common
    `{"data": [...]}` / `{"data": {...}}` / `{"user": {...}}` wrappers.
    """
    objs: list[dict] = []
    try:
        parsed = json.loads(body)
    except (ValueError, TypeError):
        return objs

    def _collect(node, depth: int = 0) -> None:
        if depth > 3:
            return
        if isinstance(node, dict):
            objs.append(node)
            for v in node.values():
                if isinstance(v, (dict, list)):
                    _collect(v, depth + 1)
        elif isinstance(node, list):
            for item in node[:25]:  # bound work on large collections
                if isinstance(item, (dict, list)):
                    _collect(item, depth + 1)

    _collect(parsed)
    return objs


def _privileged_keys(obj: dict) -> List[str]:
    hits: list[str] = []
    for key in obj.keys():
        if not isinstance(key, str):
            continue
        norm = key.strip().lower().replace("-", "_")
        flat = norm.replace("_", "")
        for field in _PRIVILEGED_FIELDS:
            f_flat = field.replace("_", "")
            if norm == field or flat == f_flat:
                hits.append(key)
                break
    return hits


def _looks_like_user_object(obj: dict) -> bool:
    """A user/account object has an identity-ish key alongside the privileged one.

    This keeps us from flagging arbitrary config blobs that merely contain a
    word like "permissions" — we want an object that models a *user record*.
    """
    identity = {
        "id", "userid", "user_id", "username", "email", "name", "login",
        "uuid", "_id", "account", "accountid",
    }
    for key in obj.keys():
        if isinstance(key, str):
            norm = key.strip().lower().replace("-", "_").replace("_", "")
            if norm in {i.replace("_", "") for i in identity}:
                return True
    return False


async def run(agent: SwarmAgent) -> List[dict]:
    url = normalize_target_url(agent.target)
    if not url:
        return []
    origin = _origin(url)
    timeout = min(agent.timeout_s, 10.0)
    findings: list[dict] = []
    seen_paths: set[str] = set()

    for path in _OBJECT_PATHS:
        obj_url = origin + path
        if obj_url in seen_paths:
            continue
        seen_paths.add(obj_url)

        resp: Optional[HttpResp] = await fetch(
            "GET", obj_url,
            headers={"Accept": "application/json"},
            timeout=timeout,
        )
        if resp is None or resp.status >= 400 or not resp.body:
            continue

        ctype = resp.headers.get("content-type", "").lower()
        # JSON object responses only — HTML pages full of words aren't object models.
        if "json" not in ctype and not resp.body.lstrip().startswith(("{", "[")):
            continue

        for obj in _json_objects(resp.body):
            if not _looks_like_user_object(obj):
                continue
            priv = _privileged_keys(obj)
            if not priv:
                continue

            # De-dup the field list, preserve order, cap evidence size.
            uniq: list[str] = []
            for k in priv:
                if k not in uniq:
                    uniq.append(k)
            fields_str = ", ".join(uniq)
            evidence = (
                f"GET {path} returned a user/account object exposing "
                f"privileged field(s): {fields_str}. Exposure implies these "
                "fields are part of the bound model and may be client-settable "
                "(mass assignment / CWE-915). Write path NOT exercised — "
                "verify manually."
            )[:_MAX_EVIDENCE]

            findings.append({
                "type": "mass_assignment_candidate",
                "vuln_type": "access_control:mass_assignment",
                "title": f"Over-permissive object binding exposed at {path}",
                "severity": "medium",
                "url": obj_url,
                "parameter": uniq[0],
                "cwe": "CWE-915",
                "confidence": 0.55,
                "evidence": evidence,
            })
            break  # one object per path is enough to flag the endpoint

    return findings


register_worker("vuln", TECHNIQUE, run)
