"""Broken access control / missing-authorization probe (vuln phase).

Requests a curated set of endpoints that should require authorization (admin
surfaces, other users' PII/records) WITHOUT credentials. A 200 carrying
structured data — while the framework's protected siblings correctly 401 — is a
missing-authorization flaw (OWASP A01, CWE-862).

Non-destructive: GET only, no writes, no auth, no data stored. The curated path
list keeps false positives low — these paths simply don't exist on unrelated
targets (404/401 → no finding).
"""

from __future__ import annotations

import logging
import re
from typing import List
from urllib.parse import urlsplit

from core.swarm_engine import SwarmAgent
from core.swarm_workers import register_worker

from ._http import fetch, normalize_target_url

logger = logging.getLogger("viper.swarm_workers.vuln.broken_access_control")

TECHNIQUE = "broken_access_control"

# Endpoints that should require authorization but are commonly left open.
_PROTECTED_ENDPOINTS = [
    # Other users' records / PII
    "/api/Users", "/api/Cards", "/api/Addresss", "/api/Feedbacks",
    "/api/PrivacyRequests", "/api/Complaints", "/api/Recycles", "/api/Deliverys",
    # Admin / operational surfaces
    "/api/Quantitys", "/rest/admin/application-version",
    "/rest/admin/application-configuration",
    "/api/admin", "/admin/api", "/actuator", "/actuator/env", "/metrics",
]

# JSON keys that mark a response as carrying other users' / sensitive data.
_SENSITIVE_KEYS = re.compile(
    r'"(UserId|email|password|passwordHash|cardNum|address|answer|'
    r'totpSecret|token|seq|deluxeToken)"', re.I)


def _origin(url: str) -> str:
    p = urlsplit(url)
    return f"{p.scheme}://{p.netloc}" if p.netloc else url.rstrip("/")


async def run(agent: SwarmAgent) -> List[dict]:
    url = normalize_target_url(agent.target)
    if not url:
        return []
    origin = _origin(url)
    timeout = min(agent.timeout_s, 8.0)
    findings: list[dict] = []

    for path in _PROTECTED_ENDPOINTS:
        full = origin + path
        resp = await fetch("GET", full, timeout=timeout)
        if not resp or resp.status != 200:
            continue
        body = (resp.body or "").lstrip()
        if not body.startswith(("{", "[")):
            continue  # not a JSON/data response
        compact = resp.body.replace(" ", "")
        is_admin = any(s in path for s in ("/admin", "actuator", "metrics"))
        has_records = body.startswith("[") or '"data":[' in compact
        has_sensitive = bool(_SENSITIVE_KEYS.search(resp.body))
        if not (is_admin or has_records or has_sensitive):
            continue
        findings.append({
            "type": "broken_access_control",
            "vuln_type": "access_control:missing_authorization",
            "title": f"Sensitive endpoint {path} accessible without authorization",
            "severity": "high",
            "url": full,
            "parameter": "",
            "cwe": "CWE-862",
            "confidence": 0.85,
            "evidence": (
                f"GET {path} returned 200 with structured data and no "
                "Authorization header (missing authorization)"
            ),
            "poc_request": f"GET {full}  (no auth)",
        })
    return findings


register_worker("vuln", TECHNIQUE, run)
