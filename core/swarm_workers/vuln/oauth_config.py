"""OAuth 2.0 / OIDC authorization-server config analyzer (read-only).

Fetches the authorization server's discovery documents
(``/.well-known/openid-configuration`` and ``/.well-known/oauth-authorization-server``)
and flags configuration-level weaknesses that the metadata itself reveals: no PKCE
support, the deprecated implicit flow enabled, or ``none`` client authentication
allowed. These are GET-only observations of a public document — no flow is exercised,
nothing is submitted.

Because advertising a weak option in metadata does not by itself prove the deployed
application is exploitable (it may never USE the implicit flow), every finding is a
confidence-capped LEAD for a human to confirm against the real client flow.
"""
from __future__ import annotations

import json
import logging
from typing import List
from urllib.parse import urlsplit

from core.swarm_engine import SwarmAgent
from core.swarm_workers import register_worker

from ._http import fetch, normalize_target_url

logger = logging.getLogger("viper.swarm_workers.vuln.oauth_config")

TECHNIQUE = "oauth_config"

_WELL_KNOWN = (
    "/.well-known/openid-configuration",
    "/.well-known/oauth-authorization-server",
)


def _lead(url: str, issue: str, title: str, evidence: str, conf: float) -> dict:
    return {
        "type": "oauth_misconfiguration",
        "vuln_type": f"oauth_misconfig:{issue}",
        "title": title,
        "severity": "medium",
        "url": url,
        "cwe": "CWE-1174",
        "confidence": conf,
        "evidence": evidence,
        "needs_manual_verification": True,
    }


def _analyze(cfg: dict, url: str) -> List[dict]:
    """Flag config-level OAuth/OIDC weaknesses. Only fires on positive evidence in the
    metadata (a present-but-weak option), never on a merely-absent optional field
    unless its absence is itself the weakness (PKCE)."""
    out: List[dict] = []
    if not isinstance(cfg, dict):
        return out

    # 1. No PKCE advertised — public clients then rely on a redirect secret alone.
    #    Only meaningful when an authorization endpoint exists (it's an authz server).
    if cfg.get("authorization_endpoint"):
        pkce = cfg.get("code_challenge_methods_supported")
        if not pkce:
            out.append(_lead(
                url, "no_pkce",
                "OAuth/OIDC server does not advertise PKCE (code_challenge_methods)",
                "code_challenge_methods_supported absent/empty — authorization-code "
                "clients (esp. public/SPA/mobile) are exposed to code interception", 0.45))
        elif isinstance(pkce, list) and "S256" not in pkce and "plain" in pkce:
            out.append(_lead(
                url, "pkce_plain_only",
                "OAuth/OIDC PKCE offers only the weak 'plain' challenge method",
                f"code_challenge_methods_supported={pkce} (no S256)", 0.4))

    # 2. Implicit / hybrid flow enabled — tokens returned in the redirect fragment.
    rts = cfg.get("response_types_supported")
    if isinstance(rts, list):
        implicit = [r for r in rts if isinstance(r, str)
                    and "token" in r.split() and "code" not in r.split()]
        if implicit:
            out.append(_lead(
                url, "implicit_flow",
                "OAuth/OIDC implicit flow enabled (access/ID token in the redirect)",
                f"response_types_supported includes {implicit} — the deprecated "
                "implicit grant leaks tokens via the URL fragment / browser history", 0.4))

    # 3. 'none' token-endpoint auth — a public client authenticates with no secret.
    tem = cfg.get("token_endpoint_auth_methods_supported")
    if isinstance(tem, list) and "none" in tem:
        out.append(_lead(
            url, "auth_none",
            "OAuth/OIDC token endpoint allows client authentication 'none'",
            "token_endpoint_auth_methods_supported includes 'none' — confidential "
            "clients may be registerable without a secret", 0.4))
    return out


async def run(agent: SwarmAgent) -> List[dict]:
    url = normalize_target_url(agent.target)
    if not url:
        return []
    timeout = min(agent.timeout_s, 8.0)
    parts = urlsplit(url)
    origin = f"{parts.scheme}://{parts.netloc}" if parts.netloc else url.rstrip("/")

    findings: List[dict] = []
    for path in _WELL_KNOWN:
        doc = origin + path
        r = await fetch("GET", doc, timeout=timeout, follow_redirects=False)
        if not r or not getattr(r, "ok", False) or not r.body:
            continue
        ctype = (r.headers or {}).get("content-type", "").lower()
        if ctype and "json" not in ctype:
            continue
        try:
            cfg = json.loads(r.body)
        except (ValueError, TypeError):
            continue
        # Must actually look like an authz-server metadata document.
        if not (cfg.get("issuer") or cfg.get("authorization_endpoint")
                or cfg.get("token_endpoint")):
            continue
        findings.extend(_analyze(cfg, doc))
        if findings:
            break   # one discovery document is enough

    uniq: dict = {}
    for f in findings:
        uniq.setdefault(f["vuln_type"], f)
    return list(uniq.values())[:6]


register_worker("vuln", TECHNIQUE, run)
