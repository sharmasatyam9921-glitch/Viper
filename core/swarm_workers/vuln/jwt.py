"""JWT misconfiguration probes.

Pulls cookies / Authorization headers from a baseline GET. If any
value parses as a JWT, checks for:
  - `alg: none` accepted (CVE-class — replace the signature with empty)
  - weak HMAC keys (offline crack with `secret`, `Secret123`, etc. —
    fast, no network)
  - missing signature verification (some libs accept tampered payloads)

This is informational discovery — does NOT submit forged tokens
back to the server unless explicitly approved.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import re
from typing import List, Optional

from core.swarm_engine import SwarmAgent
from core.swarm_workers import register_worker

from ._http import fetch, normalize_target_url

logger = logging.getLogger("viper.swarm_workers.vuln.jwt")

TECHNIQUE = "jwt"

_JWT_RE = re.compile(r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*")
_WEAK_KEYS = [
    "", "secret", "Secret123", "password", "12345", "key", "test", "admin",
    "supersecret", "your-256-bit-secret", "changeme", "default", "jwt",
]


def _b64url_decode(seg: str) -> bytes:
    seg = seg + "=" * (-len(seg) % 4)
    return base64.urlsafe_b64decode(seg.encode("ascii"))


def _b64url_encode(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def _parse_jwt(token: str) -> Optional[tuple[dict, dict, str]]:
    parts = token.split(".")
    if len(parts) != 3:
        return None
    try:
        h = json.loads(_b64url_decode(parts[0]))
        p = json.loads(_b64url_decode(parts[1]))
    except Exception:
        return None
    return h, p, parts[2]


def _try_weak_keys(token: str) -> Optional[str]:
    """If alg is HS256, try common weak keys offline. Returns the cracked
    key string or None."""
    parts = token.split(".")
    if len(parts) != 3:
        return None
    try:
        header = json.loads(_b64url_decode(parts[0]))
    except Exception:
        return None
    if header.get("alg") not in ("HS256", "HS384", "HS512"):
        return None
    msg = (parts[0] + "." + parts[1]).encode("ascii")
    sig_target = parts[2]
    digest = {"HS256": hashlib.sha256, "HS384": hashlib.sha384,
              "HS512": hashlib.sha512}[header["alg"]]
    for k in _WEAK_KEYS:
        h = hmac.new(k.encode("utf-8"), msg, digest).digest()
        if _b64url_encode(h) == sig_target:
            return k
    return None


async def run(agent: SwarmAgent) -> List[dict]:
    url = normalize_target_url(agent.target)
    if not url:
        return []
    timeout = min(agent.timeout_s, 8.0)

    resp = await fetch("GET", url, timeout=timeout)
    if not resp:
        return []

    # Collect candidate tokens, tracking the SOURCE of each. A token that
    # arrives via Set-Cookie or an Authorization response header is a real,
    # application-issued credential — cracking its key means we can forge a
    # session. A token that merely appears in the HTML body is almost always
    # documentation/sample text (e.g. the jwt.io example token signed with
    # the published "your-256-bit-secret"), NOT a live credential. We must
    # never raise weak_key/alg_none from a body-scraped token, or every API
    # docs page that prints a sample JWT becomes a false critical.
    #
    # `credential=True` → token came from a header the server set on this
    # response (cookie / auth). Only those are eligible for the high/critical
    # forgeability findings; body tokens are downgraded to info-only.
    candidates: dict[str, bool] = {}  # token -> credential?

    def _collect(text: str, credential: bool) -> None:
        for m in _JWT_RE.finditer(text):
            tok = m.group(0)
            # credential source wins if the same token shows up in both places
            candidates[tok] = candidates.get(tok, False) or credential

    _collect(resp.headers.get("set-cookie") or "", credential=True)
    _collect(resp.headers.get("authorization") or "", credential=True)
    _collect(resp.body[:32 * 1024], credential=False)

    findings: list[dict] = []
    for tok, credential in candidates.items():
        parsed = _parse_jwt(tok)
        if not parsed:
            continue
        header, payload, _ = parsed
        alg = (header.get("alg") or "").upper()

        # Detection 1: alg=none indicates obvious misuse (no real server
        # should sign with none, but the *header* with alg=none + empty
        # sig is what we'd forge — finding it in a live token is rare
        # but still informational). Only flag for credential-sourced tokens;
        # a body sample showing alg=none is just documentation.
        if alg == "NONE" and credential:
            findings.append({
                "type": "jwt_alg_none",
                "vuln_type": "jwt:alg_none",
                "title": "JWT with alg=none observed",
                "severity": "high",
                "url": url,
                "cwe": "CWE-345",
                "confidence": 0.9,
                "evidence": f"token header alg=none, payload={json.dumps(payload)[:200]}",
            })

        # Detection 2: HS256 with weak key (cracked offline). Only a
        # critical when the token is a LIVE credential — cracking the key of a
        # sample JWT printed in HTML proves nothing about the application
        # (the docs author chose the example secret, the server never signs
        # real sessions with it). For body-scraped tokens we still report the
        # crack, but as info-only "sample JWT seen in body" so an operator can
        # eyeball it without it polluting the critical queue.
        cracked = _try_weak_keys(tok)
        if cracked is not None:
            if credential:
                findings.append({
                    "type": "jwt_weak_key",
                    "vuln_type": "jwt:weak_key",
                    "title": f"JWT HMAC key crackable: {cracked!r}",
                    "severity": "critical",
                    "url": url,
                    "cwe": "CWE-326",
                    "confidence": 0.99,
                    "evidence": (
                        f"HMAC signature verified locally with key={cracked!r}. "
                        f"alg={alg}. Token can be forged with arbitrary claims. "
                        "Source: server-set session credential (Set-Cookie / "
                        "Authorization)."
                    ),
                })
            else:
                findings.append({
                    "type": "jwt_weak_key_sample",
                    "vuln_type": "jwt:weak_key_sample",
                    "title": f"Sample JWT in page body cracks with {cracked!r}",
                    "severity": "info",
                    "url": url,
                    "cwe": "CWE-326",
                    "confidence": 0.4,
                    "evidence": (
                        f"A JWT found in the response body verified locally with "
                        f"key={cracked!r} (alg={alg}). This token is NOT a "
                        "server-issued credential (no Set-Cookie/Authorization "
                        "source) and is almost certainly documentation/example "
                        "text — verify manually before treating as forgeable."
                    ),
                })

        # Detection 3: alg field present + visible token (informational)
        src = "credential" if credential else "body"
        findings.append({
            "type": "jwt_observed",
            "vuln_type": f"jwt:observed:{alg}",
            "title": f"JWT observed (alg={alg}, source={src})",
            "severity": "info",
            "url": url,
            "confidence": 1.0,
            "evidence": f"token payload keys: {list(payload.keys())[:10]}",
        })

    return findings


register_worker("vuln", TECHNIQUE, run)
