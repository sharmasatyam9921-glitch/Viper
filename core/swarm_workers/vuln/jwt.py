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

# Cracking a weak HMAC key is only CRITICAL when forging the token escalates
# privilege — i.e. the token AUTHORIZES an identity. Many JWTs that the server
# sets on every anonymous visitor authorize nothing: anti-CSRF double-submit
# nonces, A/B feature-flag buckets, cookie-consent records, guest markers. Their
# signing key is often a copy-pasted tutorial default, so they crack instantly,
# but forging them grants no access. Two signals gate the escalation:
#
# (1) Cookie NAME convention: cookies named XSRF-TOKEN / CSRF-TOKEN / _csrf /
#     *consent* / *flags* / ab_* are non-credential by convention. Never escalate.
# (2) Payload claims: a session must carry an identity claim (sub/user/uid/
#     email/role/scope/...) AND must not be explicitly marked non-auth
#     (xsrf/csrf/nonce/bucket/consent). A payload whose only fields are a nonce
#     or a bucket is not a session.
_IDENTITY_CLAIMS = frozenset({
    "sub", "user", "username", "uid", "user_id", "userid", "email",
    "role", "roles", "scope", "scopes", "authorities", "groups", "perms",
    "permissions", "account", "actor", "client_id", "azp", "preferred_username",
})
_NON_AUTH_MARKERS = frozenset({
    "xsrf", "csrf", "_csrf", "nonce", "bucket", "variant", "experiment",
    "consent", "flag", "flags", "feature", "ab", "abtest", "guest",
    "anonymous", "anon", "csrf_token", "xsrf_token", "antiforgery",
})
# Cookie-name substrings that mark a conventionally non-credential cookie.
_NON_CRED_COOKIE_NAME_RE = re.compile(
    r"(xsrf|csrf|antiforgery|consent|flag|bucket|variant|experiment|^ab[_-])",
    re.IGNORECASE,
)


def _cookie_name(set_cookie_segment: str) -> str:
    """Best-effort cookie name from a single Set-Cookie value (`name=value; ...`)."""
    head = set_cookie_segment.split(";", 1)[0].strip()
    return head.split("=", 1)[0].strip() if "=" in head else ""


def _authorizes_identity(payload: dict, cookie_name: str) -> bool:
    """True only if cracking the token's key would let us forge an *identity*.

    A conventionally non-credential cookie name, or a payload that carries no
    identity claim, or one explicitly marked as a non-auth artifact (CSRF nonce /
    A-B bucket / consent flag) does NOT authorize an identity — forging it
    escalates nothing, so a weak key there is not a critical.
    """
    if cookie_name and _NON_CRED_COOKIE_NAME_RE.search(cookie_name):
        return False
    keys = {str(k).lower() for k in payload.keys()}
    if keys & _NON_AUTH_MARKERS:
        return False
    aud = payload.get("aud")
    if isinstance(aud, str) and aud.lower() in ("anti-csrf", "csrf", "xsrf"):
        return False
    return bool(keys & _IDENTITY_CLAIMS)


def _b64url_decode(seg: str) -> bytes:
    seg = seg + "=" * (-len(seg) % 4)
    return base64.urlsafe_b64decode(seg.encode("ascii"))


def _b64url_encode(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


# --- RS256->HS256 algorithm confusion: JWK -> PEM (hand-rolled DER, no crypto dep) ---
#
# A verifier that trusts the token's `alg` header can be tricked: the RSA PUBLIC key is
# public (published at jwks.json), so an attacker forges an HS256 token whose HMAC
# secret IS the server's public key in its usual byte form — the SubjectPublicKeyInfo
# PEM. If the server HMAC-verifies with that key, the forgery is accepted (CWE-347).
# We reconstruct that exact PEM from the JWK so the gate can attempt the forge.

def _der_len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    out = bytearray()
    while n:
        out.insert(0, n & 0xFF)
        n >>= 8
    return bytes([0x80 | len(out)]) + bytes(out)


def _der_uint(x: int) -> bytes:
    """DER INTEGER (non-negative): a leading 0x00 is prepended when the high bit is set
    so the value stays positive."""
    b = x.to_bytes((x.bit_length() + 7) // 8 or 1, "big")
    if b[0] & 0x80:
        b = b"\x00" + b
    return b"\x02" + _der_len(len(b)) + b


def _der_seq(*parts: bytes) -> bytes:
    body = b"".join(parts)
    return b"\x30" + _der_len(len(body)) + body


def jwk_rsa_to_pem(n_b64url: str, e_b64url: str) -> str:
    """Convert an RSA JWK (n, e as base64url) to a canonical SubjectPublicKeyInfo PEM —
    the byte form a JWT library loads as the verification key, hence the exact HMAC
    secret for an RS256->HS256 forgery. DER is deterministic, so this matches OpenSSL's
    output. Raises on malformed input (callers guard)."""
    n = int.from_bytes(_b64url_decode(n_b64url), "big")
    e = int.from_bytes(_b64url_decode(e_b64url), "big")
    rsa_pub = _der_seq(_der_uint(n), _der_uint(e))
    alg_id = _der_seq(bytes.fromhex("06092A864886F70D010101"), b"\x05\x00")  # rsaEncryption, NULL
    bit_string = b"\x03" + _der_len(len(rsa_pub) + 1) + b"\x00" + rsa_pub
    spki = _der_seq(alg_id, bit_string)
    b64 = base64.b64encode(spki).decode("ascii")
    body = "\n".join(b64[i:i + 64] for i in range(0, len(b64), 64))
    return f"-----BEGIN PUBLIC KEY-----\n{body}\n-----END PUBLIC KEY-----\n"


_JWKS_PATHS = ("/.well-known/jwks.json", "/jwks.json", "/jwks",
               "/.well-known/openid-configuration")


async def _fetch_pubkey_pem(root: str, kid: Optional[str], timeout: float) -> Optional[str]:
    """Fetch jwks.json (read-only) and return the RSA public key (matching `kid` if the
    token carried one) as a SubjectPublicKeyInfo PEM, or None. Follows an
    openid-configuration ``jwks_uri`` one hop, same host only."""
    for path in _JWKS_PATHS:
        r = await fetch("GET", root + path, timeout=timeout)
        if not r or not getattr(r, "body", None):
            continue
        try:
            data = json.loads(r.body)
        except (ValueError, TypeError):
            continue
        keys = data.get("keys") if isinstance(data, dict) else None
        if keys is None and isinstance(data, dict) and data.get("jwks_uri"):
            juri = str(data["jwks_uri"])
            from ._http import _host_key
            # Compare HOSTS, not a string prefix: startswith(root) let
            # target.com.attacker.com and target.com@attacker.com through.
            if _host_key(juri) == _host_key(root):   # same host only — never chase off-scope
                jr = await fetch("GET", juri, timeout=timeout)
                try:
                    keys = (json.loads(jr.body) or {}).get("keys") if jr and jr.body else None
                except (ValueError, TypeError):
                    keys = None
        for k in keys or []:
            if not isinstance(k, dict) or k.get("kty") != "RSA":
                continue
            if kid and k.get("kid") and k.get("kid") != kid:
                continue
            n, e = k.get("n"), k.get("e")
            if n and e:
                try:
                    return jwk_rsa_to_pem(str(n), str(e))
                except Exception:  # noqa: BLE001 — malformed JWK, try the next key
                    continue
    return None


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


def _mask_key(k: str) -> str:
    """Redact a recovered credential for report/title/evidence text — no chars of the
    secret leak (Ethical Rule #6). The full value stays in the finding's `_jwt_key`
    (underscore-prefixed → skipped by disk/notification serializers) for the operator."""
    return f"<{len(k)}-char key, redacted>" if k else "<redacted>"


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
    # `credential=True` -> token came from a header the server set on this
    # response (cookie / auth). Only those are eligible for the high/critical
    # forgeability findings; body tokens are downgraded to info-only. We also
    # remember the cookie NAME a token arrived under (empty for Authorization /
    # body) — it's a strong signal of whether the token is a session credential
    # or a non-credential artifact (XSRF-TOKEN, ab_*, *consent*).
    candidates: dict[str, bool] = {}  # token -> credential?
    cookie_names: dict[str, str] = {}  # token -> originating cookie name

    def _collect(text: str, credential: bool, cookie_name: str = "") -> None:
        for m in _JWT_RE.finditer(text):
            tok = m.group(0)
            # credential source wins if the same token shows up in both places
            candidates[tok] = candidates.get(tok, False) or credential
            if cookie_name and not cookie_names.get(tok):
                cookie_names[tok] = cookie_name

    # Set-Cookie may carry several cookies (one header value, comma-joined, or
    # repeated). Split on the segment boundary and collect the JWT in each so we
    # can attribute it to the right cookie name.
    raw_set_cookie = resp.headers.get("set-cookie") or ""
    for seg in re.split(r",(?=[^;,]+?=)", raw_set_cookie):
        _collect(seg, credential=True, cookie_name=_cookie_name(seg))
    _collect(resp.headers.get("authorization") or "", credential=True)
    _collect(resp.body[:32 * 1024], credential=False)

    findings: list[dict] = []
    for tok, credential in candidates.items():
        parsed = _parse_jwt(tok)
        if not parsed:
            continue
        header, payload, _ = parsed
        alg = (header.get("alg") or "").upper()
        cookie_name = cookie_names.get(tok, "")

        # A credential-sourced token only justifies a high/critical forgeability
        # finding if cracking/forging it would let us escalate — i.e. the token
        # AUTHORIZES an identity. Anonymous CSRF nonces, A/B buckets, and consent
        # records arrive via Set-Cookie too, but forging them grants nothing.
        # `forgeable` = real session credential we could escalate by forging.
        forgeable = credential and _authorizes_identity(payload, cookie_name)

        # Detection 1: alg=none indicates obvious misuse (no real server
        # should sign with none, but the *header* with alg=none + empty
        # sig is what we'd forge — finding it in a live token is rare
        # but still informational). Only flag for credential-sourced tokens
        # that authorize an identity; a body sample, or a non-credential CSRF/
        # bucket cookie, showing alg=none escalates nothing.
        if alg == "NONE" and forgeable:
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
        # critical when the token is a LIVE, IDENTITY-BEARING credential —
        # cracking the key of a sample JWT printed in HTML, or of an anonymous
        # CSRF-nonce / A-B-bucket cookie, proves nothing about session security
        # (forging it forges no identity). For those we still report the crack,
        # but downgraded to info-only so it doesn't pollute the critical queue.
        cracked = _try_weak_keys(tok)
        if cracked is not None:
            if forgeable:
                findings.append({
                    "type": "jwt_weak_key",
                    "vuln_type": "jwt:weak_key",
                    "title": f"JWT HMAC key crackable: {_mask_key(cracked)}",
                    "severity": "critical",
                    "url": url,
                    "cwe": "CWE-326",
                    "confidence": 0.99,
                    # Structured fields let the validation gate attempt a forge-accept
                    # confirmation (opt-in, operator-supplied endpoint). Cracking the
                    # key OFFLINE proves the key is weak, not that the SERVER accepts a
                    # forged token — the gate closes that gap when given an endpoint.
                    "_jwt_token": tok,
                    "_jwt_key": cracked,
                    "jwt_alg": alg,
                    "jwt_source": cookie_name or "authorization",
                    "evidence": (
                        f"HMAC signature verified locally with key={_mask_key(cracked)}. "
                        f"alg={alg}. Token can be forged with arbitrary claims. "
                        "Source: server-set session credential (Set-Cookie / "
                        f"Authorization) carrying an identity claim "
                        f"({sorted({str(k).lower() for k in payload} & _IDENTITY_CLAIMS)})."
                    ),
                })
            elif credential:
                # Credential-sourced but authorizes no identity: a weak key on a
                # CSRF nonce / feature-flag / consent cookie. Worth noting (the
                # key is still leaked / shared) but forging it escalates nothing.
                findings.append({
                    "type": "jwt_weak_key_noauth",
                    "vuln_type": "jwt:weak_key_noauth",
                    "title": f"Non-identity JWT cookie cracks with {_mask_key(cracked)}",
                    "severity": "info",
                    "url": url,
                    "cwe": "CWE-326",
                    "confidence": 0.5,
                    "evidence": (
                        f"Server-set cookie {cookie_name or '<unnamed>'!r} is a JWT "
                        f"verified locally with key={_mask_key(cracked)} (alg={alg}), but its "
                        f"payload carries NO identity claim "
                        f"(keys={list(payload.keys())[:10]}) — it looks like an "
                        "anti-CSRF nonce / feature-flag / consent record. Forging it "
                        "escalates no privilege; not a session-forgery critical."
                    ),
                })
            else:
                findings.append({
                    "type": "jwt_weak_key_sample",
                    "vuln_type": "jwt:weak_key_sample",
                    "title": f"Sample JWT in page body cracks with {_mask_key(cracked)}",
                    "severity": "info",
                    "url": url,
                    "cwe": "CWE-326",
                    "confidence": 0.4,
                    "evidence": (
                        f"A JWT found in the response body verified locally with "
                        f"key={_mask_key(cracked)} (alg={alg}). This token is NOT a "
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

    # Detection 4: RS256->HS256 algorithm confusion. A server that issues an
    # RSA-signed identity token verifies with an RSA PUBLIC key it publishes at
    # jwks.json. If its verifier trusts the token's `alg` header, an attacker can
    # forge an HS256 token whose HMAC secret is that public key. We emit an opt-in
    # LEAD carrying the token + reconstructed public-key PEM; the gate confirms it
    # only when an operator supplies jwt_probe_endpoint (never auto-submitted).
    from urllib.parse import urlsplit as _urlsplit
    _p = _urlsplit(url)
    root = f"{_p.scheme}://{_p.netloc}"
    rs_tok = next(
        (t for t, cred in candidates.items()
         if cred and _parse_jwt(t)
         and (_parse_jwt(t)[0].get("alg") or "").upper().startswith("RS")
         and _authorizes_identity(_parse_jwt(t)[1], cookie_names.get(t, ""))),
        None)
    if rs_tok:
        hdr = _parse_jwt(rs_tok)[0]
        try:
            pem = await _fetch_pubkey_pem(root, hdr.get("kid"), timeout)
        except Exception as e:  # noqa: BLE001 — jwks fetch is best-effort
            logger.debug("jwks fetch failed: %s", e)
            pem = None
        if pem:
            findings.append({
                "type": "jwt_alg_confusion",
                "vuln_type": "jwt:alg_confusion",
                "title": "JWT RS256->HS256 algorithm-confusion candidate",
                "severity": "high",
                "url": url,
                "cwe": "CWE-347",
                "confidence": 0.5,
                "_jwt_token": rs_tok,
                "jwt_pubkey_pem": pem,
                "jwt_source": cookie_names.get(rs_tok, "") or "authorization",
                "evidence": (
                    "server issues an RS-signed identity token and publishes its RSA "
                    "public key at jwks.json; a verifier that trusts the alg header would "
                    "accept an HS256 token signed with that public key. Supply "
                    "jwt_probe_endpoint to confirm the forged token is accepted."
                ),
            })

    return findings


register_worker("vuln", TECHNIQUE, run)
