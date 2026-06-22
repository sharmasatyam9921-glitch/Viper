"""Relay wire protocol: newline-delimited, HMAC-SHA256-authenticated JSON.

Every message line is ``<hex-hmac> <compact-json>\\n``. The HMAC is computed over
the JSON bytes with the shared pairing secret, so a peer without the secret can
neither forge nor tamper with a message. ``verify`` uses a constant-time compare.
"""
from __future__ import annotations

import hashlib
import hmac
import json
from typing import Optional


def _secret_bytes(secret) -> bytes:
    return secret if isinstance(secret, (bytes, bytearray)) else str(secret).encode()


def sign(payload: dict, secret) -> bytes:
    body = json.dumps(payload, separators=(",", ":"), default=str).encode("utf-8")
    mac = hmac.new(_secret_bytes(secret), body, hashlib.sha256).hexdigest()
    return mac.encode("ascii") + b" " + body + b"\n"


def verify(line, secret) -> Optional[dict]:
    """Return the payload dict iff the line's HMAC is valid, else None."""
    try:
        if isinstance(line, (bytes, bytearray)):
            line = line.decode("utf-8", "replace")
        line = line.rstrip("\n")
        mac, sep, body = line.partition(" ")
        if not sep or not mac:
            return None
        expected = hmac.new(_secret_bytes(secret), body.encode("utf-8"),
                            hashlib.sha256).hexdigest()
        if not hmac.compare_digest(mac, expected):
            return None
        return json.loads(body)
    except Exception:
        return None
