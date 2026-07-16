"""Isolated credential vault — full auth material NEVER enters a finding dict.

A leaked app-session credential (a JWT found on a server-side surface) can escalate to an
authenticated re-sweep of the SAME app. But the credential VALUE must never be serialized
into a report, the tamper-evident custody manifest, or a submission draft (Ethical Rule #6
— findings are redacted). So the value lives ONLY here, keyed by an opaque ref; findings
carry the ref + the host it belongs to, never the value.

Host-bound by construction: each ref records the exact host the credential was found on, and
the host-scoped auth in ``_http`` guarantees it is only ever sent to THAT host — never to
another in-scope host and never to a third-party/cloud API. Cleared at the hunt boundary.

This module is imported ONLY by the credential producer (secrets worker) and consumer
(hack_mode re-sweep) — never by any reporter/serializer/manifest writer.
"""
from __future__ import annotations

import secrets as _secrets
import threading
from typing import Dict, Optional, Tuple

_lock = threading.Lock()
# ref -> (host, header_name, header_value). Module-global, process-local, never serialized.
_vault: Dict[str, Tuple[str, str, str]] = {}


def stash(host: str, header_name: str, header_value: str) -> Optional[str]:
    """Store an auth header bound to ``host`` and return an opaque ref (goes in the finding
    instead of the value). Returns None if any field is missing."""
    if not (host and header_name and header_value):
        return None
    ref = "authref_" + _secrets.token_hex(8)
    with _lock:
        _vault[ref] = (str(host), str(header_name), str(header_value))
    return ref


def resolve(ref: str) -> Optional[Tuple[str, Dict[str, str]]]:
    """Return (host, {header_name: header_value}) for a ref, or None if unknown."""
    if not ref:
        return None
    with _lock:
        item = _vault.get(ref)
    if not item:
        return None
    host, hn, hv = item
    return host, {hn: hv}


def clear() -> None:
    """Drop all stored material (called at the hunt boundary)."""
    with _lock:
        _vault.clear()
