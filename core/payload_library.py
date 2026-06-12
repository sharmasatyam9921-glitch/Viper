"""Curated attack-payload library.

Loads ``knowledge/payloads.json`` once, caches it, and exposes payloads keyed
by vuln class. The loader is defensive by design: a missing, unreadable, or
corrupt JSON file degrades to an empty library rather than raising, so a worker
can safely call :func:`merge_payloads` at import time without guarding it.

Typical worker usage::

    from core.payload_library import merge_payloads

    _PAYLOADS = merge_payloads(_PAYLOADS, "sql_injection")
"""

from __future__ import annotations

import json
import threading
from pathlib import Path
from typing import Dict, List

_PAYLOADS_PATH: Path = Path(__file__).parent / "selfimprove" / "payloads.json"

# Cache: vuln_class -> list of payload dicts. ``None`` means "not yet loaded".
_cache: Dict[str, List[dict]] | None = None
_lock = threading.Lock()


def _load() -> Dict[str, List[dict]]:
    """Read and validate the payload file, returning a class -> entries map.

    Never raises. Any error (missing file, bad JSON, wrong shape) yields ``{}``.
    Keys beginning with ``_`` (e.g. ``_meta``) and non-list values are skipped,
    and each entry list is filtered to dicts only.
    """
    try:
        raw = json.loads(_PAYLOADS_PATH.read_text(encoding="utf-8"))
    except (OSError, ValueError, UnicodeDecodeError):
        return {}

    if not isinstance(raw, dict):
        return {}

    # Accept both a flat {class: [...]} file and a wrapped
    # {"version":..., "classes": {class: [...]}} file.
    source = raw.get("classes") if isinstance(raw.get("classes"), dict) else raw

    library: Dict[str, List[dict]] = {}
    for vuln_class, entries in source.items():
        if not isinstance(vuln_class, str) or vuln_class.startswith("_"):
            continue
        if not isinstance(entries, list):
            continue
        library[vuln_class] = [e for e in entries if isinstance(e, dict)]
    return library


def _library() -> Dict[str, List[dict]]:
    """Return the cached library, loading it once on first use (thread-safe)."""
    global _cache
    if _cache is None:
        with _lock:
            if _cache is None:
                _cache = _load()
    return _cache


def reload() -> None:
    """Drop the cache so the next access re-reads the file (mainly for tests)."""
    global _cache
    with _lock:
        _cache = None


# Alias scorer/worker class names to the library's keys so either resolves.
_ALIASES = {
    "rce": "command_injection",
    "cmdi": "command_injection",
    "command_injection": "command_injection",
    "sqli": "sql_injection",
    "path_traversal": "lfi",
    "nosql": "nosql_injection",
}


def get_payloads(vuln_class: str) -> List[dict]:
    """Return payload entry dicts for ``vuln_class`` (``[]`` if unknown).

    Returns a fresh list copy so callers can mutate it freely without
    corrupting the shared cache.
    """
    lib = _library()
    key = vuln_class if vuln_class in lib else _ALIASES.get(vuln_class, vuln_class)
    return list(lib.get(key, []))


def merge_payloads(
    defaults: List[str],
    vuln_class: str,
    *,
    waf_only: bool = False,
) -> List[str]:
    """Merge ``defaults`` with library payload strings, deduped, defaults first.

    The returned list preserves the order of ``defaults`` (and their relative
    order), then appends library payloads for ``vuln_class`` that are not
    already present. Duplicates within ``defaults`` are also collapsed.

    Args:
        defaults: A worker's built-in payload strings. Order is preserved.
        vuln_class: Library key to pull extra payloads from.
        waf_only: If true, only library entries flagged ``waf_bypass`` are
            added (``defaults`` are always kept regardless of this flag).
    """
    merged: List[str] = []
    seen: set[str] = set()

    for payload in defaults:
        if payload not in seen:
            seen.add(payload)
            merged.append(payload)

    for entry in get_payloads(vuln_class):
        if waf_only and not entry.get("waf_bypass"):
            continue
        payload = entry.get("payload")
        if not isinstance(payload, str) or payload in seen:
            continue
        seen.add(payload)
        merged.append(payload)

    return merged


def payload_count() -> int:
    """Return the total number of payload entries across all classes."""
    return sum(len(entries) for entries in _library().values())
