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
_HINTS_PATH: Path = Path(__file__).parent / "selfimprove" / "param_hints.json"
_PRIORS_PATH: Path = Path(__file__).parent / "selfimprove" / "vuln_class_priors.json"

# Cache: vuln_class -> list of payload dicts. ``None`` means "not yet loaded".
_cache: Dict[str, List[dict]] | None = None
_hints_cache: List[str] | None = None
_priors_cache: Dict | None = None
_lock = threading.Lock()


_discovered_params: set = set()
_DISCOVERED_CAP = 60


def add_discovered_params(params) -> None:
    """Register parameter names the crawler discovered THIS hunt (URL query keys,
    form inputs). Injection workers append these to their candidate set so they
    probe the app's REAL parameter names instead of only a static default list —
    the recall fix for endpoints whose vuln param isn't a common guess.

    Empty by default, so when no crawler has run the workers behave exactly as
    before (no behavior change for the precision benchmark)."""
    for p in params or []:
        s = str(p).strip()
        if s and len(s) <= 64 and len(_discovered_params) < _DISCOVERED_CAP:
            _discovered_params.add(s)


_BLP_PATH: Path = Path(__file__).parent / "selfimprove" / "business_logic_params.json"
_blp_cache: Dict[str, List[str]] | None = None


def get_business_logic_params(category: Optional[str] = None) -> List[str]:
    """Business-logic / object-reference parameter names mined from disclosed
    access-control + logic-flaw reports. `category` ∈ object_ref | auth_priv |
    signature | redirect | payment, or None for the flat union. The IDOR/BOLA
    workers and the logic modeler probe these — the params real authz/logic bugs
    hide in. Never raises; [] if unavailable."""
    global _blp_cache
    if _blp_cache is None:
        try:
            data = json.loads(_BLP_PATH.read_text(encoding="utf-8"))
            _blp_cache = {k: [str(x) for x in v] for k, v in data.items()
                          if isinstance(v, list)}
        except Exception:
            _blp_cache = {}
    if category:
        return list(_blp_cache.get(category, []))
    seen: dict = {}
    for vals in _blp_cache.values():
        for p in vals:
            seen[p] = None
    return list(seen)


_BLS_PATH: Path = Path(__file__).parent / "selfimprove" / "business_logic_subclasses.json"
_bls_cache: Dict[str, dict] | None = None


def get_business_logic_subclasses() -> Dict[str, dict]:
    """Business-logic SUBCLASS taxonomy (test patterns + hot params per sub-flaw:
    password_reset, idor_horizontal, privilege_escalation, captcha_bypass,
    credential_stuffing, payment_tampering, auth_bypass) curated from disclosed
    reports. Sharper than the flat class list — tells the logic modeler which
    sub-flaw to test and where. Never raises; {} if unavailable."""
    global _bls_cache
    if _bls_cache is None:
        try:
            _bls_cache = json.loads(_BLS_PATH.read_text(encoding="utf-8")).get(
                "subclasses", {})
        except Exception:
            _bls_cache = {}
    return dict(_bls_cache)


def get_discovered_params() -> List[str]:
    return list(_discovered_params)


def clear_discovered_params() -> None:
    _discovered_params.clear()


def get_param_hints() -> List[str]:
    """Real-world parameter names mined from 7,982 disclosed HackerOne reports
    (host, url, redirect, id, state, relaystate, …). Injection workers merge
    these into their candidate-parameter set so they probe the params that
    actually carry bugs in practice. Never raises; [] if unavailable."""
    global _hints_cache
    if _hints_cache is None:
        try:
            data = json.loads(_HINTS_PATH.read_text(encoding="utf-8"))
            _hints_cache = [str(x) for x in data if isinstance(x, str) and x]
        except Exception:
            _hints_cache = []
    return list(_hints_cache)


def get_class_priors() -> Dict[str, dict]:
    """Per-vuln-class frequency + bounty priors learned from disclosed reports.
    {class: {reports, avg_bounty, value_score, viper_covered}}. Used to dispatch
    high-value workers first within a time budget. Never raises; {} if missing."""
    global _priors_cache
    if _priors_cache is None:
        try:
            _priors_cache = json.loads(_PRIORS_PATH.read_text(encoding="utf-8")).get("priors", {})
        except Exception:
            _priors_cache = {}
    return dict(_priors_cache)


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
