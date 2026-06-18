"""Normalize + dedup captured HTTP traffic into unique endpoint/param candidates.

Mirrors a proxy -> agent pipeline: every observed request is normalized to a
canonical *signature* — method + host + path + the SORTED SET OF PARAM NAMES
(values dropped) — so ``/api/orders?id=1`` and ``/api/orders?id=2`` collapse to a
single candidate. That hands the swarm a deduplicated work-list instead of
thousands of value-variant URLs, and surfaces the parameter names worth fuzzing.
Pure functions + a small accumulator; no I/O, no browser.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import parse_qsl, urlsplit


def request_signature(method: str, url: str) -> str:
    """Canonical signature collapsing value-variants of the same endpoint.

    ``GET /api/orders?id=1`` and ``GET /api/orders?id=2`` -> same signature;
    a different param set or path -> different signature.
    """
    parts = urlsplit(url)
    names = sorted({k for k, _ in parse_qsl(parts.query, keep_blank_values=True)})
    host = (parts.hostname or "").lower()
    if parts.port:
        host = f"{host}:{parts.port}"
    path = parts.path or "/"
    pstr = ("?" + ",".join(names)) if names else ""
    return f"{method.upper()} {parts.scheme}://{host}{path}{pstr}"


@dataclass
class _Entry:
    method: str
    url: str               # a representative concrete URL for this signature
    statuses: Set[int] = field(default_factory=set)
    roles: Set[str] = field(default_factory=set)
    count: int = 0


class RequestCorpus:
    """Accumulates captured requests, deduplicated by signature."""

    def __init__(self):
        self._by_sig: Dict[str, _Entry] = {}

    def add(self, method: str, url: str, status: Optional[int] = None,
            role: Optional[str] = None) -> str:
        if not url or urlsplit(url).scheme.lower() not in ("http", "https"):
            return ""
        sig = request_signature(method, url)
        e = self._by_sig.get(sig)
        if e is None:
            e = _Entry(method.upper(), url)
            self._by_sig[sig] = e
        e.count += 1
        if status is not None:
            e.statuses.add(int(status))
        if role:
            e.roles.add(role)
        return sig

    def __len__(self) -> int:
        return len(self._by_sig)

    def signatures(self) -> List[str]:
        return list(self._by_sig.keys())

    def candidates(self) -> List[Tuple[str, str]]:
        """One representative (method, url) per unique signature."""
        return [(e.method, e.url) for e in self._by_sig.values()]

    def params(self) -> Set[str]:
        """All distinct query-parameter names seen across captured traffic."""
        out: Set[str] = set()
        for e in self._by_sig.values():
            for k, _ in parse_qsl(urlsplit(e.url).query, keep_blank_values=True):
                out.add(k)
        return out

    def endpoints(self) -> Set[Tuple[str, str, str]]:
        """Distinct (method, host, path) tuples (ignores params entirely)."""
        out: Set[Tuple[str, str, str]] = set()
        for e in self._by_sig.values():
            p = urlsplit(e.url)
            host = (p.hostname or "").lower()
            out.add((e.method, host, p.path or "/"))
        return out

    def to_har(self) -> dict:
        """Minimal HAR-shaped export of the deduplicated corpus (for replay)."""
        entries = []
        for e in self._by_sig.values():
            entries.append({
                "request": {"method": e.method, "url": e.url},
                "response": {"status": (sorted(e.statuses)[0] if e.statuses else 0)},
                "_roles": sorted(e.roles),
                "_count": e.count,
            })
        return {"log": {"version": "1.2", "creator": {"name": "VIPER"},
                        "entries": entries}}
