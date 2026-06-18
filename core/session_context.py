"""Per-hunt shared session context (foundation for authenticated, multi-role testing).

Holds, for one hunt:

  * **roles**        — named authenticated identities (auth headers + the identity
                       markers that prove a piece of data is privately theirs).
  * **reachability** — a ``(role, url) -> HTTP status`` matrix: which identity can
                       reach which endpoint, and with what result.
  * **corpus**       — a bounded log of captured requests, for replay / PoC.

This is the substrate multi-account testing reads. A *role-diff* over the
reachability matrix (an endpoint the owner can reach) seeds two-account BOLA, and
:meth:`bola_config_for` produces exactly the config dict the validation gate and
the ``bola_multi`` worker already consume — so the context plugs into the existing
authorization-testing path without changing it.

Async-safe: every mutation is guarded by a lock, because HTTP capture can land
from worker threads (``fetch`` runs in ``asyncio.to_thread``). Serializable to and
from a plain dict so it can be persisted on the knowledge graph and restored on
resume. No external dependencies.
"""
from __future__ import annotations

import threading
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple


@dataclass
class Role:
    """One authenticated identity under test."""

    name: str
    headers: Dict[str, str] = field(default_factory=dict)   # Cookie / Authorization
    markers: List[str] = field(default_factory=list)        # strings unique to this user

    def clean_markers(self) -> List[str]:
        """Markers usable for leak detection: >= 3 chars, stripped, de-blanked."""
        return [m.strip() for m in self.markers
                if isinstance(m, str) and len(m.strip()) >= 3]


@dataclass
class CapturedRequest:
    role: str
    method: str
    url: str
    status: int


def _ok(status: Optional[int]) -> bool:
    return status is not None and 200 <= status < 300


class SessionContext:
    """Thread/async-safe per-hunt session + reachability state."""

    def __init__(self, hunt_id: str = "", corpus_limit: int = 1000):
        self.hunt_id = hunt_id
        self.corpus_limit = max(1, int(corpus_limit))
        self._roles: Dict[str, Role] = {}
        self._reach: Dict[Tuple[str, str], int] = {}
        self._corpus: List[CapturedRequest] = []
        self._lock = threading.Lock()

    # --- roles -------------------------------------------------------------

    def add_role(self, name: str, headers: Optional[dict] = None,
                 markers: Optional[List[str]] = None) -> Role:
        role = Role(name, dict(headers or {}), list(markers or []))
        with self._lock:
            self._roles[name] = role
        return role

    def get_role(self, name: str) -> Optional[Role]:
        with self._lock:
            return self._roles.get(name)

    @property
    def roles(self) -> List[str]:
        with self._lock:
            return list(self._roles.keys())

    # --- reachability + corpus --------------------------------------------

    def record(self, role: str, method: str, url: str, status: int) -> None:
        """Record that `role` saw `status` for `url` (updates matrix + corpus)."""
        with self._lock:
            self._reach[(role, url)] = int(status)
            self._corpus.append(CapturedRequest(role, method.upper(), url, int(status)))
            if len(self._corpus) > self.corpus_limit:    # keep only the most recent
                self._corpus = self._corpus[-self.corpus_limit:]

    def status(self, role: str, url: str) -> Optional[int]:
        with self._lock:
            return self._reach.get((role, url))

    def reachable_urls(self, role: str, ok_only: bool = True) -> List[str]:
        """URLs this role has been observed to reach (2xx only by default)."""
        with self._lock:
            return [url for (r, url), st in self._reach.items()
                    if r == role and (not ok_only or _ok(st))]

    def role_diff(self, url: str) -> Dict[str, int]:
        """For one URL, the status each role observed — who can reach it."""
        with self._lock:
            return {r: st for (r, u), st in self._reach.items() if u == url}

    @property
    def corpus(self) -> List[CapturedRequest]:
        with self._lock:
            return list(self._corpus)

    # --- BOLA bridge -------------------------------------------------------

    def candidate_urls_for_bola(self, owner: str) -> List[str]:
        """Endpoints the owner can reach (2xx) — worth a cross-user BOLA replay."""
        return self.reachable_urls(owner, ok_only=True)

    def bola_config_for(self, owner: str, attacker: str) -> dict:
        """Build the bola_config dict the gate / bola_multi worker consume.

        Raises KeyError if either role is unknown — callers should add both roles
        (with the owner's identity markers) first.
        """
        with self._lock:
            o = self._roles[owner]
            a = self._roles[attacker]
        return {
            "owner_name": o.name,
            "owner_headers": dict(o.headers),
            "owner_markers": o.clean_markers(),
            "attacker_name": a.name,
            "attacker_headers": dict(a.headers),
            "attacker_markers": a.clean_markers(),
        }

    def reachability_matrix(self) -> Dict[Tuple[str, str], int]:
        """A copy of the (role, url) -> status matrix (for find_bola's optimizer)."""
        with self._lock:
            return dict(self._reach)

    # --- serialization (graph persistence / resume) ------------------------

    def to_dict(self) -> dict:
        with self._lock:
            return {
                "hunt_id": self.hunt_id,
                "corpus_limit": self.corpus_limit,
                "roles": [
                    {"name": r.name, "headers": r.headers, "markers": r.markers}
                    for r in self._roles.values()
                ],
                "reachability": [[role, url, st]
                                 for (role, url), st in self._reach.items()],
                "corpus": [[c.role, c.method, c.url, c.status] for c in self._corpus],
            }

    def summary(self) -> dict:
        """Compact, secret-free shape for report/result serialization."""
        with self._lock:
            return {
                "hunt_id": self.hunt_id,
                "roles": list(self._roles.keys()),
                "endpoints_observed": len({u for (_r, u) in self._reach}),
                "reachability_entries": len(self._reach),
                "corpus_size": len(self._corpus),
            }

    @classmethod
    def from_dict(cls, d: dict) -> "SessionContext":
        ctx = cls(hunt_id=d.get("hunt_id", ""),
                  corpus_limit=d.get("corpus_limit", 1000))
        for r in d.get("roles", []):
            if isinstance(r, dict) and r.get("name"):
                ctx.add_role(r["name"], r.get("headers"), r.get("markers"))
        # Tolerate malformed persisted state (a corrupt graph row must not crash
        # a resume): skip entries that are not well-formed rather than raising.
        for entry in d.get("reachability", []):
            if not isinstance(entry, (list, tuple)) or len(entry) != 3:
                continue
            role, url, st = entry
            try:
                ctx._reach[(role, url)] = int(st)
            except (TypeError, ValueError):
                continue
        for c in d.get("corpus", []):
            if not isinstance(c, (list, tuple)) or len(c) != 4:
                continue
            role, method, url, st = c
            try:
                ctx._corpus.append(CapturedRequest(role, method, url, int(st)))
            except (TypeError, ValueError):
                continue
        return ctx

    def __repr__(self) -> str:
        s = self.summary()
        return (f"<SessionContext hunt={s['hunt_id']!r} roles={s['roles']} "
                f"endpoints={s['endpoints_observed']} "
                f"reach={s['reachability_entries']}>")
