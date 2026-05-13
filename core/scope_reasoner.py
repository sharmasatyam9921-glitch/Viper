"""Scope reasoner — aggressive within scope, hard-stop at the edge.

Wraps the existing `scope.scope_manager.ScopeManager`. Adds:

1. **Caching layer** — decisions keyed by (target, scope-rules-hash) persist
   in SQLite so the same target isn't re-evaluated across runs.

2. **LLM fallback for ambiguous cases** — when the deterministic match
   says "no" but the target looks plausibly related (subdomain variant,
   common prefix, IP near an in-scope CIDR), optionally consult an LLM
   via `ai/model_router.py` and cache the decision. Off by default.

3. **Strict-on-error policy** — any exception or out-of-scope-violation
   returns ``Decision(allowed=False, …)`` so the hack loop never crosses
   the boundary. The "aggressive" part is that we explicitly enumerate
   common in-scope variants (`*.example.com` matches `api.example.com`,
   `mail.api.example.com`, etc.) — current `ScopeManager` already
   handles this via wildcard matching, the reasoner just makes the
   answers explicit, logged, and replayable.

4. **Structured decision objects** — every decision carries a reason +
   confidence + provenance so the audit log can show why.
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
import sqlite3
import threading
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse


logger = logging.getLogger("viper.scope_reasoner")


# ----- Result type ----------------------------------------------------------


@dataclass
class ScopeDecision:
    """Outcome of a single scope check."""
    target: str
    allowed: bool
    reason: str
    confidence: float = 1.0      # 0.0 (unknown) … 1.0 (deterministic match)
    source: str = "deterministic"  # "deterministic" | "cache" | "llm" | "default-deny" | "no-scope"
    matched_entry: Optional[str] = None  # which scope rule matched
    decided_at: float = field(default_factory=time.time)

    def to_dict(self) -> dict:
        return asdict(self)


# ----- Helpers --------------------------------------------------------------


def _normalize(target: str) -> str:
    """Strip scheme, port, trailing slash, lowercase host."""
    t = target.strip().lower()
    if "://" in t:
        try:
            parsed = urlparse(t)
            t = parsed.netloc or parsed.path
        except Exception:
            pass
    t = t.split("/", 1)[0]    # drop path
    t = t.split(":", 1)[0]    # drop port
    return t.strip().rstrip(".")


def _scope_fingerprint(scope_manager) -> str:
    """Cheap stable hash of the loaded scope so cached decisions invalidate
    when the scope changes."""
    parts: list[str] = []
    if scope_manager is None or scope_manager.active_scope is None:
        return "no-scope"
    sc = scope_manager.active_scope
    parts.append(sc.program_name or "")
    for e in sorted(sc.in_scope, key=lambda x: (x.asset_type, x.target)):
        parts.append(f"+{e.asset_type}:{e.target}")
    for e in sorted(sc.out_of_scope, key=lambda x: (x.asset_type, x.target)):
        parts.append(f"-{e.asset_type}:{e.target}")
    blob = "|".join(parts).encode()
    return hashlib.sha256(blob).hexdigest()[:16]


# ----- ScopeReasoner --------------------------------------------------------


class ScopeReasoner:
    """Decision API on top of ScopeManager.

    Usage:
        sr = ScopeReasoner(scope_manager=sm, db_path=Path("data/viper.db"))
        d = sr.decide("api.example.com")
        if d.allowed:
            ...attack...
    """

    def __init__(
        self,
        scope_manager=None,
        *,
        db_path: Optional[Path] = None,
        llm_callback=None,            # Optional[Callable[[str, list[str]], (bool, str)]]
        default_when_no_scope: bool = False,
        cache_in_memory: bool = True,
    ) -> None:
        self.scope_manager = scope_manager
        self.db_path = Path(db_path) if db_path else None
        self.llm_callback = llm_callback
        self.default_when_no_scope = default_when_no_scope
        self._mem_cache: dict[str, ScopeDecision] = {} if cache_in_memory else None
        self._cache_lock = threading.Lock()
        self._scope_hash = _scope_fingerprint(scope_manager)
        if self.db_path:
            self.db_path.parent.mkdir(parents=True, exist_ok=True)
            self._ensure_schema()

    # ------------------------------------------------------------------
    # Public decision API
    # ------------------------------------------------------------------

    def decide(self, target: str, *, allow_llm: bool = False) -> ScopeDecision:
        """Authoritative scope check. Strict-on-error, fail-closed."""
        if not target or not target.strip():
            return ScopeDecision(target=target, allowed=False,
                                 reason="empty target", confidence=1.0,
                                 source="default-deny")

        norm = _normalize(target)

        # 1. Cache lookup
        cached = self._cache_get(norm)
        if cached is not None:
            return cached

        # 2. No scope loaded — fall back to default policy
        if self.scope_manager is None or self.scope_manager.active_scope is None:
            d = ScopeDecision(
                target=norm,
                allowed=self.default_when_no_scope,
                reason="no scope loaded",
                confidence=0.5,
                source="no-scope",
            )
            self._cache_put(norm, d)
            return d

        # 3. Deterministic match via ScopeManager
        try:
            allowed, reason = self.scope_manager.is_in_scope(norm)
        except Exception as e:  # never crash the hack loop
            logger.exception("scope check raised — failing closed: %s", e)
            return ScopeDecision(
                target=norm, allowed=False,
                reason=f"scope check error: {e!r}",
                confidence=1.0, source="default-deny",
            )

        # 4. Pull the matched entry (for audit)
        matched = self._find_matched_entry(norm) if allowed else None

        if allowed:
            d = ScopeDecision(
                target=norm, allowed=True, reason=reason or "matched in-scope rule",
                confidence=1.0, source="deterministic",
                matched_entry=matched,
            )
            self._cache_put(norm, d)
            return d

        # 5. Ambiguous-but-related → optional LLM fallback
        if allow_llm and self.llm_callback is not None and self._looks_related(norm):
            try:
                rules = self._serialized_rules()
                allowed_llm, llm_reason = self.llm_callback(norm, rules)
                d = ScopeDecision(
                    target=norm, allowed=bool(allowed_llm),
                    reason=f"LLM: {llm_reason}",
                    confidence=0.7, source="llm",
                )
                self._cache_put(norm, d)
                return d
            except Exception as e:
                logger.warning("LLM scope check failed: %s — falling back to deny", e)

        # 6. Default deny
        d = ScopeDecision(
            target=norm, allowed=False,
            reason=reason or "no in-scope rule matched",
            confidence=1.0, source="deterministic",
        )
        self._cache_put(norm, d)
        return d

    # Convenience: filter a list
    def filter_in_scope(self, targets: list[str], *, allow_llm: bool = False) -> list[str]:
        return [t for t in targets if self.decide(t, allow_llm=allow_llm).allowed]

    # Convenience: stats
    def stats(self) -> dict:
        with self._cache_lock:
            cached = dict(self._mem_cache or {})
        allowed = sum(1 for d in cached.values() if d.allowed)
        return {
            "scope_hash": self._scope_hash,
            "cached_decisions": len(cached),
            "allowed": allowed,
            "denied": len(cached) - allowed,
            "sources": {
                s: sum(1 for d in cached.values() if d.source == s)
                for s in ("deterministic", "cache", "llm", "default-deny", "no-scope")
            },
        }

    # ------------------------------------------------------------------
    # Cache (mem + sqlite)
    # ------------------------------------------------------------------

    def _ensure_schema(self) -> None:
        with sqlite3.connect(str(self.db_path), timeout=5.0) as con:
            con.executescript(
                """
                CREATE TABLE IF NOT EXISTS scope_decisions (
                    target       TEXT NOT NULL,
                    scope_hash   TEXT NOT NULL,
                    allowed      INTEGER NOT NULL,
                    reason       TEXT,
                    source       TEXT,
                    matched_entry TEXT,
                    confidence   REAL,
                    decided_at   REAL,
                    PRIMARY KEY (target, scope_hash)
                );
                """
            )
            con.commit()

    def _cache_get(self, target: str) -> Optional[ScopeDecision]:
        # In-memory first
        if self._mem_cache is not None:
            with self._cache_lock:
                d = self._mem_cache.get(target)
            if d is not None:
                return d
        # SQLite fallback
        if not self.db_path:
            return None
        try:
            with sqlite3.connect(str(self.db_path), timeout=2.0) as con:
                row = con.execute(
                    "SELECT allowed, reason, source, matched_entry, confidence, decided_at "
                    "FROM scope_decisions WHERE target = ? AND scope_hash = ?",
                    (target, self._scope_hash),
                ).fetchone()
        except sqlite3.Error:
            return None
        if row is None:
            return None
        d = ScopeDecision(
            target=target,
            allowed=bool(row[0]),
            reason=row[1] or "",
            confidence=row[4] or 0.0,
            source=row[2] or "cache",
            matched_entry=row[3],
            decided_at=row[5] or time.time(),
        )
        if self._mem_cache is not None:
            with self._cache_lock:
                self._mem_cache[target] = d
        return d

    def _cache_put(self, target: str, decision: ScopeDecision) -> None:
        if self._mem_cache is not None:
            with self._cache_lock:
                self._mem_cache[target] = decision
        if not self.db_path:
            return
        try:
            with sqlite3.connect(str(self.db_path), timeout=2.0) as con:
                con.execute(
                    "INSERT OR REPLACE INTO scope_decisions "
                    "(target, scope_hash, allowed, reason, source, matched_entry, "
                    " confidence, decided_at) VALUES (?,?,?,?,?,?,?,?)",
                    (
                        target, self._scope_hash, int(decision.allowed),
                        decision.reason, decision.source, decision.matched_entry,
                        decision.confidence, decision.decided_at,
                    ),
                )
                con.commit()
        except sqlite3.Error:
            pass  # cache is a perf optimization; never block the hack loop

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _find_matched_entry(self, target: str) -> Optional[str]:
        """Walk in_scope entries and return the first one whose `matches`
        returns True. Used for audit attribution."""
        if not self.scope_manager or not self.scope_manager.active_scope:
            return None
        for e in self.scope_manager.active_scope.in_scope:
            try:
                if e.matches(target):
                    return f"{e.asset_type}:{e.target}"
            except Exception:
                continue
        return None

    def _looks_related(self, target: str) -> bool:
        """Heuristic: is `target` plausibly a variant of an in-scope rule?
        Used only to gate LLM calls (so we don't spam the LLM on garbage)."""
        if not self.scope_manager or not self.scope_manager.active_scope:
            return False
        target_parts = set(re.findall(r"[a-z0-9]+", target))
        for e in self.scope_manager.active_scope.in_scope:
            rule_parts = set(re.findall(r"[a-z0-9]+", e.target.lower()))
            # Strip generic short tokens
            rule_parts -= {"www", "api", "app", "dev", "stage", "staging",
                           "test", "com", "net", "org", "io", "co"}
            if not rule_parts:
                continue
            # If 2+ characteristic tokens overlap, treat as plausibly related
            if len(target_parts & rule_parts) >= 2:
                return True
            # Single strong overlap (>= 6 chars) also qualifies
            if any(p in target_parts and len(p) >= 6 for p in rule_parts):
                return True
        return False

    def _serialized_rules(self) -> list[str]:
        sc = self.scope_manager.active_scope
        out = [f"PROGRAM: {sc.program_name}"]
        for e in sc.in_scope:
            out.append(f"IN_SCOPE  {e.asset_type:8}  {e.target}")
        for e in sc.out_of_scope:
            out.append(f"OUT_SCOPE {e.asset_type:8}  {e.target}")
        return out


# ----- Default LLM callback (uses model_router if available) ---------------


def llm_scope_callback(target: str, scope_rules: list[str]) -> tuple[bool, str]:
    """Reference LLM callback. Imports model_router lazily so the reasoner
    works without LLM credentials.

    Returns (allowed: bool, reason: str). Conservative on any LLM error.
    """
    try:
        from ai.model_router import ModelRouter  # type: ignore
    except Exception:
        return False, "no model_router available"

    rules_text = "\n".join(scope_rules)
    prompt = (
        "You are a bug-bounty scope checker. Given the program rules below, "
        "decide if the target is IN-SCOPE for active testing.\n\n"
        f"Target: {target}\n\n"
        f"Rules:\n{rules_text}\n\n"
        "Respond as JSON only: {\"allowed\": true|false, \"reason\": \"...\"}\n"
        "Be conservative: if unsure, say allowed=false."
    )
    try:
        router = ModelRouter()
        resp = router.complete(prompt=prompt, max_tokens=200, temperature=0.0)
    except Exception as e:
        return False, f"LLM call failed: {e!r}"
    try:
        # Strip code fences if present
        clean = resp.strip().lstrip("`").rstrip("`")
        if clean.lower().startswith("json"):
            clean = clean[4:].strip()
        d = json.loads(clean)
        return bool(d.get("allowed", False)), str(d.get("reason", "no reason"))
    except Exception:
        # If LLM returned natural text, default to deny but include text
        return False, f"LLM returned non-JSON: {resp[:200]!r}"
