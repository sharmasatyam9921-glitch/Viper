"""Thread-safe store of out-of-band (OOB) interactions, keyed by canary token.

A blind vulnerability is *confirmed* when the target's backend reaches out to our
listener carrying a unique canary token. This store records those interactions
and lets the validation gate ask, irrefutably, "did canary X fire?".
"""
from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional


@dataclass
class Interaction:
    token: str
    protocol: str          # "dns" | "http"
    source_ip: str
    detail: str            # request line / queried name
    timestamp: float
    headers: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {"token": self.token, "protocol": self.protocol,
                "source_ip": self.source_ip, "detail": self.detail,
                "timestamp": self.timestamp}


class InteractionStore:
    """Append-only, bounded, thread-safe; supports blocking poll for a token."""

    def __init__(self, limit: int = 10000, clock=time.time, accept=None):
        self._by_token: Dict[str, List[Interaction]] = {}
        self._all: List[Interaction] = []
        self._limit = max(1, int(limit))
        self._cond = threading.Condition()
        self._clock = clock
        # Optional predicate: only record interactions for tokens this returns
        # True for. The OOBServer wires this to its ISSUED-token set, so random /
        # background / legitimate-looking-hex traffic to the listener can never
        # seed a false confirmation. None = record everything (raw store).
        self._accept = accept

    def record(self, token: str, protocol: str, source_ip: str,
               detail: str = "", headers: Optional[dict] = None) -> Optional[Interaction]:
        if self._accept is not None and not self._accept(token):
            return None                       # not a token we issued — ignore
        it = Interaction(token=token, protocol=protocol, source_ip=source_ip,
                         detail=detail, timestamp=self._clock(),
                         headers=dict(headers or {}))
        with self._cond:
            self._by_token.setdefault(token, []).append(it)
            self._all.append(it)
            if len(self._all) > self._limit:          # trim oldest, keep index sane
                drop = self._all[:-self._limit]
                self._all = self._all[-self._limit:]
                for d in drop:
                    lst = self._by_token.get(d.token)
                    if lst and d in lst:
                        lst.remove(d)
                        if not lst:
                            self._by_token.pop(d.token, None)
            self._cond.notify_all()
        return it

    def has_interaction(self, token: str) -> bool:
        with self._cond:
            return bool(self._by_token.get(token))

    def interactions_for(self, token: str) -> List[Interaction]:
        with self._cond:
            return list(self._by_token.get(token, []))

    def count(self) -> int:
        with self._cond:
            return len(self._all)

    def all(self) -> List[Interaction]:
        with self._cond:
            return list(self._all)

    def poll(self, token: str, timeout: float = 5.0) -> bool:
        """Block up to `timeout` seconds for an interaction on `token`.

        Uses a MONOTONIC deadline (immune to wall-clock jumps) and the standard
        condition-variable pattern: predicate is checked under the lock before
        every wait, so a notify from record() can't be lost.
        """
        deadline = time.monotonic() + max(0.0, timeout)
        with self._cond:
            while not self._by_token.get(token):
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return False
                self._cond.wait(remaining)
            return True
