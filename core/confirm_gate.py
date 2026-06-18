"""Reusable three-gate confirmation protocol.

Generalizes the per-class re-tests into one differential confirmer any tester can
call:

  * **gate 1 — baseline**  a benign value, no payload.
  * **gate 2 — attack**    the payload.
  * **gate 3 — compare**   a differential over (status / length / reflection /
                           marker / timing) between baseline and attack.
  * **re-test**            the attack is replayed; the same signal must fire again
                           for the finding to count as *reproduced*.

The contract is FP-averse, matching the rest of VIPER's gate: a finding is only
``is_real`` when a differential signal is present AND reproduced AND its calibrated
confidence clears ``min_confidence``. Transient / race wins (a signal that fires
once but vanishes on replay) come back ``reproduced=False`` so the caller keeps
them as leads and never auto-submits.

This is a *generic* differential engine — it complements, and does not replace,
the specialized per-class re-checks in ``swarm_validation``, which encode
context-sensitive logic (XSS markup context, SSTI string-op disambiguation, BOLA
two-account proof) that a generic differential cannot. Use it for new testers, or
as a uniform second opinion. It takes an injected ``fetch`` so it is fully
testable without a network.

Scope: this generic engine varies a single GET **query parameter** (baseline vs
attack). Findings carried in a request body (POST/PUT JSON) need a body-aware
confirmer; a finding without a ``parameter`` is reported insufficient rather than
silently "confirmed".
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Awaitable, Callable, Optional
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

# Confidence each reproduced signal earns. Ordered weakest -> strongest.
# length and generic reflection stay BELOW the 0.5 is_real floor on purpose: a
# size shift or a raw echo (e.g. payload reflected inside an error message) is a
# strong lead, not proof. Execution/error proof (marker, 5xx differential) or a
# reproduced timing delay are what clear is_real. Context-aware XSS confirmation
# is the specialized re-check's job, not this generic engine's.
_SIGNAL_CONFIDENCE = {
    "length": 0.45,      # body size shifted — lead only
    "reflection": 0.49,  # raw payload echoed live — strong lead, not execution proof
    "timing": 0.60,      # reproduced delay — moderate (timing-noise guarded below)
    "status": 0.80,      # benign 2xx -> attack 5xx — error-based differential
    "marker": 0.85,      # an out-of-band proof marker appeared — strongest
}
# Priority by strength: a stronger co-firing signal wins the verdict.
_SIGNAL_PRIORITY = ["marker", "status", "timing", "reflection", "length"]


def _set_param(url: str, name: str, value: str) -> str:
    """Return `url` with query parameter `name` set to `value` (added if absent)."""
    if not name:
        return url
    parts = urlsplit(url)
    pairs = parse_qsl(parts.query, keep_blank_values=True)
    out, seen = [], False
    for k, v in pairs:
        if k == name:
            out.append((k, value))
            seen = True
        else:
            out.append((k, v))
    if not seen:
        out.append((name, value))
    return urlunsplit((parts.scheme, parts.netloc, parts.path,
                       urlencode(out), parts.fragment))


@dataclass
class _Resp:
    status: int = 0
    body: str = ""

    @classmethod
    def of(cls, resp) -> "_Resp":
        if resp is None:
            return cls(0, "")
        return cls(int(getattr(resp, "status", 0) or 0),
                   getattr(resp, "body", "") or "")


@dataclass
class ConfirmationVerdict:
    is_real: bool
    signal: Optional[str]        # which differential fired: marker/status/reflection/timing/length/None
    reproduced: bool
    confidence: float
    reason: str
    delta: dict = field(default_factory=dict)


def _detect(base: _Resp, atk: _Resp, payload: str, marker: Optional[str],
            base_t: float, atk_t: float, *, min_len_delta: int,
            timing_ratio: float, timing_floor: float) -> tuple[Optional[str], dict]:
    """Return (primary_signal, delta-dict) for one baseline/attack pair."""
    delta = {
        "status_base": base.status, "status_attack": atk.status,
        "len_base": len(base.body), "len_attack": len(atk.body),
        "time_base": round(base_t, 4), "time_attack": round(atk_t, 4),
    }
    fired = {}
    # marker: an explicit proof string the caller expects only on success
    if marker and marker in atk.body and marker not in base.body:
        fired["marker"] = True
    # status: benign request is 2xx, payload drives a server error (error-based)
    if atk.status >= 500 and base.status < 500:
        fired["status"] = True
    # reflection: the raw payload is echoed under attack but not baseline
    if payload and payload in atk.body and payload not in base.body:
        fired["reflection"] = True
    # timing: attack visibly slower — above an absolute floor, a ratio above the
    # baseline, AND an absolute delta (so a uniformly-slow app at the floor, where
    # baseline and attack are both ~floor, does not fire on every payload).
    if (atk_t >= timing_floor
            and atk_t >= base_t * timing_ratio
            and (atk_t - base_t) >= timing_floor * 0.5):
        fired["timing"] = True
    # length: response size shifted materially (boolean-blind suggestive)
    if abs(len(atk.body) - len(base.body)) >= min_len_delta:
        fired["length"] = True

    delta["fired"] = sorted(fired.keys())
    for sig in _SIGNAL_PRIORITY:
        if fired.get(sig):
            return sig, delta
    return None, delta


class ThreeGateConfirmer:
    """Baseline -> attack -> differential-compare + reproducibility re-test."""

    def __init__(self, fetch: Callable[..., Awaitable[object]], *,
                 timeout: float = 10.0, retests: int = 1,
                 min_confidence: float = 0.5, min_len_delta: int = 24,
                 timing_ratio: float = 2.0, timing_floor: float = 0.5,
                 clock: Callable[[], float] = time.monotonic):
        self.fetch = fetch
        self.timeout = timeout
        self.retests = max(0, int(retests))
        # Floor at 0.5 so the weakest signals (length 0.45 / generic reflection
        # 0.49) can never alone clear is_real, even if a caller passes a lower
        # value. Callers may raise it for stricter gating.
        self.min_confidence = max(0.5, float(min_confidence))
        self.min_len_delta = min_len_delta
        self.timing_ratio = timing_ratio
        self.timing_floor = timing_floor
        self._clock = clock

    async def _timed_get(self, url: str) -> tuple[_Resp, float]:
        t0 = self._clock()
        resp = await self.fetch("GET", url, timeout=self.timeout)
        return _Resp.of(resp), self._clock() - t0

    async def confirm(self, finding: dict, *, benign: str = "1",
                      marker: Optional[str] = None) -> ConfirmationVerdict:
        url = finding.get("url") or finding.get("target") or ""
        param = finding.get("parameter") or ""
        payload = finding.get("payload") or ""
        marker = marker or finding.get("marker")
        if not url or not payload:
            return ConfirmationVerdict(False, None, False, 0.0,
                                       "insufficient finding: need url + payload")
        if not param:
            return ConfirmationVerdict(
                False, None, False, 0.0,
                "insufficient finding: no query parameter to vary "
                "(this confirmer tests GET query parameters)")

        base_url = _set_param(url, param, benign)
        atk_url = _set_param(url, param, payload)

        base, base_t = await self._timed_get(base_url)
        # Fail closed if the BASELINE is unavailable: without a valid control
        # response there is no differential, so any signal on the attack alone is
        # not proof. (A failed *attack* is fine — that simply yields no signal.)
        if base.status == 0:
            return ConfirmationVerdict(
                False, None, False, 0.0,
                "baseline request failed — no control response to compare "
                "against (fail closed)")
        atk, atk_t = await self._timed_get(atk_url)
        if atk.status == 0:
            return ConfirmationVerdict(False, None, False, 0.0,
                                       "attack request failed (network error)")

        signal, delta = self._detect(base, atk, payload, marker, base_t, atk_t)
        if signal is None:
            return ConfirmationVerdict(False, None, False, 0.0,
                                       "no differential signal between baseline and attack",
                                       delta)

        # reproducibility: replay the attack; the SAME primary signal must fire.
        reproduced = True
        for _ in range(self.retests):
            atk2, atk_t2 = await self._timed_get(atk_url)
            sig2, _ = self._detect(base, atk2, payload, marker, base_t, atk_t2)
            if sig2 != signal:
                reproduced = False
                break

        base_conf = _SIGNAL_CONFIDENCE[signal]
        confidence = base_conf if reproduced else min(0.3, base_conf / 2)
        is_real = reproduced and confidence >= self.min_confidence
        if reproduced:
            reason = f"{signal} differential reproduced across {self.retests + 1} attempts"
        else:
            reason = f"{signal} differential did not reproduce on replay (transient)"
        return ConfirmationVerdict(is_real, signal, reproduced,
                                   round(confidence, 3), reason, delta)

    def _detect(self, base, atk, payload, marker, base_t, atk_t):
        return _detect(base, atk, payload, marker, base_t, atk_t,
                       min_len_delta=self.min_len_delta,
                       timing_ratio=self.timing_ratio,
                       timing_floor=self.timing_floor)


async def confirm_finding(finding: dict, fetch, *, timeout: float = 10.0,
                          retests: int = 1, marker: Optional[str] = None,
                          benign: str = "1") -> ConfirmationVerdict:
    """Convenience one-shot: confirm a single finding with a fresh confirmer."""
    return await ThreeGateConfirmer(fetch, timeout=timeout, retests=retests).confirm(
        finding, benign=benign, marker=marker)
