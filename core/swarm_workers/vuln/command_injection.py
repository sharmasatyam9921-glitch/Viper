"""OS command-injection probe (vuln phase, non-destructive).

For each candidate query parameter we inject BENIGN command-injection markers
that, if the value is concatenated into a shell, cause a unique marker string to
be echoed back into the response. We confirm a flaw ONLY when:

  * a control request (a harmless value, no shell metacharacters) does NOT
    contain the unique marker — so the marker isn't naturally reflected — AND
  * an injection payload makes that same unique marker appear in the body.

A time-based fallback covers blind injection: a `; sleep 5` style payload whose
response is markedly slower than a control is flagged at lower confidence, with
the measured timings recorded in the evidence.

Detection only. Payloads are strictly read-only shell commands (`echo`, `sleep`)
— never anything that writes, deletes, exfiltrates, or otherwise mutates state.
vuln_type carries the scorer's RCE class token (`rce:cmdi:<param>`); CWE-78.
"""

from __future__ import annotations

import logging
import secrets
import time
import urllib.parse
from typing import List, Optional
from urllib.parse import urlsplit

from core.swarm_engine import SwarmAgent
from core.swarm_workers import register_worker

from ._http import HttpResp, add_query, fetch, normalize_target_url

logger = logging.getLogger("viper.swarm_workers.vuln.command_injection")

TECHNIQUE = "command_injection"

# Parameters worth probing when the target URL carries no query of its own.
_DEFAULT_PARAMS = [
    "cmd", "exec", "command", "ping", "host", "ip", "domain", "query",
    "search", "name", "file", "path", "url", "id", "page",
]

# Time-based blind detection uses a PAIRED-CONTROL DIFFERENTIAL. The naive
# "response was +Ns slower than an early control" trips on latency noise, and
# even a scaling/floor check is defeated by a server whose latency grows over
# time (GC pressure / a memory leak under scan load): each successive probe is
# slower than the last, faking the floor, the scaling AND the reproduction.
#
# The fix: for each sleep duration, measure a benign control IMMEDIATELY before
# the sleep probe and take the difference. A real `sleep N` adds ~N over its
# adjacent control; a slow, uniformly-laggy, or monotonically-degrading server
# adds ~0, because the control taken moments earlier is just as slow. The delta
# must land in [N - _ABS_TOL, N + _DELTA_HI] (lower bound: it really waited;
# upper bound: a spike didn't inflate it), the per-duration deltas must scale
# with the sleep, and the long delta must reproduce. This is also robust to a
# slow base page (the base cancels in the difference), so no skip-gate is needed.
_SLEEP_SHORT = 2    # seconds — first probe duration
_SLEEP_LONG = 6     # seconds — confirmation probe duration (delta must be ~4s more)
_ABS_TOL = 0.6      # how far below N the (probe - adjacent control) delta may fall
_DELTA_HI = 2.5     # how far ABOVE N the delta may rise before it's a spike, not a sleep
_SCALE_TOL = 1.25   # slack on the (LONG-SHORT) scaling of the deltas
_BLIND_HEADROOM = 6.0  # extra seconds over _SLEEP_LONG allowed for base+jitter

# A benign control value: alphanumeric, no shell metacharacters, never reflects
# the marker.
_CONTROL_VALUE = "viperctl"


def _marker() -> str:
    """A unique-per-call benign marker string, e.g. CMDIa1b2c3d4."""
    return "CMDI" + secrets.token_hex(4)


def _echo_payloads(marker: str) -> list[str]:
    """Benign echo-based command-injection payloads for `marker`.

    Each tries a different shell-injection context (command separator, pipe,
    sub-shell, backticks, AND-chain). All are read-only `echo` commands.
    """
    return [
        f";echo {marker}",
        f"|echo {marker}",
        f"$(echo {marker})",
        f"`echo {marker}`",
        f"&& echo {marker}",
    ]


# Shell-injection contexts for the blind probe. `{n}` is filled with the sleep
# duration so the SAME context can be measured at two durations (scaling check).
_SLEEP_SEPARATORS = [
    ";sleep {n}",
    "|sleep {n}",
    "$(sleep {n})",
    "`sleep {n}`",
    "&& sleep {n}",
]


def _target_params(url: str) -> list[str]:
    """Params present in the URL's own query, else a small default set."""
    qs = urllib.parse.parse_qsl(urlsplit(url).query)
    present = [k for k, _ in qs]
    return present or list(_DEFAULT_PARAMS)


def _executed_not_reflected(body: str, marker: str, injected_value: str) -> bool:
    """True only if `marker` appears as ECHOED COMMAND OUTPUT, not as a mere
    reflection of the injected payload.

    Pages routinely reflect the query string into canonical / og:url / analytics
    tags, so the raw marker appearing is NOT proof of execution — that was a
    critical-severity false positive (e.g. an ASP.NET catalog page echoing
    ``?p=viperctl|echo MARKER`` into <meta og:url>). Strip every reflected copy
    of the injected value (raw + URL-encoded forms) and the literal ``echo
    MARKER`` command; only if the marker still appears did the shell consume the
    command and emit the marker on its own.
    """
    if not body or marker not in body:
        return False
    variants = {
        injected_value,
        urllib.parse.quote(injected_value, safe=""),
        urllib.parse.quote_plus(injected_value),
        injected_value.replace(" ", "+"),
        injected_value.replace(" ", "%20"),
    }
    # Also strip the bare `echo MARKER` command in any whitespace encoding, so a
    # reflected command (without the control prefix) doesn't count as output.
    for sep in (" ", "+", "%20", "%09"):
        variants.add(f"echo{sep}{marker}")
    stripped = body
    for v in variants:
        if v:
            stripped = stripped.replace(v, "")
    return marker in stripped


async def _timed_fetch(url: str, timeout: float):
    """GET `url`, returning (elapsed_seconds, resp). (None, None) on failure."""
    t = time.monotonic()
    resp = await fetch("GET", url, timeout=timeout)
    if resp is None:
        return None, None
    return time.monotonic() - t, resp


async def run(agent: SwarmAgent) -> List[dict]:
    url = normalize_target_url(agent.target)
    if not url:
        return []
    timeout = min(agent.timeout_s, 10.0)
    findings: list[dict] = []

    marker = _marker()
    params = _target_params(url)

    for param in params:
        # Control: a benign value must NOT surface the unique marker. If the
        # control already contains it (impossible by construction, but guards
        # against a target that echoes arbitrary input as our marker), bail.
        control_url = add_query(url, param, _CONTROL_VALUE)
        control = await fetch("GET", control_url, timeout=timeout)
        if control is None:
            continue
        if marker in (control.body or ""):
            continue  # marker leaks without injection → no signal

        # --- Marker reflection (high confidence) ---------------------------
        reflected = False
        for payload in _echo_payloads(marker):
            injected_value = _CONTROL_VALUE + payload
            inj_url = add_query(url, param, injected_value)
            resp = await fetch("GET", inj_url, timeout=timeout)
            if resp is None or not resp.body:
                continue
            # The marker must appear as EXECUTED OUTPUT, not as a reflection of
            # the payload itself (query strings get echoed into og:url/canonical
            # tags all the time — that is NOT command execution).
            if _executed_not_reflected(resp.body, marker, injected_value):
                findings.append({
                    "type": "command_injection",
                    "vuln_type": f"rce:cmdi:{param}",
                    "title": f"OS command injection in '{param}'",
                    "severity": "critical",
                    "url": inj_url,
                    "parameter": param,
                    "payload": payload,
                    "cwe": "CWE-78",
                    "confidence": 0.9,
                    "evidence": (
                        f"benign marker {marker!r} appeared as echoed command "
                        f"output via {payload!r} (present even after stripping every "
                        "reflected copy of the payload), while the control did not"
                    ),
                })
                reflected = True
                break
        if reflected:
            # One confirmed param is plenty; don't hammer the rest.
            break

        # --- Time-based blind fallback (paired-control differential) -------
        # See the constants block: each sleep probe is differenced against a
        # benign control taken IMMEDIATELY before it, so a slow/degrading base
        # cancels out. delta = probe - adjacent_control must be ~the sleep.
        blind_budget = agent.timeout_s if agent.timeout_s else (_SLEEP_LONG + _BLIND_HEADROOM)
        if blind_budget < _SLEEP_LONG + 1.5:
            continue  # too little budget to observe a LONG sleep even on a fast base
        bt = min(blind_budget, _SLEEP_LONG + _BLIND_HEADROOM)

        async def _paired_delta(sep_tmpl, dur):
            """(probe_time - adjacent_control_time) for one sleep duration, or None."""
            cb, _ = await _timed_fetch(control_url, bt)
            if cb is None:
                return None
            pu = add_query(url, param, _CONTROL_VALUE + sep_tmpl.format(n=dur))
            pe, _ = await _timed_fetch(pu, bt)
            if pe is None:
                return None
            return pe - cb

        expected_delta = _SLEEP_LONG - _SLEEP_SHORT
        blind_hit = False
        for sep in _SLEEP_SEPARATORS:
            # 1) Short sleep must add ~SHORT over an adjacent control — and not
            #    wildly more (a spike), and not ~0 (a slow base that never slept).
            d_short = await _paired_delta(sep, _SLEEP_SHORT)
            if d_short is None or not (
                    _SLEEP_SHORT - _ABS_TOL <= d_short <= _SLEEP_SHORT + _DELTA_HI):
                continue
            # 2) Long sleep must add ~LONG over its own adjacent control.
            d_long = await _paired_delta(sep, _SLEEP_LONG)
            if d_long is None or not (
                    _SLEEP_LONG - _ABS_TOL <= d_long <= _SLEEP_LONG + _DELTA_HI):
                continue
            # 3) The deltas themselves must scale with the sleep — rules out a
            #    server whose latency just grows over time (monotonic drift).
            if (d_long - d_short) < expected_delta - _SCALE_TOL:
                continue
            # 4) Reproduce the long differential once more.
            d_rep = await _paired_delta(sep, _SLEEP_LONG)
            if d_rep is None or not (
                    _SLEEP_LONG - _ABS_TOL <= d_rep <= _SLEEP_LONG + _DELTA_HI):
                continue
            findings.append({
                "type": "command_injection",
                "vuln_type": f"rce:cmdi:{param}",
                "title": f"Blind OS command injection in '{param}'",
                "severity": "high",
                "url": add_query(url, param, _CONTROL_VALUE + sep.format(n=_SLEEP_LONG)),
                "parameter": param,
                "payload": sep.format(n=_SLEEP_LONG),
                "cwe": "CWE-78",
                "confidence": 0.7,
                "evidence": (
                    "each sleep probe, measured against a control taken moments "
                    "earlier, added ~the commanded duration and the delays scaled: "
                    f"sleep {_SLEEP_SHORT}s -> +{d_short:.2f}s, "
                    f"sleep {_SLEEP_LONG}s -> +{d_long:.2f}s, "
                    f"repeat sleep {_SLEEP_LONG}s -> +{d_rep:.2f}s over the adjacent "
                    "control. A slow, laggy, or degrading server cancels in the "
                    "difference, so this is consistent with `sleep` in a shell."
                ),
            })
            blind_hit = True
            break
        if blind_hit:
            break

    return findings


register_worker("vuln", TECHNIQUE, run)
