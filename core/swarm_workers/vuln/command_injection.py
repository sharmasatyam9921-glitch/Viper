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

# Time-based blind detection uses a SCALING confirmation, not a single
# threshold. A lone "response was +Ns slower than the control" trips on latency
# noise — under concurrent load the control itself was observed ranging
# 0.02s..1.2s on the same target, so a transient spike on the payload request
# reads as a 5s "sleep" and produces a false-positive RCE. Instead we require
# the delay to TRACK the injected duration: a short sleep must delay by ~its
# duration, and a longer sleep must delay proportionally MORE. A load spike
# cannot grow linearly with the commanded sleep, so scaling rules it out.
_SLEEP_SHORT = 3    # seconds — first probe
_SLEEP_LONG = 7     # seconds — confirmation probe (must delay ~4s more)
# A genuine `sleep N` response takes AT LEAST ~N seconds (the server actually
# waited), plus network — it can never come back faster. _ABS_TOL is the most a
# real response may fall below its commanded sleep (clock jitter only). The
# false positives that survived a scaling-only check returned FASTER than the
# sleep (sleep 3 -> 2.1s, sleep 7 -> 5.0s) — load rose between probes so the
# delta scaled, but neither probe actually slept. The absolute floor catches it.
_ABS_TOL = 0.75     # seconds a real `sleep N` response may fall below N
_SCALE_TOL = 1.25   # slack on the (LONG-SHORT) scaling delta

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

        # --- Time-based blind fallback (lower confidence) ------------------
        # A single slow response is NOT proof: under concurrent load the control
        # itself spikes (observed 0.02s..1.2s on the same target), so a lone
        # "+Ns over control" threshold trips on latency noise and emits a
        # false-positive RCE. Confirm by SCALING instead — the delay must track
        # the injected sleep: `sleep SHORT` delays ~SHORT, `sleep LONG` delays
        # proportionally MORE. A transient spike can't grow with the command.
        if timeout < _SLEEP_LONG + 2.0:
            continue  # not enough budget for the long confirmation probe

        # Two controls characterize the noise floor (use the worse of them).
        c1, _ = await _timed_fetch(control_url, timeout)
        c2, _ = await _timed_fetch(control_url, timeout)
        if c1 is None or c2 is None:
            continue
        noise_floor = max(c1, c2)
        if noise_floor >= timeout - _SLEEP_LONG:
            continue  # control already too slow to measure a LONG sleep cleanly

        expected_delta = _SLEEP_LONG - _SLEEP_SHORT
        blind_hit = False
        for sep in _SLEEP_SEPARATORS:
            # 1) Short probe must ACTUALLY wait ~SHORT seconds (not merely be
            #    "slow"). A real `sleep N` can't return faster than N.
            short_url = add_query(url, param, _CONTROL_VALUE + sep.format(n=_SLEEP_SHORT))
            e_short, _ = await _timed_fetch(short_url, timeout)
            if e_short is None or e_short < _SLEEP_SHORT - _ABS_TOL:
                continue
            # 2) Long probe must wait ~LONG seconds too.
            long_url = add_query(url, param, _CONTROL_VALUE + sep.format(n=_SLEEP_LONG))
            e_long, _ = await _timed_fetch(long_url, timeout)
            if e_long is None or e_long < _SLEEP_LONG - _ABS_TOL:
                continue
            # 3) The extra delay must match the extra sleep (scaling) — rules out
            #    a uniformly-slow endpoint that isn't sleeping at all.
            if (e_long - e_short) < expected_delta - _SCALE_TOL:
                continue
            # 4) Reproduce the long delay once more — a coincidental load spike
            #    won't sleep ~LONG seconds twice in a row; a real shell will.
            e_rep, _ = await _timed_fetch(long_url, timeout)
            if e_rep is None or e_rep < _SLEEP_LONG - _ABS_TOL:
                continue
            findings.append({
                "type": "command_injection",
                "vuln_type": f"rce:cmdi:{param}",
                "title": f"Blind OS command injection in '{param}'",
                "severity": "high",
                "url": long_url,
                "parameter": param,
                "payload": sep.format(n=_SLEEP_LONG),
                "cwe": "CWE-78",
                "confidence": 0.7,
                "evidence": (
                    f"response time matched the injected sleep on every probe: "
                    f"sleep {_SLEEP_SHORT}s -> {e_short:.2f}s, "
                    f"sleep {_SLEEP_LONG}s -> {e_long:.2f}s, "
                    f"repeat sleep {_SLEEP_LONG}s -> {e_rep:.2f}s "
                    f"(control {noise_floor:.2f}s) — each response waited at least "
                    "the commanded duration and the delay scaled with it, which a "
                    "load spike cannot fake. Consistent with `sleep` in a shell."
                ),
            })
            blind_hit = True
            break
        if blind_hit:
            break

    return findings


register_worker("vuln", TECHNIQUE, run)
