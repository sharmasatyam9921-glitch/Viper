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
import re
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
_SLEEP_SAMPLES = 3  # trials per duration; the MEDIAN delta beats per-request jitter
                    # (probe and control base latencies are independent draws, so a
                    # single difference is defeated by request-to-request jitter).

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
    # Also strip the bare `echo MARKER` command in any whitespace encoding —
    # INCLUDING the zero-separator form `echoMARKER` produced by a sanitizer that
    # strips metacharacters AND collapses whitespace (that was a gate FP).
    for sep in (" ", "+", "%20", "%09", ""):
        variants.add(f"echo{sep}{marker}")
    stripped = body
    for v in variants:
        if v:
            stripped = stripped.replace(v, "")
    if marker not in stripped:
        return False
    # Belt-and-suspenders: re-check with ALL whitespace removed, so a reflection
    # that merely re-spaced `echo` and the marker can't smuggle it past the strip.
    nows = re.sub(r"\s+", "", stripped)
    for v in variants:
        if v:
            nows = nows.replace(re.sub(r"\s+", "", v), "")
    return marker in nows


def _reflects_bare_marker(body: str, marker: str, inert_value: str) -> bool:
    """True if the server echoes the BARE marker as a standalone token.

    ``inert_value`` carries the marker inside a benign, space-separated value with
    NO shell metacharacter, so nothing can execute — the marker can only appear by
    being reflected. If it survives after stripping every reflected copy of the
    whole inert value, the endpoint echoes the marker on its own: a search
    highlighter, a breadcrumb, a "you searched for X" banner that extracts and
    re-displays a single token. The strip in :func:`_executed_not_reflected` only
    removes the WHOLE injected value and the ``echo MARKER`` command, so such a
    bare-token reflection would otherwise be misread as executed output. When this
    fires, the echo-based signal is a reflection artifact, not proof of execution.
    """
    if not body or marker not in body:
        return False
    variants = {
        inert_value,
        urllib.parse.quote(inert_value, safe=""),
        urllib.parse.quote_plus(inert_value),
        inert_value.replace(" ", "+"),
        inert_value.replace(" ", "%20"),
    }
    stripped = body
    for v in variants:
        if v:
            stripped = stripped.replace(v, "")
    if marker not in stripped:
        return False
    nows = re.sub(r"\s+", "", stripped)
    return marker in nows


# Clock seam: real time in production; tests patch this to a virtual clock so the
# timing logic can be exercised without real sleeps (and without touching the
# asyncio event loop's own time.monotonic).
_clock = time.monotonic


async def _timed_fetch(url: str, timeout: float):
    """GET `url`, returning (elapsed_seconds, resp). (None, None) on failure."""
    t = _clock()
    resp = await fetch("GET", url, timeout=timeout)
    if resp is None:
        return None, None
    return _clock() - t, resp


async def run(agent: SwarmAgent) -> List[dict]:
    url = normalize_target_url(agent.target)
    if not url:
        return []
    timeout = min(agent.timeout_s, 10.0)
    findings: list[dict] = []

    marker = _marker()
    params = _target_params(url)

    # Blind OS command injection: fire an OOB canary at each candidate param
    # (no-op without an OOB server). A timing differential is unreliable (the
    # cmdi tarpit lesson); a DNS/HTTP callback from the shell is irrefutable.
    from ._oob import fire_oob
    for param in params:
        findings.extend(await fire_oob(
            url, param, vuln_type=f"rce:cmdi:blind:{param}",
            title=f"Blind command injection candidate via ?{param}= (out-of-band)",
            cwe="CWE-78", payload_key="cmdi_curl", severity="critical",
            timeout=timeout))

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

        # Reflection guard: probe with the marker as data that CANNOT execute to
        # emit it, then check whether the BARE marker comes back (a search
        # highlighter / breadcrumb echoing a standalone token would slip past the
        # injected-value strip and look like executed output). Two shapes:
        #   1. a plain benign value with NO metacharacter — catches endpoints that
        #      reflect any input token;
        #   2. behind a shell separator with a NO-OUTPUT command (`;true MARKER`, and
        #      `true` ignores its args) — catches endpoints that only reflect when a
        #      metacharacter is present, yet still cannot emit the marker by running.
        # If either surfaces the bare marker, the echo signal is a reflection, not
        # execution, so skip it and rely on timing/OOB (differential, un-spoofable).
        reflects_marker = False
        for inert_value in (f"{_CONTROL_VALUE} {marker}", f";true {marker}"):
            inert = await fetch("GET", add_query(url, param, inert_value), timeout=timeout)
            if inert is not None and _reflects_bare_marker(inert.body or "", marker,
                                                           inert_value):
                reflects_marker = True
                break

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
            # tags all the time — that is NOT command execution). Also skip when the
            # endpoint reflects the bare marker as a standalone token (see above).
            if not reflects_marker and _executed_not_reflected(resp.body, marker, injected_value):
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
        #
        # Known, accepted limits of timing-only detection (documented, not bugs):
        #  * It cannot distinguish a real shell `sleep N` from a server that
        #    deliberately simulates that latency (an anti-automation tarpit /
        #    honeypot). This is structural — hence confidence stays 0.7 and the
        #    evidence flags it as timing-only for the triager to corroborate.
        #  * A server vulnerable via only ONE shell separator AND with heavy
        #    request-to-request base jitter (>=~0.5s on a 6s sleep) can be missed
        #    (false negative). Raise _SLEEP_SAMPLES (median of 5-7) to recover
        #    recall there, at the cost of more requests per probe.
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

        async def _median_delta(sep_tmpl, dur):
            """Median paired delta over _SLEEP_SAMPLES trials. The probe's and
            control's base latencies are INDEPENDENT draws, so one difference is
            defeated by request-to-request jitter (cold serverless, GC pauses,
            noisy neighbours); the median concentrates near the true sleep and
            requires the delay to be CONSISTENT (subsuming a reproduction probe)."""
            ds = []
            for _ in range(_SLEEP_SAMPLES):
                d = await _paired_delta(sep_tmpl, dur)
                if d is not None:
                    ds.append(d)
            if len(ds) * 2 <= _SLEEP_SAMPLES:   # need a usable majority
                return None
            ds.sort()
            return ds[len(ds) // 2]

        expected_delta = _SLEEP_LONG - _SLEEP_SHORT
        blind_hit = False
        for sep in _SLEEP_SEPARATORS:
            # 1) Short = pre-gate: median delay ~SHORT over an adjacent control, not
            #    a spike (both bounds), not ~0 (a slow base that never slept).
            d_short = await _median_delta(sep, _SLEEP_SHORT)
            if d_short is None or not (
                    _SLEEP_SHORT - _ABS_TOL <= d_short <= _SLEEP_SHORT + _DELTA_HI):
                continue
            # 2) Long = decisive: median delay must be AT LEAST ~LONG. No upper bound
            #    here — a real `sleep` can only ADD time, so a high long delay is
            #    still consistent with execution; rejecting it caused false negatives
            #    on jittery targets. Spikes are absorbed by the median; non-executing
            #    latency is caught by the scaling and number-control checks below.
            d_long = await _median_delta(sep, _SLEEP_LONG)
            if d_long is None or d_long < _SLEEP_LONG - _ABS_TOL:
                continue
            # 3) The deltas must scale with the sleep — rules out a uniformly-slow or
            #    monotonically-degrading server (both deltas collapse toward zero).
            if (d_long - d_short) < expected_delta - _SCALE_TOL:
                continue
            # 4) Number-driven-latency guard: a value with the SAME integer but NO
            #    shell metacharacter ("viperctl6") must NOT reproduce the delay. If
            #    it does, the latency tracks a parsed number (?limit/?count/?page),
            #    not shell execution — a real `sleep` needs the metacharacter to
            #    break out, so the bare number stays fast on a vulnerable target.
            cb_n, _ = await _timed_fetch(control_url, bt)
            num_url = add_query(url, param, f"{_CONTROL_VALUE}{_SLEEP_LONG}")
            pe_n, _ = await _timed_fetch(num_url, bt)
            if cb_n is not None and pe_n is not None \
                    and (pe_n - cb_n) >= _SLEEP_LONG - _ABS_TOL:
                continue  # latency is a function of the number, not the shell
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
                    "time-based: the median delay over an adjacent control tracked "
                    f"the injected sleep (short {_SLEEP_SHORT}s -> +{d_short:.2f}s, "
                    f"long {_SLEEP_LONG}s -> +{d_long:.2f}s, scaled "
                    f"+{d_long - d_short:.2f}s) and a bare-number control with no "
                    "shell metacharacter did NOT reproduce it — consistent with "
                    "`sleep` in a shell, not slow/degrading latency or a "
                    "number-parsing endpoint. Timing-only signal (confidence 0.7): "
                    "corroborate before reporting — a server that deliberately "
                    "simulates sleep latency (anti-automation tarpit) would also match."
                ),
            })
            blind_hit = True
            break
        if blind_hit:
            break

    return findings


register_worker("vuln", TECHNIQUE, run)
