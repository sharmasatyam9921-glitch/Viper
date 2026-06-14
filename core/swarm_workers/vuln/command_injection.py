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

# How much slower a sleep response must be vs the control to count as blind.
_SLEEP_SECONDS = 5
_TIME_DELTA_MIN = 4.0  # response must be >= control + this many seconds

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


def _sleep_payloads() -> list[str]:
    """Benign time-delay payloads for the blind fallback (read-only `sleep`)."""
    return [
        f";sleep {_SLEEP_SECONDS}",
        f"|sleep {_SLEEP_SECONDS}",
        f"$(sleep {_SLEEP_SECONDS})",
        f"`sleep {_SLEEP_SECONDS}`",
        f"&& sleep {_SLEEP_SECONDS}",
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
        # Baseline timing from the control request.
        t0 = time.monotonic()
        base = await fetch("GET", control_url, timeout=timeout)
        base_elapsed = time.monotonic() - t0
        if base is None:
            continue
        # Only attempt the sleep probe if the control returns fast enough that a
        # +5s delay could fit inside the timeout window.
        if base_elapsed >= timeout - _SLEEP_SECONDS:
            continue

        blind_hit = False
        for payload in _sleep_payloads():
            inj_url = add_query(url, param, _CONTROL_VALUE + payload)
            t1 = time.monotonic()
            resp = await fetch("GET", inj_url, timeout=timeout)
            elapsed = time.monotonic() - t1
            if resp is None:
                continue
            if elapsed >= base_elapsed + _TIME_DELTA_MIN:
                # Confirm with a second control to rule out a transient spike.
                t2 = time.monotonic()
                confirm = await fetch("GET", control_url, timeout=timeout)
                confirm_elapsed = time.monotonic() - t2
                if confirm is None:
                    continue
                if elapsed >= confirm_elapsed + _TIME_DELTA_MIN:
                    findings.append({
                        "type": "command_injection",
                        "vuln_type": f"rce:cmdi:{param}",
                        "title": f"Blind OS command injection in '{param}'",
                        "severity": "high",
                        "url": inj_url,
                        "parameter": param,
                        "payload": payload,
                        "cwe": "CWE-78",
                        "confidence": 0.6,
                        "evidence": (
                            f"time-based probe {payload!r} responded in "
                            f"{elapsed:.2f}s vs control {base_elapsed:.2f}s / "
                            f"{confirm_elapsed:.2f}s (>= +{_TIME_DELTA_MIN:.0f}s "
                            "delay), consistent with `sleep` executing in a shell"
                        ),
                    })
                    blind_hit = True
                    break
        if blind_hit:
            break

    return findings


register_worker("vuln", TECHNIQUE, run)
