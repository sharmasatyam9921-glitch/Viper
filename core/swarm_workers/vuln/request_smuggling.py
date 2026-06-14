"""HTTP request-smuggling probe (vuln phase) — DETECTION ONLY, non-destructive.

Request smuggling can corrupt OTHER users' requests, so this worker NEVER sends
a smuggled payload that poisons the shared queue. It uses only the **timing
differential** technique (the safe method): a CL.TE / TE.CL desync makes the
*back-end wait for bytes that never arrive*, so YOUR OWN connection hangs. The
delay is self-inflicted — no other request is affected. A probe that stalls
while a normal request returns fast is the signal.

Raw sockets are required to control request framing (conflicting Content-Length
/ Transfer-Encoding headers that urllib would normalize away). Each probe uses a
fresh connection that is closed immediately, so nothing is left desynced.

Timing detection is inherently FP-prone (a slow backend looks like a hang), so:
  * the delay must clear a high threshold over a measured baseline, AND
  * it must reproduce on a second attempt, AND
  * findings are emitted as needs-manual-confirmation, not auto-critical.
"""

from __future__ import annotations

import asyncio
import logging
import socket
import ssl
import time
from typing import List, Optional, Tuple
from urllib.parse import urlsplit

from core.swarm_engine import SwarmAgent
from core.swarm_workers import register_worker

logger = logging.getLogger("viper.swarm_workers.vuln.request_smuggling")

TECHNIQUE = "request_smuggling"

_CONNECT_TIMEOUT = 8.0
_READ_TIMEOUT = 10.0          # how long we wait for the first response byte
_DELAY_THRESHOLD = 5.0        # probe must be >= baseline + this to be suspicious


def _origin(url: str) -> Tuple[str, int, bool, str]:
    p = urlsplit(url if "://" in url else "https://" + url)
    use_tls = p.scheme != "http"
    host = p.hostname or ""
    port = p.port or (443 if use_tls else 80)
    path = p.path or "/"
    return host, port, use_tls, path


def _baseline_req(host: str, path: str) -> bytes:
    return (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        "Content-Type: application/x-www-form-urlencoded\r\n"
        "Content-Length: 5\r\n"
        "Connection: close\r\n"
        "\r\n"
        "x=1\r\n"
    ).encode()


def _clte_req(host: str, path: str) -> bytes:
    # Front-end uses Content-Length (forwards 4 bytes: "1\r\nA"), back-end uses
    # Transfer-Encoding and waits for the next chunk that never comes -> hang.
    return (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        "Content-Type: application/x-www-form-urlencoded\r\n"
        "Transfer-Encoding: chunked\r\n"
        "Content-Length: 4\r\n"
        "Connection: close\r\n"
        "\r\n"
        "1\r\nA\r\n0\r\n\r\n"
    ).encode()


def _tecl_req(host: str, path: str) -> bytes:
    # Front-end uses Transfer-Encoding (request ends at "0\r\n\r\n"), back-end
    # uses Content-Length: 6 and waits for 6 body bytes that never arrive -> hang.
    return (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        "Content-Type: application/x-www-form-urlencoded\r\n"
        "Transfer-Encoding: chunked\r\n"
        "Content-Length: 6\r\n"
        "Connection: close\r\n"
        "\r\n"
        "0\r\n\r\nX"
    ).encode()


def _send_raw(host: str, port: int, use_tls: bool, payload: bytes) -> Tuple[float, bool]:
    """Send one raw request on a fresh, immediately-closed connection.
    Returns (elapsed_seconds, timed_out). Blocking — call via to_thread."""
    sock = None
    try:
        sock = socket.create_connection((host, port), timeout=_CONNECT_TIMEOUT)
        if use_tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            sock = ctx.wrap_socket(sock, server_hostname=host)
        sock.settimeout(_READ_TIMEOUT)
        t0 = time.monotonic()
        sock.sendall(payload)
        try:
            sock.recv(64)
            return time.monotonic() - t0, False
        except socket.timeout:
            return time.monotonic() - t0, True
    except (OSError, ssl.SSLError) as e:
        logger.debug("smuggling raw send failed for %s:%s: %s", host, port, e)
        return 0.0, False
    finally:
        if sock is not None:
            try:
                sock.close()
            except Exception:
                pass


async def _timed(host, port, use_tls, payload) -> Tuple[float, bool]:
    return await asyncio.to_thread(_send_raw, host, port, use_tls, payload)


async def run(agent: SwarmAgent) -> List[dict]:
    host, port, use_tls, path = _origin(agent.target)
    if not host:
        return []

    # Establish a baseline; if it already hangs the server is just slow — bail.
    base_t, base_to = await _timed(host, port, use_tls, _baseline_req(host, path))
    if base_to or base_t <= 0:
        return []

    findings: list[dict] = []
    for label, builder in (("CL.TE", _clte_req), ("TE.CL", _tecl_req)):
        probe = builder(host, path)
        t1, to1 = await _timed(host, port, use_tls, probe)
        suspicious = to1 or (t1 >= base_t + _DELAY_THRESHOLD)
        if not suspicious:
            continue
        # Confirm: the delay must reproduce, and a fresh baseline must stay fast,
        # to rule out a transiently slow backend.
        base2_t, base2_to = await _timed(host, port, use_tls, _baseline_req(host, path))
        t2, to2 = await _timed(host, port, use_tls, probe)
        reproduced = (to2 or t2 >= base2_t + _DELAY_THRESHOLD)
        baseline_fast = (not base2_to and base2_t < _DELAY_THRESHOLD)
        if reproduced and baseline_fast:
            findings.append({
                "type": "request_smuggling",
                "vuln_type": f"request_smuggling:{label}",
                "title": f"Possible HTTP request smuggling ({label}, timing)",
                "severity": "high",
                "url": f"{'https' if use_tls else 'http'}://{host}:{port}{path}",
                "cwe": "CWE-444",
                "confidence": 0.55,
                "evidence": (
                    f"{label} timing probe stalled (~{t1:.1f}s / {t2:.1f}s) while "
                    f"a normal request returned fast (~{base_t:.1f}s / {base2_t:.1f}s). "
                    "Timing-based signal — CONFIRM MANUALLY (re-test, rule out a slow "
                    "backend; never send a payload that poisons other users)."
                ),
                "needs_manual_confirmation": True,
            })
    return findings


register_worker("vuln", TECHNIQUE, run)
