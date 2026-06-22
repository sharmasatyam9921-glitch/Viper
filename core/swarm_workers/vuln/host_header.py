"""Host header injection probe (vuln phase, non-destructive).

Apps that build absolute URLs (password-reset links, redirects, cached asset
references, canonical tags) from the incoming Host / X-Forwarded-Host header let
an attacker control those URLs by spoofing the header. Impact ranges from web
cache poisoning and open redirect to password-reset poisoning (the reset link in
the victim's email points at the attacker) and, when the app FETCHES the host,
server-side SSRF.

Detection is differential and FP-averse: a benign control request (the real
Host) must NOT contain the marker; the spoofed-header request must reflect the
marker host into a Location redirect (strong) or an absolute URL in the body
(medium). The marker is a unique attacker-looking host, so a server echoing it
into a generated URL is the bug — a plain reflection of the request path is not.

When an out-of-band server is active, the probe also sends the canary host so a
BLIND host-header bug (server-side fetch / emailed link) is confirmed by a
callback. GET-only, read-only.
"""
from __future__ import annotations

import logging
import secrets
from typing import List, Optional

from core.swarm_engine import SwarmAgent
from core.swarm_workers import register_worker

from ._http import HttpResp, fetch, get_oob, normalize_target_url

logger = logging.getLogger("viper.swarm_workers.vuln.host_header")

TECHNIQUE = "host_header"

# Headers a reverse proxy / framework may trust to set the effective host.
_HEADERS = ["X-Forwarded-Host", "Host", "X-Host", "X-Original-Host",
            "X-Forwarded-Server", "Forwarded"]


def _marker() -> str:
    return f"viperhh{secrets.token_hex(4)}.example.net"


def _header_value(header: str, host: str) -> str:
    return f"host={host}" if header.lower() == "forwarded" else host


def _loc(resp: Optional[HttpResp]) -> str:
    return ((resp.headers or {}).get("location", "") if resp else "")


async def _probe(url: str, header: str, timeout: float) -> Optional[dict]:
    marker = _marker()
    control = await fetch("GET", url, timeout=timeout, follow_redirects=False)
    probe = await fetch("GET", url, headers={header: _header_value(header, marker)},
                        timeout=timeout, follow_redirects=False)
    if probe is None:
        return None
    cbody = (control.body or "") if control else ""

    # Strongest: the spoofed host lands in the Location redirect (cache poisoning /
    # open redirect / reset-link poisoning), and the control redirect did not.
    if marker in _loc(probe) and marker not in _loc(control):
        return _finding(url, header, marker, "high", 0.8,
                        "reflected into the Location redirect header")
    # Medium: spoofed host appears as an absolute URL in the body (links, canonical,
    # script src) that the benign control did not contain.
    if (f"//{marker}" in (probe.body or "")) and (f"//{marker}" not in cbody):
        return _finding(url, header, marker, "medium", 0.6,
                        "reflected into an absolute URL in the response body")
    return None


def _finding(url, header, marker, severity, conf, where) -> dict:
    return {
        "type": "host_header",
        "vuln_type": f"host_header:{header.lower()}",
        "title": f"Host header injection via {header}",
        "severity": severity,
        "url": url,
        "parameter": header,
        "payload": marker,
        "cwe": "CWE-644",
        "confidence": conf,
        "needs_manual_verification": True,
        "evidence": (f"A spoofed '{header}: {marker}' was {where}, while a benign "
                     f"control request (real Host) was not — the app builds URLs "
                     f"from an attacker-controlled host header."),
    }


async def run(agent: SwarmAgent) -> List[dict]:
    url = normalize_target_url(agent.target)
    if not url:
        return []
    timeout = min(agent.timeout_s, 10.0)
    findings: list[dict] = []
    oob = get_oob()

    for header in _HEADERS:
        try:
            f = await _probe(url, header, timeout)
            if f:
                findings.append(f)
        except Exception as exc:  # noqa: BLE001
            logger.debug("host-header probe %s failed: %s", header, exc)

    # Blind host-header (server-side fetch / emailed link): send the canary host;
    # the gate confirms iff the app calls our listener back. (One canary; cheap.)
    if oob is not None:
        try:
            canary = oob.new_canary("host_header")
            await fetch("GET", url,
                        headers={"X-Forwarded-Host": canary.domain},
                        timeout=timeout, follow_redirects=False)
            findings.append({
                "type": "host_header",
                "vuln_type": "host_header:blind",
                "title": "Blind host header injection (out-of-band canary)",
                "severity": "high",
                "url": url,
                "parameter": "X-Forwarded-Host",
                "payload": canary.domain,
                "cwe": "CWE-644",
                "oob_token": canary.token,
                "confidence": 0.5,
                "needs_oob_confirmation": True,
                "evidence": (f"Sent X-Forwarded-Host: {canary.domain}; submittable "
                             "only if the app fetches it / emails a link to it and "
                             "our listener is called back."),
            })
        except Exception as exc:  # noqa: BLE001
            logger.debug("host-header oob probe failed: %s", exc)

    return findings


register_worker("vuln", TECHNIQUE, run)
