"""CORS misconfiguration probe.

Sends an Origin header with a clearly attacker-controlled value
(`https://evil-tester.example`) and checks the response for any of:

  - `Access-Control-Allow-Origin: *` with `Allow-Credentials: true`
    (severe — credentialed cross-origin)
  - `Access-Control-Allow-Origin` reflecting the attacker origin
    (medium-high — likely arbitrary origin acceptance)
  - `Access-Control-Allow-Origin: null` accepted
    (medium — sandboxed iframes / data: URIs can spoof null)
"""

from __future__ import annotations

import logging
import secrets
from typing import List

from core.swarm_engine import SwarmAgent
from core.swarm_workers import register_worker

from ._http import fetch, normalize_target_url

logger = logging.getLogger("viper.swarm_workers.vuln.cors")

TECHNIQUE = "cors"


async def run(agent: SwarmAgent) -> List[dict]:
    url = normalize_target_url(agent.target)
    if not url:
        return []
    timeout = min(agent.timeout_s, 10.0)
    findings: list[dict] = []

    # Test 1: arbitrary attacker origin
    attacker = f"https://evil-{secrets.token_hex(4)}.example"
    resp = await fetch("GET", url, headers={"Origin": attacker}, timeout=timeout)
    if resp:
        aco = (resp.headers.get("access-control-allow-origin") or "").strip()
        acc = (resp.headers.get("access-control-allow-credentials") or "").strip().lower()
        # A bare `ACAO: *` WITHOUT credentials is the INTENDED, safe config for
        # public read-only APIs / CDNs: per the Fetch spec a wildcard origin is
        # invalid together with credentials, so `*` alone exposes only data the
        # server already chose to make publicly readable to any origin. That is
        # not CWE-942 (which requires a credentialed or origin-trusting
        # misconfig). Only flag the genuinely severe credentialed-wildcard case
        # (`* ` + `Allow-Credentials: true`), which browsers reject but some
        # non-browser clients honor.
        if aco == "*" and acc == "true":
            findings.append({
                "type": "cors_misconfig",
                "vuln_type": "cors_wildcard",
                "title": "CORS: Access-Control-Allow-Origin: * with Allow-Credentials: true",
                "severity": "high",
                "url": url,
                "cwe": "CWE-942",
                "confidence": 0.95,
                "evidence": "ACAO=*, ACAC=true",
            })
        elif aco == attacker:
            sev = "high" if acc == "true" else "medium"
            findings.append({
                "type": "cors_misconfig",
                "vuln_type": "cors_origin_reflect",
                "title": "CORS reflects arbitrary attacker Origin",
                "severity": sev,
                "url": url,
                "cwe": "CWE-942",
                "confidence": 0.9,
                "evidence": f"ACAO={aco}, ACAC={acc or 'unset'}",
            })

    # Test 2: `Origin: null`
    null_resp = await fetch("GET", url, headers={"Origin": "null"}, timeout=timeout)
    if null_resp:
        aco = (null_resp.headers.get("access-control-allow-origin") or "").strip()
        if aco == "null":
            findings.append({
                "type": "cors_misconfig",
                "vuln_type": "cors_null_origin",
                "title": "CORS accepts Origin: null",
                "severity": "medium",
                "url": url,
                "cwe": "CWE-942",
                "confidence": 0.8,
                "evidence": "ACAO=null — exploitable from sandboxed iframes / data: URIs",
            })

    return findings


register_worker("vuln", TECHNIQUE, run)
