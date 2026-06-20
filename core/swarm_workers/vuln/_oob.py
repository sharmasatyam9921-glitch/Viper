"""Shared out-of-band probe helper for blind-vulnerability workers.

When an OOB server is active (set via the hunt context), a worker can fire a
canary payload at a candidate parameter and emit a single oob-tagged candidate
finding. That finding is a LEAD until the validation gate sees the target's
backend call the listener back — at which point it becomes submittable. No OOB
server configured -> no-op, so this is safe to call unconditionally.
"""
from __future__ import annotations

import logging
from typing import List

from ._http import add_query, fetch, get_oob

logger = logging.getLogger("viper.swarm_workers.vuln.oob")


async def fire_oob(url: str, parameter: str, *, vuln_type: str, title: str,
                   cwe: str, payload_key: str, severity: str = "high",
                   timeout: float = 10.0) -> List[dict]:
    """Fire an OOB canary at `parameter`; return a tagged candidate finding or []."""
    oob = get_oob()
    if oob is None:
        return []
    try:
        from core.oob.canary import payloads_for
        canary = oob.new_canary(vuln_type)
        payloads = payloads_for(canary)
        payload = payloads.get(payload_key) or payloads["ssrf"]
        probe = add_query(url, parameter, payload)
        # Fire it. We do NOT need the response — confirmation is the callback.
        await fetch("GET", probe, timeout=timeout)
        return [{
            "type": vuln_type.split(":")[0],
            "vuln_type": vuln_type,
            "title": title,
            "severity": severity,
            "url": probe,
            "parameter": parameter,
            "payload": payload,
            "cwe": cwe,
            "oob_token": canary.token,
            "confidence": 0.5,
            "needs_oob_confirmation": True,
            "evidence": (f"Out-of-band canary {canary.token} fired via "
                         f"?{parameter}=; the gate confirms this only if the "
                         "target's backend calls our listener back."),
        }]
    except Exception as exc:   # noqa: BLE001 — never let an OOB probe break a worker
        logger.debug("oob probe failed (%s ?%s=): %s", vuln_type, parameter, exc)
        return []
