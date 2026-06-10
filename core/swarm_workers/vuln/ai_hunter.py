"""Swarm worker for the OWASP Agentic AI tester.

Dispatched on phase=vuln, technique=ai_hunter. Payload accepts the same
fields as the ``ChatTarget`` dataclass — ``url``, ``request_template``,
``response_path``, ``method``, ``headers``, ``session_header``,
``auth_token`` — plus tester selection via ``only`` / ``skip``.

Job envelope example::

    bus.publish("vuln", {
        "target": "https://example.com/api/chat",
        "technique": "ai_hunter",
        "kwargs": {
            "request_template": {"messages": [{"role":"user","content":"{prompt}"}]},
            "response_path": "choices.0.message.content",
            "auth_token": "...",
            "only": ["prompt_injection", "system_prompt_leak"],
        },
    })
"""

from __future__ import annotations

import logging
from typing import List

from core.swarm_engine import SwarmAgent
from core.swarm_workers import register_worker

from core.ai_hunter.probes import ChatTarget
from core.ai_hunter.orchestrator import run_all_testers
from core.ai_hunter.detector import detect_ai_endpoint

logger = logging.getLogger("viper.swarm_workers.vuln.ai_hunter")

TECHNIQUE = "ai_hunter"


async def run(agent: SwarmAgent) -> List[dict]:
    """Entry point invoked by the swarm worker daemon."""
    kw = agent.payload or {}
    url = agent.target
    if not url:
        return []

    template = kw.get("request_template")
    response_path = kw.get("response_path")

    # If the caller didn't provide the request shape, try to detect.
    if template is None or response_path is None:
        try:
            det = await detect_ai_endpoint(
                url,
                timeout_s=min(agent.timeout_s, 10.0),
                auth_token=kw.get("auth_token"),
            )
            if det.is_ai:
                template = template or det.request_template
                response_path = response_path or det.response_path
            else:
                logger.info("[%s] %s doesn't look like an AI endpoint "
                            "(confidence %.2f) — skipping", agent.agent_id, url,
                            det.confidence)
                return []
        except Exception as exc:  # noqa: BLE001
            logger.debug("detection failed: %s", exc)
            return []

    target = ChatTarget(
        url=url,
        method=kw.get("method", "POST"),
        headers=kw.get("headers") or {},
        request_template=template,
        response_path=response_path,
        session_header=kw.get("session_header"),
        auth_token=kw.get("auth_token"),
        timeout_s=min(agent.timeout_s, 30.0),
    )

    findings = await run_all_testers(
        target,
        only=kw.get("only"),
        skip=kw.get("skip"),
        concurrency=int(kw.get("concurrency", 3)),
        use_llm_gen=bool(kw.get("use_llm_gen", False)),
        toolkit_max=int(kw.get("toolkit_max", 25)),
        adaptive_variants=int(kw.get("adaptive_variants", 5)),
    )

    # Stamp each finding with the worker's URL for the dashboard
    for f in findings:
        f.setdefault("url", url)
        f.setdefault("target", url)
    return findings


register_worker("vuln", TECHNIQUE, run)
