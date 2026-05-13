"""GraphQL probe.

Detects:
  - Public GraphQL endpoint at common paths (/graphql, /api/graphql, /v1/graphql)
  - Introspection enabled (high — leaks schema)
  - GraphiQL / Playground IDE exposed (medium — assists exploitation)
  - Error-message disclosure (low-medium)

Read-only. Never mutates data.
"""

from __future__ import annotations

import json
import logging
from typing import List

from core.swarm_engine import SwarmAgent
from core.swarm_workers import register_worker

from ._http import fetch, normalize_target_url

logger = logging.getLogger("viper.swarm_workers.vuln.graphql")

TECHNIQUE = "graphql"

_GRAPHQL_PATHS = [
    "/graphql", "/api/graphql", "/v1/graphql", "/v2/graphql",
    "/graphql/v1", "/graphql/v2", "/query", "/api/query",
]

_INTROSPECTION_Q = (
    '{"query":"{ __schema { types { name } } }"}'
)


async def _probe_path(base: str, path: str, timeout: float) -> List[dict]:
    url = base.rstrip("/") + path
    findings: list[dict] = []

    # Probe 1: GET — detects GraphiQL / Playground UIs
    g = await fetch("GET", url, timeout=timeout)
    if g and g.ok and g.body:
        body_lower = g.body.lower()
        if any(marker in body_lower for marker in (
            "graphiql", "graphql playground", "altair", "apollo sandbox",
        )):
            findings.append({
                "type": "graphql_ide_exposed",
                "vuln_type": f"graphql_ide:{path}",
                "title": f"GraphQL IDE exposed at {path}",
                "severity": "medium",
                "url": url,
                "cwe": "CWE-200",
                "confidence": 0.9,
                "evidence": "GraphiQL / Playground / Altair / Apollo Sandbox markers in HTML",
            })

    # Probe 2: POST introspection
    resp = await fetch(
        "POST", url,
        headers={"Content-Type": "application/json"},
        body=_INTROSPECTION_Q.encode("utf-8"),
        timeout=timeout, follow_redirects=False,
    )
    if not resp:
        return findings
    if resp.status not in (200, 400, 422):
        return findings

    body = resp.body
    if not body:
        return findings

    try:
        data = json.loads(body)
    except json.JSONDecodeError:
        # Some endpoints respond with non-JSON when introspection blocked
        return findings

    # Introspection succeeded → schema leaked
    schema = (data or {}).get("data", {}) or {}
    types = (schema.get("__schema", {}) or {}).get("types") or []
    if types:
        findings.append({
            "type": "graphql_introspection",
            "vuln_type": f"graphql_introspection:{path}",
            "title": f"GraphQL introspection enabled at {path}",
            "severity": "medium",
            "url": url,
            "cwe": "CWE-200",
            "confidence": 0.99,
            "evidence": f"__schema returned {len(types)} types",
            "schema_type_count": len(types),
        })
        return findings

    # Introspection blocked but endpoint LIVE — informational
    errors = (data or {}).get("errors")
    if errors:
        msg = errors[0].get("message", "") if isinstance(errors, list) else str(errors)
        findings.append({
            "type": "graphql_endpoint",
            "vuln_type": f"graphql_endpoint:{path}",
            "title": f"GraphQL endpoint at {path}",
            "severity": "info",
            "url": url,
            "confidence": 0.9,
            "evidence": f"introspection blocked; error: {msg[:200]}",
        })
    return findings


async def run(agent: SwarmAgent) -> List[dict]:
    base = normalize_target_url(agent.target)
    if not base:
        return []
    timeout = min(agent.timeout_s, 8.0)

    findings: list[dict] = []
    for path in _GRAPHQL_PATHS:
        try:
            findings.extend(await _probe_path(base, path, timeout))
        except Exception as e:  # noqa: BLE001
            logger.debug("graphql probe %s failed: %s", path, e)
        # If we found an endpoint, stop probing other paths (no need to
        # hammer every alias)
        if findings:
            break
    return findings


register_worker("vuln", TECHNIQUE, run)
