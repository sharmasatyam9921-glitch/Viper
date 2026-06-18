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
import re
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

# Structural signatures of a LIVE GraphQL IDE — bootstrap markup / renderer
# calls / asset references — NOT the product name appearing in human prose.
# A benign docs/marketing page that merely says "we offered a GraphiQL
# explorer" must not match any of these; only a page that actually ships an
# IDE does. Each alternative is the keyword in a markup/code context (an id or
# class attribute, a mount tag, a render call, or a bundle/static asset path).
_IDE_LIVE_MARKERS = re.compile(
    r"""(?ix)                       # case-insensitive, verbose
    (?: id | class ) \s* = \s* ["']? graphiql               # <div id="graphiql">
  | (?: id | class ) \s* = \s* ["']? graphql-playground     # playground mount node
  | > \s* graphiql \s* <                                    # <…>GraphiQL</…> tag text
  | render (?: graphiql | playgroundpage )                  # renderGraphiQL / renderPlaygroundPage
  | graphiql (?: options | settings )                       # GraphiQLOptions / GraphiQLSettings
  | createelement \s* \( \s* graphiql                       # React.createElement(GraphiQL
  | (?: src | href ) \s* = \s* ["'][^"']* graphiql[^"']*\.(?:js|css)   # graphiql bundle
  | (?: src | href ) \s* = \s* ["'][^"']*(?:graphql-playground|playground)[^"']*\.(?:js|css)
  | /static/ (?: graphiql | playground )                    # /static/graphiql bundle path
  | altair-graphql                                          # altair package signature
  | embeddablesandbox | apollographql/sandbox               # Apollo Sandbox embed
    """,
)


def _is_graphql_schema(schema_obj: dict, types: list) -> bool:
    """True only if `__schema` looks like a genuine GraphQL introspection result.

    A generic JSON API can coincidentally nest ``data.__schema.types`` as a
    non-empty list (e.g. a reporting endpoint enumerating column types as
    plain strings). That is NOT GraphQL. A real introspection result is shaped
    like GraphQL's ``__Schema``: it carries a ``queryType`` and/or its
    ``types`` entries are objects with GraphQL-canonical fields
    (``name`` + ``kind``/``fields``). We require structural evidence, not just
    a non-empty list.
    """
    if not isinstance(schema_obj, dict):
        return False

    # Strong signal: an explicit queryType naming the root Query object.
    query_type = schema_obj.get("queryType")
    if isinstance(query_type, dict) and query_type.get("name"):
        return True

    # Otherwise require the type entries themselves to be GraphQL-shaped:
    # dict objects that carry a `name` AND at least one of the canonical
    # introspection fields (`kind`, `fields`, `inputFields`, `enumValues`,
    # `interfaces`, `possibleTypes`). Plain strings / bare {"x":...} fail this.
    _CANONICAL = ("kind", "fields", "inputFields", "enumValues",
                  "interfaces", "possibleTypes")
    shaped = 0
    for t in types:
        if (isinstance(t, dict) and t.get("name")
                and any(k in t for k in _CANONICAL)):
            shaped += 1
    if shaped:
        return True

    # Last resort: every entry is a dict carrying a `name` (the minimal
    # introspection projection `{ __schema { types { name } } }` returns
    # exactly this). A list of plain strings or non-`name` dicts is rejected.
    return bool(types) and all(
        isinstance(t, dict) and t.get("name") for t in types
    )


async def _probe_path(base: str, path: str, timeout: float) -> List[dict]:
    url = base.rstrip("/") + path
    findings: list[dict] = []

    # Probe 1: GET — detects a LIVE GraphiQL / Playground IDE.
    # The product name appearing anywhere in the body is NOT sufficient: a
    # benign docs / "explorer disabled" / marketing page that merely mentions
    # "GraphiQL" in prose would trip a bare substring match (FP). We instead
    # require the IDE's bootstrap markup / renderer call / asset signature
    # (see _IDE_LIVE_MARKERS), and only consider HTML responses.
    g = await fetch("GET", url, timeout=timeout)
    if g and g.ok and g.body and _IDE_LIVE_MARKERS.search(g.body):
        ctype = (g.headers or {}).get("content-type", "")
        # Live IDEs are served as HTML. If a content-type is present, require an
        # HTML-ish one; absence of the header (e.g. minimal test doubles) is
        # tolerated rather than assumed non-HTML.
        if (not ctype) or ("html" in ctype.lower()):
            m = _IDE_LIVE_MARKERS.search(g.body)
            findings.append({
                "type": "graphql_ide_exposed",
                "vuln_type": f"graphql_ide:{path}",
                "title": f"GraphQL IDE exposed at {path}",
                "severity": "medium",
                "url": url,
                "cwe": "CWE-200",
                "confidence": 0.9,
                "evidence": f"live GraphQL IDE bootstrap marker: {m.group(0)[:80]!r}",
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

    # A real GraphQL endpoint answers introspection as JSON. A generic API that
    # happens to nest a "__schema" key in some other content-type is not
    # GraphQL — require application/json (tolerating an absent header, e.g.
    # minimal test doubles) before trusting the shape below.
    ctype = (resp.headers or {}).get("content-type", "")
    if ctype and "json" not in ctype.lower():
        return findings

    try:
        data = json.loads(body)
    except json.JSONDecodeError:
        # Some endpoints respond with non-JSON when introspection blocked
        return findings

    # Introspection succeeded → schema leaked. Guard against a generic JSON API
    # that merely nests data.__schema.types as a non-empty list (e.g. a
    # reporting endpoint listing column types as plain strings): require the
    # payload to be GraphQL-CANONICAL before claiming introspection.
    schema = (data or {}).get("data", {}) or {}
    schema_obj = schema.get("__schema") or {}
    types = schema_obj.get("types") if isinstance(schema_obj, dict) else None
    types = types or []
    if types and _is_graphql_schema(schema_obj, types):
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
