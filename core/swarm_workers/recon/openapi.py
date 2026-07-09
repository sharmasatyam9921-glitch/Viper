"""OpenAPI / Swagger spec ingestion (read-only discovery).

The confirmed injection / SSRF / access-control workers are only as good as the
endpoints and parameter names they are handed. When a target publishes an OpenAPI 3.x
or Swagger 2.0 document (extremely common for APIs), it is a free, authoritative map
of every route, method, and parameter — far better than guessing. This worker GETs the
usual spec locations, parses the JSON (dependency-free), and:

  * emits one ``endpoint`` finding per documented path — path templates like
    ``/users/{id}`` filled with a benign sample and query parameters seeded
    (``?limit=1``) so the vuln workers probe the REAL routes, and
  * registers every documented parameter NAME via
    :func:`core.payload_library.add_discovered_params`, so the injection workers test
    the params that actually exist instead of a static guess list.

Purely read-only: it fetches only the spec document and produces discovery leads — it
never touches the validation gate, so it cannot affect precision. Endpoints are kept on
the TARGET host (the spec's own declared host is ignored) so discovery can't wander
out of scope; the scope reasoner remains the downstream authority.
"""
from __future__ import annotations

import json
import logging
import re
from typing import List, Set, Tuple
from urllib.parse import urlsplit

from core.swarm_engine import SwarmAgent
from core.swarm_workers import register_worker

from ..vuln._http import fetch, normalize_target_url

logger = logging.getLogger("viper.swarm_workers.recon.openapi")

TECHNIQUE = "openapi"

# Well-known spec locations, most-specific first. Probed until one parses as a spec.
_SPEC_PATHS = (
    "/openapi.json", "/swagger.json", "/swagger/v1/swagger.json", "/v3/api-docs",
    "/v2/api-docs", "/api-docs", "/api/swagger.json", "/api/openapi.json",
    "/api/v1/openapi.json", "/.well-known/openapi.json", "/swagger/doc.json",
)

_HTTP_METHODS = {"get", "post", "put", "patch", "delete", "head", "options", "trace"}
_PARAM_CAP = 200
_ENDPOINT_CAP = 150


def _template_path(path: str) -> str:
    """Fill OpenAPI path templates with a benign sample: /users/{id} -> /users/1."""
    return re.sub(r"\{[^}]+\}", "1", path)


def _resolve_ref(spec: dict, ref: str) -> dict:
    """Resolve a local ``$ref`` (#/components/schemas/X or #/definitions/X). One hop."""
    if not isinstance(ref, str) or not ref.startswith("#/"):
        return {}
    node = spec
    for part in ref[2:].split("/"):
        if not isinstance(node, dict):
            return {}
        node = node.get(part, {})
    return node if isinstance(node, dict) else {}


def _schema_prop_names(spec: dict, schema: dict) -> List[str]:
    """Top-level property names of a JSON schema, resolving one ``$ref`` hop."""
    if not isinstance(schema, dict):
        return []
    if "$ref" in schema:
        schema = _resolve_ref(spec, schema["$ref"])
    props = schema.get("properties")
    return [str(k) for k in props] if isinstance(props, dict) else []


def _body_param_names(spec: dict, op: dict) -> List[str]:
    """Request-body property names, for both OpenAPI 3.x and Swagger 2.0."""
    names: List[str] = []
    # OpenAPI 3.x: requestBody.content.<media>.schema
    body = op.get("requestBody")
    if isinstance(body, dict):
        content = body.get("content")
        if isinstance(content, dict):
            for media in content.values():
                if isinstance(media, dict):
                    names += _schema_prop_names(spec, media.get("schema") or {})
    # Swagger 2.0: a parameter with in=body carries a schema
    for p in op.get("parameters") or []:
        if isinstance(p, dict) and (p.get("in") or "").lower() == "body":
            names += _schema_prop_names(spec, p.get("schema") or {})
    return names


def _api_base(spec: dict, base_url: str) -> str:
    """Base path for documented routes, kept on the TARGET host (the spec's declared
    host/servers host is deliberately ignored so discovery stays in scope). Uses only
    the PATH portion of an OpenAPI ``servers[0].url`` or Swagger ``basePath``."""
    parts = urlsplit(base_url)
    host = f"{parts.scheme}://{parts.netloc}"
    prefix = ""
    servers = spec.get("servers")
    if isinstance(servers, list) and servers and isinstance(servers[0], dict):
        prefix = urlsplit(str(servers[0].get("url") or "")).path or ""
    elif isinstance(spec.get("basePath"), str):
        prefix = spec["basePath"]
    return host + "/" + prefix.strip("/") if prefix.strip("/") else host


def parse_openapi(spec: dict, base_url: str) -> Tuple[List[str], Set[str]]:
    """Parse an OpenAPI 3.x / Swagger 2.0 doc into (endpoint URLs, parameter names).

    Endpoint URLs are on the target host, path-templated, and seeded with any query
    parameters (``?p=1``) so the vuln workers can probe them directly. Never raises;
    returns ([], set()) for a non-spec dict."""
    endpoints: List[str] = []
    params: Set[str] = set()
    if not isinstance(spec, dict):
        return [], set()
    paths = spec.get("paths")
    if not isinstance(paths, dict):
        return [], set()
    api_base = _api_base(spec, base_url).rstrip("/")
    seen: Set[str] = set()
    for path, item in paths.items():
        if not isinstance(path, str) or not isinstance(item, dict):
            continue
        shared = item.get("parameters") or []          # path-level parameters
        query_names: List[str] = []
        for method, op in item.items():
            if method.lower() not in _HTTP_METHODS or not isinstance(op, dict):
                continue
            for p in list(shared) + list(op.get("parameters") or []):
                if not isinstance(p, dict):
                    continue
                nm = p.get("name")
                if not nm:
                    continue
                params.add(str(nm))
                if (p.get("in") or "").lower() == "query" and str(nm) not in query_names:
                    query_names.append(str(nm))
            for nm in _body_param_names(spec, op):
                params.add(nm)
        full = api_base + "/" + _template_path(path).lstrip("/")
        if query_names:
            full += "?" + "&".join(f"{n}=1" for n in query_names[:8])
        if full not in seen:
            seen.add(full)
            endpoints.append(full)
        if len(endpoints) >= _ENDPOINT_CAP or len(params) >= _PARAM_CAP:
            break
    return endpoints[:_ENDPOINT_CAP], set(list(params)[:_PARAM_CAP])


def _looks_like_spec(data) -> bool:
    return (isinstance(data, dict) and isinstance(data.get("paths"), dict)
            and ("openapi" in data or "swagger" in data))


async def run(agent: SwarmAgent) -> List[dict]:
    base = normalize_target_url(agent.target)
    if not base:
        return []
    timeout = min(agent.timeout_s, 8.0)
    parts = urlsplit(base)
    root = f"{parts.scheme}://{parts.netloc}"

    spec = None
    spec_url = ""
    for path in _SPEC_PATHS:
        resp = await fetch("GET", root + path, timeout=timeout)
        if not resp or not (200 <= getattr(resp, "status", 0) < 300) or not resp.body:
            continue
        try:
            data = json.loads(resp.body)
        except (ValueError, TypeError):
            continue
        if _looks_like_spec(data):
            spec, spec_url = data, root + path
            break
    if spec is None:
        return []

    endpoints, params = parse_openapi(spec, base)
    if params:
        try:
            from core.payload_library import add_discovered_params
            add_discovered_params(params)
        except Exception as e:  # noqa: BLE001 — seeding is best-effort
            logger.debug("openapi param seeding failed: %s", e)

    findings: List[dict] = [{
        "type": "endpoint",
        "vuln_type": f"endpoint:{u}",
        "title": u,
        "asset": parts.netloc,
        "url": u,
        "severity": "info",
        "evidence": f"documented in OpenAPI/Swagger spec {spec_url}",
    } for u in endpoints]
    logger.info("openapi: %d endpoints, %d params from %s",
                len(endpoints), len(params), spec_url)
    return findings


register_worker("recon", TECHNIQUE, run)
