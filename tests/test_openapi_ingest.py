"""OpenAPI/Swagger ingestion: map documented routes + params into discovery leads
that feed the confirmed workers. Read-only; never touches the gate."""
from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import core.swarm_workers  # noqa: F401,E402
from core.swarm_engine import SwarmAgent  # noqa: E402
from core.swarm_workers import get_worker_runner, list_workers  # noqa: E402
from core.swarm_workers.recon.openapi import parse_openapi  # noqa: E402
from core.swarm_workers.vuln._http import HttpResp  # noqa: E402

_OPENAPI3 = {
    "openapi": "3.0.1",
    "servers": [{"url": "https://declared-elsewhere.example/api/v2"}],
    "paths": {
        "/users/{id}": {
            "get": {"parameters": [
                {"name": "id", "in": "path"},
                {"name": "expand", "in": "query"},
            ]},
        },
        "/search": {
            "get": {"parameters": [{"name": "q", "in": "query"},
                                   {"name": "limit", "in": "query"}]},
            "post": {"requestBody": {"content": {"application/json": {
                "schema": {"$ref": "#/components/schemas/Search"}}}}},
        },
    },
    "components": {"schemas": {"Search": {"properties": {
        "term": {"type": "string"}, "page": {"type": "integer"}}}}},
}

_SWAGGER2 = {
    "swagger": "2.0",
    "basePath": "/v1",
    "host": "declared-elsewhere.example",
    "paths": {
        "/orders/{orderId}": {
            "get": {"parameters": [{"name": "orderId", "in": "path"}]},
            "put": {"parameters": [{"name": "body", "in": "body", "schema": {
                "properties": {"status": {}, "note": {}}}}]},
        },
    },
}

_TARGET = "https://target.example/"


def test_registered():
    assert "openapi" in list_workers("recon")


def test_parse_openapi3_templates_paths_seeds_query_collects_body():
    endpoints, params = parse_openapi(_OPENAPI3, _TARGET)
    # host is the TARGET host (declared servers host ignored); server PATH kept
    assert all(u.startswith("https://target.example/api/v2/") for u in endpoints)
    # path template filled, query seeded
    assert any(u == "https://target.example/api/v2/users/1?expand=1" for u in endpoints)
    assert any(u.startswith("https://target.example/api/v2/search?") for u in endpoints)
    # every documented param name is registered — query, path, AND body ($ref-resolved)
    assert {"id", "expand", "q", "limit", "term", "page"} <= params


def test_parse_swagger2_basepath_and_body_params():
    endpoints, params = parse_openapi(_SWAGGER2, _TARGET)
    assert any(u == "https://target.example/v1/orders/1" for u in endpoints)
    assert {"orderId", "status", "note"} <= params        # incl. in:body schema props


def test_parse_non_spec_is_empty():
    assert parse_openapi({"not": "a spec"}, _TARGET) == ([], set())
    assert parse_openapi("nope", _TARGET) == ([], set())
    assert parse_openapi({"paths": "wrong-type"}, _TARGET) == ([], set())


def _agent():
    return SwarmAgent(agent_id="t", objective="x", target=_TARGET,
                      technique="openapi", payload={}, timeout_s=8.0)


def _run(spec_path: str, spec: dict):
    async def fake(method, url, **kw):
        if spec_path and url.endswith(spec_path):
            return HttpResp(200, {"content-type": "application/json"},
                            json.dumps(spec), url)
        return HttpResp(404, {}, "not found", url)
    async def go():
        with patch("core.swarm_workers.recon.openapi.fetch", side_effect=fake):
            return await get_worker_runner("recon", "openapi")(_agent())
    return asyncio.run(go())


def test_worker_emits_endpoints_and_seeds_params():
    from core.payload_library import clear_discovered_params, get_discovered_params
    clear_discovered_params()
    try:
        findings = _run("/openapi.json", _OPENAPI3)
        assert findings and all(f["type"] == "endpoint" for f in findings)
        assert all("OpenAPI/Swagger spec" in f["evidence"] for f in findings)
        # params were seeded for the injection workers to consume
        seeded = set(get_discovered_params())
        assert {"expand", "q", "limit", "term"} <= seeded
    finally:
        clear_discovered_params()


def test_worker_no_spec_present_is_noop():
    findings = _run("", {})           # every probe 404s
    assert findings == []
