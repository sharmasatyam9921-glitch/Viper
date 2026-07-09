"""GraphQL introspection also seeds the injection workers with the schema's real
field/argument names (read-only discovery; never a finding, never touches the gate)."""
from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import core.swarm_workers  # noqa: F401,E402
from core.swarm_engine import SwarmAgent  # noqa: E402
from core.swarm_workers import get_worker_runner  # noqa: E402
from core.swarm_workers.vuln._http import HttpResp  # noqa: E402
from core.swarm_workers.vuln.graphql import _schema_param_names  # noqa: E402

_SCHEMA = {"data": {"__schema": {"types": [
    {"name": "User", "kind": "OBJECT",
     "fields": [{"name": "id", "args": []}, {"name": "email", "args": []}]},
    {"name": "Query", "kind": "OBJECT",
     "fields": [{"name": "user", "args": [{"name": "login"}]}]},
    {"name": "CreateUserInput", "kind": "INPUT_OBJECT",
     "inputFields": [{"name": "password"}]},
    {"name": "__Type", "kind": "OBJECT",           # GraphQL meta-type — must be skipped
     "fields": [{"name": "ofType", "args": []}]},
]}}}


def test_extractor_collects_fields_args_inputfields_skips_meta():
    names = _schema_param_names(_SCHEMA)
    assert {"id", "email", "user", "login", "password"} <= names
    assert "ofType" not in names                    # __Type meta-type skipped


def test_extractor_is_empty_on_junk():
    assert _schema_param_names({"nope": 1}) == set()
    assert _schema_param_names(None) == set()
    assert _schema_param_names({"data": {"__schema": {"types": ["String", "Int"]}}}) == set()


def _agent():
    return SwarmAgent(agent_id="t", objective="x", target="http://t/",
                      technique="graphql", payload={}, timeout_s=8.0)


def _run(fake):
    async def go():
        with patch("core.swarm_workers.vuln.graphql.fetch", side_effect=fake):
            return await get_worker_runner("vuln", "graphql")(_agent())
    return asyncio.run(go())


def test_confirmed_introspection_seeds_field_and_arg_names():
    from core.payload_library import clear_discovered_params, get_discovered_params

    async def fake(method, url, **kw):
        if method == "POST":
            return HttpResp(200, {"content-type": "application/json"},
                            json.dumps(_SCHEMA), url)
        return HttpResp(200, {"content-type": "text/html"}, "<html>home</html>", url)

    clear_discovered_params()
    try:
        findings = _run(fake)
        assert any(f["type"] == "graphql_introspection" for f in findings)
        seeded = set(get_discovered_params())
        assert {"id", "email", "user", "login", "password"} <= seeded
        assert "ofType" not in seeded
    finally:
        clear_discovered_params()


def test_no_introspection_seeds_nothing():
    from core.payload_library import clear_discovered_params, get_discovered_params

    async def fake(method, url, **kw):
        # introspection blocked: a GraphQL error, no schema
        if method == "POST":
            return HttpResp(200, {"content-type": "application/json"},
                            '{"errors":[{"message":"introspection is disabled"}]}', url)
        return HttpResp(200, {"content-type": "text/html"}, "<html>home</html>", url)

    clear_discovered_params()
    try:
        _run(fake)
        assert get_discovered_params() == []
    finally:
        clear_discovered_params()
