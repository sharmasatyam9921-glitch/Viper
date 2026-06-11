import asyncio
import json
import sys
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import core.swarm_workers  # noqa: F401
from core.swarm_engine import SwarmAgent
from core.swarm_workers import get_worker_runner, list_workers
from core.swarm_workers.vuln._http import HttpResp


def _agent(target="http://t", timeout=5.0):
    return SwarmAgent(
        agent_id="t", objective="x", target=target,
        technique="mass_assignment", payload={}, timeout_s=timeout,
    )


def _run(fake):
    async def go():
        with patch(
            "core.swarm_workers.vuln.mass_assignment.fetch", side_effect=fake
        ):
            return await get_worker_runner("vuln", "mass_assignment")(_agent())
    return asyncio.run(go())


_JSON = {"content-type": "application/json"}


def test_registered():
    assert "mass_assignment" in list_workers("vuln")


def test_true_positive_privileged_field_exposed():
    """A user object exposing isAdmin/role -> mass-assignment candidate."""
    body = json.dumps({
        "id": 5, "email": "user@t", "username": "bob",
        "role": "customer", "isAdmin": False,
    })

    async def fake(method, url, **kw):
        if url.endswith("/api/Users"):
            return HttpResp(200, dict(_JSON), body, url)
        return HttpResp(404, {}, "", url)

    findings = _run(fake)
    assert len(findings) == 1
    f = findings[0]
    assert "access_control" in f["vuln_type"]
    assert f["vuln_type"] == "access_control:mass_assignment"
    assert f["cwe"] == "CWE-915"
    assert f["severity"] in {"info", "low", "medium", "high", "critical"}
    assert f["url"].endswith("/api/Users")
    # the exposed privileged field is named in evidence/parameter
    assert "isAdmin" in f["evidence"] or "role" in f["evidence"]
    assert f["parameter"] in {"role", "isAdmin"}


def test_true_positive_collection_list():
    """A top-level list of user objects is still inspected."""
    body = json.dumps([
        {"id": 1, "name": "a", "permissions": ["read"]},
        {"id": 2, "name": "b"},
    ])

    async def fake(method, url, **kw):
        if url.endswith("/api/users"):
            return HttpResp(200, dict(_JSON), body, url)
        return HttpResp(404, {}, "", url)

    findings = _run(fake)
    assert len(findings) >= 1
    assert findings[0]["vuln_type"] == "access_control:mass_assignment"


def test_fp_benign_object_no_privileged_fields():
    """A plain profile with only safe fields -> no finding."""
    body = json.dumps({"id": 5, "email": "user@t", "username": "bob",
                       "displayName": "Bob", "avatar": "/a.png"})

    async def fake(method, url, **kw):
        if url.endswith("/api/users") or url.endswith("/api/Users"):
            return HttpResp(200, dict(_JSON), body, url)
        return HttpResp(404, {}, "", url)

    assert _run(fake) == []


def test_fp_html_page_with_privileged_words():
    """An HTML page mentioning 'role'/'admin' is not an object model."""
    html = "<html><body>Your role is admin. isAdmin settings here.</body></html>"

    async def fake(method, url, **kw):
        return HttpResp(200, {"content-type": "text/html"}, html, url)

    assert _run(fake) == []


def test_fp_non_user_config_blob():
    """A config object with 'permissions' but no user-identity key -> no finding."""
    body = json.dumps({"feature": "billing", "permissions": ["x", "y"],
                       "enabled": True})

    async def fake(method, url, **kw):
        if url.endswith("/api/account") or url.endswith("/api/Users"):
            return HttpResp(200, dict(_JSON), body, url)
        return HttpResp(404, {}, "", url)

    assert _run(fake) == []


def test_no_finding_on_errors():
    async def fake(method, url, **kw):
        return None

    assert _run(fake) == []
