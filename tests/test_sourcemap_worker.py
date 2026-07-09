"""Source-map mining: recover secrets (gate-confirmable) + routes/params from a
served .map. Read-only; the secret half reuses the existing secrets gate unchanged."""
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
from core.swarm_workers.recon.sourcemap import (  # noqa: E402
    _secrets_in, _sourcemap_url, mine_sourcemap,
)
from core.swarm_workers.vuln._http import HttpResp  # noqa: E402
from core.swarm_validation import validate_findings  # noqa: E402

_LIVE = "AKIA2E0K8Z9QXVB7N3RT"       # shape-specific, not a placeholder
_MAP = json.dumps({
    "version": 3, "sources": ["webpack://src/api.js"],
    "sourcesContent": [
        f"const KEY='{_LIVE}';\n"
        "fetch('/api/internal/admin?token=1');\n"
        "axios.get('/v2/users?id=5');\n"
        "const doc='https://cdn.other-host.example/x';"],   # cross-host -> dropped
})
_MAP_URL = "http://t/app.js.map"


def test_registered():
    assert "sourcemap" in list_workers("recon")


def test_mine_extracts_same_host_routes_and_params():
    eps, params = mine_sourcemap(_MAP, "http://t/")
    assert "http://t/api/internal/admin?token=1" in eps
    assert "http://t/v2/users?id=5" in eps
    assert not any("other-host" in u for u in eps)      # cross-host dropped
    assert {"token", "id"} <= params


def test_mine_failclosed_on_junk():
    assert mine_sourcemap("not json", "http://t/") == ([], set())
    assert mine_sourcemap(json.dumps({"no": "content"}), "http://t/") == ([], set())


def test_secrets_in_skips_placeholder_example_keys():
    assert _LIVE in _secrets_in(f"x='{_LIVE}'")
    assert _secrets_in("k='AKIAIOSFODNN7EXAMPLE'") == []      # EXAMPLE placeholder


def test_sourcemap_url_prefers_annotation_then_fallback():
    assert _sourcemap_url("//# sourceMappingURL=app.js.map", "http://t/app.js") \
        == "http://t/app.js.map"
    assert _sourcemap_url("no annotation", "http://t/app.js") == "http://t/app.js.map"
    assert _sourcemap_url("//# sourceMappingURL=data:application/json;base64,e30=",
                          "http://t/app.js") == ""            # inline -> nothing to GET


def _agent():
    return SwarmAgent(agent_id="t", objective="x", target="http://t/",
                      technique="sourcemap", payload={}, timeout_s=8.0)


async def _fake(method, url, **kw):
    if url.endswith(".js.map"):
        return HttpResp(200, {"content-type": "application/json"}, _MAP, url)
    if url.endswith(".js"):
        return HttpResp(200, {"content-type": "application/javascript"},
                        "//# sourceMappingURL=app.js.map", url)
    return HttpResp(200, {"content-type": "text/html"},
                    '<script src="/app.js"></script>', url)


def _run():
    async def go():
        with patch("core.swarm_workers.recon.sourcemap.fetch", side_effect=_fake):
            return await get_worker_runner("recon", "sourcemap")(_agent())
    return asyncio.run(go())


def test_worker_emits_secret_and_endpoints_and_seeds_params():
    from core.payload_library import clear_discovered_params, get_discovered_params
    clear_discovered_params()
    try:
        findings = _run()
        secrets = [f for f in findings if f["type"] == "secrets"]
        eps = [f for f in findings if f["type"] == "endpoint"]
        assert secrets and secrets[0]["url"] == _MAP_URL
        assert secrets[0]["vuln_type"] == "secrets:sourcemap"
        assert any("/api/internal/admin" in f["url"] for f in eps)
        assert {"token", "id"} <= set(get_discovered_params())
    finally:
        clear_discovered_params()


def test_sourcemap_secret_confirms_through_the_existing_secrets_gate():
    # The secrets finding (url = .map) routes through _recheck_secrets: re-fetch the
    # map, re-run the same shape regex -> submittable, with ZERO new gate logic.
    findings = _run()
    secret = next(f for f in findings if f["type"] == "secrets")

    def responder(m, url, h):
        return HttpResp(200, {"content-type": "application/json"}, _MAP, url)

    async def fetch(method, url, *, headers=None, timeout=10.0, **kw):
        return responder(method, url, headers or {})
    out = asyncio.run(validate_findings([secret], fetch=fetch))[0]
    assert out["submittable"] and out["validation_confidence"] >= 0.5


def test_placeholder_key_in_map_is_not_submittable():
    safe_map = json.dumps({"version": 3, "sources": ["a.js"],
                           "sourcesContent": ["k='AKIAIOSFODNN7EXAMPLE';"]})

    def responder(m, url, h):
        return HttpResp(200, {"content-type": "application/json"}, safe_map, url)

    async def fetch(method, url, *, headers=None, timeout=10.0, **kw):
        return responder(method, url, headers or {})
    finding = {"type": "secrets", "vuln_type": "secrets:sourcemap", "url": _MAP_URL,
               "severity": "high"}
    out = asyncio.run(validate_findings([finding], fetch=fetch))[0]
    assert not out["submittable"]
