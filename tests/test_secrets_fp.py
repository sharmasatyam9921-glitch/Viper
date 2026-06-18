"""False-positive regression for the `vuln/secrets` swarm worker.

Audit scenario: a catch-all SPA (React/Vue/Angular client-side routing, or a
CDN-fronted app) returns its normal index.html with HTTP 200 for ANY unmatched
route, including `/.env`. The pre-fix worker gated the high-severity
`env_exposed` finding on `r.ok and r.body` plus a bare `"=" in r.body` test —
which ANY HTML body satisfies (`lang="en"`, `charset="utf-8"`, any attr=value).
So the SPA index tripped a high-severity .env-exposed finding even though no
secret is exposed.

Test (a) reproduces that FP (must FAIL pre-fix). Test (b) pins the genuine
true-positive: a real dotenv body served as text/plain still fires.
"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import core.swarm_workers  # noqa: F401,E402  (registers vuln workers)
from core.swarm_engine import SwarmAgent  # noqa: E402
from core.swarm_workers import get_worker_runner  # noqa: E402
from core.swarm_workers.vuln._http import HttpResp  # noqa: E402


def _agent(target: str) -> SwarmAgent:
    return SwarmAgent(
        agent_id="t",
        objective="secrets on " + target,
        target=target,
        technique="secrets",
        payload={},
        timeout_s=10.0,
    )


# The catch-all SPA index served for EVERY path, including /.env. Has plenty of
# `attr=value` so the old bare `"=" in body` test fired; declared text/html so
# the content-type guard recognizes it. No secret of any kind is present.
_SPA_INDEX = (
    '<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">'
    '<title>My App</title></head><body><div id="root"></div>'
    '<script src="/static/js/main.abc123.js"></script></body></html>'
)


def _run(target: str, fake):
    async def go():
        with patch("core.swarm_workers.vuln.secrets.fetch", side_effect=fake):
            runner = get_worker_runner("vuln", "secrets")
            return await runner(_agent(target))

    return asyncio.run(go())


def test_spa_catchall_env_not_flagged():
    """A catch-all SPA that returns index.html for /.env must NOT be flagged.

    Pre-fix this FAILS: the SPA index body trips `env_exposed:/.env` (high).
    """
    async def fake(method, url, **kw):
        # Catch-all: same 200 text/html SPA index for absolutely every path,
        # including /.env, /.git/HEAD, /.aws/credentials, etc.
        return HttpResp(200, {"content-type": "text/html; charset=utf-8"},
                        _SPA_INDEX, url)

    result = _run("http://t/", fake)
    offenders = [r for r in result if r["type"] in
                 ("env_exposed", "secret_leak", "git_exposed",
                  "actuator_exposed")]
    assert offenders == [], (
        "catch-all SPA index must not produce any exposure/secret finding, got: "
        + repr(offenders)
    )


def test_real_dotenv_still_flagged():
    """A genuinely exposed .env (text/plain, KEY=value lines) STILL fires.

    Guards against over-correcting the FP fix into a false negative.
    """
    dotenv_body = (
        "# production env\n"
        "API_KEY=sk_realvalue_9f8c3a21bd\n"
        "DB_PASSWORD=Sup3rSecretPw!\n"
        "DEBUG=false\n"
    )

    async def fake(method, url, **kw):
        if url.endswith("/.env"):
            return HttpResp(200, {"content-type": "text/plain"}, dotenv_body, url)
        # Everything else: an honest 404 so nothing else fires.
        return HttpResp(404, {"content-type": "text/html"}, "Not Found", url)

    result = _run("http://t/", fake)
    env = [r for r in result if r["type"] == "env_exposed"]
    assert env, "a real text/plain dotenv with KEY=value lines must be flagged"
    assert env[0]["severity"] == "high"
