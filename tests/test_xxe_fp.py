"""False-positive regression test for the xxe vuln worker.

Audit scenario (confirmed FP): a NON-vulnerable endpoint accepts an XML body
and returns a 4xx validation error whose response body REFLECTS the submitted
payload verbatim, e.g. {"error":"invalid_request","received":"<raw body>"}.
Because the worker's own XXE payload literally contains the substring
`<!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]>`, the reflected
response matches _ENTITY_ERR_RE (which keyed on the bare word DOCTYPE). The
benign control body has no DOCTYPE, so the control-differential passes and the
worker (wrongly) raised a medium xxe:entity_processing finding. The server
never parsed XML, never resolved an entity, never read a file.

The fix: a bare echo of the payload we sent is reflection, not a parser error.
Only count an entity-error signal that appears OUTSIDE a verbatim echo of our
payload, and require genuine parser-error phrasing rather than the bare
DOCTYPE token that every XXE payload carries.
"""
from __future__ import annotations

import asyncio
import sys
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import core.swarm_workers  # noqa: F401,E402  (registers workers)
from core.swarm_engine import SwarmAgent  # noqa: E402
from core.swarm_workers import get_worker_runner  # noqa: E402
from core.swarm_workers.vuln._http import HttpResp  # noqa: E402


def _agent(target="http://t", timeout=5.0):
    return SwarmAgent(agent_id="t", objective="xxe", target=target,
                      technique="xxe", payload={}, timeout_s=timeout)


def _run(fake):
    async def go():
        with patch("core.swarm_workers.vuln.xxe.fetch", side_effect=fake):
            return await get_worker_runner("vuln", "xxe")(_agent())

    return asyncio.run(go())


def _body(kw):
    return (kw.get("body") or b"").decode("utf-8", errors="replace")


def test_reflected_payload_not_flagged():
    """NON-vulnerable: endpoint accepts XML and echoes the raw body in a 400
    validation error. The XXE payload it echoes contains the literal DOCTYPE/
    ENTITY tokens, but the server never parses XML. Must NOT be flagged."""
    async def fake(method, url, **kw):
        if url != "http://t":
            return HttpResp(404, {}, "", url)
        body = _body(kw)
        # Generic JSON validation error that REFLECTS the raw request body.
        # No XML parser ran; the only DOCTYPE/ENTITY text present is our echo.
        reflected = (
            '{"error":"invalid_request",'
            '"received":' + repr(body).replace("'", '"') + "}"
        )
        return HttpResp(400, {"content-type": "application/json"}, reflected, url)

    assert _run(fake) == [], "reflection of our own payload must not be a finding"


def test_true_positive_still_fires():
    """GENUINELY vulnerable: the parser emits a real external-entity error that
    is NOT just an echo of our payload (distinct lxml phrasing referencing a
    file the payload names but with parser-specific wording the control never
    produces). The worker MUST still raise a finding."""
    async def fake(method, url, **kw):
        if url != "http://t":
            return HttpResp(404, {}, "", url)
        body = _body(kw)
        if "file:///etc/passwd" in body:
            # Real lxml/expat parser error — phrasing the worker never sent and
            # the benign control never triggers. This is genuine entity leakage.
            return HttpResp(
                500, {"content-type": "application/xml"},
                "<error>lxml.etree.XMLSyntaxError: failed to load external "
                "entity \"file:///etc/passwd\", line 1, column 1</error>", url)
        # Benign control parses cleanly.
        return HttpResp(200, {"content-type": "application/xml"},
                        "<r>ok</r>", url)

    result = _run(fake)
    assert result, "a genuine external-entity parser error must still be flagged"
    f = result[0]
    assert "xxe" in f["vuln_type"]
    assert f["cwe"] == "CWE-611"


def test_true_positive_file_read_still_fires():
    """GENUINELY vulnerable: the response reflects actual /etc/passwd content
    introduced ONLY by the XXE payload (root:x:0:0:). Must still be flagged."""
    passwd = "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin/nologin\n"

    async def fake(method, url, **kw):
        if url != "http://t":
            return HttpResp(404, {}, "", url)
        body = _body(kw)
        if "file:///etc/passwd" in body:
            return HttpResp(200, {"content-type": "application/xml"},
                            f"<r>{passwd}</r>", url)
        return HttpResp(200, {"content-type": "application/xml"},
                        "<r>ok</r>", url)

    result = _run(fake)
    assert result, "a real /etc/passwd file read must still be flagged"
    assert result[0]["vuln_type"] == "xxe:file_read"
    assert result[0]["severity"] == "high"
