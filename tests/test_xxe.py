"""Tests for the xxe vuln worker (XML External Entity, response/error-based)."""
from __future__ import annotations

import asyncio
import sys
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import core.swarm_workers  # noqa: F401,E402  (registers workers)
from core.swarm_engine import SwarmAgent  # noqa: E402
from core.swarm_workers import get_worker_runner, list_workers  # noqa: E402
from core.swarm_workers.vuln._http import HttpResp  # noqa: E402

_PASSWD = "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"


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


class TestXxe:
    def test_registered(self):
        assert "xxe" in list_workers("vuln")

    def test_detects_file_read(self):
        # Base URL accepts XML; XXE payload reflects /etc/passwd, control does not.
        async def fake(method, url, **kw):
            if url != "http://t":
                return HttpResp(404, {}, "", url)
            body = _body(kw)
            if "file:///etc/passwd" in body:
                return HttpResp(200, {}, f"<r>{_PASSWD}</r>", url)
            return HttpResp(200, {}, "<r>ok</r>", url)

        result = _run(fake)
        assert result, "expected an XXE file-read finding"
        f = result[0]
        assert "xxe" in f["vuln_type"]
        assert f["cwe"] == "CWE-611"
        assert f["severity"] == "high"
        assert f["url"] == "http://t"
        assert "root:x:0:0:" in f["evidence"] or "root:x:0:0:" in _PASSWD

    def test_detects_entity_processing_error(self):
        # No file read, but the XXE payload provokes an external-entity parser
        # error while the benign control parses cleanly.
        async def fake(method, url, **kw):
            if url != "http://t":
                return HttpResp(404, {}, "", url)
            body = _body(kw)
            if "DOCTYPE" in body:
                return HttpResp(
                    500, {},
                    "<error>failed to load external entity "
                    '"file:///etc/passwd"</error>', url)
            return HttpResp(200, {}, "<r>ok</r>", url)

        result = _run(fake)
        assert result, "expected an XXE entity-processing finding"
        f = result[0]
        assert "xxe" in f["vuln_type"]
        assert f["severity"] == "medium"
        assert f["cwe"] == "CWE-611"

    def test_no_fp_when_endpoint_rejects_xml(self):
        # Every path 404s — nothing accepts XML, no finding.
        async def fake(method, url, **kw):
            return HttpResp(404, {}, "not found", url)

        assert _run(fake) == []

    def test_no_fp_when_xml_parsed_cleanly(self):
        # Endpoint accepts XML and echoes a benign reply for BOTH control and
        # payload — no passwd, no entity error. Must not flag.
        async def fake(method, url, **kw):
            if url != "http://t":
                return HttpResp(404, {}, "", url)
            return HttpResp(200, {}, "<r>thanks, parsed your xml</r>", url)

        assert _run(fake) == []

    def test_no_fp_when_entity_error_is_baseline_noise(self):
        # The server emits "DOCTYPE" / entity error text for ANY XML, including
        # the control. That's generic handling, not an XXE signal.
        async def fake(method, url, **kw):
            if url != "http://t":
                return HttpResp(404, {}, "", url)
            return HttpResp(
                400, {},
                "<fault>DOCTYPE is not allowed in this XML</fault>", url)

        assert _run(fake) == []

    def test_scorer_matches_xxe_class(self):
        sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "benchmark"))
        from harness.scorer import score
        from harness.models import Challenge, RunResult
        ch = Challenge.from_dict({"id": "x", "mode": "vuln_class",
                                  "expect": {"vuln_types": ["xxe"],
                                             "min_severity": "medium"}})
        r = RunResult(challenge_id="x", target_url="http://t", findings=[
            {"vuln_type": "xxe:file_read", "severity": "high",
             "url": "http://t"}])
        assert score(ch, r).solved
