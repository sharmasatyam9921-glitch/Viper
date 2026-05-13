"""Tests for the 5 post-exploit workers."""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import core.swarm_workers  # noqa: F401,E402
from core.swarm_engine import SwarmAgent  # noqa: E402
from core.swarm_workers import get_worker_runner, list_workers  # noqa: E402
from core.swarm_workers.vuln._http import HttpResp  # noqa: E402


def _agent(target: str, *, technique: str, findings: list[dict] | None = None,
           timeout: float = 5.0) -> SwarmAgent:
    return SwarmAgent(
        agent_id="test_post",
        objective=f"{technique} on {target}",
        target=target,
        technique=technique,
        payload={"findings": findings or []},
        timeout_s=timeout,
    )


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------


class TestPostRegistry:
    def test_all_five_post_workers_registered(self):
        techs = set(list_workers("post"))
        expected = {"flag_hunter", "linpeas", "windows_privesc",
                    "ad_enum", "gtfobins"}
        assert expected.issubset(techs)


# ---------------------------------------------------------------------------
# flag_hunter — covers most CTF flag formats
# ---------------------------------------------------------------------------


class TestFlagHunter:
    @pytest.mark.parametrize("body,expected_kind", [
        ("hello flag{viper_pwned_42} bye", "generic"),
        ("dump: FLAG{xyz-abc-99}", "generic"),
        ("you found HTB{hacking_is_fun}", "hackthebox"),
        ("picoCTF{nice_one_2024}", "picoctf"),
        ("THM{good_job}", "tryhackme"),
        ("CTF{flag_value_here}", "ctf_generic"),
    ])
    def test_pattern_detection(self, body, expected_kind):
        resp = HttpResp(200, {}, body, "http://t/")

        async def go():
            with patch("core.swarm_workers.post.flag_hunter.fetch",
                       return_value=resp):
                runner = get_worker_runner("post", "flag_hunter")
                return await runner(_agent("http://t/", technique="flag_hunter"))

        results = asyncio.run(go())
        assert results, f"flag pattern {expected_kind!r} not detected"
        f = results[0]
        assert f["type"] == "flag_captured"
        assert f["severity"] == "critical"
        assert f["flag_format"] == expected_kind
        assert f["confidence"] == 1.0

    def test_no_flag_returns_empty(self):
        resp = HttpResp(200, {}, "harmless welcome page", "http://t/")

        async def go():
            with patch("core.swarm_workers.post.flag_hunter.fetch",
                       return_value=resp):
                runner = get_worker_runner("post", "flag_hunter")
                return await runner(_agent("http://t/", technique="flag_hunter"))

        assert asyncio.run(go()) == []

    def test_dedupe_across_paths(self):
        # Same flag appears at root + /flag — should be reported once
        resp = HttpResp(200, {}, "Found flag{dup_test_42} here.", "http://t/")

        async def go():
            with patch("core.swarm_workers.post.flag_hunter.fetch",
                       return_value=resp):
                runner = get_worker_runner("post", "flag_hunter")
                return await runner(_agent("http://t/", technique="flag_hunter"))

        results = asyncio.run(go())
        # Multiple paths probed, but the same flag is deduped to one finding
        flags = {f["flag_value"] for f in results}
        assert len(flags) == 1
        assert "flag{dup_test_42}" in flags

    def test_finds_flag_in_prior_finding_evidence(self):
        async def fake(method, url, **kw):
            return HttpResp(200, {}, "no flag here", url)

        prior_findings = [
            {"type": "sqli_exploited",
             "evidence": "leaked: HTB{nested_flag_in_evidence}"},
        ]

        async def go():
            with patch("core.swarm_workers.post.flag_hunter.fetch",
                       side_effect=fake):
                runner = get_worker_runner("post", "flag_hunter")
                return await runner(_agent(
                    "http://t/", technique="flag_hunter",
                    findings=prior_findings,
                ))

        results = asyncio.run(go())
        assert results
        assert "HTB{nested_flag_in_evidence}" in {f["flag_value"] for f in results}


# ---------------------------------------------------------------------------
# linpeas / windows_privesc — recommendation workers (no real ssh)
# ---------------------------------------------------------------------------


class TestLinpeasRecommend:
    def test_no_foothold_returns_empty(self):
        async def go():
            runner = get_worker_runner("post", "linpeas")
            return await runner(_agent("http://t/", technique="linpeas"))

        assert asyncio.run(go()) == []

    def test_foothold_yields_recommendation(self):
        findings = [{"type": "cmdi_exploited", "foothold": True,
                      "url": "http://t/cmd"}]

        async def go():
            runner = get_worker_runner("post", "linpeas")
            return await runner(_agent("http://t/", technique="linpeas",
                                         findings=findings))

        result = asyncio.run(go())
        assert result
        assert result[0]["type"] == "post_recommend"
        assert "linpeas_runner" in result[0]["next_action"]


class TestWindowsPrivescRecommend:
    def test_no_windows_foothold_empty(self):
        findings = [{"type": "cmdi_exploited", "foothold": True,
                      "evidence": "uid=0(root)"}]

        async def go():
            runner = get_worker_runner("post", "windows_privesc")
            return await runner(_agent("http://t/", technique="windows_privesc",
                                         findings=findings))

        # Linux uid output → no Windows recommendation
        assert asyncio.run(go()) == []

    def test_windows_marker_triggers_recommend(self):
        findings = [{
            "type": "cmdi_exploited", "foothold": True,
            "evidence": "Microsoft Windows [Version 10.0]",
            "title": "cmd injection on Windows server",
            "url": "http://t/cmd",
        }]

        async def go():
            runner = get_worker_runner("post", "windows_privesc")
            return await runner(_agent("http://t/", technique="windows_privesc",
                                         findings=findings))

        result = asyncio.run(go())
        assert result
        assert "winpeas" in result[0]["next_action"].lower()


# ---------------------------------------------------------------------------
# ad_enum recommendation
# ---------------------------------------------------------------------------


class TestAdEnumRecommend:
    def test_kerberos_port_triggers_recommend(self):
        findings = [
            {"type": "open_port", "port": 88, "asset": "dc.corp.local"},
            {"type": "open_port", "port": 445, "asset": "dc.corp.local"},
            {"type": "open_port", "port": 80, "asset": "web.corp.local"},  # not AD
        ]

        async def go():
            runner = get_worker_runner("post", "ad_enum")
            return await runner(_agent("corp.local", technique="ad_enum",
                                         findings=findings))

        result = asyncio.run(go())
        assert result
        assert any("dc.corp.local" in r["title"] for r in result)
        # Web-only host should NOT trigger AD recommendation
        assert not any("web.corp.local" in r["title"] for r in result)

    def test_no_ad_ports_no_finding(self):
        findings = [{"type": "open_port", "port": 80, "asset": "x"}]

        async def go():
            runner = get_worker_runner("post", "ad_enum")
            return await runner(_agent("x", technique="ad_enum",
                                         findings=findings))

        assert asyncio.run(go()) == []


# ---------------------------------------------------------------------------
# gtfobins recommendation
# ---------------------------------------------------------------------------


class TestGtfobinsRecommend:
    def test_sudo_find_yields_recommendation(self):
        findings = [{"type": "sudo_binary", "binary": "find"}]

        async def go():
            runner = get_worker_runner("post", "gtfobins")
            return await runner(_agent("host", technique="gtfobins",
                                         findings=findings))

        result = asyncio.run(go())
        assert result
        assert any("find" in r["title"].lower() for r in result)

    def test_known_safe_suid_skipped(self):
        findings = [{"type": "suid_binary", "binary": "passwd"}]  # safe

        async def go():
            runner = get_worker_runner("post", "gtfobins")
            return await runner(_agent("host", technique="gtfobins",
                                         findings=findings))

        assert asyncio.run(go()) == []

    def test_no_binary_findings_empty(self):
        async def go():
            runner = get_worker_runner("post", "gtfobins")
            return await runner(_agent("host", technique="gtfobins"))

        assert asyncio.run(go()) == []


# ---------------------------------------------------------------------------
# Contract
# ---------------------------------------------------------------------------


class TestPostContract:
    @pytest.mark.parametrize("technique", [
        "flag_hunter", "linpeas", "windows_privesc",
        "ad_enum", "gtfobins",
    ])
    def test_workers_never_raise_on_empty_input(self, technique):
        async def go():
            runner = get_worker_runner("post", technique)
            with patch("core.swarm_workers.vuln._http._fetch_sync",
                       return_value=None):
                return await runner(_agent("", technique=technique))

        result = asyncio.run(go())
        assert isinstance(result, list)
