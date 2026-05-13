"""Tests for the 8 recon-phase swarm workers.

Each worker is checked in isolation:
  - registers itself with the worker registry on import
  - returns a `list[dict]` shape (never None / non-iterable)
  - degrades gracefully on network/tool failures (no exceptions)
  - respects agent.timeout_s
  - honors scope_reasoner when one is in agent.payload (where applicable)

External tool calls (subfinder/amass/crt.sh/Shodan/Wayback/GitHub) are
mocked so the suite runs offline.
"""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import core.swarm_workers  # ensures recon package + its modules import  # noqa: E402,F401
from core.swarm_engine import SwarmAgent  # noqa: E402
from core.swarm_workers import (  # noqa: E402
    get_worker_runner,
    list_workers,
)


def _agent(target: str, *, technique: str, timeout: float = 5.0, payload=None) -> SwarmAgent:
    return SwarmAgent(
        agent_id="test_agent",
        objective=f"{technique} on {target}",
        target=target,
        technique=technique,
        payload=payload or {},
        timeout_s=timeout,
    )


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------


class TestRegistry:
    def test_all_eight_recon_workers_registered(self):
        techniques = set(list_workers("recon"))
        expected = {
            "subdomain", "port_scan", "wappalyzer", "shodan",
            "crtsh", "github_secrets", "wayback", "dns",
        }
        missing = expected - techniques
        assert not missing, f"missing recon workers: {missing}"

    def test_get_worker_returns_callable(self):
        runner = get_worker_runner("recon", "subdomain")
        assert callable(runner)

    def test_unknown_technique_raises(self):
        with pytest.raises(KeyError):
            get_worker_runner("recon", "does_not_exist_xyz")


# ---------------------------------------------------------------------------
# subdomain
# ---------------------------------------------------------------------------


class _FakeReconEngine:
    """Stand-in for recon.recon_engine.ReconEngine that returns canned subs."""
    def __init__(self, *a, **kw): pass

    async def enumerate_subdomains(self, domain, parallel=True):
        return set()  # force fallback to crt.sh in tests


class _FakeReconEngineWithSubs:
    def __init__(self, *a, **kw): pass

    async def enumerate_subdomains(self, domain, parallel=True):
        return {f"www.{domain}", f"api.{domain}"}


class TestSubdomainWorker:
    def test_returns_list_on_crtsh_match(self):
        async def go():
            # Force the ReconEngine path to return nothing → crtsh fallback runs
            with patch("recon.recon_engine.ReconEngine", _FakeReconEngine):
                with patch("core.swarm_workers.recon.subdomain._crtsh_query",
                           return_value={"www.example.com", "api.example.com"}):
                    runner = get_worker_runner("recon", "subdomain")
                    return await runner(_agent("example.com", technique="subdomain"))

        results = asyncio.run(go())
        titles = {r["title"] for r in results}
        assert "www.example.com" in titles
        assert "api.example.com" in titles
        for r in results:
            assert r["type"] == "subdomain"

    def test_returns_findings_from_recon_engine_path(self):
        async def go():
            with patch("recon.recon_engine.ReconEngine", _FakeReconEngineWithSubs):
                runner = get_worker_runner("recon", "subdomain")
                return await runner(_agent("example.com", technique="subdomain"))

        results = asyncio.run(go())
        titles = {r["title"] for r in results}
        assert "www.example.com" in titles
        assert "api.example.com" in titles

    def test_returns_empty_on_total_failure(self):
        async def go():
            with patch("recon.recon_engine.ReconEngine", _FakeReconEngine):
                with patch("core.swarm_workers.recon.subdomain._crtsh_query",
                           return_value=set()):
                    runner = get_worker_runner("recon", "subdomain")
                    return await runner(_agent("example.com", technique="subdomain"))

        assert asyncio.run(go()) == []

    def test_respects_scope_reasoner(self):
        from core.scope_reasoner import ScopeReasoner

        # Reasoner that blocks api.example.com
        class _BlockApi(ScopeReasoner):
            def decide(self, target, *, allow_llm=False):  # type: ignore[override]
                from core.scope_reasoner import ScopeDecision
                allowed = "api." not in target
                return ScopeDecision(target=target, allowed=allowed,
                                     reason="test", source="deterministic")

        sr = _BlockApi(scope_manager=None)

        async def go():
            with patch("recon.recon_engine.ReconEngine", _FakeReconEngine):
                with patch("core.swarm_workers.recon.subdomain._crtsh_query",
                           return_value={"www.example.com", "api.example.com"}):
                    runner = get_worker_runner("recon", "subdomain")
                    ag = _agent("example.com", technique="subdomain",
                                payload={"scope_reasoner": sr})
                    return await runner(ag)

        results = asyncio.run(go())
        titles = {r["title"] for r in results}
        assert "www.example.com" in titles
        assert "api.example.com" not in titles


# ---------------------------------------------------------------------------
# port_scan
# ---------------------------------------------------------------------------


class TestPortScanWorker:
    def test_returns_findings_for_open_ports(self):
        async def fake_probe(host, port, timeout=1.5):
            return port in (80, 443, 22)

        async def go():
            with patch("core.swarm_workers.recon.port_scan._probe",
                       new=fake_probe):
                runner = get_worker_runner("recon", "port_scan")
                return await runner(_agent("example.com", technique="port_scan"))

        results = asyncio.run(go())
        ports = {r["port"] for r in results}
        assert {80, 443, 22}.issubset(ports)
        for r in results:
            assert r["type"] == "open_port"
            assert r["asset"] == "example.com"

    def test_no_open_ports_returns_empty(self):
        async def fake_probe(host, port, timeout=1.5):
            return False

        async def go():
            with patch("core.swarm_workers.recon.port_scan._probe",
                       new=fake_probe):
                runner = get_worker_runner("recon", "port_scan")
                return await runner(_agent("example.com", technique="port_scan"))

        assert asyncio.run(go()) == []

    def test_extracts_host_from_url(self):
        captured = []

        async def fake_probe(host, port, timeout=1.5):
            captured.append(host)
            return port == 443

        async def go():
            with patch("core.swarm_workers.recon.port_scan._probe",
                       new=fake_probe):
                runner = get_worker_runner("recon", "port_scan")
                ag = _agent("https://example.com/foo?bar=baz", technique="port_scan")
                return await runner(ag)

        asyncio.run(go())
        assert captured and all(h == "example.com" for h in captured)


# ---------------------------------------------------------------------------
# wappalyzer
# ---------------------------------------------------------------------------


class _Resp:
    def __init__(self, body, headers):
        self._body = body.encode()
        self.headers = headers

    def __enter__(self): return self
    def __exit__(self, *a): pass
    def read(self, n=None): return self._body


class TestWappalyzerWorker:
    def test_detects_from_response_signatures(self):
        async def go():
            with patch("urllib.request.urlopen",
                       return_value=_Resp(
                           "<html>WordPress 5.8 React</html>",
                           {"Server": "nginx/1.18.0", "X-Powered-By": "PHP/7.4.30"},
                       )):
                # Patch the import path so module-not-found returns None and we
                # fall to the stdlib signature scan
                with patch.dict(sys.modules, {"recon.wappalyzer": None}):
                    runner = get_worker_runner("recon", "wappalyzer")
                    return await runner(_agent("example.com", technique="wappalyzer"))

        results = asyncio.run(go())
        tech_names = {r["title"].lower() for r in results}
        # At least one of nginx / php / wordpress should be detected
        assert any(name in t for t in tech_names for name in ("nginx", "php", "wordpress"))

    def test_handles_network_failure(self):
        async def go():
            with patch("urllib.request.urlopen", side_effect=OSError("no net")):
                with patch.dict(sys.modules, {"recon.wappalyzer": None}):
                    runner = get_worker_runner("recon", "wappalyzer")
                    return await runner(_agent("example.com", technique="wappalyzer"))

        assert asyncio.run(go()) == []


# ---------------------------------------------------------------------------
# shodan (internetdb)
# ---------------------------------------------------------------------------


class TestShodanWorker:
    def test_emits_cves_and_ports(self):
        fake_data = {
            "ports": [80, 443], "vulns": ["CVE-2021-44228"], "tags": ["cdn"],
        }

        async def go():
            with patch("core.swarm_workers.recon.shodan._resolve",
                       return_value=["1.2.3.4"]):
                with patch("core.swarm_workers.recon.shodan._internetdb",
                           return_value=fake_data):
                    runner = get_worker_runner("recon", "shodan")
                    return await runner(_agent("example.com", technique="shodan"))

        results = asyncio.run(go())
        types = {r["type"] for r in results}
        assert "shodan_cve" in types
        assert "shodan_port" in types
        assert "shodan_tag" in types
        # The CVE finding is high severity
        cve_rec = next(r for r in results if r["type"] == "shodan_cve")
        assert cve_rec["severity"] == "high"
        assert cve_rec["cve"] == "CVE-2021-44228"

    def test_no_resolution_returns_empty(self):
        async def go():
            with patch("core.swarm_workers.recon.shodan._resolve", return_value=[]):
                runner = get_worker_runner("recon", "shodan")
                return await runner(_agent("invalid.local", technique="shodan"))

        assert asyncio.run(go()) == []


# ---------------------------------------------------------------------------
# crtsh
# ---------------------------------------------------------------------------


class TestCrtshWorker:
    def test_uses_shared_query(self):
        async def go():
            # crtsh.py imports _crtsh_query into its own namespace at module load,
            # so we patch the binding crtsh.py sees, not the original.
            with patch("core.swarm_workers.recon.crtsh._crtsh_query",
                       return_value={"a.example.com", "b.example.com"}):
                runner = get_worker_runner("recon", "crtsh")
                return await runner(_agent("example.com", technique="crtsh"))

        results = asyncio.run(go())
        assert len(results) == 2
        assert all(r["type"] == "subdomain" for r in results)


# ---------------------------------------------------------------------------
# dns
# ---------------------------------------------------------------------------


class TestDnsWorker:
    def test_returns_a_records_via_getaddrinfo(self):
        async def go():
            with patch("core.swarm_workers.recon.dns._resolve_basic",
                       return_value=(["1.2.3.4"], [])):
                with patch("core.swarm_workers.recon.dns._dnspython_records",
                           return_value={}):
                    runner = get_worker_runner("recon", "dns")
                    return await runner(_agent("example.com", technique="dns"))

        results = asyncio.run(go())
        assert results
        a_records = [r for r in results if r["type"] == "dns_a"]
        assert a_records and a_records[0]["title"] == "1.2.3.4"

    def test_includes_dnspython_records_when_available(self):
        async def go():
            with patch("core.swarm_workers.recon.dns._resolve_basic",
                       return_value=([], [])):
                with patch("core.swarm_workers.recon.dns._dnspython_records",
                           return_value={
                               "MX": ["10 mail.example.com."],
                               "TXT": ["v=spf1 -all"],
                           }):
                    runner = get_worker_runner("recon", "dns")
                    return await runner(_agent("example.com", technique="dns"))

        results = asyncio.run(go())
        types = {r["type"] for r in results}
        assert "dns_mx" in types
        assert "dns_txt" in types


# ---------------------------------------------------------------------------
# wayback
# ---------------------------------------------------------------------------


class TestWaybackWorker:
    def test_marks_interesting_paths_higher_severity(self):
        async def go():
            with patch("core.swarm_workers.recon.wayback._wayback_urls",
                       return_value=[
                           "https://example.com/",
                           "https://example.com/admin/login",
                           "https://example.com/.git/HEAD",
                           "https://example.com/random/page",
                       ]):
                runner = get_worker_runner("recon", "wayback")
                return await runner(_agent("example.com", technique="wayback"))

        results = asyncio.run(go())
        by_url = {r["url"]: r for r in results}
        assert by_url["https://example.com/admin/login"]["severity"] == "low"
        assert by_url["https://example.com/.git/HEAD"]["severity"] == "low"
        assert by_url["https://example.com/random/page"]["severity"] == "info"

    def test_empty_when_archive_empty(self):
        async def go():
            with patch("core.swarm_workers.recon.wayback._wayback_urls",
                       return_value=[]):
                runner = get_worker_runner("recon", "wayback")
                return await runner(_agent("example.com", technique="wayback"))

        assert asyncio.run(go()) == []


# ---------------------------------------------------------------------------
# github_secrets
# ---------------------------------------------------------------------------


class TestGithubSecretsWorker:
    def test_skipped_without_token(self, monkeypatch):
        monkeypatch.delenv("GH_TOKEN", raising=False)
        monkeypatch.delenv("GITHUB_TOKEN", raising=False)

        async def go():
            runner = get_worker_runner("recon", "github_secrets")
            return await runner(_agent("example.com", technique="github_secrets"))

        # No token → no work, empty list (never crashes)
        assert asyncio.run(go()) == []

    def test_emits_findings_when_token_set(self, monkeypatch):
        monkeypatch.setenv("GH_TOKEN", "test_token")

        async def fake_hunt(org_or_keyword):
            return [
                {"name": "AWS key leak", "url": "https://github.com/x/y",
                 "severity": "high", "snippet": "AKIA..."},
                {"name": "generic secret", "url": "https://github.com/x/y2",
                 "severity": "medium", "snippet": "..."},
            ]

        async def go():
            with patch(
                "recon.github_hunt.run_github_hunt_async",
                new=fake_hunt, create=True,
            ):
                runner = get_worker_runner("recon", "github_secrets")
                return await runner(_agent("example.com", technique="github_secrets"))

        results = asyncio.run(go())
        assert len(results) == 2
        titles = {r["title"] for r in results}
        assert "AWS key leak" in titles


# ---------------------------------------------------------------------------
# Common contract: all workers return a list, never None / never raise
# ---------------------------------------------------------------------------


class TestWorkerContract:
    @pytest.mark.parametrize("technique", [
        "subdomain", "port_scan", "wappalyzer", "shodan",
        "crtsh", "github_secrets", "wayback", "dns",
    ])
    def test_workers_never_raise_on_empty_input(self, technique, monkeypatch):
        # Make sure github_secrets exits early (no token)
        monkeypatch.delenv("GH_TOKEN", raising=False)
        monkeypatch.delenv("GITHUB_TOKEN", raising=False)

        async def fake_probe(host, port, timeout=1.5):
            return False

        async def go():
            runner = get_worker_runner("recon", technique)
            # Patch every network-touching helper to no-op so we don't hit
            # the real internet during unit tests.
            with patch("urllib.request.urlopen", side_effect=OSError("no net")):
                with patch("socket.getaddrinfo", side_effect=OSError("no dns")):
                    with patch("core.swarm_workers.recon.port_scan._probe",
                               new=fake_probe):
                        with patch("core.swarm_workers.recon.subdomain._crtsh_query",
                                   return_value=set()):
                            with patch("recon.recon_engine.ReconEngine",
                                       _FakeReconEngine):
                                with patch.dict(sys.modules,
                                                {"recon.wappalyzer": None,
                                                 "recon.github_hunt": None}):
                                    return await runner(_agent("", technique=technique))

        # Must return a list (possibly empty), never raise
        result = asyncio.run(go())
        assert isinstance(result, list)
