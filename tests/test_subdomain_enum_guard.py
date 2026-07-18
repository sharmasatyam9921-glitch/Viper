"""Dogfood fix: the subdomain worker must NOT enumerate a non-FQDN / loopback / lab target.
On most OSes *.localhost resolves to loopback (RFC 6761), so a wordlist brute-force against
`localhost` 'finds' every word and wastes the whole vuln phase on phantom hosts."""
from __future__ import annotations

import asyncio
import sys
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.swarm_engine import SwarmAgent  # noqa: E402
from core.swarm_workers.recon import subdomain as sub  # noqa: E402


def _agent(t):
    return SwarmAgent(agent_id="t", objective="x", target=t, technique="subdomain",
                      payload={}, timeout_s=6.0)


def test_is_enumerable_domain():
    for bad in ("localhost", "127.0.0.1", "192.168.1.10", "10.0.0.5", "::1",
                "app.localhost", "dev.internal", "box.local", "x.test"):
        assert sub._is_enumerable_domain(bad) is False, bad
    for good in ("example.com", "api.example.com", "target.co.uk"):
        assert sub._is_enumerable_domain(good) is True, good


def test_non_fqdn_targets_skip_enumeration_entirely():
    # Must return [] WITHOUT ever invoking the (network) ReconEngine.
    def _boom(*a, **k):
        raise AssertionError("subdomain enum must not run for a non-FQDN/loopback target")
    for t in ("http://localhost:8080", "http://127.0.0.1:3000", "http://app.localhost/"):
        with patch("recon.recon_engine.ReconEngine", _boom):
            assert asyncio.run(sub.run(_agent(t))) == []


def test_real_fqdn_filters_out_reserved_suffix_phantoms():
    class _Eng:
        def __init__(self, *a, **k):
            pass

        async def enumerate_subdomains(self, domain, parallel=True):
            # a source returns a real sub + a *.localhost phantom -> phantom dropped
            return {"api.example.com", "mail.example.com.localhost"}

    with patch("recon.recon_engine.ReconEngine", _Eng):
        out = asyncio.run(sub.run(_agent("http://example.com/")))
    hosts = {f["title"] for f in out}
    assert "api.example.com" in hosts
    assert not any(".localhost" in h for h in hosts)
