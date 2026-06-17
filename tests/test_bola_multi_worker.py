"""Tests for the bola_multi swarm worker (self-gated two-account BOLA)."""
import asyncio, sys
from dataclasses import dataclass
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import core.swarm_workers  # noqa: F401
from core.swarm_engine import SwarmAgent
from core.swarm_workers import get_worker_runner, list_workers

@dataclass
class _R:
    status: int
    body: str

def _agent(payload):
    return SwarmAgent(agent_id="t", objective="x", target="https://t/api/orders/1001",
                      technique="bola_multi", payload=payload, timeout_s=5.0)

def test_registered():
    assert "bola_multi" in list_workers("vuln")

def test_self_gated_no_config_returns_empty():
    # The critical safety/UX test: with no two-session config, do nothing.
    r = asyncio.run(get_worker_runner("vuln", "bola_multi")(_agent({})))
    assert r == []

def test_detects_cross_user_with_config():
    cfg = {"bola": {"owner_headers": {"Cookie": "s=a"}, "owner_markers": ["alice@victim.io"],
                    "attacker_headers": {"Cookie": "s=b"}}}
    async def fake(method, url, *, headers=None, timeout=10.0, **kw):
        if headers in ({"Cookie": "s=a"}, {"Cookie": "s=b"}):
            return _R(200, '{"email":"alice@victim.io"}')
        return _R(401, "")
    with patch("core.swarm_workers.vuln.bola_multi.fetch", side_effect=fake):
        r = asyncio.run(get_worker_runner("vuln", "bola_multi")(_agent(cfg)))
    assert len(r) == 1 and "idor" in r[0]["vuln_type"]
