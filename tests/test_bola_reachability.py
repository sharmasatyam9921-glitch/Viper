"""find_bola's optional reachability optimizer: skips pointless probes, never FPs."""
from __future__ import annotations

import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.specialist.bola_engine import Session, find_bola  # noqa: E402
from core.swarm_workers.vuln._http import HttpResp  # noqa: E402

_A = "alice@victim.io"


def _leaky_fetch(counter):
    # Every URL leaks A's marker to everyone (a real BOLA on each).
    async def fetch(method, url, *, headers=None, timeout=10.0):
        counter["n"] += 1
        return HttpResp(200, {}, '{"owner":"%s"}' % _A, url)
    return fetch


def _run(reachability):
    counter = {"n": 0}
    owner = Session("A", {"Cookie": "s=alice"}, [_A])
    attacker = Session("B", {"Cookie": "s=bob"}, [])
    urls = ["http://t/api/orders/1", "http://t/api/orders/2"]
    findings = asyncio.run(find_bola(owner, attacker, urls,
                                     fetch=_leaky_fetch(counter),
                                     unauth_control=False,
                                     reachability=reachability))
    return findings, counter["n"]


def test_no_reachability_finds_all_leaks():
    findings, _ = _run(None)
    assert len(findings) == 2          # both URLs leak


def test_reachability_skips_attacker_denied_url():
    # B is known-403 on /orders/1 -> that URL is skipped entirely (no fetches),
    # but /orders/2 (unknown for B) is still tested and found.
    reach = {("B", "http://t/api/orders/1"): 403}
    findings, _ = _run(reach)
    urls = [f["url"] for f in findings]
    assert urls == ["http://t/api/orders/2"]


def test_reachability_skips_owner_unreachable_url():
    # Owner can't even reach /orders/1 -> nothing to leak -> skipped.
    reach = {("A", "http://t/api/orders/1"): 404}
    findings, _ = _run(reach)
    assert [f["url"] for f in findings] == ["http://t/api/orders/2"]


def test_reachability_skip_saves_requests():
    _, n_all = _run(None)
    _, n_skip = _run({("B", "http://t/api/orders/1"): 403})
    assert n_skip < n_all              # skipping a URL means fewer probes
