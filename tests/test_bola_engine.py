"""Tests for the two-account BOLA/IDOR engine."""
from __future__ import annotations

import asyncio
import sys
from dataclasses import dataclass
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.specialist.bola_engine import Session, find_bola, id_bearing_urls  # noqa: E402


@dataclass
class _Resp:
    status: int
    body: str


ALICE = Session("alice", {"Cookie": "s=alice"}, ["alice@victim.io", "user-1001"])
BOB = Session("bob", {"Cookie": "s=bob"}, ["bob@x.io", "user-2002"])
A_OBJ = "https://t/api/orders/1001"


def _run(fetch):
    return asyncio.run(find_bola(ALICE, BOB, [A_OBJ], fetch=fetch))


def test_id_bearing_urls_filters():
    urls = [
        "https://t/api/orders",                 # collection — drop
        "https://t/api/orders/55",              # numeric id — keep
        "https://t/u/3f2504e0-4f89-41d3-9a0c-0305e82c3301/x",  # uuid — keep
        "https://t/profile?account=778",        # id query — keep
        "https://t/about",                      # static — drop
    ]
    out = id_bearing_urls(urls)
    assert "https://t/api/orders/55" in out
    assert any("3f2504e0" in u for u in out)
    assert "https://t/profile?account=778" in out
    assert "https://t/api/orders" not in out
    assert "https://t/about" not in out


def test_true_bola_detected():
    # Alice's order leaks her email to BOTH sessions (broken authz).
    async def fetch(method, url, *, headers=None, timeout=10.0):
        if headers == ALICE.headers or headers == BOB.headers:
            return _Resp(200, '{"order":1001,"email":"alice@victim.io"}')
        return _Resp(401, "")  # unauth control: not public
    findings = _run(fetch)
    assert len(findings) == 1
    f = findings[0]
    assert "idor" in f["vuln_type"]
    assert f["cwe"] == "CWE-639"
    assert f["owner"] == "alice" and f["attacker"] == "bob"
    assert "alice@victim.io" in f["evidence"]


def test_proper_authz_not_flagged():
    # Bob gets 403 on Alice's object — access control works.
    async def fetch(method, url, *, headers=None, timeout=10.0):
        if headers == ALICE.headers:
            return _Resp(200, '{"email":"alice@victim.io"}')
        return _Resp(403, "Forbidden")
    assert _run(fetch) == []


def test_public_object_not_flagged():
    # The marker is present for everyone INCLUDING unauthenticated → public data.
    async def fetch(method, url, *, headers=None, timeout=10.0):
        return _Resp(200, '{"email":"alice@victim.io"}')  # same for all incl anon
    assert _run(fetch) == []


def test_bob_sees_only_his_own_data_not_flagged():
    # Bob gets 200 but the body is HIS data, not Alice's marker.
    async def fetch(method, url, *, headers=None, timeout=10.0):
        if headers == ALICE.headers:
            return _Resp(200, '{"email":"alice@victim.io"}')
        if headers == BOB.headers:
            return _Resp(200, '{"email":"bob@x.io"}')  # bob's own — no leak
        return _Resp(401, "")
    assert _run(fetch) == []


def test_owner_object_without_marker_skipped():
    # Alice's response doesn't contain her marker → not provably her private obj.
    async def fetch(method, url, *, headers=None, timeout=10.0):
        return _Resp(200, '{"status":"ok"}')
    assert _run(fetch) == []


def test_no_owner_markers_returns_empty():
    nomark = Session("alice", {"Cookie": "s=alice"}, [])

    async def fetch(method, url, *, headers=None, timeout=10.0):
        return _Resp(200, "alice@victim.io")
    assert asyncio.run(find_bola(nomark, BOB, [A_OBJ], fetch=fetch)) == []
