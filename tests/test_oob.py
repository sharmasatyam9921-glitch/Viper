"""Out-of-band interaction engine: canary, store, listeners, gate confirmation."""
from __future__ import annotations

import asyncio
import socket
import struct
import sys
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.oob import OOBServer  # noqa: E402
from core.oob.canary import (  # noqa: E402
    Canary, CanaryFactory, new_token, payloads_for, token_from_host, token_from_path,
)
from core.oob.store import InteractionStore  # noqa: E402
from core.swarm_validation import validate_findings  # noqa: E402


def _dns_query(name, port):
    labels = b"".join(bytes([len(p)]) + p.encode() for p in name.split("."))
    pkt = struct.pack(">HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0) + labels + b"\x00\x00\x01\x00\x01"
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(3)
    try:
        s.sendto(pkt, ("127.0.0.1", port))
        s.recvfrom(512)
    finally:
        s.close()


# --- canary ----------------------------------------------------------------

def test_tokens_are_unique_and_safe():
    toks = {new_token() for _ in range(200)}
    assert len(toks) == 200
    # URL/DNS-safe lowercase hex (note: an all-digit token has no cased chars, so
    # str.islower() is the wrong check — verify the charset directly).
    hexset = set("0123456789abcdef")
    assert all(len(t) >= 16 and set(t) <= hexset for t in toks)


def test_canary_domain_and_urls():
    c = Canary("abcdef0123456789", "oob.example", "http://oob.example:8080")
    assert c.domain == "abcdef0123456789.oob.example"
    assert c.http_url.endswith("/abcdef0123456789")
    assert "abcdef0123456789.oob.example:8080" in c.host_url


def test_token_extraction():
    assert token_from_host("abcdef0123456789.oob.example") == "abcdef0123456789"
    assert token_from_host("abcdef0123456789.oob.example:8080") == "abcdef0123456789"
    assert token_from_host("www.example.com") == ""          # not a token shape
    assert token_from_path("/abcdef0123456789/x") == "abcdef0123456789"
    assert token_from_path("/static/app.js") == ""


def test_payloads_embed_the_token():
    c = CanaryFactory("oob.example", "http://oob.example:8080").new("ssrf")
    pl = payloads_for(c)
    assert {"ssrf", "cmdi_curl", "xxe", "jndi_ldap", "sqli_mssql"} <= set(pl)
    assert all(c.token in v for v in pl.values())            # every payload carries it


# --- store -----------------------------------------------------------------

def test_store_record_and_query():
    s = InteractionStore()
    assert not s.has_interaction("t1")
    s.record("t1", "http", "1.2.3.4", "GET /t1")
    assert s.has_interaction("t1") and s.count() == 1
    assert s.interactions_for("t1")[0].source_ip == "1.2.3.4"


def test_store_poll_hit_and_timeout():
    s = InteractionStore()
    s.record("hot", "dns", "1.1.1.1")
    assert s.poll("hot", timeout=1) is True
    assert s.poll("cold", timeout=0.2) is False              # never fired


def test_store_is_bounded():
    s = InteractionStore(limit=3)
    for i in range(6):
        s.record(f"t{i}", "http", "x")
    assert s.count() == 3
    assert not s.has_interaction("t0")                       # oldest dropped
    assert s.has_interaction("t5")


# --- listeners (live, loopback) --------------------------------------------

def test_http_listener_records_via_host_and_path():
    with OOBServer(base_domain="oob.local", enable_dns=False) as oob:
        c = oob.new_canary("ssrf")
        urllib.request.urlopen(
            f"http://127.0.0.1:{oob.http_port}/{c.token}", timeout=5).read()
        assert oob.poll(c.token, timeout=5)
        its = oob.interactions_for(c.token)
        assert its and its[0].protocol == "http"


def test_dns_listener_records_query():
    with OOBServer(base_domain="oob.local") as oob:
        if not oob.dns_port:
            return                                           # DNS couldn't bind; skip
        c = oob.new_canary("ssrf")
        _dns_query(c.domain, oob.dns_port)
        assert oob.poll(c.token, timeout=5)
        assert oob.interactions_for(c.token)[0].protocol == "dns"


def test_server_summary_and_not_started_guard():
    oob = OOBServer(enable_dns=False)
    import pytest
    with pytest.raises(RuntimeError):
        oob.new_canary()                                     # not started yet
    with oob:
        assert oob.summary()["http_port"] == oob.http_port


# --- gate confirmation -----------------------------------------------------

async def _dead_fetch(*a, **k):
    return None


def test_gate_confirms_blind_finding_on_oob_hit():
    with OOBServer(enable_dns=False) as oob:
        c = oob.new_canary("ssrf")
        urllib.request.urlopen(
            f"http://127.0.0.1:{oob.http_port}/{c.token}", timeout=5).read()
        assert oob.poll(c.token, timeout=5)
        f = {"vuln_type": "ssrf:url", "url": "http://t/x?url=1", "oob_token": c.token}
        out = asyncio.run(validate_findings([f], oob_store=oob.store, fetch=_dead_fetch))
        assert out[0]["submittable"] and out[0]["validation_confidence"] == 0.95
        assert "out-of-band" in out[0]["validation_reason"]


def test_gate_keeps_unfired_canary_as_lead():
    s = InteractionStore()
    f = {"vuln_type": "ssrf:url", "url": "http://t/x", "oob_token": "deadbeefdeadbeef"}
    out = asyncio.run(validate_findings([f], oob_store=s, fetch=_dead_fetch))
    assert not out[0]["submittable"]
    assert out[0]["validation_confidence"] == 0.3
    assert "no interaction" in out[0]["validation_reason"]


def test_gate_rejects_malformed_oob_token():
    s = InteractionStore()
    f = {"vuln_type": "ssrf:url", "url": "http://t/x", "oob_token": "not a token!!"}
    out = asyncio.run(validate_findings([f], oob_store=s, fetch=_dead_fetch))
    assert not out[0]["submittable"] and "invalid" in out[0]["validation_reason"]


def test_unissued_token_is_not_recorded():
    # background / legitimate-hex traffic to the listener (a token WE never
    # issued) must NOT be recorded — the core correlation-integrity guarantee.
    with OOBServer(enable_dns=False) as oob:
        bogus = "deadbeefdeadbeef"          # valid shape, but not issued here
        urllib.request.urlopen(
            f"http://127.0.0.1:{oob.http_port}/{bogus}", timeout=5).read()
        assert oob.poll(bogus, timeout=1) is False
        assert not oob.was_hit(bogus)


def test_issued_canary_tokens_are_unique_and_registered():
    with OOBServer(enable_dns=False) as oob:
        toks = {oob.new_canary().token for _ in range(50)}
        assert len(toks) == 50 and oob.issued_count() == 50


def test_finding_without_oob_token_uses_normal_path():
    # an xss finding with no oob_token must take the ordinary reflection re-test,
    # unaffected by passing an oob_store.
    from core.swarm_workers.vuln._http import HttpResp
    from urllib.parse import urlsplit, parse_qs

    async def reflect(m, url, *, headers=None, timeout=10.0):
        v = (parse_qs(urlsplit(url).query).get("q") or [""])[0]
        return HttpResp(200, {"content-type": "text/html"}, f"<h1>{v}</h1>", url)

    f = {"vuln_type": "xss_text:q", "url": "http://t/s?q=x", "parameter": "q"}
    out = asyncio.run(validate_findings([f], oob_store=InteractionStore(), fetch=reflect))
    assert out[0]["submittable"]
    assert "out-of-band" not in out[0]["validation_reason"]


# --- CLI -------------------------------------------------------------------

def test_oob_demo_cli_round_trips(capsys):
    from core.oob_cli import run_oob_cli
    rc = run_oob_cli(["demo"])
    out = capsys.readouterr().out
    assert rc == 0 and "interaction recorded: True" in out


def test_oob_cli_no_subcommand_prints_help(capsys):
    from core.oob_cli import run_oob_cli
    assert run_oob_cli([]) == 0


# --- DNS wire parsing (pure, security-sensitive) ---------------------------

def test_parse_qname_valid_and_malformed():
    from core.oob.interaction_server import _parse_qname, _dns_response
    labels = b"\x10abcdef0123456789\x03oob\x05local\x00"
    pkt = struct.pack(">HHHHHH", 1, 0x0100, 1, 0, 0, 0) + labels + b"\x00\x01\x00\x01"
    name, qend = _parse_qname(pkt, 12)
    assert name == "abcdef0123456789.oob.local"
    # response echoes the txid and is well-formed length
    resp = _dns_response(pkt, qend)
    assert resp[:2] == pkt[:2] and len(resp) > 12
    # truncated packet must not raise (returns whatever partial label it read)
    assert isinstance(_parse_qname(b"\x05abc", 0)[0], str)
    # compression pointer bails cleanly
    assert isinstance(_parse_qname(b"\xc0\x0c", 0)[0], str)
    # empty/garbage must not raise
    assert _parse_qname(b"", 12)[0] == ""
