"""Distributed relay: PSK pairing, dispatch, server-side scope re-check."""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.relay import RelayControl, RelayNode, sign, verify  # noqa: E402
from core.relay.control import RelayError  # noqa: E402

_SECRET = "pairing-secret-abc123"


def test_sign_verify_roundtrip_and_tamper():
    line = sign({"type": "ping", "id": 1}, _SECRET)
    assert verify(line, _SECRET) == {"type": "ping", "id": 1}
    assert verify(line, "wrong-secret") is None          # bad key -> rejected
    tampered = line.replace(b"ping", b"pong")
    assert verify(tampered, _SECRET) is None              # tampered -> rejected


def test_handle_payload_unit():
    n = RelayNode(_SECRET, scope_allows=lambda u: "in-scope" in u,
                  fetch=lambda u, timeout=10.0: {"status": 200, "len": 5})
    assert n.handle_payload({"type": "ping", "id": 1})["type"] == "pong"
    assert n.handle_payload(None)["error"] == "unauthorized"
    ok = n.handle_payload({"type": "task", "action": "fetch",
                           "url": "http://in-scope/x", "id": 2})
    assert ok["status"] == 200
    # server-side scope re-check refuses an out-of-scope URL the controller asked for
    refused = n.handle_payload({"type": "task", "action": "fetch",
                                "url": "http://evil/x", "id": 3})
    assert refused["error"] == "out of scope"


def _node(**kw):
    return RelayNode(_SECRET, host="127.0.0.1", port=0, **kw).start()


def test_controller_pairs_and_dispatches_over_socket():
    node = _node(scope_allows=lambda u: "in-scope" in u,
                 fetch=lambda u, timeout=10.0: {"status": 204, "len": 0})
    try:
        ctl = RelayControl("127.0.0.1", node.port, _SECRET)
        assert ctl.paired() is True                       # PSK handshake works
        res = ctl.dispatch("fetch", url="http://in-scope/api")
        assert res["status"] == 204
    finally:
        node.stop()


def test_node_refuses_out_of_scope_over_socket():
    node = _node(scope_allows=lambda u: "in-scope" in u,
                 fetch=lambda u, timeout=10.0: {"status": 200, "len": 1})
    try:
        ctl = RelayControl("127.0.0.1", node.port, _SECRET)
        res = ctl.dispatch("fetch", url="http://out-of-scope/secret")
        assert res["error"] == "out of scope"             # node re-checked, refused
    finally:
        node.stop()


def test_wrong_key_controller_is_rejected():
    node = _node()
    try:
        bad = RelayControl("127.0.0.1", node.port, "WRONG-SECRET")
        assert bad.paired() is False                      # node response fails auth
        import pytest
        with pytest.raises(RelayError):
            bad.dispatch("fetch", url="http://x/")
    finally:
        node.stop()
