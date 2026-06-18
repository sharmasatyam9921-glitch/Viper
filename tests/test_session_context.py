"""Per-hunt SessionContext: roles, reachability matrix, BOLA bridge, serialization."""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.session_context import Role, SessionContext  # noqa: E402


def _two_role_ctx():
    ctx = SessionContext(hunt_id="h1")
    ctx.add_role("A", {"Cookie": "s=alice"}, ["alice@victim.io", "1001"])
    ctx.add_role("B", {"Cookie": "s=bob"}, ["bob@victim.io"])
    ctx.record("A", "GET", "http://t/api/orders/1", 200)
    ctx.record("B", "GET", "http://t/api/orders/1", 403)
    ctx.record("A", "GET", "http://t/api/orders/2", 200)
    return ctx


def test_records_build_reachability_matrix():
    ctx = _two_role_ctx()
    assert ctx.status("A", "http://t/api/orders/1") == 200
    assert ctx.status("B", "http://t/api/orders/1") == 403
    assert set(ctx.reachable_urls("A")) == {
        "http://t/api/orders/1", "http://t/api/orders/2"}
    assert ctx.reachable_urls("B") == []        # B only ever got 403


def test_role_diff_reports_per_role_status():
    diff = _two_role_ctx().role_diff("http://t/api/orders/1")
    assert diff == {"A": 200, "B": 403}


def test_bola_config_for_has_gate_shape():
    cfg = _two_role_ctx().bola_config_for("A", "B")
    assert cfg["owner_headers"] == {"Cookie": "s=alice"}
    assert cfg["attacker_headers"] == {"Cookie": "s=bob"}
    assert "alice@victim.io" in cfg["owner_markers"]
    assert cfg["owner_name"] == "A" and cfg["attacker_name"] == "B"


def test_candidate_urls_for_bola_is_owner_reachable():
    cands = _two_role_ctx().candidate_urls_for_bola("A")
    assert set(cands) == {"http://t/api/orders/1", "http://t/api/orders/2"}


def test_markers_below_three_chars_dropped():
    r = Role("A", {}, ["ok@x.io", "x", "  ", "abc"])
    assert sorted(r.clean_markers()) == ["abc", "ok@x.io"]


def test_corpus_is_bounded():
    ctx = SessionContext(corpus_limit=3)
    ctx.add_role("A")
    for i in range(10):
        ctx.record("A", "GET", f"http://t/{i}", 200)
    assert len(ctx.corpus) == 3
    assert ctx.corpus[-1].url == "http://t/9"     # keeps most recent


def test_serialization_round_trips():
    ctx = _two_role_ctx()
    back = SessionContext.from_dict(ctx.to_dict())
    assert set(back.roles) == {"A", "B"}
    assert back.status("A", "http://t/api/orders/1") == 200
    assert back.status("B", "http://t/api/orders/1") == 403
    assert back.bola_config_for("A", "B")["owner_markers"] == \
        ctx.bola_config_for("A", "B")["owner_markers"]


def test_summary_is_secret_free():
    s = _two_role_ctx().summary()
    assert s["roles"] == ["A", "B"]
    assert s["endpoints_observed"] == 2
    assert s["reachability_entries"] == 3
    # no header/cookie values leak into the compact summary
    assert "alice" not in str(s)


def test_repr_is_secret_free():
    # If anything ever str()s the live object (e.g. an audit fallback), it must
    # not leak cookies/tokens/markers.
    r = repr(_two_role_ctx())
    assert "SessionContext" in r
    assert "alice" not in r and "s=alice" not in r and "bob" not in r


def test_from_dict_tolerates_malformed_state():
    # A corrupt persisted row must not crash a resume — bad entries are skipped.
    d = {
        "hunt_id": "h",
        "roles": [{"name": "A", "headers": {}, "markers": ["m"]},
                  {"no_name": 1}],                       # malformed role -> skipped
        "reachability": [["A", "http://t/ok", 200],
                         ["A", "http://t/bad"],          # missing status -> skipped
                         ["A", "http://t/x", "NaN"]],    # bad status -> skipped
        "corpus": [["A", "GET", "http://t/ok", 200],
                   ["A", "GET"]],                        # short tuple -> skipped
    }
    ctx = SessionContext.from_dict(d)
    assert ctx.roles == ["A"]
    assert ctx.status("A", "http://t/ok") == 200
    assert ctx.status("A", "http://t/bad") is None
    assert len(ctx.corpus) == 1
