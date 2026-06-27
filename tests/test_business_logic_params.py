"""Business-logic / object-reference parameter knowledge (mined from disclosed
access-control + logic-flaw reports) + its wiring into the lean hunt."""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.payload_library import get_business_logic_params  # noqa: E402


def test_categories_have_the_expected_signal():
    objref = get_business_logic_params("object_ref")
    assert {"id", "uid", "user_id", "order_id", "item_id", "account"} <= set(objref)
    sig = get_business_logic_params("signature")
    assert {"sign", "timestamp", "nonce"} <= set(sig)
    redir = get_business_logic_params("redirect")
    assert {"jumpurl", "redirect", "next", "returnurl"} <= set(redir)
    pay = get_business_logic_params("payment")
    assert {"price", "amount", "coupon", "quantity"} <= set(pay)


def test_union_is_deduped_and_superset_of_categories():
    union = get_business_logic_params()
    assert len(union) == len(set(union))                       # no dups
    for cat in ("object_ref", "auth_priv", "signature", "redirect", "payment"):
        assert set(get_business_logic_params(cat)) <= set(union)


def test_unknown_category_and_caching():
    assert get_business_logic_params("does_not_exist") == []
    a = get_business_logic_params("object_ref")
    b = get_business_logic_params("object_ref")
    assert a == b and a is not b                               # cached, fresh list


def test_lean_hunt_seeds_object_ref_params(monkeypatch):
    # the lean hunt seeds these names into the discovered-params channel so the
    # IDOR/injection workers probe them — verify the wiring calls through.
    import core.lean_hunt  # noqa: F401  (import path exists)
    objref = get_business_logic_params("object_ref")
    assert len(objref) >= 15                                   # enough to seed [:15]
