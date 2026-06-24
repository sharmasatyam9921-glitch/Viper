"""Bugcrowd / Intigriti scope normalizers + dispatcher (offline, fixture-based)."""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scope.hackerone_scope import to_scope  # noqa: E402
from scope.platform_scope import (  # noqa: E402
    fetch_scope,
    parse_bugcrowd,
    parse_intigriti,
    platform_creds,
)

_BUGCROWD = {"data": [
    {"type": "target", "attributes": {"name": "*.acme.com", "category": "website", "in_scope": True}},
    {"type": "target", "attributes": {"name": "api.acme.com", "category": "api", "in_scope": True}},
    {"type": "target", "attributes": {"name": "Acme Android", "category": "android", "in_scope": True}},
    {"type": "target", "attributes": {"name": "old.acme.com", "category": "website", "in_scope": False}},
]}
_INTIGRITI = {"domains": [
    {"endpoint": "*.acme.com", "type": 2, "tier": {"value": "Tier 1"}},
    {"endpoint": "api.acme.com", "type": 1, "tier": "Tier 2"},
    {"endpoint": "old.acme.com", "type": 1, "tier": {"value": "Out of scope"}},
    {"endpoint": "Acme iOS", "type": 3},
]}


def test_parse_bugcrowd_normalizes_and_skips_mobile():
    raw = parse_bugcrowd(_BUGCROWD)
    scope = to_scope(raw, program_name="acme", handle="acme")
    assert {e.target for e in scope.in_scope} == {"*.acme.com", "api.acme.com"}
    assert {e.target for e in scope.out_of_scope} == {"old.acme.com"}     # in_scope False
    assert not any("Android" in e.target for e in scope.in_scope + scope.out_of_scope)
    wc = [e for e in scope.in_scope if e.target == "*.acme.com"][0]
    assert wc.asset_type == "wildcard"


def test_parse_intigriti_types_and_out_of_scope_tier():
    raw = parse_intigriti(_INTIGRITI)
    scope = to_scope(raw, program_name="acme", handle="acme")
    assert {e.target for e in scope.in_scope} == {"*.acme.com", "api.acme.com"}
    assert {e.target for e in scope.out_of_scope} == {"old.acme.com"}     # Out-of-scope tier
    assert not any("iOS" in e.target for e in scope.in_scope)             # type 3 skipped


def test_parse_intigriti_content_wrapped():
    raw = parse_intigriti({"content": {"domains": [{"endpoint": "x.io", "type": 1}]}})
    assert raw and raw[0]["asset_identifier"] == "x.io"


def test_fetch_scope_unknown_platform_raises():
    with pytest.raises(ValueError):
        fetch_scope("synack", "prog", token="t")


def test_platform_creds_env(monkeypatch):
    monkeypatch.setenv("BUGCROWD_API_TOKEN", "bc-tok")
    monkeypatch.setenv("INTIGRITI_API_TOKEN", "in-tok")
    assert platform_creds("bugcrowd") == (None, "bc-tok")
    assert platform_creds("intigriti") == (None, "in-tok")
    assert platform_creds("synack") == (None, None)
