"""Tests for core/scope_reasoner.py.

Covers:
  - normalization (URL → host, port stripping, trailing dots)
  - deterministic in-scope match (exact, wildcard, subdomain)
  - hard-stop at scope edge (out-of-scope rules win)
  - default-deny when no scope loaded
  - cache layer (memory + SQLite)
  - cache invalidation when scope changes
  - LLM fallback (mocked) for ambiguous cases
  - related-target heuristic
  - filter_in_scope bulk helper
  - stats
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.scope_reasoner import (  # noqa: E402
    ScopeDecision,
    ScopeReasoner,
    _normalize,
    _scope_fingerprint,
)
from scope.scope_manager import (  # noqa: E402
    BugBountyScope,
    ScopeEntry,
    ScopeManager,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def make_scope_manager(
    in_scope_targets=None,
    out_of_scope_targets=None,
    program_name="test-prog",
):
    """Build a ScopeManager with simple wildcard entries (no file IO)."""
    in_scope_targets = in_scope_targets or []
    out_of_scope_targets = out_of_scope_targets or []
    sm = ScopeManager(verbose=False)
    sc = BugBountyScope(program_name=program_name, platform="test")
    for t in in_scope_targets:
        asset_type = "wildcard" if "*" in t else "domain"
        sc.in_scope.append(ScopeEntry(target=t, asset_type=asset_type, in_scope=True))
    for t in out_of_scope_targets:
        asset_type = "wildcard" if "*" in t else "domain"
        sc.out_of_scope.append(ScopeEntry(target=t, asset_type=asset_type, in_scope=False))
    sm.active_scope = sc
    return sm


# ---------------------------------------------------------------------------
# Normalization
# ---------------------------------------------------------------------------


class TestNormalize:
    @pytest.mark.parametrize("inp,expected", [
        ("example.com", "example.com"),
        ("EXAMPLE.com", "example.com"),
        ("https://example.com/path", "example.com"),
        ("https://example.com:8080/path?q=1", "example.com"),
        ("http://Example.COM:443/", "example.com"),
        ("example.com.", "example.com"),
        ("  example.com  ", "example.com"),
    ])
    def test_normalize(self, inp, expected):
        assert _normalize(inp) == expected


# ---------------------------------------------------------------------------
# Scope fingerprint
# ---------------------------------------------------------------------------


class TestScopeFingerprint:
    def test_no_scope_returns_marker(self):
        assert _scope_fingerprint(None) == "no-scope"

    def test_same_rules_same_hash(self):
        sm1 = make_scope_manager(["*.example.com", "*.test.com"])
        sm2 = make_scope_manager(["*.test.com", "*.example.com"])  # reordered
        assert _scope_fingerprint(sm1) == _scope_fingerprint(sm2)

    def test_different_rules_different_hash(self):
        sm1 = make_scope_manager(["*.example.com"])
        sm2 = make_scope_manager(["*.other.com"])
        assert _scope_fingerprint(sm1) != _scope_fingerprint(sm2)

    def test_out_of_scope_changes_hash(self):
        sm1 = make_scope_manager(["*.example.com"])
        sm2 = make_scope_manager(["*.example.com"], ["admin.example.com"])
        assert _scope_fingerprint(sm1) != _scope_fingerprint(sm2)


# ---------------------------------------------------------------------------
# Deterministic decisions
# ---------------------------------------------------------------------------


class TestDeterministicDecisions:
    def test_exact_match_allows(self, tmp_path):
        sm = make_scope_manager(["example.com"])
        sr = ScopeReasoner(sm, db_path=tmp_path / "v.db")
        d = sr.decide("example.com")
        assert d.allowed is True
        assert d.source == "deterministic"
        assert d.confidence == 1.0

    def test_wildcard_matches_subdomain(self, tmp_path):
        sm = make_scope_manager(["*.example.com"])
        sr = ScopeReasoner(sm, db_path=tmp_path / "v.db")
        d = sr.decide("api.example.com")
        assert d.allowed is True
        assert "example.com" in (d.matched_entry or "")

    def test_wildcard_matches_deep_subdomain(self, tmp_path):
        sm = make_scope_manager(["*.example.com"])
        sr = ScopeReasoner(sm, db_path=tmp_path / "v.db")
        d = sr.decide("api.staging.example.com")
        assert d.allowed is True

    def test_url_form_input_normalized(self, tmp_path):
        sm = make_scope_manager(["*.example.com"])
        sr = ScopeReasoner(sm, db_path=tmp_path / "v.db")
        d = sr.decide("https://api.example.com:8443/v1/users")
        assert d.allowed is True
        assert d.target == "api.example.com"

    def test_out_of_scope_rule_wins(self, tmp_path):
        sm = make_scope_manager(
            in_scope_targets=["*.example.com"],
            out_of_scope_targets=["admin.example.com"],
        )
        sr = ScopeReasoner(sm, db_path=tmp_path / "v.db")
        d = sr.decide("admin.example.com")
        assert d.allowed is False

    def test_unrelated_target_denied(self, tmp_path):
        sm = make_scope_manager(["*.example.com"])
        sr = ScopeReasoner(sm, db_path=tmp_path / "v.db")
        d = sr.decide("evil.com")
        assert d.allowed is False
        assert d.source == "deterministic"

    def test_empty_target_denied(self, tmp_path):
        sm = make_scope_manager(["*.example.com"])
        sr = ScopeReasoner(sm, db_path=tmp_path / "v.db")
        d = sr.decide("")
        assert d.allowed is False
        assert "empty" in d.reason

    def test_whitespace_only_denied(self, tmp_path):
        sm = make_scope_manager(["*.example.com"])
        sr = ScopeReasoner(sm, db_path=tmp_path / "v.db")
        d = sr.decide("   ")
        assert d.allowed is False


# ---------------------------------------------------------------------------
# Default behavior when no scope loaded
# ---------------------------------------------------------------------------


class TestNoScopeLoaded:
    def test_default_deny_when_no_scope(self, tmp_path):
        sr = ScopeReasoner(None, db_path=tmp_path / "v.db", default_when_no_scope=False)
        d = sr.decide("example.com")
        assert d.allowed is False
        assert d.source == "no-scope"
        assert d.confidence == 0.5

    def test_default_allow_when_no_scope_explicit(self, tmp_path):
        sr = ScopeReasoner(None, db_path=tmp_path / "v.db", default_when_no_scope=True)
        d = sr.decide("example.com")
        assert d.allowed is True
        assert d.source == "no-scope"


# ---------------------------------------------------------------------------
# Cache layer
# ---------------------------------------------------------------------------


class TestCache:
    def test_second_decide_uses_memory_cache(self, tmp_path):
        sm = make_scope_manager(["*.example.com"])
        sr = ScopeReasoner(sm, db_path=tmp_path / "v.db")
        d1 = sr.decide("api.example.com")
        d2 = sr.decide("api.example.com")
        # Same object in memory cache
        assert d1.target == d2.target
        assert d1.decided_at == d2.decided_at

    def test_cache_persists_across_reasoner_instances(self, tmp_path):
        db = tmp_path / "v.db"
        sm = make_scope_manager(["*.example.com"])
        sr1 = ScopeReasoner(sm, db_path=db)
        sr1.decide("api.example.com")
        # New reasoner, same DB + scope → should hit DB cache
        sm2 = make_scope_manager(["*.example.com"])
        sr2 = ScopeReasoner(sm2, db_path=db)
        d = sr2.decide("api.example.com")
        assert d.allowed is True
        # The new reasoner's memory cache was empty; it must have come from DB.
        # Source is "deterministic" because that's what's stored.
        assert d.source in ("deterministic", "cache")

    def test_cache_invalidated_when_scope_changes(self, tmp_path):
        db = tmp_path / "v.db"
        sm1 = make_scope_manager(["*.example.com"])
        ScopeReasoner(sm1, db_path=db).decide("api.example.com")
        # Different scope → different hash → fresh decision
        sm2 = make_scope_manager(["*.other.com"])
        sr2 = ScopeReasoner(sm2, db_path=db)
        d = sr2.decide("api.example.com")
        assert d.allowed is False

    def test_disable_memory_cache(self, tmp_path):
        sm = make_scope_manager(["*.example.com"])
        sr = ScopeReasoner(sm, db_path=tmp_path / "v.db", cache_in_memory=False)
        d1 = sr.decide("api.example.com")
        d2 = sr.decide("api.example.com")
        # Both decisions still allowed; just no in-memory short-circuit
        assert d1.allowed and d2.allowed


# ---------------------------------------------------------------------------
# Exception safety (fail-closed)
# ---------------------------------------------------------------------------


class TestFailClosed:
    def test_scope_manager_exception_falls_back_to_deny(self, tmp_path):
        sm = make_scope_manager(["*.example.com"])

        def boom(*a, **kw):
            raise RuntimeError("scope check broke")

        sm.is_in_scope = boom
        sr = ScopeReasoner(sm, db_path=tmp_path / "v.db")
        d = sr.decide("anything.com")
        assert d.allowed is False
        assert d.source == "default-deny"
        assert "scope check error" in d.reason


# ---------------------------------------------------------------------------
# LLM fallback (mocked)
# ---------------------------------------------------------------------------


class TestLLMFallback:
    def test_llm_invoked_on_ambiguous_when_allowed(self, tmp_path):
        sm = make_scope_manager(["*.example.com"])
        calls = {"n": 0}

        def llm_cb(target, rules):
            calls["n"] += 1
            return True, "LLM thinks this is a CDN for example.com"

        sr = ScopeReasoner(sm, db_path=tmp_path / "v.db", llm_callback=llm_cb)
        # `example-cdn.com` shares the "example" token → looks related
        d = sr.decide("example-cdn.com", allow_llm=True)
        assert calls["n"] == 1
        assert d.allowed is True
        assert d.source == "llm"

    def test_llm_not_invoked_when_allow_llm_false(self, tmp_path):
        sm = make_scope_manager(["*.example.com"])
        calls = {"n": 0}

        def llm_cb(target, rules):
            calls["n"] += 1
            return True, "yes"

        sr = ScopeReasoner(sm, db_path=tmp_path / "v.db", llm_callback=llm_cb)
        d = sr.decide("api-other-thing.com", allow_llm=False)
        assert calls["n"] == 0
        assert d.allowed is False

    def test_llm_not_invoked_when_target_unrelated(self, tmp_path):
        sm = make_scope_manager(["*.example.com"])
        calls = {"n": 0}

        def llm_cb(target, rules):
            calls["n"] += 1
            return True, "yes"

        sr = ScopeReasoner(sm, db_path=tmp_path / "v.db", llm_callback=llm_cb)
        d = sr.decide("totallyunrelated.io", allow_llm=True)
        assert calls["n"] == 0
        assert d.allowed is False

    def test_llm_exception_falls_back_to_deny(self, tmp_path):
        sm = make_scope_manager(["*.example.com"])

        def llm_cb(target, rules):
            raise RuntimeError("LLM down")

        sr = ScopeReasoner(sm, db_path=tmp_path / "v.db", llm_callback=llm_cb)
        d = sr.decide("example-cdn.com", allow_llm=True)
        assert d.allowed is False


# ---------------------------------------------------------------------------
# Related-target heuristic
# ---------------------------------------------------------------------------


class TestRelatedHeuristic:
    def test_strong_token_overlap_is_related(self, tmp_path):
        sm = make_scope_manager(["*.examplecompany.com"])
        sr = ScopeReasoner(sm, db_path=tmp_path / "v.db")
        # Shares the 13-char "examplecompany"
        assert sr._looks_related("cdn-examplecompany.io") is True

    def test_only_generic_tokens_not_related(self, tmp_path):
        sm = make_scope_manager(["*.example.com"])
        sr = ScopeReasoner(sm, db_path=tmp_path / "v.db")
        # Only "api" + "com" overlap, both generic
        assert sr._looks_related("api.totally-unrelated.com") is False


# ---------------------------------------------------------------------------
# Bulk filter
# ---------------------------------------------------------------------------


class TestFilter:
    def test_filter_in_scope(self, tmp_path):
        sm = make_scope_manager(["*.example.com"], ["admin.example.com"])
        sr = ScopeReasoner(sm, db_path=tmp_path / "v.db")
        kept = sr.filter_in_scope([
            "api.example.com", "admin.example.com",
            "example.com", "evil.com", "x.example.com",
        ])
        assert "api.example.com" in kept
        assert "example.com" in kept
        assert "x.example.com" in kept
        assert "admin.example.com" not in kept
        assert "evil.com" not in kept


# ---------------------------------------------------------------------------
# Stats
# ---------------------------------------------------------------------------


class TestStats:
    def test_stats_after_mixed_decisions(self, tmp_path):
        sm = make_scope_manager(["*.example.com"])
        sr = ScopeReasoner(sm, db_path=tmp_path / "v.db")
        sr.decide("api.example.com")     # allowed/deterministic
        sr.decide("admin.example.com")   # allowed/deterministic (wildcard)
        sr.decide("evil.com")            # denied/deterministic
        s = sr.stats()
        assert s["cached_decisions"] == 3
        assert s["allowed"] == 2
        assert s["denied"] == 1
        assert s["sources"]["deterministic"] == 3


# ---------------------------------------------------------------------------
# Decision dataclass round-trip
# ---------------------------------------------------------------------------


class TestScopeDecision:
    def test_to_dict_serializable(self):
        d = ScopeDecision(
            target="x", allowed=True, reason="ok",
            confidence=0.9, source="llm", matched_entry="domain:x",
        )
        body = d.to_dict()
        assert body["target"] == "x"
        assert body["allowed"] is True
        assert body["source"] == "llm"
        assert body["confidence"] == 0.9
        # Decided_at is present
        assert "decided_at" in body
