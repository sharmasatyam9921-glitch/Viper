"""Scope-precision fix (found dogfooding a real Flipkart hunt): a URL/API scope asset means
the EXACT host, not a subdomain wildcard. VIPER had probed 1.www.flipkart.com for an exact
`https://www.flipkart.com` H1 entry (scope creep -> risk of an out-of-scope submission).
Also: load_scope must accept a path as-given (it prepended SCOPE_DIR and mangled a relative
path, so --scope scopes/current_scope.json silently failed to load)."""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scope.scope_manager import ScopeEntry, ScopeManager  # noqa: E402


def test_url_asset_matches_exact_host_only():
    e = ScopeEntry(target="www.flipkart.com", asset_type="url")
    assert e.matches("https://www.flipkart.com/") is True
    assert e.matches("https://www.flipkart.com/path?q=1") is True
    assert e.matches("www.flipkart.com") is True
    # subdomains of the exact host are OUT of scope (the bug)
    assert e.matches("https://1.www.flipkart.com/") is False
    assert e.matches("https://x.www.flipkart.com/") is False
    # a look-alike suffix must not match either
    assert e.matches("https://www.flipkart.com.evil.com/") is False
    assert e.matches("https://notwww.flipkart.com/") is False


def test_api_asset_matches_exact_host_only():
    e = ScopeEntry(target="api.myntra.com", asset_type="api")
    assert e.matches("https://api.myntra.com/v1/x") is True
    assert e.matches("https://x.api.myntra.com/") is False


def test_domain_asset_still_covers_subdomains():
    # Regression guard: the fix must NOT break deliberate subdomain coverage.
    e = ScopeEntry(target="example.com", asset_type="domain")
    assert e.matches("https://example.com/") is True
    assert e.matches("https://sub.example.com/") is True
    assert e.matches("https://deep.sub.example.com/") is True


def test_wildcard_asset_still_covers_subdomains():
    e = ScopeEntry(target="*.example.com", asset_type="wildcard")
    assert e.matches("https://a.example.com/") is True
    assert e.matches("https://example.com/") is True
    assert e.matches("https://evil.com/") is False


def test_url_with_scheme_and_path_prefix():
    e = ScopeEntry(target="https://host.com/app/", asset_type="url")
    assert e.matches("https://host.com/app/x") is True
    assert e.matches("https://host.com/other") is False


def test_manager_is_in_scope_exact_host(tmp_path):
    scope = {
        "program_name": "t", "platform": "hackerone",
        "in_scope": [{"target": "www.flipkart.com", "asset_type": "url"},
                     {"target": "payments.myntra.com", "asset_type": "url"}],
        "out_of_scope": [],
    }
    f = tmp_path / "scope.json"
    f.write_text(json.dumps(scope), encoding="utf-8")
    sm = ScopeManager(verbose=False)
    # load_scope must accept a full/relative path AS GIVEN (was forced under SCOPE_DIR)
    assert sm.load_scope(str(f)) is True
    assert sm.is_in_scope("https://www.flipkart.com/")[0] is True
    assert sm.is_in_scope("https://payments.myntra.com/x")[0] is True
    assert sm.is_in_scope("https://1.www.flipkart.com/")[0] is False
    assert sm.is_in_scope("https://x.payments.myntra.com/")[0] is False
