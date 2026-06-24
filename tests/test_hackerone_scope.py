"""HackerOne scope auto-pull: API/CSV/Burp parsing + scope conversion (offline)."""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scope.hackerone_scope import (  # noqa: E402
    parse_api_payload,
    parse_burp_excludes,
    parse_csv_scopes,
    save_current_scope,
    to_scope,
)
from scope.scope_manager import BugBountyScope  # noqa: E402

# synthetic fixtures only (no real program data)
_CSV = (
    "identifier,asset_type,instruction,eligible_for_bounty,eligible_for_submission,max_severity\n"
    "*.example.com,WILDCARD,,true,true,critical\n"
    "api.example.com,URL,,true,true,critical\n"
    "staging.example.com,URL,please don't test,false,false,critical\n"
    "com.example.app,GOOGLE_PLAY_APP_ID,android app,true,true,critical\n"
)
_BURP = {"target": {"scope": {"exclude": [
    {"host": r"^staging\.example\.com$"}, {"host": r"^.*\.internal\.example\.com$"}]}}}
_API = {"data": [
    {"type": "structured-scope", "attributes": {
        "asset_identifier": "*.example.com", "asset_type": "WILDCARD",
        "eligible_for_bounty": True, "eligible_for_submission": True,
        "max_severity": "critical", "instruction": ""}},
    {"type": "structured-scope", "attributes": {
        "asset_identifier": "434613896", "asset_type": "APPLE_STORE_APP_ID",
        "eligible_for_submission": True}},
], "links": {}}


def test_parse_csv_and_convert(tmp_path):
    p = tmp_path / "scope.csv"
    p.write_text(_CSV, encoding="utf-8")
    raw = parse_csv_scopes(str(p))
    scope = to_scope(raw, program_name="example", handle="example")
    in_targets = {e.target for e in scope.in_scope}
    out_targets = {e.target for e in scope.out_of_scope}
    assert in_targets == {"*.example.com", "api.example.com"}      # submittable web assets
    assert "staging.example.com" in out_targets                    # ineligible -> out
    assert "com.example.app" not in in_targets | out_targets       # mobile app skipped
    assert scope.program_url == "https://hackerone.com/example"


def test_parse_burp_excludes(tmp_path):
    p = tmp_path / "burp.json"
    p.write_text(json.dumps(_BURP), encoding="utf-8")
    excl = parse_burp_excludes(str(p))
    assert "staging.example.com" in excl and "*.internal.example.com" in excl


def test_api_payload_skips_mobile_and_maps_wildcard():
    raw = parse_api_payload(_API)
    scope = to_scope(raw, program_name="example", handle="example")
    assert [e.target for e in scope.in_scope] == ["*.example.com"]  # app id dropped
    assert scope.in_scope[0].asset_type == "wildcard"


def test_extra_excludes_merge_and_dedup(tmp_path):
    raw = parse_csv_scopes_str(_CSV, tmp_path)
    scope = to_scope(raw, program_name="example",
                     extra_excludes=["*.internal.example.com", "*.example.com"])
    out = {e.target for e in scope.out_of_scope}
    assert "*.internal.example.com" in out                         # new exclude added
    # *.example.com already in-scope -> not duplicated into out-of-scope
    assert [e.target for e in scope.in_scope].count("*.example.com") == 1


def test_saved_scope_roundtrips_through_scope_manager(tmp_path):
    raw = parse_csv_scopes_str(_CSV, tmp_path)
    scope = to_scope(raw, program_name="example", handle="example")
    path = save_current_scope(scope, str(tmp_path / "current_scope.json"))
    loaded = BugBountyScope.from_dict(json.loads(Path(path).read_text(encoding="utf-8")))
    assert {e.target for e in loaded.in_scope} == {"*.example.com", "api.example.com"}
    # and the loaded scope correctly matches an in-scope host
    assert any(e.matches("admin.example.com") for e in loaded.in_scope)


def parse_csv_scopes_str(text, tmp_path):
    p = tmp_path / "s.csv"
    p.write_text(text, encoding="utf-8")
    return parse_csv_scopes(str(p))
