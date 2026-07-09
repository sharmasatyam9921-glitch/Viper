"""HAR / Postman import: recover endpoints + param NAMES (read-only), never persist auth
header/cookie VALUES, and scope to the in-scope host before a hunt consumes it."""
from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import pytest  # noqa: E402

from core.har_import import (  # noqa: E402
    ImportedSurface, load_surface, parse_har, parse_postman,
)

_HAR = {
    "log": {"entries": [
        {"request": {
            "method": "GET",
            "url": "https://api.example.com/v2/orders?status=open&page=2",
            "queryString": [{"name": "status", "value": "open"},
                            {"name": "page", "value": "2"}],
            "headers": [{"name": "Authorization", "value": "Bearer SECRET-TOKEN-xyz"},
                        {"name": "X-Api-Key", "value": "live_key_9999"},
                        {"name": "Accept", "value": "application/json"}],
        }},
        {"request": {
            "method": "POST",
            "url": "https://api.example.com/v2/login",
            "headers": [{"name": "Cookie", "value": "session=abc123"}],
            "postData": {"mimeType": "application/x-www-form-urlencoded",
                         "params": [{"name": "email"}, {"name": "password"}]},
        }},
        {"request": {"method": "GET", "url": "https://cdn.other-host.net/asset.js"}},
    ]},
}

_POSTMAN = {
    "info": {"schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json"},
    "item": [
        {"name": "orders", "request": {
            "method": "GET",
            "url": {"raw": "https://api.example.com/v2/orders?status=open",
                    "host": ["api", "example", "com"], "path": ["v2", "orders"],
                    "query": [{"key": "status", "value": "open"}]},
            "header": [{"key": "Authorization", "value": "Bearer NOPE"}],
        }},
        {"name": "folder", "item": [
            {"name": "profile", "request": {
                "method": "PATCH",
                "url": {"raw": "https://api.example.com/v2/profile"},
                "body": {"mode": "urlencoded", "urlencoded": [{"key": "displayName"}]},
            }},
        ]},
    ],
}


def test_har_extracts_endpoints_and_param_names():
    surf = parse_har(_HAR)
    assert "https://api.example.com/v2/orders?status=open&page=2" in surf.endpoints
    assert {"status", "page", "email", "password"} <= surf.params


def test_har_never_persists_auth_values_only_header_names():
    surf = parse_har(_HAR)
    blob = json.dumps({"endpoints": surf.endpoints, "params": sorted(surf.params),
                       "headers": sorted(surf.header_names)})
    # Header NAMES are recorded (useful surface)...
    assert "Authorization" in surf.header_names and "X-Api-Key" in surf.header_names
    # ...but no auth/cookie VALUE ever enters the surface.
    for secret in ("SECRET-TOKEN-xyz", "Bearer", "live_key_9999", "session=abc123", "abc123"):
        assert secret not in blob


def test_postman_walks_folders_and_reads_url_object():
    surf = parse_postman(_POSTMAN)
    assert "https://api.example.com/v2/orders?status=open" in surf.endpoints
    assert any(u.endswith("/v2/profile") for u in surf.endpoints)   # nested folder item
    assert {"status", "displayName"} <= surf.params
    assert "NOPE" not in json.dumps(surf.endpoints + sorted(surf.params))


def test_scoped_drops_out_of_scope_hosts():
    surf = parse_har(_HAR)
    scoped = surf.scoped("api.example.com")
    assert scoped.endpoints and all("api.example.com" in u for u in scoped.endpoints)
    assert not any("other-host" in u for u in scoped.endpoints)
    # Params are host-agnostic surface -> carried over unchanged.
    assert scoped.params == surf.params


def test_scoped_accepts_full_url_and_normalizes_default_port():
    surf = ImportedSurface()
    surf.add_endpoint("https://api.example.com:443/a?x=1")
    surf.add_endpoint("https://api.example.com/b")
    assert len(surf.scoped("https://api.example.com/").endpoints) == 2


def test_load_surface_autodetects_kind():
    assert load_surface(_HAR)[0] == "har"
    assert load_surface(json.dumps(_POSTMAN))[0] == "postman"


def test_load_surface_rejects_unknown_and_bad_json():
    with pytest.raises(ValueError):
        load_surface('{"random": "object"}')
    with pytest.raises(ValueError):
        load_surface("not json at all {")


def test_parsers_failclosed_on_garbage():
    assert parse_har({"log": {"entries": "nope"}}).endpoints == []
    assert parse_har({}).endpoints == []
    assert parse_postman({"item": "nope"}).endpoints == []


def _hackmode(tmp_path, **kw):
    from core.audit_logger import AuditLogger
    from core.hack_mode import HackMode
    from core.hack_profile import LabProfile
    from core.narrator import Narrator
    audit = AuditLogger.for_hunt("t", hunts_dir=tmp_path / "h", db_path=tmp_path / "v.db")
    prof = LabProfile()
    for k, v in kw.items():
        setattr(prof, k, v)
    return HackMode(target="http://t/", profile=prof, narrator=Narrator(quiet=True),
                    audit=audit)


def test_hackmode_folds_scoped_import_into_surface(tmp_path):
    from core.payload_library import clear_discovered_params, get_discovered_params
    har = {"log": {"entries": [
        {"request": {"url": "http://t/api/orders?status=open",
                     "headers": [{"name": "Authorization", "value": "Bearer XYZ"}]}},
        {"request": {"url": "http://evil.example/x?a=1"}},   # out of scope -> dropped
    ]}}
    f = tmp_path / "session.har"
    f.write_text(json.dumps(har), encoding="utf-8")
    hm = _hackmode(tmp_path, import_file=str(f))
    clear_discovered_params()
    try:
        asyncio.run(hm._run_import_surface())
        urls = [x["url"] for x in hm._state.get("findings", []) if x.get("type") == "endpoint"]
        assert any("/api/orders" in u for u in urls)
        assert not any("evil.example" in u for u in urls)     # scoped to target host
        assert "status" in set(get_discovered_params())
    finally:
        clear_discovered_params()


def test_hackmode_import_is_noop_without_file(tmp_path):
    hm = _hackmode(tmp_path)               # LabProfile has no import_file
    asyncio.run(hm._run_import_surface())  # must not raise
    assert not [x for x in hm._state.get("findings", []) if x.get("type") == "endpoint"]
