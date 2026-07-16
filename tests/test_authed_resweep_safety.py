"""#7(c) leaked-credential authenticated re-sweep — SAFETY properties.

The escalation is only safe because of two structural guarantees, tested here:
  1. the credential VALUE never enters a finding dict (isolated vault; finding carries a
     ref) — so it can't leak into a report / custody manifest / submission draft (rule #6);
  2. a host-bound credential is applied ONLY to that host — never another host, never a
     third-party/cloud API.
Plus: only a JWT (app-session) is stashed; cloud/provider keys are never replayable.
"""
from __future__ import annotations

import asyncio
import sys
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core import auth_material  # noqa: E402
from core.swarm_engine import SwarmAgent  # noqa: E402
from core.swarm_workers.vuln import _http  # noqa: E402
from core.swarm_workers.vuln import secrets as secrets_mod  # noqa: E402
from core.swarm_workers.vuln._http import HttpResp  # noqa: E402

_JWT = ("eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjoiYWRtaW4iLCJyb2xlIjoiYWRtaW4ifQ."
        + "s" * 32)


# ── vault: stash / resolve / clear, value isolated ───────────────────────────
def test_vault_roundtrip_and_clear():
    auth_material.clear()
    ref = auth_material.stash("a.example", "Authorization", "Bearer XYZ")
    assert ref and ref.startswith("authref_")
    host, headers = auth_material.resolve(ref)
    assert host == "a.example" and headers == {"Authorization": "Bearer XYZ"}
    auth_material.clear()
    assert auth_material.resolve(ref) is None


# ── host-scoped auth: bound host only, never leaks ───────────────────────────
def test_host_auth_applies_only_to_bound_host():
    _http.clear_host_auth()
    _http.add_host_auth("a.example", {"Authorization": "Bearer SECRET"})
    seen: dict[str, dict] = {}

    def fake_sync(method, url, headers=None, **kw):
        seen[url] = dict(headers or {})
        return HttpResp(200, {}, "ok", url)

    with patch.object(_http, "_fetch_sync", fake_sync), \
         patch.object(_http, "is_in_scope", lambda u: True):
        asyncio.run(_http.fetch("GET", "http://a.example/x", rate_limit=False))
        asyncio.run(_http.fetch("GET", "http://b.example/x", rate_limit=False))
        asyncio.run(_http.fetch("GET", "http://a.example:8443/y", rate_limit=False))

    assert seen["http://a.example/x"].get("Authorization") == "Bearer SECRET"
    # A DIFFERENT host never receives the credential — the core safety guarantee.
    assert "Authorization" not in seen["http://b.example/x"]
    # Same host, different port is still the same program host -> bound.
    assert seen["http://a.example:8443/y"].get("Authorization") == "Bearer SECRET"
    _http.clear_host_auth()


def test_per_call_headers_and_opt_out_win():
    _http.clear_host_auth()
    _http.add_host_auth("a.example", {"Authorization": "Bearer HOST"})
    seen: dict[str, dict] = {}

    def fake_sync(method, url, headers=None, **kw):
        seen[url] = dict(headers or {})
        return HttpResp(200, {}, "ok", url)

    with patch.object(_http, "_fetch_sync", fake_sync), \
         patch.object(_http, "is_in_scope", lambda u: True):
        # use_session_auth=False opts out entirely (identity-controlled probes).
        asyncio.run(_http.fetch("GET", "http://a.example/x", rate_limit=False,
                                use_session_auth=False))
    assert "Authorization" not in seen["http://a.example/x"]
    _http.clear_host_auth()


# ── secrets worker: JWT value goes to the vault, NOT the finding ─────────────
def _agent(t):
    return SwarmAgent(agent_id="t", objective="x", target=t, technique="secrets",
                      payload={}, timeout_s=6.0)


def test_jwt_value_never_in_finding_only_a_ref():
    auth_material.clear()
    # server-side JSON config surface (not a public JS bundle) so the JWT is a real leak
    body = '{"config":{"token":"' + _JWT + '"}}'
    findings = secrets_mod._scan_body(body, "http://app.example/config.json", is_html=False)
    jwt_finds = [f for f in findings if f.get("vuln_type") == "secret:jwt_token"]
    assert jwt_finds, "a JWT on a server-side surface must be flagged"
    f = jwt_finds[0]
    # The full value must appear NOWHERE in the serialized finding (rule #6 + isolation).
    blob = repr(f)
    assert _JWT not in blob and _JWT[10:40] not in blob
    # It carries an opaque host-bound ref instead, resolving to the real Bearer header.
    assert f.get("auth_host") == "app.example"
    host, headers = auth_material.resolve(f["auth_ref"])
    assert host == "app.example"
    assert headers == {"Authorization": f"Bearer {_JWT}"}
    auth_material.clear()


def test_cloud_and_thirdparty_keys_are_not_stashed():
    auth_material.clear()
    # An AWS key / Slack token must NEVER be made replayable (using it against the
    # provider is prohibited) — no auth_ref on those findings. The token literals are
    # assembled at runtime so no contiguous secret string sits in source (satisfies
    # secret-scanning push protection) while still matching the secrets worker regexes.
    slack = "xox" + "b-1234567890-abcdefghijklmnop"
    aws = "AKIA" + "IOSFODNN7EXAMPLE"
    body = f"{aws} and {slack}"
    findings = secrets_mod._scan_body(body, "http://app.example/.env", is_html=False)
    for f in findings:
        assert "auth_ref" not in f, f"{f.get('vuln_type')} must not be replayable"
    auth_material.clear()


# ── redirect handler: a credential NEVER follows a redirect off-host ──────────
def test_credential_stripped_on_cross_host_redirect():
    import email.message
    import urllib.request
    req = urllib.request.Request(
        "http://a.example/logout",
        headers={"Authorization": "Bearer HOSTA", "Cookie": "s=1"})
    handler = _http._SafeRedirect()
    m = email.message.Message()

    with patch.object(_http, "is_in_scope", lambda u: True):
        # same-host redirect keeps the credential
        same = handler.redirect_request(req, None, 302, "Found", m, "http://a.example/home")
        assert same is not None and same.get_header("Authorization") == "Bearer HOSTA"
        # cross-host redirect (even if in scope) STRIPS Authorization + Cookie
        cross = handler.redirect_request(req, None, 302, "Found", m, "http://evil.example/x")
        assert cross is not None
        assert cross.get_header("Authorization") is None
        assert cross.get_header("Cookie") is None

    # an out-of-scope redirect target is dropped entirely (fail closed)
    with patch.object(_http, "is_in_scope", lambda u: u.startswith("http://a.example")):
        assert handler.redirect_request(
            req, None, 302, "Found", m, "http://evil.example/x") is None
