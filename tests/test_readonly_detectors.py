"""Read-only, lead-only 'later-tier' detectors: deserialization surface, OAuth/OIDC
config, and safe web-cache-poisoning risk. Each observes (or safely probes) without
any destructive action, and every finding stays a manual-review lead at the gate."""
from __future__ import annotations

import asyncio
import json
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.swarm_validation import validate_findings  # noqa: E402
from core.swarm_workers.vuln import cache_poisoning, deser_surface, oauth_config  # noqa: E402


class _Agent:
    def __init__(self, t):
        self.target = t
        self.timeout_s = 8.0
        self.payload = {}


def _serve(handler_body):
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            status, headers, body = handler_body(self)
            self.send_response(status)
            for k, v in headers.items():
                self.send_header(k, v)
            b = body.encode() if isinstance(body, str) else body
            self.send_header("Content-Length", str(len(b)))
            self.end_headers()
            self.wfile.write(b)
    srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, f"http://127.0.0.1:{srv.server_address[1]}"


# ── deserialization surface ──

def test_deser_scan_detects_format_magic():
    java = "session=rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcAAAAAA="
    assert deser_surface._scan(java, "http://t/", "cookie")[0]["vuln_type"] \
        == "insecure_deserialization:java"
    assert deser_surface._scan("!!python/object:os.system", "http://t/", "b")
    assert deser_surface._scan('O:8:"Example":1:{s:1:"x";i:1;}', "http://t/", "b")
    assert deser_surface._scan("token=_$$ND_FUNC$$_function(){}", "http://t/", "b")


def test_deser_scan_ignores_benign_text():
    assert deser_surface._scan("just a normal base64 aGVsbG8gd29ybGQ= value", "http://t/", "b") == []
    assert deser_surface._scan('{"user":"alice","role":"admin"}', "http://t/", "b") == []


def test_deser_run_flags_serialized_cookie():
    def body(h):
        return (200, {"Content-Type": "text/html",
                      "Set-Cookie": "sess=rO0ABXNyAA1qYXZhLnV0aWwuTWFw"}, "hi")
    srv, base = _serve(body)
    try:
        out = asyncio.run(deser_surface.run(_Agent(base)))
        assert any(f["vuln_type"] == "insecure_deserialization:java" for f in out)
        assert all(f["needs_manual_verification"] for f in out)
    finally:
        srv.shutdown()


# ── OAuth/OIDC config ──

def test_oauth_analyze_flags_weak_config():
    cfg = {"issuer": "https://t/", "authorization_endpoint": "https://t/auth",
           "token_endpoint": "https://t/token",
           "response_types_supported": ["code", "token", "id_token token"],
           "token_endpoint_auth_methods_supported": ["client_secret_basic", "none"]}
    issues = {f["vuln_type"] for f in oauth_config._analyze(cfg, "http://t/wk")}
    assert "oauth_misconfig:no_pkce" in issues            # no code_challenge_methods
    assert "oauth_misconfig:implicit_flow" in issues       # token response type
    assert "oauth_misconfig:auth_none" in issues           # none auth method


def test_oauth_analyze_clean_config_is_silent():
    cfg = {"issuer": "https://t/", "authorization_endpoint": "https://t/auth",
           "response_types_supported": ["code"],
           "code_challenge_methods_supported": ["S256"],
           "token_endpoint_auth_methods_supported": ["client_secret_basic"]}
    assert oauth_config._analyze(cfg, "http://t/wk") == []


def test_oauth_run_reads_discovery_document():
    cfg = json.dumps({"issuer": "x", "authorization_endpoint": "x/auth",
                      "response_types_supported": ["code", "token"]})

    def body(h):
        if "openid-configuration" in h.path:
            return (200, {"Content-Type": "application/json"}, cfg)
        return (404, {}, "nope")
    srv, base = _serve(body)
    try:
        out = asyncio.run(oauth_config.run(_Agent(base)))
        assert any(f["vuln_type"].startswith("oauth_misconfig:") for f in out)
    finally:
        srv.shutdown()


# ── web-cache poisoning (safe: cache-buster + benign marker) ──

def _cache_server(reflect: bool, cacheable: bool):
    def body(h):
        xfh = h.headers.get("X-Forwarded-Host", "")
        html = f"<a href='https://{xfh}/login'>login</a>" if reflect else "<a>home</a>"
        headers = ({"Cache-Control": "public, max-age=60"} if cacheable
                   else {"Set-Cookie": "sid=abc"})  # per-user cookie -> not shared-cacheable
        return (200, headers, html)
    return _serve(body)


def test_cache_poisoning_flags_unkeyed_reflection_into_cacheable():
    srv, base = _cache_server(reflect=True, cacheable=True)
    try:
        out = asyncio.run(cache_poisoning.run(_Agent(base)))
        assert out and out[0]["vuln_type"].startswith("web_cache_poisoning:")
        assert out[0]["needs_manual_verification"]
        assert "cache buster" in out[0]["evidence"]
    finally:
        srv.shutdown()


def test_cache_poisoning_not_flagged_when_uncacheable():
    srv, base = _cache_server(reflect=True, cacheable=False)   # reflects but per-user
    try:
        assert asyncio.run(cache_poisoning.run(_Agent(base))) == []
    finally:
        srv.shutdown()


def test_cache_poisoning_not_flagged_without_reflection():
    srv, base = _cache_server(reflect=False, cacheable=True)   # cacheable but no reflection
    try:
        assert asyncio.run(cache_poisoning.run(_Agent(base))) == []
    finally:
        srv.shutdown()


# ── gate keeps all three as actionable leads ──

def test_gate_holds_all_three_as_leads():
    for vt, marker in (("insecure_deserialization:java", "gadget"),
                       ("web_cache_poisoning:x-forwarded-host", "SHARED cache"),
                       ("oauth_misconfig:no_pkce", "discovery document")):
        out = asyncio.run(validate_findings([{"vuln_type": vt, "url": "http://t/"}]))
        assert not out[0]["submittable"]
        assert marker in out[0]["validation_reason"]
