"""Per-class precision/recall scorecard for the validation gate.

Runs the gate over a labeled benchmark of *vulnerable* and *safe* responders for
each weakness class, then reports a confusion matrix and precision/recall per
class.

The gate's contract is FP-averse: a safe responder must NEVER be marked
``submittable`` (per-class precision target = 1.0, i.e. zero false positives).
Recall is the secondary metric — a missed vuln degrades to an unconfirmed lead a
human can still review, which is the safe failure direction.

Run as a script::

    python -m core.gate_benchmark          # print the scorecard
    python -m core.gate_benchmark --strict # exit 1 if any class has a false positive

Each scenario reuses the same vulnerable/safe responder models the gate's unit
tests assert against, so the scorecard tracks the gate's real behaviour rather
than a parallel re-implementation.
"""
from __future__ import annotations

import asyncio
import html as _html
import re as _re
from dataclasses import dataclass, field
from unittest.mock import patch
from urllib.parse import parse_qs, unquote, urlsplit

from core.swarm_validation import validate_findings
from core.swarm_workers.vuln._http import HttpResp

# --- shared fixtures -------------------------------------------------------

_AKIA = "AKIA2E0K8Z9QXVB7N3RT"          # AKIA + 16, no EXAMPLE/placeholder
_PWHASH = '[{"id":1,"email":"a@b.co","passwordHash":"$2b$10$abcdefghijklmno"}]'
_A_MARKER = "alice@victim.io"
_BOLA_CFG = {"owner_headers": {"Cookie": "s=alice"}, "owner_markers": [_A_MARKER],
             "attacker_headers": {"Cookie": "s=bob"}}


def _injected(url: str) -> str:
    q = parse_qs(urlsplit(url).query)
    for v in q.values():
        if v:
            return v[0]
    return ""


def _fetch(responder):
    async def fake(method, url, *, headers=None, timeout=10.0, body=None, **kw):
        # Body-aware responders (e.g. NoSQL login, which must distinguish a bogus
        # credential from an operator body) opt in via a `wants_body` attribute;
        # every existing responder keeps its (method, url, headers) signature.
        if getattr(responder, "wants_body", False):
            return responder(method, url, headers or {}, body)
        return responder(method, url, headers or {})
    return fake


# --- responders: each models one server's behaviour ------------------------

def _xss_live(m, url, h):
    return HttpResp(200, {"content-type": "text/html"},
                    f"<h1>Results for {_injected(url)}</h1>", url)


def _xss_escaped(m, url, h):
    return HttpResp(200, {"content-type": "text/html"},
                    f"<h1>Results for {_html.escape(_injected(url))}</h1>", url)


def _xss_textarea(m, url, h):
    return HttpResp(200, {"content-type": "text/html"},
                    f"<form><textarea>{_injected(url)}</textarea></form>", url)


def _xss_attribute(m, url, h):
    return HttpResp(200, {"content-type": "text/html"},
                    f'<input type="text" value="{_injected(url)}">', url)


def _sqli_real(m, url, h):
    v = _injected(url)
    if v.count("'") % 2 == 1 or v.count('"') % 2 == 1:
        return HttpResp(500, {}, "You have an error in your SQL syntax near", url)
    return HttpResp(200, {}, "ok", url)


def _sqli_waf(m, url, h):
    v = _injected(url)
    if "'" in v or '"' in v:
        return HttpResp(403, {}, "Request blocked by Web Application Firewall: "
                        "incorrect syntax near the submitted token", url)
    return HttpResp(200, {}, "ok", url)


def _sqli_dsl(m, url, h):
    v = _injected(url)
    if v.count("'") % 2 == 1:
        return HttpResp(500, {}, "ParseException: near \"'\": syntax error", url)
    return HttpResp(200, {}, "ok", url)


def _sqli_inert(m, url, h):
    return HttpResp(200, {}, "ordinary content, no DB error", url)


def _ssti_engine(m, url, h):
    import re as _re
    v = _injected(url)
    am = _re.search(r"\$\{(\d+)\*(\d+)\}", v)
    if am:
        return HttpResp(200, {}, f"Result: {int(am.group(1)) * int(am.group(2))}", url)
    if any(op in v for op in ('"+"', '"~"', '.concat(')):
        words = _re.findall(r'"(\w+)"', v)
        if len(words) >= 2:
            return HttpResp(200, {}, "Result: " + "".join(words), url)
    return HttpResp(200, {}, f"Result: {v}", url)


def _ssti_calculator(m, url, h):
    import re as _re
    v = _injected(url)
    mm = _re.search(r"(\d+)\*(\d+)", v)
    return HttpResp(200, {}, f"Result: {int(mm.group(1)) * int(mm.group(2))}" if mm
                    else f"Result: {v}", url)


def _lfi_passwd(m, url, h):
    v = _injected(url)
    if "etc/passwd" in v and "../" in v:
        return HttpResp(200, {}, "root:x:0:0:root:/root:/bin/bash\n"
                        "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
                        "bin:x:2:2:bin:/bin:/usr/sbin/nologin\n", url)
    return HttpResp(200, {}, "no such doc", url)


def _lfi_prose(m, url, h):
    return HttpResp(200, {}, "The file starts with root:x:0:0:root:/root (one line).", url)


def _lfi_html_doc(m, url, h):
    v = _injected(url)
    if "etc/passwd" in v:
        return HttpResp(200, {"content-type": "text/html"},
                        "<html>root:x:0:0:root:/root:/bin/bash\n"
                        "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin</html>", url)
    return HttpResp(200, {"content-type": "text/html"}, "<html>no match</html>", url)


def _secret_live(m, url, h):
    return HttpResp(200, {"content-type": "application/javascript"},
                    f'var k="{_AKIA}";', url)


def _secret_placeholder(m, url, h):
    return HttpResp(200, {"content-type": "application/javascript"},
                    'var k="AKIAIOSFODNN7EXAMPLE";', url)


def _secret_changelog(m, url, h):
    return HttpResp(200, {"content-type": "text/plain"},
                    f"v1.2: rotated key {_AKIA}", url)


def _ac_pwhash(m, url, h):
    return HttpResp(200, {"content-type": "application/json"}, _PWHASH, url)


def _ac_public_email(m, url, h):
    return HttpResp(200, {"content-type": "application/json"},
                    '{"name":"Acme Co","email":"contact@acme.example"}', url)


def _ac_publishable(m, url, h):
    return HttpResp(200, {"content-type": "application/json"},
                    '{"api_key":"pk_live_51ABCdefGHIjklMNOpqr"}', url)


def _ac_forbidden(m, url, h):
    return HttpResp(403, {}, "Forbidden", url)


def _cors_creds(m, url, h):
    return HttpResp(200, {"access-control-allow-origin": h.get("Origin", ""),
                          "access-control-allow-credentials": "true"}, "{}", url)


def _cors_no_creds(m, url, h):
    return HttpResp(200, {"access-control-allow-origin": h.get("Origin", "")},
                    '{"price":1}', url)


def _cors_static(m, url, h):
    return HttpResp(200, {"content-type": "text/css",
                          "access-control-allow-origin": h.get("Origin", ""),
                          "access-control-allow-credentials": "true"}, "body{}", url)


def _env_real(m, url, h):
    return HttpResp(200, {"content-type": "text/plain"},
                    f"DB_PASSWORD=s3cret\nAWS_KEY={_AKIA}\n", url)


def _env_example(m, url, h):
    return HttpResp(200, {"content-type": "text/plain"},
                    "DB_PASSWORD=changeme\nAWS_KEY=YOUR_KEY_HERE\n", url)


def _dir_real(m, url, h):
    return HttpResp(200, {}, "<html><h1>Index of /ftp</h1><a href='x'>x</a></html>", url)


def _dir_prose(m, url, h):
    links = "".join(f'<a href="/p{i}">page {i}</a>' for i in range(12))
    return HttpResp(200, {}, f"<html><h2>Our index of services</h2>{links}</html>", url)


def _bola_cross_read(m, url, h):
    ck = (h or {}).get("Cookie", "")
    if "s=alice" in ck or "s=bob" in ck:           # both authed see A's object
        return HttpResp(200, {}, '{"owner":"%s"}' % _A_MARKER, url)
    return HttpResp(401, {}, "", url)              # anon control -> not public


def _bola_proper_authz(m, url, h):
    ck = (h or {}).get("Cookie", "")
    if "s=alice" in ck:
        return HttpResp(200, {}, '{"owner":"%s"}' % _A_MARKER, url)
    return HttpResp(403, {}, "", url)              # attacker forbidden -> no cross-read


def _ok(m, url, h):
    return HttpResp(200, {}, "x", url)


def _hh_reflect(m, url, h):
    xfh = h.get("X-Forwarded-Host")
    if xfh:                                    # builds a redirect from the spoofed host
        return HttpResp(302, {"location": f"https://{xfh}/login"}, "", url)
    return HttpResp(200, {}, "home", url)


def _hh_safe(m, url, h):
    return HttpResp(200, {}, "home", url)      # never reflects the host header


def _takeover(m, url, h):
    return HttpResp(404, {}, "<html>There isn't a GitHub Pages site here.</html>", url)


def _takeover_safe(m, url, h):
    return HttpResp(404, {}, "<html>404 Not Found - page missing</html>", url)


def _s3_public(m, url, h):
    return HttpResp(200, {}, '<?xml version="1.0"?><ListBucketResult xmlns='
                    '"http://s3.amazonaws.com/doc/2006-03-01/"><Name>b</Name>'
                    '<Contents><Key>db-backup.sql</Key></Contents></ListBucketResult>', url)


def _s3_private(m, url, h):
    return HttpResp(403, {}, '<?xml version="1.0"?><Error><Code>AccessDenied'
                    '</Code></Error>', url)


def _ssrf_meta(v: str) -> bool:
    return "169.254.169.254" in v or "metadata.google" in v or "127.0.0.1" in v


def _ssrf_imds(m, url, h):
    # The internal payload returns the metadata service's own body (a real AKIA
    # credential + service markers); the benign baseline returns a plain page.
    if _ssrf_meta(_injected(url)):
        return HttpResp(200, {"content-type": "application/json"},
                        '{"AccessKeyId":"AKIAIOSFODNN7EXAMPLE","instance-id":"i-0abc123"}', url)
    return HttpResp(200, {"content-type": "text/html"}, "<html>Example Domain</html>", url)


def _ssrf_echo(m, url, h):
    # Open-redirect / URL-validator that merely REFLECTS the submitted url on both
    # baseline and probe — pure reflection, the payload-strip must kill it.
    return HttpResp(200, {"content-type": "text/html"},
                    f"<p>Could not reach {_injected(url)}</p>", url)


def _ssrf_waf(m, url, h):
    # A defending guard that 200s a JSON "blocked" envelope naming the metadata
    # service — the denial-language veto must reject it.
    if _ssrf_meta(_injected(url)):
        return HttpResp(200, {"content-type": "application/json"},
                        '{"error":"request to the cloud metadata service was blocked by '
                        'the WAF for your security"}', url)
    return HttpResp(200, {"content-type": "text/html"}, "ok", url)


def _ssrf_akia_benign(m, url, h):
    # Adversarial review: a benign endpoint whose response carries an AKIA-SHAPED
    # vendor token (no metadata marker names) that varies with the parameter. A bare
    # credential-shaped string without a co-occurring metadata marker must NOT confirm.
    if _ssrf_meta(_injected(url)):
        return HttpResp(200, {"content-type": "application/json"},
                        '{"status":"ok","api_key":"AKIA2E0K8Z9QXVB7N3RT"}', url)
    return HttpResp(200, {"content-type": "application/json"},
                    '{"status":"ok","api_key":"EXAMPLEKEY1234567890"}', url)


def _oredir_vuln(m, url, h):
    # Parameter-driven: bounces (302 Location) to whatever host the param names —
    # so injecting the gate's FRESH random host makes it the redirect target.
    v = _injected(url)
    if v.startswith("http://t/") or v.startswith("https://t/"):
        return HttpResp(302, {"location": v}, "", url)   # benign same-host control
    return HttpResp(302, {"location": v}, "", url)


def _oredir_reflect(m, url, h):
    # Reflects the value in the BODY but never actually redirects (200, no channel).
    return HttpResp(200, {"content-type": "text/html"},
                    f"<p>Taking you to {_injected(url)} shortly...</p>", url)


def _oredir_fixed(m, url, h):
    # Always bounces to its OWN dashboard, ignoring the param (not attacker-driven).
    return HttpResp(302, {"location": "https://t/dashboard"}, "", url)


def _oredir_gesture(m, url, h):
    # Reflects the value into a CLICK handler — the browser only navigates after a
    # user gesture, so it is a safe interstitial, not an auto open redirect.
    v = _injected(url)
    return HttpResp(200, {"content-type": "text/html"},
                    f"<button onclick=\"location.href='{v}'\">continue</button>", url)


def _graphql_live(m, url, h):
    return HttpResp(200, {"content-type": "application/json"},
                    '{"data":{"__schema":{"queryType":{"name":"Query"},'
                    '"types":[{"name":"User","kind":"OBJECT"}]}}}', url)


def _graphql_fake(m, url, h):
    # Generic JSON API that merely nests __schema.types as plain strings — NOT GraphQL.
    return HttpResp(200, {"content-type": "application/json"},
                    '{"data":{"__schema":{"types":["invoices","customers"]}}}', url)


def _graphql_names_only(m, url, h):
    # Adversarial-review FP: a generic metadata API whose __schema.types are dicts
    # carrying only a "name" — no queryType, no canonical kind. The name-only
    # fallback would misread this as GraphQL; the richer gate query must reject it.
    return HttpResp(200, {"content-type": "application/json"},
                    '{"data":{"__schema":{"types":[{"name":"users"},{"name":"orders"},'
                    '{"name":"products"}]}}}', url)


def _graphql_coincidental_kind(m, url, h):
    # A columnar/metadata API that DOES carry a "kind", but a non-GraphQL one
    # (table/view). Must not be mistaken for the canonical __TypeKind enum.
    return HttpResp(200, {"content-type": "application/json"},
                    '{"data":{"__schema":{"types":[{"name":"users","kind":"table"},'
                    '{"name":"orders","kind":"view"}]}}}', url)


def _graphql_kinds_no_querytype(m, url, h):
    # Adversarial re-review: a metadata API whose type "kind" labels happen to be
    # uppercase GraphQL enums (OBJECT/SCALAR) but with NO queryType. The kind signal
    # alone must not confirm — GraphQL introspection always names a queryType.
    return HttpResp(200, {"content-type": "application/json"},
                    '{"data":{"__schema":{"types":[{"name":"users","kind":"OBJECT"},'
                    '{"name":"id","kind":"SCALAR"}]}}}', url)


def _graphql_querytype_no_kind(m, url, h):
    # Adversarial re-review: an API that nests a "queryType" key but whose types
    # carry no canonical __TypeKind. queryType alone must not confirm.
    return HttpResp(200, {"content-type": "application/json"},
                    '{"data":{"__schema":{"queryType":{"name":"Query"},'
                    '"types":[{"name":"User"},{"name":"Post"}]}}}', url)


# --- clickjacking (fetch-driven; both directions offline) ---

def _cj_framable(m, url, h):
    return HttpResp(200, {"content-type": "text/html"},
                    "<html><body>Account settings</body></html>", url)


def _cj_xfo(m, url, h):
    return HttpResp(200, {"content-type": "text/html", "x-frame-options": "DENY"},
                    "<html></html>", url)


def _cj_csp(m, url, h):
    return HttpResp(200, {"content-type": "text/html",
                          "content-security-policy": "frame-ancestors 'none'"},
                    "<html></html>", url)


def _cj_json(m, url, h):
    return HttpResp(200, {"content-type": "application/json"}, '{"ok":true}', url)


# --- NoSQL login auth-bypass (body-aware; token differential) ---

_NOSQL_JWT = ('{"token":"eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjoxfQ.'
              + "s" * 24 + '"}')


def _nosql_has_operator(body) -> bool:
    raw = body.decode() if isinstance(body, (bytes, bytearray)) else (body or "")
    return "$ne" in raw or "$gt" in raw


def _nosql_login_vuln(m, url, h, body):
    # Operator body mints a token; a bogus credential does not — real injection.
    if _nosql_has_operator(body):
        return HttpResp(200, {"content-type": "application/json"}, _NOSQL_JWT, url)
    return HttpResp(200, {"content-type": "application/json"},
                    '{"authentication":"failed"}', url)


_nosql_login_vuln.wants_body = True


def _nosql_login_promiscuous(m, url, h, body):
    # Hands a token to ANY credential (bogus too) — baseline discipline rejects it.
    return HttpResp(200, {"content-type": "application/json"}, _NOSQL_JWT, url)


_nosql_login_promiscuous.wants_body = True


def _nosql_login_safe(m, url, h, body):
    # Never mints a token — the operator body does not reproduce a session.
    return HttpResp(200, {"content-type": "application/json"},
                    '{"authentication":"failed"}', url)


_nosql_login_safe.wants_body = True


def _mk_jwt(header: dict, payload: dict) -> str:
    import base64 as _b64
    import json as _j

    def e(o):
        return _b64.urlsafe_b64encode(
            _j.dumps(o, separators=(",", ":")).encode()).rstrip(b"=").decode()
    return f"{e(header)}.{e(payload)}.AAAA"   # signature is irrelevant to the gate


_JWT_KEY = "secret"
_JWT_TOKEN = _mk_jwt({"alg": "HS256", "typ": "JWT"}, {"sub": "user1"})


def _jwt_verifies_sig(h) -> bool:
    """Model a server that verifies the HS256 signature with the weak key: True iff
    the Authorization Bearer token carries a valid signature under _JWT_KEY."""
    import base64 as _b64
    import hashlib as _hashlib
    import hmac as _hmac
    auth = (h or {}).get("Authorization", "")
    tok = auth[7:] if auth.startswith("Bearer ") else ""
    parts = tok.split(".")
    if len(parts) != 3:
        return False
    want = _b64.urlsafe_b64encode(
        _hmac.new(_JWT_KEY.encode(), (parts[0] + "." + parts[1]).encode(),
                  _hashlib.sha256).digest()).rstrip(b"=").decode()
    return parts[2] == want


def _jwt_forge_accept(m, url, h):
    # Verifies signatures with the weak key: a weak-key-forged token is accepted, a
    # bad-signature control is rejected — the forge-accept a real bypass produces.
    return (HttpResp(200, {}, '{"ok":true}', url) if _jwt_verifies_sig(h)
            else HttpResp(401, {}, "unauthorized", url))


def _jwt_accept_all(m, url, h):
    # Accepts ANY token (no signature verification / no auth) — forging proves nothing.
    return HttpResp(200, {}, '{"ok":true}', url)


# --- xxe / crlf: model the worker the gate re-runs (patched via patch_workers) ---
def _xxe_vuln(m, url, h, body):
    # A parser that resolves the external entity: the XXE payload (file:///etc/passwd)
    # returns passwd content; the benign control XML does not -> file-read confirmed.
    b = body.decode() if isinstance(body, (bytes, bytearray)) else (body or "")
    if "file:///etc/passwd" in b:
        return HttpResp(200, {}, "<r>root:x:0:0:root:/root:/bin/bash</r>", url)
    return HttpResp(200, {}, "<r>viper-xxe-control</r>", url)


_xxe_vuln.wants_body = True


def _xxe_reflect_safe(m, url, h, body):
    # A hardened endpoint that merely ECHOES the request body (no parsing): the worker
    # strips the payload echo, so our own DOCTYPE/ENTITY text can't fake a signal.
    b = body.decode() if isinstance(body, (bytes, bytearray)) else (body or "")
    return HttpResp(200, {}, f"<echo>{b}</echo>", url)


_xxe_reflect_safe.wants_body = True


def _xxe_inert_safe(m, url, h, body):
    # Accepts XML but never resolves entities and emits no parser error -> no signal.
    return HttpResp(200, {}, "<r>ok</r>", url)


_xxe_inert_safe.wants_body = True


def _crlf_vuln(m, url, h):
    # A server that splits on our CRLF and emits the injected header carrying the
    # worker's unique per-run token (viper<hex>) — genuine response-header injection.
    q = parse_qs(urlsplit(url).query)
    raw_q = urlsplit(url).query.lower()
    for vals in q.values():
        v = vals[0]
        mk = _re.search(r"viper[0-9a-f]{16}", v)
        if mk and ("\r" in v or "\n" in v or "%0d%0a" in raw_q or "%0a" in raw_q):
            return HttpResp(200, {"x-crlf-test": mk.group(0)}, "ok", url)
    return HttpResp(200, {}, "ok", url)


def _crlf_reflect_safe(m, url, h):
    # Reflects the payload into the BODY (that's reflection/XSS, not header injection)
    # but never emits the attacker header — the worker must NOT flag it.
    q = parse_qs(urlsplit(url).query)
    v = next((vals[0] for vals in q.values() if vals), "")
    return HttpResp(200, {}, f"you searched for {unquote(v)}", url)


def _ldap_vuln(m, url, h):
    # A breaker snaps the LDAP filter -> engine error; a benign value returns cleanly.
    v = _injected(url)
    if ("viperbenign" not in v) and (")(" in v or "*)(" in v or "\\" in v):
        return HttpResp(500, {}, "javax.naming.NamingException: [LDAP: error code 53 - "
                                 "Bad search filter]", url)
    return HttpResp(200, {}, "no results", url)


def _xpath_vuln(m, url, h):
    v = _injected(url)
    if ("viperbenign" not in v) and ("'" in v or "']" in v):
        return HttpResp(500, {}, "Warning: SimpleXMLElement::xpath(): Invalid XPath "
                                 "expression (XPathException)", url)
    return HttpResp(200, {}, "ok", url)


def _query_reflect_safe(m, url, h):
    # Reflects the payload into the body but emits NO engine error -> not injectable.
    return HttpResp(200, {}, f"you searched for {_injected(url)}", url)


def _query_noisy_safe(m, url, h):
    # Emits the LDAP engine error for EVERYTHING incl. the benign control -> the
    # control veto must reject it (the endpoint is noisy, not injectable).
    return HttpResp(500, {}, "javax.naming.NamingException: LDAP: error code 1", url)


# RS256->HS256 algorithm confusion: reconstruct a public-key PEM from a JWK and model a
# verifier that (vulnerably) HMAC-checks HS256 with that public key.
from core.swarm_workers.vuln.jwt import (  # noqa: E402
    _b64url_encode as _b64u, jwk_rsa_to_pem as _jwk_pem)


def _bjson_dumps(o):
    import json as _j
    return _j.dumps(o, separators=(",", ":")).encode()


_AC_PEM = _jwk_pem(_b64u(((1 << 1023) | 0x9F13).to_bytes(128, "big")),
                   _b64u((65537).to_bytes(3, "big")))
_AC_TOKEN = f'{_b64u(_bjson_dumps({"alg": "RS256", "kid": "k1"}))}.' \
            f'{_b64u(_bjson_dumps({"sub": "user1"}))}.AAAA'


def _jwt_alg_confusion_accept(m, url, h):
    # Vulnerably HMAC-verifies HS256 using the RSA public-key PEM as the secret: a
    # forged token signed with the public key is accepted, a bad-sig control rejected.
    import hashlib as _hl
    import hmac as _hm
    auth = (h or {}).get("Authorization", "")
    tok = auth[7:] if auth.startswith("Bearer ") else ""
    p = tok.split(".")
    if len(p) == 3:
        want = _b64u(_hm.new(_AC_PEM.encode(), (p[0] + "." + p[1]).encode(),
                             _hl.sha256).digest())
        if p[2] == want:
            return HttpResp(200, {}, '{"ok":true}', url)
    return HttpResp(401, {}, "unauthorized", url)


def _nosql_object_session(m, url, h, body):
    # Adversarial review: hands a token to ANY object-typed credential (e.g. a guest
    # session created for object bodies), regardless of operator matching semantics —
    # a bogus STRING credential gets none. The $eq-to-bogus operator-semantics control
    # must catch this: mere object-presence is not a confirmed injection.
    raw = body.decode() if isinstance(body, (bytes, bytearray)) else (body or "")
    # a field whose value is a JSON object (operator or not); whitespace-tolerant
    # because the gate serializes bodies with `json.dumps` default separators.
    minted = '":{' in raw.replace(" ", "")
    return HttpResp(200, {"content-type": "application/json"},
                    _NOSQL_JWT if minted else '{"authentication":"failed"}', url)


_nosql_object_session.wants_body = True


def _graphql_blocked(m, url, h):
    return HttpResp(400, {"content-type": "application/json"},
                    '{"errors":[{"message":"introspection is disabled"}]}', url)


def _graphql_ide_live(m, url, h):
    return HttpResp(200, {"content-type": "text/html"},
                    '<html><body><div id="graphiql">Loading...</div></body></html>', url)


def _graphql_ide_prose(m, url, h):
    return HttpResp(200, {"content-type": "text/html"},
                    "<html><p>We previously offered a GraphiQL explorer here.</p></html>", url)


# --- the labeled benchmark -------------------------------------------------

@dataclass(frozen=True)
class Scenario:
    cls: str            # weakness class label for grouping
    label: str          # "vuln" (should be submittable) | "safe" (must not be)
    name: str           # human-readable scenario id
    finding: dict
    responder: object
    bola_config: dict = None
    min_confidence: float = 0.5   # gate threshold; lowered in scenarios that prove
                                  # a low threshold still can't leak a class
    patch_workers: tuple = ()     # worker modules whose module-level `fetch` the gate's
                                  # recheck re-runs (xxe/crlf) — patched to this
                                  # scenario's responder so it can be modeled offline


BENCHMARK = [
    # xss
    Scenario("xss", "vuln", "live markup in content",
             {"vuln_type": "xss_text:q", "url": "http://t/s?q=x", "parameter": "q"}, _xss_live),
    Scenario("xss", "safe", "html-escaped reflection",
             {"vuln_type": "xss_text:q", "url": "http://t/s?q=x", "parameter": "q"}, _xss_escaped),
    Scenario("xss", "safe", "reflection inside <textarea>",
             {"vuln_type": "xss_text:q", "url": "http://t/s?q=x", "parameter": "q"}, _xss_textarea),
    Scenario("xss", "safe", "reflection inside attribute value",
             {"vuln_type": "xss_text:q", "url": "http://t/s?q=x", "parameter": "q"}, _xss_attribute),

    # sqli
    Scenario("sqli", "vuln", "unbalanced quote -> 500 DB error",
             {"vuln_type": "sqli:id", "url": "http://t/x?id=1", "parameter": "id"}, _sqli_real),
    Scenario("sqli", "safe", "WAF 403 mentioning SQL",
             {"vuln_type": "sqli:id", "url": "http://t/x?id=1", "parameter": "id"}, _sqli_waf),
    Scenario("sqli", "safe", "DSL parser generic syntax error",
             {"vuln_type": "sqli:q", "url": "http://t/search?q=docs", "parameter": "q"}, _sqli_dsl),
    Scenario("sqli", "safe", "inert content, no DB error",
             {"vuln_type": "sqli:id", "url": "http://t/x?id=1", "parameter": "id"}, _sqli_inert),

    # ssti
    Scenario("ssti", "vuln", "template engine evals ${8*8} and string ops",
             {"vuln_type": "ssti", "url": "http://t/x?n=1", "parameter": "n"}, _ssti_engine),
    Scenario("ssti", "safe", "calculator evals bare arithmetic too",
             {"vuln_type": "ssti", "url": "http://t/order?qty=1", "parameter": "qty"}, _ssti_calculator),

    # lfi
    Scenario("lfi", "vuln", "multi-account /etc/passwd via traversal",
             {"vuln_type": "lfi:file", "parameter": "file",
              "url": "http://t/x?file=../../../../etc/passwd"}, _lfi_passwd),
    Scenario("lfi", "safe", "doc quoting only the canonical root line",
             {"vuln_type": "lfi:file", "parameter": "file",
              "url": "http://t/x?file=../../../../etc/passwd"}, _lfi_prose),
    Scenario("lfi", "safe", "man-page tutorial returned as HTML",
             {"vuln_type": "lfi:file", "parameter": "file",
              "url": "http://t/x?file=../../../../etc/passwd"}, _lfi_html_doc),

    # secrets
    Scenario("secrets", "vuln", "live AWS key in JS",
             {"vuln_type": "secret:aws", "url": "http://t/main.js"}, _secret_live),
    Scenario("secrets", "safe", "AWS canonical EXAMPLE key",
             {"vuln_type": "secret:aws", "url": "http://t/main.js"}, _secret_placeholder),
    Scenario("secrets", "safe", "rotated key in CHANGELOG",
             {"vuln_type": "secret:aws", "url": "http://t/CHANGELOG.txt"}, _secret_changelog),

    # access_control
    Scenario("access_control", "vuln", "unauth password hashes",
             {"vuln_type": "access_control:missing_authorization", "url": "http://t/api/Users"},
             _ac_pwhash),
    Scenario("access_control", "safe", "public profile exposing email",
             {"vuln_type": "access_control:missing_authorization",
              "url": "http://t/api/public-profile"}, _ac_public_email),
    Scenario("access_control", "safe", "Stripe publishable key in SPA config",
             {"vuln_type": "access_control:missing_authorization", "url": "http://t/config.json"},
             _ac_publishable),
    Scenario("access_control", "safe", "endpoint returns 403",
             {"vuln_type": "access_control:missing_authorization", "url": "http://t/api/Users"},
             _ac_forbidden),

    # cors
    Scenario("cors", "vuln", "reflects arbitrary origin + credentials",
             {"vuln_type": "cors_origin_reflect", "url": "http://t/api"}, _cors_creds),
    Scenario("cors", "safe", "reflects origin, no credentials",
             {"vuln_type": "cors_origin_reflect", "url": "http://t/ticker"}, _cors_no_creds),
    Scenario("cors", "safe", "reflect+creds on static .css asset",
             {"vuln_type": "cors_origin_reflect", "url": "http://t/brand.css"}, _cors_static),

    # env_exposed
    Scenario("env_exposed", "vuln", "live /.env with real secrets",
             {"vuln_type": "env_exposed:/.env", "url": "http://t/.env"}, _env_real),
    Scenario("env_exposed", "safe", ".env.example with placeholders",
             {"vuln_type": "env_exposed:/.env.example", "url": "http://t/.env.example"}, _env_example),

    # dir_listing
    Scenario("dir_listing", "vuln", "real Apache autoindex",
             {"vuln_type": "information_disclosure:listing:/ftp", "url": "http://t/ftp"}, _dir_real),
    Scenario("dir_listing", "safe", "prose page mentioning 'index of'",
             {"vuln_type": "information_disclosure:listing:/x", "url": "http://t/services"}, _dir_prose),

    # idor / bola escalation
    Scenario("idor", "vuln", "single-session IDOR escalates to two-account BOLA",
             {"vuln_type": "idor:user", "url": "http://t/api/users/5"},
             _bola_cross_read, _BOLA_CFG),
    Scenario("idor", "safe", "attacker forbidden -> proper authz",
             {"vuln_type": "idor:user", "url": "http://t/api/users/5"},
             _bola_proper_authz, _BOLA_CFG),
    Scenario("idor", "safe", "single session, no two-account config",
             {"vuln_type": "idor:user", "url": "http://t/api/users/5"}, _ok),

    # cmdi (offline: real re-test can't reproduce -> safe direction only)
    Scenario("cmdi", "safe", "non-reproducible / unreachable target",
             {"vuln_type": "rce:cmdi:id", "url": "http://127.0.0.1:9/x?id=1", "parameter": "id"},
             _ok),

    # host header injection
    Scenario("host_header", "vuln", "spoofed X-Forwarded-Host reflected into Location",
             {"vuln_type": "host_header:x-forwarded-host", "url": "http://t/",
              "parameter": "X-Forwarded-Host"}, _hh_reflect),
    Scenario("host_header", "safe", "host header not reflected",
             {"vuln_type": "host_header:x-forwarded-host", "url": "http://t/",
              "parameter": "X-Forwarded-Host"}, _hh_safe),

    # subdomain takeover
    Scenario("subdomain_takeover", "vuln", "GitHub Pages unclaimed fingerprint",
             {"vuln_type": "subdomain_takeover:github_pages", "url": "http://t/"},
             _takeover),
    Scenario("subdomain_takeover", "safe", "generic 404 (not a takeover)",
             {"vuln_type": "subdomain_takeover:github_pages", "url": "http://t/"},
             _takeover_safe),

    # cloud storage exposure
    Scenario("cloud_exposure", "vuln", "public listable S3 bucket",
             {"vuln_type": "cloud_exposure:public_bucket_listing", "url": "http://t/"},
             _s3_public),
    Scenario("cloud_exposure", "safe", "private bucket (AccessDenied)",
             {"vuln_type": "cloud_exposure:public_bucket_listing", "url": "http://t/"},
             _s3_private),

    # web cache deception (gate trusts the worker's two-identity cache proof)
    Scenario("web_cache_deception", "vuln", "anon retrieved victim data from cache",
             {"vuln_type": "web_cache_deception:/account",
              "url": "http://t/account/x.css", "cache_confirmed": True}, _ok),
    Scenario("web_cache_deception", "safe", "unconfirmed cache candidate",
             {"vuln_type": "web_cache_deception:/account",
              "url": "http://t/account/x.css"}, _ok),

    # open_redirect — fresh random attacker host must be the real redirect target
    Scenario("open_redirect", "vuln", "parameter-driven 302 to a fresh attacker host",
             {"vuln_type": "open_redirect:next", "url": "http://t/redirect?next=x",
              "parameter": "next"}, _oredir_vuln),
    Scenario("open_redirect", "safe", "value reflected in body, no actual redirect",
             {"vuln_type": "open_redirect:next", "url": "http://t/redirect?next=x",
              "parameter": "next"}, _oredir_reflect),
    Scenario("open_redirect", "safe", "hardcoded redirect ignoring the parameter",
             {"vuln_type": "open_redirect:next", "url": "http://t/redirect?next=x",
              "parameter": "next"}, _oredir_fixed),
    Scenario("open_redirect", "safe", "gesture-gated JS assignment (interstitial)",
             {"vuln_type": "open_redirect:next", "url": "http://t/redirect?next=x",
              "parameter": "next"}, _oredir_gesture),

    # graphql — independent introspection re-query must return a canonical schema
    Scenario("graphql", "vuln", "introspection returns a canonical GraphQL schema",
             {"vuln_type": "graphql_introspection:/graphql", "url": "http://t/graphql"},
             _graphql_live),
    Scenario("graphql", "safe", "generic JSON nesting __schema as plain strings",
             {"vuln_type": "graphql_introspection:/graphql", "url": "http://t/graphql"},
             _graphql_fake),
    Scenario("graphql", "safe", "metadata API: __schema.types are name-only dicts",
             {"vuln_type": "graphql_introspection:/graphql", "url": "http://t/graphql"},
             _graphql_names_only),
    Scenario("graphql", "safe", "metadata API with non-GraphQL kind (table/view)",
             {"vuln_type": "graphql_introspection:/graphql", "url": "http://t/graphql"},
             _graphql_coincidental_kind),
    Scenario("graphql", "safe", "canonical kinds but no queryType (kind-only spoof)",
             {"vuln_type": "graphql_introspection:/graphql", "url": "http://t/graphql"},
             _graphql_kinds_no_querytype),
    Scenario("graphql", "safe", "queryType but no canonical kind (queryType-only spoof)",
             {"vuln_type": "graphql_introspection:/graphql", "url": "http://t/graphql"},
             _graphql_querytype_no_kind),
    Scenario("graphql", "safe", "introspection disabled (errors)",
             {"vuln_type": "graphql_introspection:/graphql", "url": "http://t/graphql"},
             _graphql_blocked),
    Scenario("graphql", "vuln", "live GraphiQL IDE bootstrap markup",
             {"vuln_type": "graphql_ide:/graphql", "url": "http://t/graphql"},
             _graphql_ide_live),
    Scenario("graphql", "safe", "prose merely mentioning GraphiQL",
             {"vuln_type": "graphql_ide:/graphql", "url": "http://t/graphql"},
             _graphql_ide_prose),

    # cmdi defense-in-depth — a non-reproducible RCE must stay a lead EVEN when the
    # operator lowers the confidence threshold (structural, not a threshold accident)
    Scenario("cmdi", "safe", "non-reproducible cmdi stays lead at min_confidence=0.05",
             {"vuln_type": "rce:cmdi:id", "url": "http://127.0.0.1:9/x?id=1",
              "parameter": "id"}, _ok, min_confidence=0.05),

    # clickjacking — framable HTML with no anti-framing controls (fetch-driven)
    Scenario("clickjacking", "vuln", "HTML page, no X-Frame-Options / no CSP frame-ancestors",
             {"vuln_type": "clickjacking_frameable:/settings", "url": "http://t/settings"},
             _cj_framable),
    Scenario("clickjacking", "safe", "X-Frame-Options: DENY present",
             {"vuln_type": "clickjacking_frameable:/settings", "url": "http://t/settings"},
             _cj_xfo),
    Scenario("clickjacking", "safe", "CSP frame-ancestors present",
             {"vuln_type": "clickjacking_frameable:/settings", "url": "http://t/settings"},
             _cj_csp),
    Scenario("clickjacking", "safe", "non-HTML (JSON) response — no framing surface",
             {"vuln_type": "clickjacking_frameable:/api", "url": "http://t/api"}, _cj_json),

    # (xxe / crlf gate branches re-run the real worker against a LIVE target, so
    # they can't be exercised offline here without a slow dead-host connect; their
    # behaviour is covered by their dedicated worker+gate tests — test_xxe_gate,
    # test_crlf_gate — rather than by a scorecard row that would slow every run.)

    # nosql login auth-bypass — bogus credential mints NO token, operator body DOES
    # (body-aware responders); the weaker query sub-class must stay a lead.
    Scenario("nosql", "vuln", "operator body mints a token, bogus does not",
             {"vuln_type": "nosql_injection:login", "url": "http://t/api/login",
              "payload": '{"email":{"$ne":null},"password":{"$ne":null}}'},
             _nosql_login_vuln),
    Scenario("nosql", "safe", "endpoint hands a token to any credential (promiscuous)",
             {"vuln_type": "nosql_injection:login", "url": "http://t/api/login",
              "payload": '{"email":{"$ne":null},"password":{"$ne":null}}'},
             _nosql_login_promiscuous),
    Scenario("nosql", "safe", "operator body does not mint a token",
             {"vuln_type": "nosql_injection:login", "url": "http://t/api/login",
              "payload": '{"email":{"$ne":null},"password":{"$ne":null}}'},
             _nosql_login_safe),
    Scenario("nosql", "safe", "token for any object body (not operator-driven)",
             {"vuln_type": "nosql_injection:login", "url": "http://t/api/login",
              "payload": '{"email":{"$ne":null},"password":{"$ne":null}}'},
             _nosql_object_session),
    Scenario("nosql", "safe", "query-divergence candidate stays a lead",
             {"vuln_type": "nosql_injection:query", "url": "http://t/search?q=x",
              "parameter": "q", "payload": "[$ne]="}, _ok),

    # ssrf (response-based) — the internal metadata payload must return the service's
    # own body (credential co-occurring with >=1 marker, or >=2 markers) absent from a
    # benign baseline, read-only. (CSRF is intentionally NOT here — it can't be
    # gate-confirmed read-only without ruling out an unobservable Origin/Referer or
    # double-submit defence, so it stays a lead.)
    Scenario("ssrf", "vuln", "IMDS credential body on the metadata payload, plain baseline",
             {"vuln_type": "ssrf:url",
              "url": "http://t/fetch?url=http://169.254.169.254/latest/meta-data/",
              "parameter": "url", "payload": "http://169.254.169.254/latest/meta-data/"},
             _ssrf_imds),
    Scenario("ssrf", "safe", "URL validator merely reflects the payload (pure reflection)",
             {"vuln_type": "ssrf:url",
              "url": "http://t/fetch?url=http://169.254.169.254/latest/meta-data/",
              "parameter": "url", "payload": "http://169.254.169.254/latest/meta-data/"},
             _ssrf_echo),
    Scenario("ssrf", "safe", "WAF 200 'blocked ... metadata service' envelope",
             {"vuln_type": "ssrf:url",
              "url": "http://t/fetch?url=http://169.254.169.254/latest/meta-data/",
              "parameter": "url", "payload": "http://169.254.169.254/latest/meta-data/"},
             _ssrf_waf),
    Scenario("ssrf", "safe", "benign AKIA-shaped vendor token, no metadata marker",
             {"vuln_type": "ssrf:url",
              "url": "http://t/license?url=http://169.254.169.254/latest/meta-data/",
              "parameter": "url", "payload": "http://169.254.169.254/latest/meta-data/"},
             _ssrf_akia_benign),

    # jwt weak-key forge-probe — a cracked key is only submittable when an operator
    # supplies an authed endpoint AND a forged token is accepted where a bad-sig
    # control is rejected. No endpoint (the autonomous default) stays a lead.
    Scenario("jwt", "vuln", "forged token accepted, bad-sig control rejected",
             {"vuln_type": "jwt:weak_key", "url": "http://t/api/me",
              "jwt_token": _JWT_TOKEN, "jwt_key": _JWT_KEY, "jwt_alg": "HS256",
              "jwt_probe_endpoint": "http://t/api/me"}, _jwt_forge_accept),
    Scenario("jwt", "safe", "weak key cracked but no probe endpoint (stays lead)",
             {"vuln_type": "jwt:weak_key", "url": "http://t/", "jwt_token": _JWT_TOKEN,
              "jwt_key": _JWT_KEY, "jwt_alg": "HS256"}, _ok),
    Scenario("jwt", "vuln", "RS256->HS256 confusion: forged HS256 (public-key HMAC) accepted",
             {"vuln_type": "jwt:alg_confusion", "url": "http://t/",
              "jwt_token": _AC_TOKEN, "jwt_pubkey_pem": _AC_PEM,
              "jwt_probe_endpoint": "http://t/api/me"}, _jwt_alg_confusion_accept),
    Scenario("jwt", "safe", "alg-confusion candidate but no probe endpoint (stays lead)",
             {"vuln_type": "jwt:alg_confusion", "url": "http://t/",
              "jwt_token": _AC_TOKEN, "jwt_pubkey_pem": _AC_PEM}, _ok),
    Scenario("jwt", "safe", "endpoint accepts any token (no signature verification)",
             {"vuln_type": "jwt:weak_key", "url": "http://t/api/me",
              "jwt_token": _JWT_TOKEN, "jwt_key": _JWT_KEY, "jwt_alg": "HS256",
              "jwt_probe_endpoint": "http://t/api/me"}, _jwt_accept_all),

    # xxe — the gate re-runs the worker (patched offline via patch_workers): confirm a
    # local file read; reject a body-reflecting or inert (no-entity) endpoint.
    Scenario("xxe", "vuln", "external entity resolves file:///etc/passwd (file read)",
             {"vuln_type": "xxe:file_read", "url": "http://t/"}, _xxe_vuln,
             patch_workers=("core.swarm_workers.vuln.xxe",)),
    Scenario("xxe", "safe", "endpoint echoes the request body (reflection, not parsing)",
             {"vuln_type": "xxe:file_read", "url": "http://t/"}, _xxe_reflect_safe,
             patch_workers=("core.swarm_workers.vuln.xxe",)),
    Scenario("xxe", "safe", "accepts XML but resolves no entity and emits no parser error",
             {"vuln_type": "xxe:file_read", "url": "http://t/"}, _xxe_inert_safe,
             patch_workers=("core.swarm_workers.vuln.xxe",)),

    # crlf — confirm an injected response header carrying the worker's unique token;
    # reject reflection into the body only (that's XSS/reflection, not header injection).
    Scenario("crlf", "vuln", "CRLF splits into an attacker-controlled response header",
             {"vuln_type": "crlf_header_injection", "url": "http://t/?q=x", "parameter": "q"},
             _crlf_vuln, patch_workers=("core.swarm_workers.vuln.crlf",)),
    Scenario("crlf", "safe", "payload reflected into the body only (not a header)",
             {"vuln_type": "crlf_header_injection", "url": "http://t/?q=x", "parameter": "q"},
             _crlf_reflect_safe, patch_workers=("core.swarm_workers.vuln.crlf",)),

    # --- LDAP / XPath injection (in-band engine-error differential) ---------------
    Scenario("ldap_injection", "vuln", "LDAP breaker snaps the filter -> javax.naming error",
             {"vuln_type": "ldap_injection:cn", "url": "http://t/search?cn=*)(uid=*",
              "parameter": "cn", "payload": "*)(uid=*"},
             _ldap_vuln),
    Scenario("ldap_injection", "safe", "payload reflected into the body, no engine error",
             {"vuln_type": "ldap_injection:cn", "url": "http://t/search?cn=*)(uid=*",
              "parameter": "cn", "payload": "*)(uid=*"},
             _query_reflect_safe),
    Scenario("ldap_injection", "safe", "endpoint emits the LDAP error for the benign control too",
             {"vuln_type": "ldap_injection:cn", "url": "http://t/search?cn=*)(uid=*",
              "parameter": "cn", "payload": "*)(uid=*"},
             _query_noisy_safe),
    Scenario("xpath_injection", "vuln", "XPath quote breaks the expression -> XPathException",
             {"vuln_type": "xpath_injection:q", "url": "http://t/find?q='",
              "parameter": "q", "payload": "'"},
             _xpath_vuln),
    Scenario("xpath_injection", "safe", "payload reflected into the body, no engine error",
             {"vuln_type": "xpath_injection:q", "url": "http://t/find?q='",
              "parameter": "q", "payload": "'"},
             _query_reflect_safe),
]


_SCENARIO_COUNTS = None


def class_scenario_counts() -> dict:
    """Per-class labeled-scenario counts from the benchmark, WITHOUT running it (cheap:
    just tallies the BENCHMARK list). {cls: {vuln, safe, total}}. The precision invariant
    (1.00 / 0 FP) is enforced separately by the scorecard + mutation harness, so a report
    can cite '<total> labeled scenarios, <safe> adversarial safe cases' as calibration."""
    global _SCENARIO_COUNTS
    if _SCENARIO_COUNTS is None:
        counts: dict = {}
        for sc in BENCHMARK:
            c = counts.setdefault(sc.cls, {"vuln": 0, "safe": 0})
            c[sc.label] = c.get(sc.label, 0) + 1
        _SCENARIO_COUNTS = {k: {**v, "total": v["vuln"] + v["safe"]}
                            for k, v in counts.items()}
    return {k: dict(v) for k, v in _SCENARIO_COUNTS.items()}


# --- scoring ---------------------------------------------------------------

@dataclass
class ClassScore:
    cls: str
    tp: int = 0   # vuln correctly marked submittable
    fp: int = 0   # safe wrongly marked submittable  <-- the dangerous error
    tn: int = 0   # safe correctly held back
    fn: int = 0   # vuln missed (degraded to lead)
    fps: list = field(default_factory=list)   # names of safe scenarios that leaked

    @property
    def precision(self) -> float:
        d = self.tp + self.fp
        return self.tp / d if d else 1.0

    @property
    def recall(self) -> float:
        d = self.tp + self.fn
        return self.tp / d if d else 1.0

    @property
    def support(self) -> int:
        return self.tp + self.fp + self.tn + self.fn


def _evaluate(sc: Scenario) -> bool:
    fake = _fetch(sc.responder)
    # The xxe/crlf rechecks re-RUN the worker, which uses its OWN module-level fetch —
    # patch it to this scenario's responder so the whole path stays offline + fast.
    patchers = [patch(f"{mod}.fetch", fake) for mod in sc.patch_workers]
    for p in patchers:
        p.start()
    try:
        out = asyncio.run(validate_findings(
            [dict(sc.finding)], fetch=fake, bola_config=sc.bola_config,
            min_confidence=sc.min_confidence))
    finally:
        for p in patchers:
            p.stop()
    return bool(out[0].get("submittable"))


def run_benchmark(scenarios=None):
    """Run the gate over every scenario; return {cls: ClassScore}."""
    scenarios = scenarios if scenarios is not None else BENCHMARK
    scores: dict[str, ClassScore] = {}
    for sc in scenarios:
        submittable = _evaluate(sc)
        cs = scores.setdefault(sc.cls, ClassScore(sc.cls))
        if sc.label == "vuln":
            if submittable:
                cs.tp += 1
            else:
                cs.fn += 1
        else:  # safe
            if submittable:
                cs.fp += 1
                cs.fps.append(sc.name)
            else:
                cs.tn += 1
    return scores


def overall(scores) -> ClassScore:
    tot = ClassScore("OVERALL")
    for cs in scores.values():
        tot.tp += cs.tp
        tot.fp += cs.fp
        tot.tn += cs.tn
        tot.fn += cs.fn
        tot.fps.extend(f"{cs.cls}:{n}" for n in cs.fps)
    return tot


def format_scorecard(scores) -> str:
    tot = overall(scores)
    lines = [
        "VIPER validation-gate precision scorecard",
        "(safe responders must never be submittable; precision target = 1.00)",
        "",
        f"{'class':<16} {'prec':>6} {'recall':>7} {'TP':>3} {'FP':>3} {'TN':>3} {'FN':>3}",
        "-" * 52,
    ]
    for cls in sorted(scores):
        cs = scores[cls]
        flag = "  <-- FP!" if cs.fp else ""
        lines.append(f"{cls:<16} {cs.precision:>6.2f} {cs.recall:>7.2f} "
                     f"{cs.tp:>3} {cs.fp:>3} {cs.tn:>3} {cs.fn:>3}{flag}")
    lines.append("-" * 52)
    lines.append(f"{'OVERALL':<16} {tot.precision:>6.2f} {tot.recall:>7.2f} "
                 f"{tot.tp:>3} {tot.fp:>3} {tot.tn:>3} {tot.fn:>3}")
    if tot.fps:
        lines.append("")
        lines.append("FALSE POSITIVES (safe responders marked submittable):")
        for n in tot.fps:
            lines.append(f"  - {n}")
    else:
        lines.append("")
        lines.append("No false positives: every safe responder was correctly held back.")
    return "\n".join(lines)


def main(argv=None) -> int:
    import sys
    argv = list(sys.argv[1:] if argv is None else argv)
    strict = "--strict" in argv
    scores = run_benchmark()
    print(format_scorecard(scores))
    if strict and overall(scores).fp:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
