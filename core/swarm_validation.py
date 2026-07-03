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
    """Confirm the reflection lands as LIVE, UNENCODED markup in an HTML context —
    not entity-encoded (the secure outcome) and not a non-HTML body."""
    import secrets
    from core.swarm_workers.vuln._http import add_query
    param = finding.get("parameter")
    url = finding.get("url") or ""
    if not param or not url:
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
        if not _SECRET_PLACEHOLDER.search(tok) and not _SECRET_PLACEHOLDER.search(ctx):
            return True, 0.75, f"live-looking credential reproduced ({tok[:4]}…)"
    return False, 0.2, "only placeholder/example credentials (or none) — manual review"


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
    if _SENSITIVE.search(body):
        return True, 0.7, "protected endpoint returns strongly-private data ANONYMOUSLY (2xx)"
    return False, 0.2, "anonymous access returns no strongly-private content"


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
    if ":weak_key" not in vt or vt.endswith(("_noauth", "_sample")):
        return False, 0.3, "jwt observation — no safe read-only auto-confirmation (lead)"
    endpoint = (finding.get("jwt_probe_endpoint") or "").strip()
    if not endpoint:
        return False, 0.3, ("weak HMAC key recovered OFFLINE, but the server's acceptance "
                            "of a forged token is unproven — supply jwt_probe_endpoint (an "
                            "in-scope authed GET) to confirm forgeability (lead)")
    tok = finding.get("jwt_token") or ""
    key = finding.get("jwt_key")
    alg = (finding.get("jwt_alg") or "").upper()
    if not tok or key is None or alg not in ("HS256", "HS384", "HS512"):
        return False, 0.0, "jwt finding missing token/key/alg for a forge-probe (lead)"
    import hashlib as _hashlib
    import hmac as _hmac
    import json as _json
    import secrets as _secrets
    from core.swarm_workers.vuln.jwt import _b64url_encode, _parse_jwt
    parsed = _parse_jwt(tok)
    if not parsed:
        return False, 0.0, "could not parse the original JWT to forge (lead)"
    header, payload, _ = parsed
    payload = dict(payload)
    payload["viper_recheck"] = _secrets.token_hex(6)   # benign marker; no privilege change
    digest = {"HS256": _hashlib.sha256, "HS384": _hashlib.sha384,
              "HS512": _hashlib.sha512}[alg]
    h_b64 = _b64url_encode(_json.dumps(header, separators=(",", ":")).encode())
    p_b64 = _b64url_encode(_json.dumps(payload, separators=(",", ":")).encode())
    signing_input = (h_b64 + "." + p_b64).encode("ascii")
    good_sig = _b64url_encode(_hmac.new(key.encode("utf-8"), signing_input, digest).digest())
    forged = f"{h_b64}.{p_b64}.{good_sig}"
    control = f"{h_b64}.{p_b64}.{_b64url_encode(b'viper-invalid-signature')}"
    src = (finding.get("jwt_source") or "authorization").lower()

    async def _probe(token):
        headers = {"Authorization": f"Bearer {token}"}
        if src and src != "authorization":     # token was set as a cookie
            headers["Cookie"] = f"{src}={token}"
        return await fetch("GET", endpoint, headers=headers, timeout=timeout,
                           use_session_auth=False)
    # Send the forged token TWICE, bracketing the control. A stateless weak-key
    # verifier accepts the SAME forged token every time; a stateful endpoint (nonce,
    # single-use, first-request-wins) rejects the repeat — so a control-401 there is
    # order/state-dependent, not a signature verdict. Confirm only when the forged
    # token is accepted BOTH times AND the control is rejected: then the sole reason
    # the control differs is its bad signature, proving weak-key signature bypass.
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
        return True, 0.85, (f"server accepted a weak-key-forged token REPEATABLY (HTTP "
                            f"{fs}/{fs2}) but rejected a bad-signature control (HTTP {cs}) "
                            "— stateless signature verification with the recovered key; "
                            "JWT forgery confirmed (CWE-347)")
    if (200 <= fs < 300) and not (200 <= fs2 < 300):
        return False, 0.2, (f"forged token accepted once (HTTP {fs}) then rejected on repeat "
                            f"(HTTP {fs2}) — order/state-dependent (nonce/single-use/replay), "
                            "not a stateless weak-key signature bypass (lead)")
    if (200 <= fs < 300) and (200 <= cs < 300):
        return False, 0.2, ("both the forged and the bad-signature token were accepted — "
                            "the endpoint does not verify signatures / needs no auth; not "
                            "a weak-key forgery proof (lead)")
    return False, 0.2, (f"forged token not accepted (HTTP {fs}) — weak key recovered but "
                        "forgery unconfirmed at this endpoint (lead)")


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
    if head.startswith("graphql"):
        return await _recheck_graphql(finding, fetch, timeout)
    if head == "nosql_injection":
        return await _recheck_nosql(finding, fetch, timeout)
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
    # Client-side prototype pollution is found by STATIC JS analysis (a user-input
    # source reaching a prototype-touching sink). Confirming it needs a real browser
    # to pollute and observe the DOM — the read-only gate does not drive one, and
    # polluting server-side would be destructive — so it stays a manual-review lead.
    if head == "prototype_pollution":
        return False, 0.3, ("client-side prototype-pollution gadget (user-input source + "
                            "prototype-reaching sink in the page's JS). Confirming needs a "
                            "browser/DOM probe the read-only gate does not run — verify "
                            "manually (lead)")

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
                    ok, conf, reason = await _reconfirm(g, fetch, timeout, bola_config,
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
