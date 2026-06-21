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
    benign = await fetch("GET", add_query(url, param, "1"), timeout=timeout)
    q1 = await fetch("GET", add_query(url, param, "1'"), timeout=timeout)
    bal = await fetch("GET", add_query(url, param, "1''"), timeout=timeout)
    if None in (benign, q1, bal):
        return False, 0.0, "re-fetch failed"
    if _waf_block(q1):
        return False, 0.1, "quote was blocked by a WAF/edge, not executed by a database"

    def dberr(r):  # a genuine DB error: an error signature AND a 5xx (query broke)
        return bool(_SQL_ERR.search(_body(r))) and getattr(r, "status", 0) >= 500
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
        return True, 0.85, ("command injection reproduced with EXECUTED command output "
                            "(marker echoed) — not timing-only")
    if any("cmdi" in str(f.get("vuln_type", "")) for f in fs):
        return False, 0.3, ("only a timing-based signal reproduced (no executed output) "
                            "— a tarpit can fake this; manual corroboration needed (lead)")
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
    if head == "access_control":
        return await _recheck_access_control(finding, fetch, timeout)
    # Two-account BOLA: the find_bola engine already proved a cross-user read with
    # owner+attacker+anon probes — that IS the independent confirmation. (Only the
    # engine's own findings get this trust; external ones fall through to re-test.)
    if (":bola:" in vt_full or head == "bola") and not _external \
            and finding.get("owner") and finding.get("attacker"):
        return True, 0.85, "two-account cross-user object read confirmed by the BOLA engine"
    # Single-session IDOR candidate: auto-escalate to the two-account BOLA test
    # when two sessions are configured; otherwise stay a lead.
    if head == "idor":
        return await _recheck_idor(finding, fetch, timeout, bola_config)

    # Classes with no SAFE read-only confirmation -> stay a LEAD (fail-closed):
    #   single-session idor  -> needs two accounts (use the two-account BOLA flow)
    #   mass_assignment      -> needs a write + read-back (non-destructive: no writes)
    #   jwt / nosql          -> need the auth flow / a body mutation to prove impact
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

    out: List[dict] = []
    for f in findings:
        g = dict(f)
        vt = g.get("vuln_type", g.get("type", ""))
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
        out.append(g)
        logger.debug("validate %s -> validated=%s conf=%.2f submittable=%s",
                     vt, g["validated"], g["validation_confidence"], g["submittable"])
    return out


def partition(findings: List[dict]) -> Tuple[List[dict], List[dict]]:
    """Split annotated findings into (submittable, leads)."""
    submittable = [f for f in findings if f.get("submittable")]
    leads = [f for f in findings if not f.get("submittable")]
    return submittable, leads
