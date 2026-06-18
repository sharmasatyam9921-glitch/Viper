"""False-positive regression tests for the nosql_injection vuln worker.

Audit scenario: a non-vulnerable login endpoint with always-200 error
envelopes plus a schema validator. The bogus-credential baseline returns
200 {"error":"user not found"} (no token), and the operator payload trips a
*validation* error returning 200 {"errors":{"authentication":"email and
password must be strings"}}. The bare JSON key "authentication" matched the
old _TOKEN_KEYS regex, so _has_token() reported a token even though NO session
was issued and NO Mongo query ran -> a CRITICAL auth_bypass_confirmed FP.

The fix: _has_token must require a real token VALUE (a JWT, or a
token-shaped key paired with a long token-like string value), never a bare
key name that a benign validation/error envelope happens to contain.
"""
from __future__ import annotations

import asyncio
import sys
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import core.swarm_workers  # noqa: F401,E402  (registers workers)
from core.swarm_engine import SwarmAgent  # noqa: E402
from core.swarm_workers import get_worker_runner  # noqa: E402
from core.swarm_workers.vuln._http import HttpResp  # noqa: E402

_JWT = "eyJhbGciOiJSUzI1NiJ9.eyJzdGF0dXMiOiJzdWNjZXNzIn0.AAAABBBBCCCCDDDD"


def _agent(target="http://t", timeout=5.0):
    return SwarmAgent(agent_id="t", objective="nosql injection", target=target,
                      technique="nosql_injection", payload={}, timeout_s=timeout)


def _run(fake, target="http://t"):
    async def go():
        with patch("core.swarm_workers.vuln.nosql_injection.fetch", side_effect=fake):
            return await get_worker_runner("vuln", "nosql_injection")(_agent(target))

    return asyncio.run(go())


def _is_op_body(body: bytes) -> bool:
    """True when the JSON body carries a Mongo operator (the injection)."""
    s = (body or b"").decode()
    return "$gt" in s or "$ne" in s


def test_nosql_login_false_positive_not_flagged():
    """The audit FP: a non-vulnerable endpoint whose validation-error envelope
    merely contains the literal key "authentication". No real token / session
    was ever issued, so the worker must NOT report an auth bypass."""
    def baseline_body():
        # bogus credential -> always-200 error envelope, no token keyword
        return '{"error":"user not found"}'

    def validator_body():
        # operator (non-string) payload trips the schema validator on a
        # SEPARATE code path. The literal key "authentication" appears but
        # there is NO token value and NO query ran.
        return '{"errors":{"authentication":"email and password must be strings"}}'

    async def fake(method, url, **kw):
        if not url.endswith("/rest/user/login"):
            # other login paths simply 404; query mode has no params on http://t
            return HttpResp(404, {}, "", url)
        body = kw.get("body") or b""
        if _is_op_body(body):
            return HttpResp(200, {}, validator_body(), url)
        return HttpResp(200, {}, baseline_body(), url)

    assert _run(fake) == [], (
        "non-vulnerable endpoint (validation error mentioning 'authentication', "
        "no token issued) was wrongly flagged as a NoSQL auth bypass"
    )


def test_nosql_login_true_positive_still_fires():
    """A GENUINELY vulnerable endpoint: bogus credentials get a 200 with NO
    token, but the operator-injection body returns a 200 carrying a real JWT
    session token. The worker MUST still report the auth bypass."""
    async def fake(method, url, **kw):
        if not url.endswith("/rest/user/login"):
            return HttpResp(404, {}, "", url)
        body = kw.get("body") or b""
        if _is_op_body(body):
            # operator made the credential comparison match anything -> real session
            return HttpResp(200, {}, '{"authentication":{"token":"%s"}}' % _JWT, url)
        # bogus credential -> rejected, no token
        return HttpResp(401, {}, '{"error":"invalid credentials"}', url)

    result = _run(fake)
    assert result, "genuinely vulnerable NoSQL auth bypass was missed"
    f = result[0]
    assert f["vuln_type"] == "nosql_injection:login"
    assert f["severity"] == "critical"
    assert f["cwe"] == "CWE-943"
    assert "/rest/user/login" in f["url"]


# --- Round-2 audit: benign catalog "browse-all on empty query" FP -----------
#
# Mode-2 (query-param) FP on a NON-Mongo search/listing endpoint:
# GET /search?q=shoes on a normal e-commerce catalog. The worker rewrites the
# key to q[$ne]=viper_nomatch_7c12; every strict query parser treats `q[$ne]`
# as a DISTINCT param, so the real `q` is simply ABSENT. Like virtually every
# real search page, the app renders its FULL default catalog for an
# empty/missing query, but a tiny "No products match ..." page for a query that
# matches nothing (the worker's viper_nomatch_7c12 baseline). No Mongo operator
# is ever interpreted — the body just grows because empty-query == browse-all.
# The old heuristic (sig[1] > base_sig[1]*2 and sig[1] > 256) fires and emits a
# HIGH nosql_injection:query / CWE-943 finding. That is a false positive.
#
# Fix: add a param-dropout control (the key removed / emptied). If that control
# already diverges from baseline the same way the payload does, the divergence
# is browse-all on empty query, NOT injection — suppress the finding.


def _query_only(url):
    from urllib.parse import urlsplit, parse_qsl
    return dict(parse_qsl(urlsplit(url).query))


# A full catalog page (browse-all) and a tiny "no match" page. Sizes are chosen
# so the catalog is >2x the no-match page and >256B, exactly tripping the old
# byte-ratio heuristic.
_CATALOG_HTML = (
    "<html><head><title>Shop</title></head><body><h1>All products</h1>"
    + "".join("<div class='product'>Product %02d</div>" % i for i in range(40))
    + "</body></html>"
)
_NOMATCH_HTML = (
    "<html><head><title>Shop</title></head><body>"
    "<p>No products match your search.</p></body></html>"
)


def _catalog_fake(method, url, **kw):
    """Benign catalog: full listing when `q` is absent/empty, a small no-match
    page when `q` has a value that matches nothing. Login paths 404."""
    if "/search" not in url:
        return HttpResp(404, {"content-type": "text/html"}, "", url)
    q = _query_only(url)
    # The real param is `q`. Any bracketed-operator key (q[$ne], q[$gt]) is a
    # DISTINCT param under a strict parser, so `q` is absent -> browse-all.
    qval = q.get("q")
    if qval is None or qval == "":
        body = _CATALOG_HTML            # empty/missing query -> full catalog
    elif qval == "viper_nomatch_7c12":
        body = _NOMATCH_HTML            # sentinel matches nothing -> tiny page
    else:
        body = _CATALOG_HTML            # a real term -> some results page
    return HttpResp(200, {"content-type": "text/html"}, body, url)


def test_nosql_query_browse_all_empty_query_not_flagged():
    """Benign catalog endpoint where dropping `q` yields browse-all. The
    operator-bracket payload q[$ne]= drops the real param, so the response grows
    to the full catalog vs the tiny no-match baseline. That divergence is param
    dropout, NOT injection, and must NOT be reported."""
    assert _run(_catalog_fake, target="http://t/search?q=shoes") == [], (
        "benign catalog (browse-all on empty/missing query) was wrongly flagged "
        "as a NoSQL query injection"
    )


def test_nosql_query_true_positive_still_fires():
    """A GENUINELY injectable Mongo-backed query: the viper_nomatch_7c12 sentinel
    returns a small empty-result page, removing `q` entirely returns the SAME
    small empty page (no browse-all — this app requires a query), but the
    operator payload q[$ne]= makes the Mongo filter match every row and returns
    a large result set. Divergence is attributable to the operator, not dropout,
    so the worker MUST still report it."""
    big = (
        "<html><body>" + "".join(
            '{"id":%d,"name":"row%d"}' % (i, i) for i in range(60)
        ) + "</body></html>"
    )
    small = '<html><body>{"results":[]}</body></html>'

    def fake(method, url, **kw):
        if "/search" not in url:
            return HttpResp(404, {"content-type": "text/html"}, "", url)
        q = _query_only(url)
        # Genuine NoSQL: the operator key q[$ne] is interpreted by Mongo as
        # "field q not-equal sentinel" -> matches everything -> big body.
        if any(k.startswith("q[") for k in q):
            return HttpResp(200, {"content-type": "text/html"}, big, url)
        # `q` absent/empty OR sentinel value -> empty result set (no browse-all).
        return HttpResp(200, {"content-type": "text/html"}, small, url)

    result = _run(fake, target="http://t/search?q=shoes")
    assert result, "genuinely injectable NoSQL query was missed"
    f = result[0]
    assert f["vuln_type"] == "nosql_injection:query"
    assert f["severity"] == "high"
    assert f["cwe"] == "CWE-943"
    assert f["parameter"] == "q"
