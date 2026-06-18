"""False-positive regression tests for the sqli_probe swarm worker.

Two audit-confirmed false positives:

  (1) A static, non-vulnerable Postgres tutorial page (GET /blog/...?id=42)
      that ALWAYS returns the same clean 200 HTML containing the ordinary
      English words "JDBC driver" and "psql command-line client". The old
      bare-keyword regex matched "JDBC"/"psql" and emitted a high-severity
      sqli finding. There is no DB and nothing executes.

  (2) A non-vulnerable /search?q=shoes page that never errors but has normal
      per-request variability (a fresh CSRF token + a rotating promo block),
      which tripped the boolean-blind length-divergence path.

Both must now return [] while genuinely-vulnerable targets still fire.

Run: python -m pytest tests/test_sqli_probe_fp.py -q
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


def _agent(target: str) -> SwarmAgent:
    return SwarmAgent(
        agent_id="t",
        objective="x",
        target=target,
        technique="sqli_probe",
        payload={},
        timeout_s=10.0,
    )


def _run(fake):
    async def go():
        with patch("core.swarm_workers.vuln.sqli_probe.fetch", side_effect=fake):
            run = get_worker_runner("vuln", "sqli_probe")
            return await run(_agent("http://docs.example.com/blog?id=42"))
    return asyncio.run(go())


# ---------------------------------------------------------------------------
# (a) FALSE POSITIVE — must return []  (FAILS before the fix)
# ---------------------------------------------------------------------------

# A real tutorial body: it names "JDBC driver" and "psql" in plain prose.
# The OLD regex matched those bare keywords -> bogus high-severity finding.
_TUTORIAL_HTML = (
    "<!doctype html><html><head><title>Connecting your app to Postgres</title>"
    "</head><body><h1>Connecting Postgres</h1>"
    "<p>Most JVM apps connect using the official PostgreSQL JDBC driver, "
    "while shell users prefer the psql command-line client. This guide walks "
    "through configuring a connection pool and running your first query.</p>"
    "<p>You can verify connectivity with a simple SELECT 1 statement.</p>"
    "</body></html>"
)


def test_static_postgres_tutorial_not_flagged():
    """Static non-vulnerable docs page: SAME clean 200 for every request.

    Reflects nothing, executes nothing; body merely *mentions* JDBC/psql.
    Worker MUST return []. (Pre-fix this returns a high-severity sqli finding.)
    """
    resp = HttpResp(200, {"content-type": "text/html"}, _TUTORIAL_HTML,
                    "http://docs.example.com/blog?id=42")

    async def fake(method, url, *, headers=None, timeout=10.0, **kw):
        # Every request — benign baseline, quote payload, boolean pairs —
        # returns the identical static page.
        return resp

    findings = _run(fake)
    assert findings == [], f"FALSE POSITIVE: static tutorial flagged: {findings}"


def test_search_page_natural_jitter_not_flagged():
    """Non-vulnerable /search that never errors but jitters per request.

    A fresh CSRF token + rotating promo block change the body length on every
    request regardless of payload. The boolean-blind path MUST NOT flag this.
    """
    import itertools
    promos = itertools.cycle([
        "Promo: 10% off boots today only!",
        "Promo: free shipping on orders over fifty dollars",
        "Promo: members earn double points this week",
    ])
    counter = itertools.count()

    def page(method, url, *, headers=None, timeout=10.0, **kw):
        # CSRF token length + promo content vary every request, independent of
        # the query value — pure content variance, no SQL behaviour.
        token = "csrf_%032x" % next(counter)
        promo = next(promos)
        body = (
            "<!doctype html><html><body>"
            "<form><input type=hidden name=csrf value=" + token + ">"
            "<input name=q></form>"
            "<div class=promo>" + promo + "</div>"
            "<p>Search results for shoes. 12 products found.</p>"
            "</body></html>"
        )
        return HttpResp(200, {"content-type": "text/html"}, body, url)

    async def fake(method, url, *, headers=None, timeout=10.0, **kw):
        return page(method, url, headers=headers, timeout=timeout, **kw)

    async def go():
        with patch("core.swarm_workers.vuln.sqli_probe.fetch", side_effect=fake):
            run = get_worker_runner("vuln", "sqli_probe")
            return await run(_agent("http://shop.example.com/search?q=shoes"))

    findings = asyncio.run(go())
    blinds = [f for f in findings if "blind" in f.get("vuln_type", "")]
    assert blinds == [], f"FALSE POSITIVE: jitter flagged as blind sqli: {blinds}"


# ---------------------------------------------------------------------------
# (b) TRUE POSITIVE — worker must STILL fire
# ---------------------------------------------------------------------------

def test_true_positive_error_banner_still_fires():
    """A genuinely vulnerable param: the quote payload "1'" breaks the query
    and the server returns a REAL MySQL error that is ABSENT from the benign
    baseline. Worker MUST still emit a high-severity finding."""
    clean = HttpResp(200, {"content-type": "text/html"},
                     "<html><body>Product #1: Running shoe</body></html>",
                     "http://shop.example.com/item?id=1")
    errored = HttpResp(500, {"content-type": "text/html"},
                       "<html><body>You have an error in your SQL syntax; "
                       "check the manual near '\\'' at line 1</body></html>",
                       "http://shop.example.com/item?id=1'")

    async def fake(method, url, *, headers=None, timeout=10.0, **kw):
        # The single quote is url-encoded as %27 in the request URL.
        if "id=1%27" in url or "id=1'" in url:
            return errored
        return clean  # benign baseline + everything else

    async def go():
        with patch("core.swarm_workers.vuln.sqli_probe.fetch", side_effect=fake):
            run = get_worker_runner("vuln", "sqli_probe")
            return await run(_agent("http://shop.example.com/item?id=1"))

    findings = asyncio.run(go())
    sqlis = [f for f in findings if f["type"] == "sqli"]
    assert sqlis, "TRUE POSITIVE missed: real differential SQL error not flagged"
    assert sqlis[0]["severity"] == "high"
    assert sqlis[0]["cwe"] == "CWE-89"


def test_true_positive_boolean_blind_still_fires():
    """Genuine boolean-blind: the page is stable across benign requests, but
    AND 1=1 returns the full product list while AND 1=2 returns an empty list.
    The directional gap reproduces on the confirming 1 OR 1=1 pair."""
    stable = "<html><body>" + ("row " * 50) + "</body></html>"        # baseline
    true_body = "<html><body>" + ("row " * 200) + "</body></html>"    # many rows
    false_body = "<html><body>No results.</body></html>"              # zero rows

    async def fake(method, url, *, headers=None, timeout=10.0, **kw):
        # url-encoded: "1 AND 1=1" -> 1+AND+1%3D1 ; "1 AND 1=2" -> ...1%3D2 ;
        # "1 OR 1=1" -> 1+OR+1%3D1 (also contains 1%3D1).
        if "AND+1%3D2" in url:
            return HttpResp(200, {}, false_body, url)
        if "1%3D1" in url:  # AND 1=1 and OR 1=1 (both true-like)
            return HttpResp(200, {}, true_body, url)
        # benign baseline (?id=1) and the quote probe — stable, no error
        return HttpResp(200, {}, stable, url)

    async def go():
        with patch("core.swarm_workers.vuln.sqli_probe.fetch", side_effect=fake):
            run = get_worker_runner("vuln", "sqli_probe")
            return await run(_agent("http://shop.example.com/list?id=1"))

    findings = asyncio.run(go())
    blinds = [f for f in findings if "blind" in f.get("vuln_type", "")]
    assert blinds, "TRUE POSITIVE missed: genuine boolean-blind not flagged"
    assert blinds[0]["cwe"] == "CWE-89"
