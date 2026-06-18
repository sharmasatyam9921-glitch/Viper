"""False-positive regression tests for the graphql vuln worker.

Audit (graphql) confirmed two FPs that the naive substring/structure-free
signals produce:

  (A) IDE check: a benign text/html page served at /graphql that merely
      MENTIONS "GraphiQL" in prose ("...we previously offered a GraphiQL
      explorer; it has been disabled in production") trips
      graphql_ide_exposed at MEDIUM. No live IDE, just the product name in
      prose.

  (B) Introspection check: a generic JSON API at /query whose POST response
      happens to nest data.__schema.types as a non-empty list (e.g. a
      reporting endpoint describing its column types) trips
      graphql_introspection at MEDIUM, because the check only verified the
      list was non-empty — never that the entries are GraphQL-shaped types.

Fix principle: establish what a *real* live IDE / *real* GraphQL response
looks like and only flag those — the bare keyword in benign prose, or a
non-empty list of plain strings, must NOT fire. True positives (a real
GraphiQL bootstrap, a real introspection schema with kind/fields) MUST still
fire.

These drive the REAL worker via patch on the worker-imported `fetch`.
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


def _agent(target: str = "http://t/") -> SwarmAgent:
    return SwarmAgent(
        agent_id="t",
        objective="x",
        target=target,
        technique="graphql",
        payload={},
        timeout_s=10.0,
    )


def _run(fake) -> list:
    async def go():
        with patch("core.swarm_workers.vuln.graphql.fetch", side_effect=fake):
            run = get_worker_runner("vuln", "graphql")
            return await run(_agent())

    return asyncio.run(go())


# ---------------------------------------------------------------------------
# (A) IDE-in-prose false positive  —  the audit headline
# ---------------------------------------------------------------------------

# A benign documentation / "explorer disabled" marketing page. text/html 200
# that names "GraphiQL" in human prose but has NO live IDE bootstrap markup and
# NO working POST GraphQL endpoint.
_DOCS_HTML = (
    "<!doctype html><html><head><title>API Documentation</title></head>"
    "<body><h1>Our API</h1>"
    "<p>We previously offered a GraphiQL explorer, but it has been "
    "disabled in production for security reasons. Please use our REST "
    "endpoints instead. Apollo Sandbox and GraphQL Playground are also "
    "not available.</p></body></html>"
)


async def _fake_docs_page(method, url, **kw):
    # GET returns the benign docs HTML; POST introspection is NOT honored
    # (this host has no GraphQL engine at all → connection yields nothing).
    if method == "GET" and url.endswith("/graphql"):
        return HttpResp(200, {"content-type": "text/html; charset=utf-8"},
                        _DOCS_HTML, url)
    return None


def test_graphql_ide_prose_mention_not_flagged():
    """A benign HTML page that merely names GraphiQL in prose must NOT fire."""
    findings = _run(_fake_docs_page)
    ide = [f for f in findings if f.get("type") == "graphql_ide_exposed"]
    assert ide == [], f"FP: benign prose mention flagged as IDE: {ide}"
    # And nothing else should fire for a page with no live GraphQL.
    assert findings == [], f"FP: benign docs page produced findings: {findings}"


# ---------------------------------------------------------------------------
# (B) Generic-JSON __schema false positive
# ---------------------------------------------------------------------------

# A generic reporting endpoint at /query whose JSON happens to carry
# data.__schema.types as a list of plain strings (column names). This is NOT
# GraphQL — the entries have no GraphQL "name"/"kind" shape and there is no
# queryType. Must NOT be flagged as introspection.
async def _fake_generic_json_schema(method, url, **kw):
    if method == "POST" and url.endswith("/query"):
        body = '{"data":{"__schema":{"types":["revenue","region","date"]}}}'
        return HttpResp(200, {"content-type": "application/json"}, body, url)
    # GET on /query returns nothing IDE-ish.
    return None


def test_graphql_generic_json_schema_not_flagged_as_introspection():
    """A non-GraphQL JSON API nesting __schema.types of strings must NOT fire."""
    findings = _run(_fake_generic_json_schema)
    intro = [f for f in findings if f.get("type") == "graphql_introspection"]
    assert intro == [], f"FP: generic JSON __schema flagged as introspection: {intro}"


# ---------------------------------------------------------------------------
# True positives — must STILL fire after the fix
# ---------------------------------------------------------------------------

# A genuinely live GraphiQL IDE: served as text/html with the canonical
# bootstrap markup (mount div + renderer call + bundle reference). This is what
# an actually-exposed IDE looks like, distinct from a prose mention.
_LIVE_GRAPHIQL_HTML = (
    "<!doctype html><html><head>"
    '<link rel="stylesheet" href="/static/graphiql/graphiql.min.css">'
    '<script src="//cdn.jsdelivr.net/npm/graphiql/graphiql.min.js"></script>'
    "</head><body>"
    '<div id="graphiql">Loading...</div>'
    "<script>ReactDOM.render("
    "React.createElement(GraphiQL, { fetcher: graphQLFetcher }),"
    ' document.getElementById("graphiql"));</script>'
    "</body></html>"
)


async def _fake_live_graphiql(method, url, **kw):
    if method == "GET" and url.endswith("/graphql"):
        return HttpResp(200, {"content-type": "text/html; charset=utf-8"},
                        _LIVE_GRAPHIQL_HTML, url)
    return None


def test_live_graphiql_ide_still_fires():
    """A real GraphiQL bootstrap page must STILL be flagged."""
    findings = _run(_fake_live_graphiql)
    ide = [f for f in findings if f.get("type") == "graphql_ide_exposed"]
    assert ide, f"TP regression: live GraphiQL not flagged: {findings}"
    assert ide[0]["severity"] == "medium"


# A real GraphQL introspection response: application/json, with a proper
# __schema carrying queryType and GraphQL-canonical type objects (name + kind,
# fields). This is the genuine schema leak the worker exists to catch.
_REAL_INTROSPECTION = (
    '{"data":{"__schema":{'
    '"queryType":{"name":"Query"},'
    '"mutationType":{"name":"Mutation"},'
    '"types":['
    '{"kind":"OBJECT","name":"Query","fields":[{"name":"user"},{"name":"users"}]},'
    '{"kind":"OBJECT","name":"User","fields":[{"name":"id"},{"name":"email"}]},'
    '{"kind":"SCALAR","name":"String","fields":null}'
    ']}}}'
)


async def _fake_real_introspection(method, url, **kw):
    if method == "POST" and url.endswith("/graphql"):
        return HttpResp(200, {"content-type": "application/json"},
                        _REAL_INTROSPECTION, url)
    return None


def test_real_introspection_still_fires():
    """A genuine GraphQL introspection schema must STILL be flagged."""
    findings = _run(_fake_real_introspection)
    intro = [f for f in findings if f.get("type") == "graphql_introspection"]
    assert intro, f"TP regression: real introspection not flagged: {findings}"
    assert intro[0]["severity"] == "medium"
    assert intro[0]["schema_type_count"] == 3
