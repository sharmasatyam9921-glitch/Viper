"""False-positive regression tests for the SSTI vuln worker.

Audit scenario (confirmed FP): a benign product-search endpoint where the
asterisk '*' is a legitimate search wildcard. The control payload `${7x7}`
(no '*') matches nothing, so the body has no '49'. The live payload `${7*7}`
contains '*', is treated as a wildcard, matches the catalog, and the results
include a product priced $49. The query is HTML-escaped and reflected verbatim
-- NO template evaluation occurs. The old worker flagged this as a critical
SSTI because the bare substring '49' appeared only under the live payload.

Principle of the fix: a real template engine CONSUMES the injection
(`${7*7}` -> `49`), so the literal injection string must be ABSENT from the
live body, and independent arithmetic pairs must all agree.
"""

import asyncio
import re
import sys
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import core.swarm_workers  # noqa: F401  (registers workers)
from core.swarm_engine import SwarmAgent
from core.swarm_workers import get_worker_runner
from core.swarm_workers.vuln._http import HttpResp


def _agent(target="http://shop.example.com/search?q=widget", timeout=5.0):
    return SwarmAgent(
        agent_id="t",
        objective="x",
        target=target,
        technique="ssti_probe",
        payload={},
        timeout_s=timeout,
    )


def _run(fake, target="http://shop.example.com/search?q=widget"):
    async def go():
        with patch(
            "core.swarm_workers.vuln.ssti_probe.fetch", side_effect=fake
        ):
            return await get_worker_runner("vuln", "ssti_probe")(_agent(target))

    return asyncio.run(go())


def _injected_value(url):
    """Pull the decoded value of the fuzzed query param out of `url`."""
    from urllib.parse import parse_qsl, urlsplit

    return " ".join(v for _, v in parse_qsl(urlsplit(url).query, keep_blank_values=True))


def test_ssti_search_wildcard_false_positive_not_flagged():
    """Benign search where '*' is a catalog wildcard surfacing a $49 product.

    Reproduces the audit FP. The injected payload is HTML-escaped and
    reflected verbatim (NOT evaluated). Under the operator-intact payload
    `${7*7}` the wildcard matches a $49 product, so '49' appears; the control
    `${7x7}` matches nothing, so '49' is absent. The worker must NOT flag this.
    """

    def render(injected):
        # The query is reflected verbatim, HTML-escaped (no special chars to
        # escape here, but the literal payload text is echoed -- proving it was
        # NOT consumed by any engine).
        page = f"<html><body><h2>Results for: {injected}</h2><ul>"
        if "*" in injected:
            # '*' is a legitimate search wildcard -> the catalog matches and a
            # product priced $49 shows up. This is where the bare '49' comes from.
            page += "<li>Deluxe Widget &mdash; $49.00</li>"
            page += "<li>Mega Widget &mdash; $88.00</li>"
        # No '*' -> wildcard matches nothing.
        page += "</ul></body></html>"
        return page

    async def fake(method, url, *, headers=None, timeout=10.0, **kw):
        injected = _injected_value(url)
        return HttpResp(200, {"content-type": "text/html"}, render(injected), url)

    findings = _run(fake)
    assert findings == [], (
        "benign search-wildcard page must NOT be flagged as SSTI; "
        f"got {findings!r}"
    )


def test_ssti_real_evaluation_true_positive_still_fires():
    """A genuine template engine evaluates ANY arithmetic and CONSUMES it.

    Modelled as a real engine, not a hardcoded lookup: it computes whatever
    `N*N` (or `N*M`) expression it is handed and substitutes the PRODUCT at the
    reflection site, so the rendered number TRACKS the operands -- `${7*7}`->49,
    `${13*13}`->169, `${6*9}`->54. The operator-mutated control `NxN` is not
    arithmetic and is reflected raw. The worker must STILL flag this.
    """

    # Matches a template expression wrapping a pure `int*int` product in any of
    # the probed syntaxes; the engine replaces the WHOLE wrapper with the result.
    _EXPR = re.compile(r"(?:\$\{|\{\{|#\{|<%=\s*|\{)\s*(\d+)\*(\d+)\s*(?:\}\}|%>|\}|\})")

    def _evaluate(text):
        # A real engine: compute every embedded product and consume the wrapper.
        return _EXPR.sub(lambda m: str(int(m.group(1)) * int(m.group(2))), text)

    async def fake(method, url, *, headers=None, timeout=10.0, **kw):
        injected = _injected_value(url)
        # The engine renders the (possibly evaluated) value at a stable site.
        rendered = _evaluate(injected)
        return HttpResp(200, {"content-type": "text/html"},
                        f"<p>rendered: {rendered}</p>", url)

    findings = _run(fake)
    assert findings, "a genuinely-vulnerable template engine must STILL be flagged"
    f = findings[0]
    assert "ssti" in f["vuln_type"]
    assert f["severity"] == "critical"
    assert f["cwe"] == "CWE-1336"


def test_ssti_slug_wildcard_false_positive_not_flagged():
    """Round-2 FP: slugified reflection + catalog wildcard, no template engine.

    Two independent benign code paths, both realistic:

      1. The search backend treats '*' as a "match anything" wildcard, so the
         operator-intact payload ``${7*7}`` (which contains '*') returns the
         FULL product catalog -- which happens to list items priced $49, $64
         and $81. The control ``${7x7}`` has no '*', matches nothing, no prices.

      2. The echoed term is rendered as a canonical SLUG in the <title>/
         breadcrumb: lowercased, ``[a-z0-9]`` kept, every other run of chars
         collapsed to '-'. So ``${7*7}`` becomes ``7-7`` and the literal
         ``${7*7}`` NEVER appears verbatim -- the old "consumption" heuristic
         (literal payload absent) is satisfied by slugification, NOT evaluation.

    Result under the old rule: all three markers 49/64/81 are present (catalog),
    the literal payloads are absent (slug), the control yields no '49' -> a bogus
    CRITICAL SSTI. No template engine is involved. The worker must return [].
    """

    import re as _re

    def _slug(value):
        # canonical search slug: lowercase, [a-z0-9] kept, other runs -> '-'
        return _re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")

    # Fixed catalog: the SAME prices regardless of which operands are queried.
    _CATALOG_PRICES = ["49", "64", "81"]

    def render(injected):
        slug = _slug(injected)
        page = (
            "<html><head><title>Search: " + slug + "</title></head><body>"
            "<nav class=breadcrumb>Home / search / " + slug + "</nav>"
            "<h2>Results</h2><ul>"
        )
        if "*" in injected:
            # '*' is a legitimate catalog wildcard -> the WHOLE catalog matches,
            # and its (fixed) prices appear no matter what the operands were.
            for price in _CATALOG_PRICES:
                page += f"<li>Product &mdash; ${price}.00</li>"
        page += "</ul></body></html>"
        return page

    async def fake(method, url, *, headers=None, timeout=10.0, **kw):
        injected = _injected_value(url)
        return HttpResp(200, {"content-type": "text/html"}, render(injected), url)

    findings = _run(fake)
    assert findings == [], (
        "slugified-reflection + catalog-wildcard page must NOT be flagged as "
        f"SSTI (no template engine evaluates anything); got {findings!r}"
    )


if __name__ == "__main__":
    import pytest

    sys.exit(pytest.main([__file__, "-v"]))
