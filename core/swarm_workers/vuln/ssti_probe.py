"""Server-Side Template Injection probe (vuln phase, response-based).

Injects polyglot arithmetic payloads into query parameters and confirms SSTI
only when the response shows the *hallmarks of evaluation* — never on a bare
substring a benign page might already carry.

A real template engine does two things to `${7*7}`:

  1. it CONSUMES the injection — the literal `${7*7}` is replaced by `49`, so
     the injection text is *gone* from the rendered body; and
  2. it does this for every arithmetic expression — `${8*8}`->`64`,
     `${9*9}`->`81` — because it actually computes them.

The old single-pair rule ("`49` present under the live payload but not the
control") was too weak: a search endpoint where `*` is a legitimate wildcard
matches the catalog under `${7*7}` (because of the `*`), surfaces a product
priced `$49`, and HTML-escapes-and-reflects the payload verbatim — yielding the
bare `49` with NO template evaluation at all. That is a confirmed false
positive.

So for the high-confidence (critical) signal we now require, per parameter,
that a probed pair (a) surface its evaluated marker under the live
operator-intact payload, (b) NOT surface it under the operator-mutated
control, AND (c) have CONSUMED the injection — the literal `${7*7}` text must
be ABSENT from the live body, because an engine that computed `49` replaced the
expression with it. The search-wildcard false positive reflects the payload
verbatim, so (c) fails and it is never flagged, even though the bare `49` from
a $49 product is present.

We additionally probe several independent operand pairs (`7*7`->`49`,
`8*8`->`64`, `9*9`->`81`) through the same syntax; every pair that a real
engine consumes raises confidence. A wildcard/search coincidence cannot conjure
`49`, `64` and `81` on demand for three different operands, nor consume the
payload, so it satisfies none of them.

Each payload targets a different template engine syntax:

    ${N*N}      — Spring SpEL / Java EL / Thymeleaf / Velocity-style
    {{N*N}}     — Jinja2 / Twig / Nunjucks / Angular
    #{N*N}      — JSF EL / Ruby (some) / Spring
    <%= N*N %>  — ERB / EJS / JSP
    {N*N}       — Tornado / simple brace engines

We also flag well-known template-engine *error* strings (often emitted when an
engine partially parses a payload) as a lower-confidence signal.

Detection only — payloads are pure arithmetic, never touch the filesystem,
environment, or process. Non-destructive (GET only) and idempotent.
"""

from __future__ import annotations

import logging
import re
from typing import List, Optional
from urllib.parse import parse_qsl, urlsplit

from core.swarm_engine import SwarmAgent
from core.swarm_workers import register_worker

from ._http import HttpResp, add_query, fetch, normalize_target_url

logger = logging.getLogger("viper.swarm_workers.vuln.ssti_probe")

TECHNIQUE = "ssti_probe"

# Default params to fuzz when the target URL carries none of its own.
_DEFAULT_PARAMS = ["id", "name", "q", "search", "page", "template", "view", "lang"]

# Template-engine syntaxes. Each is a (open, close) wrapper rendered around an
# arithmetic expression. We probe several independent operand pairs through the
# SAME wrapper so a real engine must agree on all of them.
_SYNTAXES = [
    ("${", "}"),       # Spring SpEL / Java EL / Thymeleaf / Velocity-style
    ("{{", "}}"),      # Jinja2 / Twig / Nunjucks / Angular
    ("#{", "}"),       # JSF EL / Ruby (some) / Spring
    ("<%= ", " %>"),   # ERB / EJS / JSP
    ("{", "}"),        # Tornado / simple brace engines
]

# Independent arithmetic pairs: (expression, evaluated-marker). Distinct
# products with no common factor so one coincidental number cannot satisfy two.
# The first pair drives the per-syntax control; corroboration needs >= MIN_PAIRS
# of these to evaluate.
_ARITH = [
    ("7*7", "49"),
    ("8*8", "64"),
    ("9*9", "81"),
]

# A critical finding requires at least this many independent pairs to evaluate
# AND be consumed for the same parameter+syntax. Consumption (the literal
# payload absent from the body) is what defeats the search-wildcard false
# positive, so a single consumed evaluation already excludes it; extra pairs
# only enrich the evidence.
MIN_PAIRS = 1


def _wrap(open_: str, close: str, expr: str) -> str:
    return f"{open_}{expr}{close}"


def _control_expr(expr: str) -> str:
    """Operator-mutated twin: 7*7 -> 7x7. Structurally identical, never math."""
    return expr.replace("*", "x")

# Known template-engine error signatures (lower-confidence corroboration).
_ERROR_SIGNATURES = [
    "jinja2.exceptions",
    "TemplateSyntaxError",
    "freemarker.core",
    "org.apache.velocity",
    "org.springframework.expression",
    "SpelEvaluationException",
    "twig\\Error",
    "Twig\\Error",
    "Smarty error",
    "TemplateProcessingException",
    "MustacheException",
    "could not be parsed as a template",
    "EL1008E",  # Spring SpEL property-not-found
]
_ERROR_RE = re.compile("|".join(re.escape(s) for s in _ERROR_SIGNATURES))

# The evaluated marker (`49`) must not already be present in the control
# response, otherwise its appearance under the live payload proves nothing.


def _params_for(url: str) -> List[str]:
    """Existing query keys if any, else the default fuzz set."""
    existing = [k for k, _ in parse_qsl(urlsplit(url).query, keep_blank_values=True)]
    return existing or _DEFAULT_PARAMS


def _body(resp: Optional[HttpResp]) -> str:
    return resp.body if (resp and resp.body) else ""


async def run(agent: SwarmAgent) -> List[dict]:
    url = normalize_target_url(agent.target)
    if not url:
        return []
    timeout = min(agent.timeout_s, 10.0)
    findings: list[dict] = []
    seen_params: set[str] = set()

    for param in _params_for(url):
        if param in seen_params:
            continue
        for open_, close in _SYNTAXES:
            if param in seen_params:
                break

            # --- per-syntax control on the FIRST pair ----------------------
            # Establish that the leading evaluated marker is NOT already in the
            # page when we send a structurally-identical, non-evaluating twin
            # (operator mutated 7*7 -> 7x7). This kills FPs on pages that just
            # contain "49" regardless of input.
            first_expr, first_marker = _ARITH[0]
            ctrl_payload = _wrap(open_, close, _control_expr(first_expr))
            ctrl_resp = await fetch(
                "GET", add_query(url, param, ctrl_payload), timeout=timeout
            )
            if ctrl_resp is None:
                continue
            ctrl_body = _body(ctrl_resp)
            if first_marker in ctrl_body:
                # Page already shows the marker without evaluation — untrustable.
                continue

            # --- probe every independent arithmetic pair -------------------
            # A genuine engine must (a) surface the evaluated marker AND
            # (b) CONSUME the injection (the literal payload text is gone from
            # the body). A page that reflects the payload verbatim — the
            # search-wildcard false positive — fails (b) even if some unrelated
            # number happens to appear.
            confirmed: list[tuple[str, str]] = []  # (payload, marker)
            evidence_bits: list[str] = []
            for expr, marker in _ARITH:
                live_payload = _wrap(open_, close, expr)
                live_resp = await fetch(
                    "GET", add_query(url, param, live_payload), timeout=timeout
                )
                if live_resp is None:
                    continue
                live_body = _body(live_resp)
                # (a) evaluated marker must be present, and (b) the literal
                # injection must have been consumed (absent from the body).
                if marker in live_body and live_payload not in live_body:
                    confirmed.append((live_payload, marker))
                    evidence_bits.append(f"{live_payload!r}->{marker!r}")

            if len(confirmed) >= MIN_PAIRS:
                lead_payload = confirmed[0][0]
                findings.append({
                    "type": "ssti",
                    "vuln_type": "ssti",
                    "title": f"Server-Side Template Injection in '{param}'",
                    "severity": "critical",
                    "url": url,
                    "parameter": param,
                    "payload": lead_payload,
                    "cwe": "CWE-1336",
                    "confidence": 0.9,
                    "evidence": (
                        f"{len(confirmed)} independent arithmetic expressions "
                        f"were evaluated and consumed ("
                        + ", ".join(evidence_bits)
                        + f"); the literal payloads were absent from the body "
                        f"(template engine computed them), while the control "
                        f"{ctrl_payload!r} did not yield {first_marker!r}"
                    ),
                })
                seen_params.add(param)
                break

            # --- lower-confidence: template-engine error under live payload --
            # Re-fetch the leading live payload only if we didn't already get a
            # consumed evaluation. An engine error string present under the
            # injection but not the control is medium-confidence corroboration.
            if param not in seen_params:
                lead_payload = _wrap(open_, close, first_expr)
                err_resp = await fetch(
                    "GET", add_query(url, param, lead_payload), timeout=timeout
                )
                if err_resp is None:
                    continue
                err_body = _body(err_resp)
                err = _ERROR_RE.search(err_body)
                # The error string must be a genuine engine error, not merely
                # the reflected payload, and must be absent from the control.
                if err and not _ERROR_RE.search(ctrl_body):
                    findings.append({
                        "type": "ssti",
                        "vuln_type": "ssti_error",
                        "title": (
                            f"Template-engine error triggered by injection in "
                            f"'{param}'"
                        ),
                        "severity": "medium",
                        "url": url,
                        "parameter": param,
                        "payload": lead_payload,
                        "cwe": "CWE-1336",
                        "confidence": 0.5,
                        "evidence": (
                            f"payload {lead_payload!r} produced template-engine "
                            f"error signature {err.group(0)!r} not present for "
                            f"the control {ctrl_payload!r}"
                        ),
                    })
                    seen_params.add(param)
                    break

    return findings


register_worker("vuln", TECHNIQUE, run)
