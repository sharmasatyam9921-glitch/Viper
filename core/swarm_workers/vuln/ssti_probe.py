"""Server-Side Template Injection probe (vuln phase, response-based).

Injects polyglot arithmetic payloads into query parameters and confirms SSTI
only when the response shows the *hallmarks of evaluation* — never on a bare
substring a benign page might already carry.

A real template engine, given `${7*7}`, returns `49` AT THE PLACE THE
EXPRESSION WAS WRITTEN, and given `${13*13}` returns `169` at that same place —
the rendered number TRACKS the operands. Nothing else does this.

Two confirmed false positives motivate the current rule:

  1. A search endpoint where `*` is a legitimate wildcard: `${7*7}` contains a
     `*`, matches the catalog, surfaces a product priced `$49`, and reflects the
     payload verbatim — the bare `49` appears with NO evaluation.
  2. A storefront that slugifies the echoed term (`${7*7}` -> `7-7`) for a
     canonical <title>/breadcrumb while ALSO treating `*` as a catalog wildcard:
     the catalog lists items priced `$49/$64/$81`, and the literal payload is
     gone (consumed by SLUGIFICATION, not evaluation). The old "literal payload
     absent" consumption heuristic was satisfied with no engine present.

The defeat for BOTH is the same and is what we now require: the evaluated
marker must (a) appear AT THE REFLECTION SITE — the slot where our injected
value round-trips into the body, located first with a benign sentinel — not
merely somewhere on the page (where catalog prices live); and (b) TRACK THE
OPERANDS — we probe operand pairs with unique products (`7*7`->`49`,
`13*13`->`169`, `6*9`->`54`) and require that each pair's marker appears at the
reflection slot under ITS OWN operands and is ABSENT at that slot under a
DIFFERENT pair's operands. A fixed catalog returns the same `49/64/81` for every
`*`-bearing payload regardless of operands, so it can never make `169` appear
for `13*13` while keeping `49` out — operand-tracking fails and it is not
flagged.

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

# Independent arithmetic pairs: (expression, evaluated-marker). Products are
# pairwise distinct AND none is a substring of another, so a marker can never be
# explained by a different pair's number. We require the marker to TRACK the
# operands across pairs: a real engine produces 49 for 7*7 and 169 for 13*13,
# whereas a fixed catalog/wildcard surfaces the same prices for every payload.
_ARITH = [
    ("7*7", "49"),
    ("13*13", "169"),
    ("6*9", "54"),
]

# A critical finding requires at least this many independent operand pairs to
# evaluate AT THE REFLECTION SITE for the same parameter+syntax. Operand-
# tracking needs at least two pairs to be meaningful (one pair alone cannot
# distinguish "the engine computed it here" from "this number was already
# here"), so MIN_PAIRS is 2.
MIN_PAIRS = 2

# Sentinel used to LOCATE the reflection site. A benign, arithmetic-free token
# that a slugifier keeps recognizable (lowercase alnum) and that no catalog/page
# is likely to carry. We split it with a marker-like middle ('7') so we can see
# how the reflection transforms separators without depending on engine output.
_SENTINEL = "viper7canary7probe"


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
    """Existing query keys if any, else the default fuzz set, plus any params the
    crawler discovered this hunt (empty by default -> unchanged behavior)."""
    existing = [k for k, _ in parse_qsl(urlsplit(url).query, keep_blank_values=True)]
    base = existing or list(_DEFAULT_PARAMS)
    from core.payload_library import get_discovered_params
    disc = get_discovered_params()
    if disc:
        return list(dict.fromkeys(base + list(_DEFAULT_PARAMS) + disc))
    return base


def _body(resp: Optional[HttpResp]) -> str:
    return resp.body if (resp and resp.body) else ""


# How far past each reflection anchor we look for the evaluated marker. An
# engine writes the number where the expression sat — immediately after the
# stable text that preceded our value. Narrow enough to exclude catalog prices
# living in unrelated elements elsewhere on the page.
_SLOT_RADIUS = 48

# Length of the stable LEFT-CONTEXT anchor captured just before the reflection.
_ANCHOR_LEN = 16


def _reflection_anchors(sentinel_body: str, sentinel: str) -> List[str]:
    """Stable LEFT-CONTEXT strings that immediately precede the reflection site.

    We send a benign sentinel, find where it round-trips into the body, and
    capture the `_ANCHOR_LEN` characters of surrounding markup that come JUST
    BEFORE it. That left-context is stable across requests (it's the page's own
    markup, e.g. ``<title>Search: ``), so when we later inject ``${7*7}`` the
    engine writes the evaluated ``49`` right after the SAME left-context — at the
    reflection site — whereas catalog prices sit after unrelated markup.

    The sentinel itself may be reflected raw, lowercased, slug-collapsed, or
    HTML-escaped, so we anchor on what precedes it (page markup), never on the
    reflected value (which changes when the payload changes).
    """
    low = sentinel_body.lower()
    s = sentinel.lower()
    anchors: list[str] = []
    # Locate the sentinel by the longest contiguous run that survived; tolerate
    # case-folding and partial slug collapse.
    for size in range(len(s), 5, -1):
        frag = s[:size]
        idx = low.find(frag)
        if idx != -1:
            i = idx
            while i != -1:
                lo = max(0, i - _ANCHOR_LEN)
                ctx = sentinel_body[lo:i]
                if ctx and ctx not in anchors:
                    anchors.append(ctx)
                i = low.find(frag, i + 1)
            break
    return anchors


def _marker_at_slot(body: str, anchors: List[str], marker: str) -> bool:
    """True iff `marker` appears within `_SLOT_RADIUS` AFTER a reflection anchor.

    Binds the marker to the reflection site: the evaluated number must sit just
    past the same left-context the sentinel did. Prices in distant <li> elements
    fall outside every anchor window and are ignored.
    """
    for anchor in anchors:
        start = 0
        a = anchor
        while True:
            i = body.find(a, start)
            if i == -1:
                break
            slot = body[i + len(a): i + len(a) + _SLOT_RADIUS]
            if marker in slot:
                return True
            start = i + 1
    return False


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

            # --- locate the reflection site with a benign sentinel ---------
            # SSTI surfaces in REFLECTED output. Send an arithmetic-free token
            # and capture the stable left-context that precedes wherever it
            # round-trips. We then only believe an evaluated marker that lands at
            # that same site — defeating catalog prices echoed elsewhere on the
            # page (both the search-wildcard and the slug+wildcard FPs).
            sent_resp = await fetch(
                "GET", add_query(url, param, _SENTINEL), timeout=timeout
            )
            if sent_resp is None:
                continue
            anchors = _reflection_anchors(_body(sent_resp), _SENTINEL)
            if not anchors:
                # Input doesn't reflect through this param → no SSTI surface here.
                continue

            # --- probe every independent operand pair ----------------------
            # For a genuine engine the evaluated marker (a) appears AT THE
            # REFLECTION SITE and (b) TRACKS THE OPERANDS: ${7*7}->49 there,
            # ${13*13}->169 there, and crucially each pair's marker is ABSENT at
            # that site under a DIFFERENT pair's operands. A fixed catalog
            # surfaces the same 49/64/81 for every '*'-payload regardless of
            # operands, so it can never make 169 appear for 13*13 while keeping
            # 49 out — operand-tracking fails and it is not flagged.
            live_bodies: dict[str, str] = {}  # expr -> body
            for expr, _ in _ARITH:
                live_payload = _wrap(open_, close, expr)
                live_resp = await fetch(
                    "GET", add_query(url, param, live_payload), timeout=timeout
                )
                if live_resp is None:
                    continue
                live_bodies[expr] = _body(live_resp)

            confirmed: list[tuple[str, str]] = []  # (payload, marker)
            evidence_bits: list[str] = []
            for expr, marker in _ARITH:
                body = live_bodies.get(expr)
                if body is None:
                    continue
                # (a) this pair's marker must sit at the reflection site.
                if not _marker_at_slot(body, anchors, marker):
                    continue
                # (b) operand-tracking: NO OTHER pair's marker may sit at the
                # reflection site under THIS pair's operands. (A fixed catalog
                # spills every price at once and fails here.)
                others_leaked = any(
                    om != marker and _marker_at_slot(body, anchors, om)
                    for _, om in _ARITH
                )
                if others_leaked:
                    continue
                live_payload = _wrap(open_, close, expr)
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
                        f"evaluated AT THE REFLECTION SITE, tracking their "
                        f"operands ("
                        + ", ".join(evidence_bits)
                        + f"); each marker appeared only under its own operands "
                        f"(not the others'), while the control "
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
