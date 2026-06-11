"""Server-Side Template Injection probe (vuln phase, response-based).

Injects polyglot arithmetic payloads into query parameters and confirms SSTI
ONLY when the *evaluated* result (`49` for `7*7`) appears in the response body
but did NOT appear for a benign control payload (`7x7`). The control request
defeats false positives on pages that already contain the literal string `49`
(prices, ids, timestamps, ...).

Each payload targets a different template engine syntax:

    ${7*7}      — Spring SpEL / Java EL / Thymeleaf / Velocity-style
    {{7*7}}     — Jinja2 / Twig / Nunjucks / Angular
    #{7*7}      — JSF EL / Ruby (some) / Spring
    <%= 7*7 %>  — ERB / EJS / JSP
    {7*7}       — Tornado / simple brace engines

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

# Polyglot math payloads: (injection, evaluated-marker, control).
# The control mutates the operator so a non-vulnerable reflection of the raw
# payload never matches the evaluated marker.
_PAYLOADS = [
    ("${7*7}", "49", "${7x7}"),
    ("{{7*7}}", "49", "{{7x7}}"),
    ("#{7*7}", "49", "#{7x7}"),
    ("<%= 7*7 %>", "49", "<%= 7x7 %>"),
    ("{7*7}", "49", "{7x7}"),
]

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
        for inject, marker, control in _PAYLOADS:
            # Control first: establish that the evaluated marker is NOT already
            # in the page when we send a structurally-similar, non-evaluating
            # payload. This kills FPs on pages that just contain "49".
            ctrl_resp = await fetch(
                "GET", add_query(url, param, control), timeout=timeout
            )
            if ctrl_resp is None:
                continue
            ctrl_body = _body(ctrl_resp)
            if marker in ctrl_body:
                # Page already shows "49" regardless of evaluation — can't trust
                # the marker for this param/payload. Skip to avoid a false flag.
                continue

            live_resp = await fetch(
                "GET", add_query(url, param, inject), timeout=timeout
            )
            if live_resp is None:
                continue
            live_body = _body(live_resp)

            # High-confidence: evaluated result appeared only under the live
            # (operator-intact) payload.
            if marker in live_body:
                findings.append({
                    "type": "ssti",
                    "vuln_type": "ssti",
                    "title": f"Server-Side Template Injection in '{param}'",
                    "severity": "critical",
                    "url": url,
                    "parameter": param,
                    "payload": inject,
                    "cwe": "CWE-1336",
                    "confidence": 0.9,
                    "evidence": (
                        f"payload {inject!r} reflected the evaluated result "
                        f"{marker!r}, absent from the control {control!r} "
                        "response — template engine evaluated the expression"
                    ),
                })
                # One confirmed payload per param is enough; move on.
                seen_params.add(param)
                break

            # Lower-confidence: a template-engine error surfaced for this param.
            if param not in seen_params:
                err = _ERROR_RE.search(live_body)
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
                        "payload": inject,
                        "cwe": "CWE-1336",
                        "confidence": 0.5,
                        "evidence": (
                            f"payload {inject!r} produced template-engine error "
                            f"signature {err.group(0)!r} not present for the "
                            f"control {control!r}"
                        ),
                    })
                    seen_params.add(param)
                    break

    return findings


register_worker("vuln", TECHNIQUE, run)
