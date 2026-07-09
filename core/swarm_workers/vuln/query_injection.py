"""LDAP / XPath injection probe (in-band error differential, non-destructive).

A parameter concatenated into an LDAP search filter or an XPath expression, when fed a
character that breaks that grammar (``)(`` / ``*`` for LDAP, ``'`` / ``']`` for XPath),
makes the backend emit an ENGINE-SPECIFIC error a benign value never triggers. Same
shape and FP-discipline as the SQLi error differential:

  * the error signatures are library/engine-specific (javax.naming, XPathException,
    xmlXPathEval, ...) — NOT generic "syntax error"/"invalid" phrasing that ordinary
    parsers reuse, and
  * a benign control value is sent first; if it already carries the error, the endpoint
    is just noisy and NO finding is raised.

Read-only GET probes; no writes, no data mutation. A confirmed finding stays a LEAD
until the validation gate independently reproduces the same differential.
"""
from __future__ import annotations

import logging
import re
from typing import List

from core.swarm_engine import SwarmAgent
from core.swarm_workers import register_worker

from ._http import add_query, fetch, normalize_target_url

logger = logging.getLogger("viper.swarm_workers.vuln.query_injection")

TECHNIQUE = "query_injection"

# Engine-specific LDAP error signatures. Deliberately LIBRARY / STACK-TRACE / error-code
# tokens ONLY — NOT human-readable prose ("Bad search filter", "Invalid DN syntax"), which
# an ordinary docs/Q&A search index can surface for a breaker search-term and so DEFEAT the
# benign-control differential (an adversarial FP vector). A real injectable backend always
# emits at least one of these library tokens alongside any prose.
LDAP_ERR = re.compile(
    r"javax\.naming\.(?:NamingException|directory|InvalidNameException)|"
    r"com\.sun\.jndi\.ldap|LDAPException|LDAP:\s*error code\s*\d+|"
    r"ldap_(?:search|bind|list|read|modify)\(\)|"
    r"System\.DirectoryServices|IPWorksASN1",
    re.I)
# Engine-specific XPath error signatures (same discipline: library/stack tokens only, no
# prose phrases like "Invalid XPath expression" / "XPath error").
XPATH_ERR = re.compile(
    r"XPathException|XPathExpressionException|XPST0003|"
    r"System\.Xml\.XPath|MS\.Internal\.Xml|"
    r"xmlXPathEval|xmlXPathCompOpEval|xmlXPathParserContext|"
    r"SimpleXMLElement::xpath|DOMXPath|net\.sf\.saxon|org\.apache\.xpath",
    re.I)

# Breakers that snap the respective grammar (read-only — they only malform the query).
_LDAP_BREAKERS = ["*)(uid=*", ")(cn=*))", "*))(|(", "\\"]
_XPATH_BREAKERS = ["'", "']", "\"]", "' or '1'='1", "'))"]
_BENIGN = "viperbenign1"

_DEFAULT_PARAMS = ("q", "search", "query", "name", "user", "username", "uid",
                   "cn", "filter", "id", "dn", "xpath", "email", "login")


def _params_for(url: str) -> List[str]:
    from urllib.parse import parse_qs, urlsplit
    present = list(parse_qs(urlsplit(url).query).keys())
    try:
        from core.payload_library import get_discovered_params
        disc = list(get_discovered_params())
    except Exception:  # noqa: BLE001
        disc = []
    return list(dict.fromkeys(present + disc + list(_DEFAULT_PARAMS)))[:24]


def _finding(kind: str, param: str, probe_url: str, payload: str, err: str) -> dict:
    label = "LDAP" if kind == "ldap" else "XPath"
    cwe = "CWE-90" if kind == "ldap" else "CWE-643"
    return {
        "type": f"{kind}_injection",
        "vuln_type": f"{kind}_injection:{param}",
        "title": f"{label} injection in '{param}'",
        "severity": "high",
        "url": probe_url,
        "parameter": param,
        "payload": payload,
        "cwe": cwe,
        "confidence": 0.8,
        "evidence": (f"A {label}-breaker in '{param}' produced an engine error "
                     f"({err[:60]!r}) absent for a benign value — the value is "
                     f"concatenated into a {label} query."),
    }


async def run(agent: SwarmAgent) -> List[dict]:
    url = normalize_target_url(agent.target)
    if not url:
        return []
    timeout = min(agent.timeout_s, 10.0)
    findings: list[dict] = []
    seen: set[str] = set()
    for param in _params_for(url):
        if param in seen:
            continue
        control = await fetch("GET", add_query(url, param, _BENIGN), timeout=timeout)
        # Strip the reflected benign token so echoed content can't mask/produce a hit.
        cbody = ((control.body if control else "") or "").replace(_BENIGN, "")
        for payload, kind, err_re in (
                [(p, "ldap", LDAP_ERR) for p in _LDAP_BREAKERS]
                + [(p, "xpath", XPATH_ERR) for p in _XPATH_BREAKERS]):
            # A control that already emits the engine error is just noisy — skip.
            if err_re.search(cbody):
                continue
            probe = add_query(url, param, payload)
            resp = await fetch("GET", probe, timeout=timeout)
            if not resp or not resp.body:
                continue
            # Strip the reflected breaker so a pure-reflection / search-echo endpoint
            # can't masquerade as a backend engine error.
            m = err_re.search(resp.body.replace(payload, ""))
            if m:
                findings.append(_finding(kind, param, probe, payload, m.group(0)))
                seen.add(param)
                break                          # one confirmed break per param is enough
    return findings


register_worker("vuln", TECHNIQUE, run)
