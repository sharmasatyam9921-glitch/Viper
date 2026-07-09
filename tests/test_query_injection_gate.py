"""LDAP / XPath injection is gate-confirmed via an in-band engine-error differential.

The worker injects a grammar-breaker (``*)(uid=*`` for LDAP, ``'`` for XPath) and flags
a param only when the response carries an ENGINE-SPECIFIC error (javax.naming /
XPathException) that a benign value does not. The gate independently reproduces that
differential: benign control clean, breaker payload errors. A reflection-only endpoint
and a noisy endpoint (errors for everything, incl. the benign control) both stay leads.
"""
from __future__ import annotations

import asyncio
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.swarm_validation import validate_findings  # noqa: E402
from core.swarm_workers.vuln.query_injection import run as qi_run  # noqa: E402

_LDAP_ERR = b"javax.naming.NamingException: [LDAP: error code 53 - Bad search filter]"
_XPATH_ERR = b"Warning: SimpleXMLElement::xpath(): Invalid XPath expression (XPathException)"


class _Agent:
    def __init__(self, t):
        self.target = t
        self.timeout_s = 8.0
        self.payload = {}


def _server(engine: str, mode: str):
    """engine: 'ldap'|'xpath'. mode: 'vuln' (breaker -> engine error, benign clean),
    'reflect' (echoes the value, never errors), 'noisy' (errors for everything)."""
    err = _LDAP_ERR if engine == "ldap" else _XPATH_ERR
    breakers = (")(", "*)(", "\\") if engine == "ldap" else ("'", "']")

    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            q = parse_qs(urlsplit(self.path).query)
            val = next((v[0] for v in q.values() if v), "")
            if mode == "noisy":
                body = err
            elif mode == "reflect":
                body = f"you searched for {val}".encode()
            else:  # vuln
                broke = ("viperbenign" not in val) and any(b in val for b in breakers)
                body = err if broke else b"no results"
            self.send_response(500 if body is err else 200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, f"http://127.0.0.1:{srv.server_address[1]}"


def _run(engine, mode):
    srv, base = _server(engine, mode)
    try:
        findings = asyncio.run(qi_run(_Agent(base + "/search?q=x")))
        out = asyncio.run(validate_findings(findings, default_target=base)) if findings else []
        return findings, out
    finally:
        srv.shutdown()


def test_ldap_injection_worker_and_gate_confirm():
    findings, out = _run("ldap", "vuln")
    ldap = [f for f in findings if f["type"] == "ldap_injection"]
    assert ldap, "worker should flag the LDAP-breaker error differential"
    sub = [f for f in out if f["submittable"]]
    assert sub and sub[0]["validation_confidence"] >= 0.75
    assert "ldap" in sub[0]["validation_reason"].lower()


def test_xpath_injection_worker_and_gate_confirm():
    findings, out = _run("xpath", "vuln")
    xp = [f for f in findings if f["type"] == "xpath_injection"]
    assert xp, "worker should flag the XPath-breaker error differential"
    sub = [f for f in out if f["submittable"]]
    assert sub and "xpath" in sub[0]["validation_reason"].lower()


def test_reflection_only_endpoint_no_finding():
    # The payload is echoed but no engine error -> the worker must not flag it.
    findings, _ = _run("ldap", "reflect")
    assert not findings


def test_noisy_endpoint_is_gate_lead():
    # An endpoint that errors for EVERYTHING (incl. the benign control) is not
    # injectable; if a stale finding reaches the gate it must stay a lead.
    f = {"vuln_type": "ldap_injection:q", "type": "ldap_injection",
         "url": None, "parameter": "q", "payload": "*)(uid=*"}
    srv, base = _server("ldap", "noisy")
    try:
        f["url"] = base + "/search?q=*)(uid=*"
        out = asyncio.run(validate_findings([f], default_target=base))
        assert not out[0]["submittable"]
        assert "noisy" in out[0]["validation_reason"] or "already" in out[0]["validation_reason"]
    finally:
        srv.shutdown()


def test_query_injection_missing_fields_is_lead():
    f = {"vuln_type": "xpath_injection:q", "type": "xpath_injection", "url": "http://127.0.0.1:9/x"}
    out = asyncio.run(validate_findings([f]))
    assert not out[0]["submittable"]


def _prose_server(engine: str):
    """Adversarial FP vector (docs/Q&A search index): the breaker search-term surfaces an
    indexed article whose PROSE mentions the vulnerability class ('Invalid XPath expression'
    / 'Bad search filter'), while the benign term returns no results — but NO library/stack
    token is present. Must stay a LEAD (the tightened signatures ignore prose)."""
    prose = (b"<h1>Search results</h1><article>How to fix Invalid XPath expression "
             b"errors</article>") if engine == "xpath" else (
             b"<h1>Search results</h1><article>LDAP Bad search filter troubleshooting</article>")
    breakers = ("'", "']") if engine == "xpath" else (")(", "*)(")

    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            q = parse_qs(urlsplit(self.path).query)
            val = next((v[0] for v in q.values() if v), "")
            hit = ("viperbenign" not in val) and any(b in val for b in breakers)
            body = prose if hit else b"<h1>Search results</h1><p>no results</p>"
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, f"http://127.0.0.1:{srv.server_address[1]}"


def test_docs_search_prose_is_not_confirmed_xpath():
    # The reviewer's #1 vector: a security-docs search index. Worker must not flag it,
    # and even a stale finding must not pass the gate.
    srv, base = _prose_server("xpath")
    try:
        assert not asyncio.run(qi_run(_Agent(base + "/search?q=x")))
        f = {"vuln_type": "xpath_injection:q", "type": "xpath_injection",
             "url": base + "/search?q='", "parameter": "q", "payload": "'"}
        out = asyncio.run(validate_findings([f], default_target=base))
        assert not out[0]["submittable"]
    finally:
        srv.shutdown()


def test_docs_search_prose_is_not_confirmed_ldap():
    srv, base = _prose_server("ldap")
    try:
        assert not asyncio.run(qi_run(_Agent(base + "/search?q=x")))
        f = {"vuln_type": "ldap_injection:q", "type": "ldap_injection",
             "url": base + "/search?q=*)(uid=*", "parameter": "q", "payload": "*)(uid=*"}
        out = asyncio.run(validate_findings([f], default_target=base))
        assert not out[0]["submittable"]
    finally:
        srv.shutdown()
