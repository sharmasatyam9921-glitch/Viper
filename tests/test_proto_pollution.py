"""Client-side prototype-pollution gadget scanner: read-only static JS analysis,
FP-averse (needs source+sink co-occurrence or a versioned vulnerable lib), lead-only."""
from __future__ import annotations

import asyncio
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.swarm_validation import validate_findings  # noqa: E402
from core.swarm_workers.vuln.proto_pollution import (  # noqa: E402
    _scan_js, _vuln_library, run,
)


# ── static detector ──

def test_source_and_sink_cooccurrence_is_a_lead():
    js = "var p = new URLSearchParams(location.search); $.extend(true, target, p);"
    out = _scan_js(js, "http://t/app.js")
    assert out and out[0]["vuln_type"] == "prototype_pollution:client"
    assert out[0]["needs_manual_verification"] is True
    assert out[0]["confidence"] <= 0.6 and out[0]["cwe"] == "CWE-1321"


def test_source_alone_or_sink_alone_is_not_flagged():
    assert _scan_js("var x = location.hash; render(x);", "http://t/a.js") == []
    assert _scan_js("_.merge(defaults, config);", "http://t/a.js") == []   # no user source


def test_shallow_object_assign_is_not_a_sink():
    assert _scan_js("var p = new URLSearchParams(location.search); "
                    "Object.assign(t, p);", "http://t/a.js") == []


def test_explicit_proto_write_from_a_source():
    js = 'var k = location.hash.slice(1); obj["__proto__"][k] = 1;'
    out = _scan_js(js, "http://t/a.js")
    assert out and "__proto__" in out[0]["title"]


def test_vulnerable_lodash_version_matched():
    assert _vuln_library("/* lodash 4.17.4 */ _.merge(dst, JSON.parse(location.hash));")
    assert _vuln_library("/* lodash 4.17.20 */ _.merge(dst, x);") is None      # patched
    assert _vuln_library("/* lodash 4.17.4 */ shallowCopy(a);") is None        # no merge sink


def test_vulnerable_jquery_version_matched():
    assert _vuln_library("jQuery JavaScript Library v3.3.1 $.extend(true, a, b)")
    assert _vuln_library("jQuery v3.5.0 $.extend(true, a, b)") is None         # patched


def test_safe_script_yields_nothing():
    assert _scan_js("function add(a,b){return a+b;} console.log(1);", "http://t/a.js") == []


# ── live run over a page + linked JS ──

class _Agent:
    def __init__(self, t):
        self.target = t
        self.timeout_s = 8.0
        self.payload = {}


def _server(html: str, js: str):
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            if self.path.endswith(".js"):
                body, ctype = js.encode(), "application/javascript"
            else:
                body, ctype = html.encode(), "text/html"
            self.send_response(200)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
    srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, f"http://127.0.0.1:{srv.server_address[1]}"


def test_run_flags_gadget_in_linked_js():
    html = '<html><head><script src="/bundle.js"></script></head><body>hi</body></html>'
    js = "var q = new URLSearchParams(location.search); _.merge(state, q);"
    srv, base = _server(html, js)
    try:
        out = asyncio.run(run(_Agent(base)))
        assert any(f["vuln_type"] == "prototype_pollution:client" for f in out)
        assert all(f.get("needs_manual_verification") for f in out)
    finally:
        srv.shutdown()


def test_run_clean_page_finds_nothing():
    html = "<html><body><script>console.log('ok');</script></body></html>"
    srv, base = _server(html, "var x = 1;")
    try:
        assert asyncio.run(run(_Agent(base))) == []
    finally:
        srv.shutdown()


# ── gate: PP stays an actionable lead ──

def test_gate_keeps_pp_as_actionable_lead():
    out = asyncio.run(validate_findings(
        [{"vuln_type": "prototype_pollution:client", "url": "http://t/app.js"}]))
    assert not out[0]["submittable"]
    assert "browser/DOM" in out[0]["validation_reason"]
