"""A deliberately-vulnerable benchmark app with LABELED ground truth.

Each endpoint is either a genuine, gate-confirmable vulnerability or a SAFE DECOY
that looks tempting but must NOT be flagged (escaped reflection, a page that just
echoes "SQL syntax", a placeholder key, strict CORS, a non-traversable download).
The decoys are the real test — they measure false-positive discipline, which is
what separates a trustworthy scanner from a noisy one.

GROUND_TRUTH maps (path, class) -> True (real vuln) so the harness can score any
tool's confirmed findings against it. Pure stdlib; we control this app, so running
VIPER against it is fully authorized.
"""
from __future__ import annotations

import html
import re
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, unquote, urlsplit

# (path, vuln_class) the tool SHOULD confirm. Everything else is a decoy.
GROUND_TRUTH = {
    ("/reflect", "xss"): True,
    ("/search", "sqli"): True,
    ("/download", "lfi"): True,
    ("/render", "ssti"): True,
    ("/.env", "secrets"): True,
    ("/api/data", "cors"): True,
}
# Tempting-but-safe endpoints (any confirmed finding here is a false positive).
DECOYS = ["/echo", "/help", "/safe_dl", "/config", "/strictcors"]

_PASSWD = ("root:x:0:0:root:/root:/bin/bash\n"
           "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
           "bin:x:2:2:bin:/bin:/usr/sbin/nologin\n")
_AWS_KEY = "AKIA2E0K8Z9QXVB7N3RT"          # real-shaped (benchmark only)
_SSTI_PATTERNS = (r"\$\{(\d+)\*(\d+)\}", r"\{\{(\d+)\*(\d+)\}\}", r"#\{(\d+)\*(\d+)\}")
# A genuine template engine also evaluates string ops (not just arithmetic) — the
# gate requires this to tell a real engine from a "delimiter-gated calculator".
_SSTI_STR = (r'\$\{"([^"{}]*)"\+"([^"{}]*)"\}', r'\{\{"([^"{}]*)"~"([^"{}]*)"\}\}',
             r'\$\{"([^"{}]*)"\.concat\("([^"{}]*)"\)\}')


def _render_ssti(name: str) -> str:
    """Evaluate templated arithmetic AND string concatenation (${N*M}, {{N*M}},
    ${"a"+"b"}, ...) — a real template engine — but NOT bare expressions without
    delimiters, so a plain calculator can't be mistaken for SSTI."""
    for pat in _SSTI_PATTERNS:
        name = re.sub(pat, lambda m: str(int(m.group(1)) * int(m.group(2))), name)
    for pat in _SSTI_STR:
        name = re.sub(pat, lambda m: m.group(1) + m.group(2), name)
    return name


def _q(path):
    return parse_qs(urlsplit(path).query)


def _val(path, key):
    return (_q(path).get(key) or [""])[0]


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, status, body, ctype="text/html", extra=None):
        if isinstance(body, str):
            body = body.encode("utf-8", "replace")
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        for k, v in (extra or {}).items():
            try:
                self.send_header(k, v)
            except Exception:
                pass
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        p = urlsplit(self.path).path
        origin = self.headers.get("Origin", "")

        # ---- TRUE VULNS ------------------------------------------------
        if p == "/reflect":                       # reflected XSS (raw reflection)
            return self._send(200, f"<html><body>q={_val(self.path,'q')}</body></html>")
        if p == "/search":                        # error-based SQLi
            v = _val(self.path, "id")
            if v.count("'") % 2 == 1:             # unbalanced quote breaks the query
                return self._send(500, "Database error: You have an error in your "
                                       "SQL syntax near line 1")
            return self._send(200, "<html>results</html>")
        if p == "/download":                      # path traversal / LFI
            f = unquote(_val(self.path, "file"))
            if "etc/passwd" in f.replace("\\", "/"):
                return self._send(200, _PASSWD, "text/plain")
            return self._send(200, "<html>file: report.pdf</html>")
        if p == "/render":                        # SSTI (evaluates templated N*M)
            return self._send(200, f"<html>Hello {_render_ssti(_val(self.path,'name'))}</html>")
        if p == "/.env":                          # exposed secret (shape-specific key)
            return self._send(200, f"AWS_ACCESS_KEY_ID={_AWS_KEY}\n"
                                   "AWS_SECRET_ACCESS_KEY=FAKE0benchmark0fixture0secret0doNotUse\n",
                              "text/plain")
        if p == "/api/data":                      # CORS: reflects arbitrary Origin
            extra = {"Access-Control-Allow-Origin": origin or "*",
                     "Access-Control-Allow-Credentials": "true"}
            return self._send(200, '{"data":"ok"}', "application/json", extra)

        # ---- DECOYS (must NOT be flagged) ------------------------------
        if p == "/echo":                          # reflection but HTML-escaped
            return self._send(200, f"<html>q={html.escape(_val(self.path,'q'))}</html>")
        if p == "/help":                          # corpus echo: always mentions SQL
            return self._send(200, "<html>Common error: You have an error in your "
                                   "SQL syntax. Here's how to fix it.</html>")
        if p == "/safe_dl":                       # download that ignores the path
            return self._send(200, "<html>static brochure content</html>")
        if p == "/config":                        # placeholder key, not a secret
            return self._send(200, "API_KEY=YOUR_API_KEY_HERE\nDEBUG=false", "text/plain")
        if p == "/strictcors":                    # CORS locked to one trusted origin
            extra = {"Access-Control-Allow-Origin": "https://trusted.example"}
            return self._send(200, '{"ok":true}', "application/json", extra)

        # index links everything so a crawler can discover the surface
        if p in ("/", "/index.html"):
            links = "".join(
                f'<a href="{pp}?x=1">{pp}</a> '
                for pp, _ in list(GROUND_TRUTH) ) + " ".join(
                f'<a href="{d}?x=1">{d}</a>' for d in DECOYS)
            return self._send(200, f"<html><body>Benchmark app{links}</body></html>")
        return self._send(404, "<html>not found</html>")

    do_POST = do_GET


def start_app(host: str = "127.0.0.1", port: int = 0):
    """Start the benchmark app in a background thread. Returns (server, base_url)."""
    srv = ThreadingHTTPServer((host, port), _Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, f"http://{host}:{srv.server_address[1]}"


# endpoint -> (param to probe, the class it tests). Used by the harness to aim
# workers; None param means the worker probes the path itself.
PROBE_MAP = {
    "/reflect": ("q", "xss"), "/echo": ("q", "xss"),
    "/search": ("id", "sqli"), "/help": ("id", "sqli"),
    "/download": ("file", "lfi"), "/safe_dl": ("file", "lfi"),
    "/render": ("name", "ssti"),
    "/.env": (None, "secrets"), "/config": (None, "secrets"),
    "/api/data": (None, "cors"), "/strictcors": (None, "cors"),
}
