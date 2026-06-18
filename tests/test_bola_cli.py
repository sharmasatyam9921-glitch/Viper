"""Tests for the `viper.py bola` CLI."""
from __future__ import annotations

import json
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.bola_cli import run_bola_cli  # noqa: E402

A_MARKER = "alice@victim.io"


class _Vuln(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        if not self.path.startswith("/api/orders/1001"):
            self.send_response(404); self.end_headers(); return
        cookie = self.headers.get("Cookie", "") or ""
        if "s=alice" in cookie or "s=bob" in cookie:
            body = ('{"order":1001,"owner":"%s"}' % A_MARKER).encode()
            self.send_response(200); self.send_header("Content-Length", str(len(body)))
            self.end_headers(); self.wfile.write(body)
        else:
            self.send_response(401); self.end_headers()


@pytest.fixture()
def server():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _Vuln)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        yield f"http://127.0.0.1:{srv.server_address[1]}"
    finally:
        srv.shutdown(); srv.server_close()


def test_missing_everything_errors():
    assert run_bola_cli([]) == 2


def test_missing_urls_errors():
    # sessions + marker present, but no candidate URLs
    rc = run_bola_cli(["http://t", "--cookie", "s=alice", "--cookie-b", "s=bob",
                       "--owner-marker", A_MARKER])
    assert rc == 2


def test_successful_bola_run(server, tmp_path):
    out = tmp_path / "bola.json"
    rc = run_bola_cli([
        server,
        "--cookie", "s=alice", "--cookie-b", "s=bob",
        "--owner-marker", A_MARKER,
        "--url", f"{server}/api/orders/1001",
        "--output", str(out),
    ])
    assert rc == 0
    findings = json.loads(out.read_text(encoding="utf-8"))
    assert len(findings) == 1
    assert findings[0]["cwe"] == "CWE-639"
    assert A_MARKER in findings[0]["evidence"]


def test_cross_host_url_in_burp_is_not_replayed(server, tmp_path):
    # A Burp export of A's browsing that also contains a THIRD-PARTY id-bearing
    # request (analytics/CDN) must not get A/B's session replayed to it. With the
    # target = server, only the server host is in scope; the foreign URL is dropped.
    import base64
    foreign = "https://track.thirdparty.example/api/users/55"
    raw1 = "GET /api/orders/1001 HTTP/1.1\r\nHost: x\r\nCookie: s=alice\r\n\r\n"
    raw2 = "GET /api/users/55 HTTP/1.1\r\nHost: track.thirdparty.example\r\nCookie: s=alice\r\n\r\n"

    def item(url, raw):
        b = base64.b64encode(raw.encode()).decode()
        return (f'<item><url>{url}</url><method>GET</method><status>200</status>'
                f'<request base64="true">{b}</request></item>')
    xml = ("<items>" + item(f"{server}/api/orders/1001", raw1)
           + item(foreign, raw2) + "</items>")
    burp = tmp_path / "A.xml"
    burp.write_text(xml, encoding="utf-8")
    out = tmp_path / "out.json"
    rc = run_bola_cli([server, "--burp-import", str(burp), "--cookie-b", "s=bob",
                       "--owner-marker", A_MARKER, "--output", str(out)])
    assert rc == 0
    findings = json.loads(out.read_text(encoding="utf-8"))
    # Only the in-scope basket IDOR is found; nothing replayed to the third party.
    assert all("thirdparty.example" not in f["url"] for f in findings)
    assert len(findings) == 1 and findings[0]["cwe"] == "CWE-639"


def test_burp_import_only_without_target_errors(tmp_path):
    # No target and no --url -> no in-scope host can be defined -> refuse to run.
    burp = tmp_path / "A.xml"
    burp.write_text("<items><item><url>https://t/api/orders/1</url><method>GET"
                    "</method><status>200</status></item></items>", encoding="utf-8")
    rc = run_bola_cli(["--burp-import", str(burp), "--cookie", "s=a",
                       "--cookie-b", "s=b", "--owner-marker", A_MARKER])
    assert rc == 2  # missing in-scope host


def test_burp_import_supplies_session_and_urls(server, tmp_path, monkeypatch):
    # A Burp export of identity A's browsing: supplies A's cookie AND the object URL.
    import base64
    raw = (f"GET /api/orders/1001 HTTP/1.1\r\nHost: x\r\nCookie: s=alice\r\n\r\n")
    b64 = base64.b64encode(raw.encode()).decode()
    xml = (f'<items><item><url>{server}/api/orders/1001</url><method>GET</method>'
           f'<status>200</status><request base64="true">{b64}</request></item></items>')
    burp = tmp_path / "A.xml"
    burp.write_text(xml, encoding="utf-8")
    out = tmp_path / "out.json"
    rc = run_bola_cli([
        server, "--burp-import", str(burp),
        "--cookie-b", "s=bob", "--owner-marker", A_MARKER,
        "--output", str(out),
    ])
    assert rc == 0
    findings = json.loads(out.read_text(encoding="utf-8"))
    assert len(findings) == 1 and findings[0]["cwe"] == "CWE-639"
