"""Opt-in password-reset token/OTP leak test (account takeover), FP-averse."""
from __future__ import annotations

import asyncio
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.logic_modeler import LogicModeler, _reset_secret_leaks  # noqa: E402

_REAL = "victim@example.com"


def _server(kind: str):
    class H(BaseHTTPRequestHandler):
        _n = 0

        def log_message(self, *a):
            pass

        def do_POST(self):
            n = int(self.headers.get("Content-Length", 0) or 0)
            acct = (parse_qs(self.rfile.read(n).decode()).get("email") or [""])[0]
            H._n += 1
            if kind == "vuln":
                # broken: echoes the reset OTP in the response for a real account
                body = (f'{{"ok":true,"reset_code":"839217"}}' if acct == _REAL
                        else '{"ok":false,"msg":"account not found"}')
            elif kind == "csrf":
                # SAFE but tempting: a per-request CSRF token (differs each call),
                # no reset secret — must NOT be flagged
                body = f'{{"ok":true,"csrf_token":"tok{H._n:040d}","msg":"email sent if it exists"}}'
            else:  # safe
                body = '{"ok":true,"msg":"if the account exists, a reset link was emailed"}'
            b = body.encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(b)))
            self.end_headers()
            self.wfile.write(b)
    srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, f"http://127.0.0.1:{srv.server_address[1]}"


def _run(kind):
    srv, base = _server(kind)
    try:
        lm = LogicModeler(base, reset_config={"url": base + "/reset", "param": "email",
                                              "value": _REAL})
        return asyncio.run(lm.test_reset_token_leak())
    finally:
        srv.shutdown()


def test_helper_flags_context_secret_absent_from_control():
    real = '{"reset_code":"839217","csrf_token":"AAAA1111"}'
    ctrl = '{"msg":"not found","csrf_token":"BBBB2222"}'
    leaks = _reset_secret_leaks(real, ctrl)
    assert "839217" in leaks           # reset_code, account-specific
    assert "AAAA1111" not in leaks      # csrf_token has no reset context


def test_leaked_otp_is_flagged():
    f = _run("vuln")
    assert f and f[0].test_name == "reset_token_leak" and f[0].severity == "critical"


def test_safe_reset_no_leak():
    assert _run("safe") == []


def test_per_request_csrf_token_is_not_a_leak():
    assert _run("csrf") == []           # differs each call but no reset context


def test_no_config_is_a_noop():
    lm = LogicModeler("http://127.0.0.1:1")
    assert asyncio.run(lm.test_reset_token_leak()) == []
