"""Relay worker node — authenticates the controller and runs SCOPED tasks.

The node verifies every inbound message's HMAC (drops unauthenticated ones) and
RE-CHECKS scope server-side before doing any work. So even a controller that asks
for an out-of-scope target is refused — the node, not the controller, is the
authority on what it will touch.
"""
from __future__ import annotations

import logging
import socketserver
import threading
import urllib.request
from typing import Callable, Optional

from .protocol import sign, verify

logger = logging.getLogger("viper.relay.node")


def _default_fetch(url: str, timeout: float = 10.0) -> dict:
    """Minimal read-only GET (the node's actual work). Returns status + length."""
    if not url.lower().startswith(("http://", "https://")):
        return {"error": "non-http scheme refused"}
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "VIPER-relay"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            body = r.read(65536)
            return {"status": r.status, "len": len(body)}
    except Exception as exc:   # noqa: BLE001
        return {"error": f"{type(exc).__name__}: {exc}"}


class RelayNode:
    def __init__(self, secret, *, scope_allows: Optional[Callable[[str], bool]] = None,
                 fetch: Optional[Callable] = None, host: str = "127.0.0.1",
                 port: int = 0):
        self.secret = secret
        self.scope_allows = scope_allows or (lambda u: True)
        self.fetch = fetch or _default_fetch
        self._host, self._port = host, port
        self._srv: Optional[socketserver.TCPServer] = None
        self._thread: Optional[threading.Thread] = None

    # --- request handling (transport-independent, unit-testable) ----------

    def handle_payload(self, payload: Optional[dict]) -> dict:
        if not isinstance(payload, dict):
            return {"type": "error", "error": "unauthorized"}
        t = payload.get("type")
        mid = payload.get("id")
        if t == "ping":
            return {"type": "pong", "id": mid, "node": "viper-relay"}
        if t == "task":
            action = payload.get("action")
            if action == "fetch":
                url = str(payload.get("url", ""))
                # SERVER-SIDE scope re-check — never trust the controller.
                if not self._in_scope(url):
                    return {"type": "result", "id": mid, "error": "out of scope"}
                return {"type": "result", "id": mid, **self.fetch(url)}
            return {"type": "result", "id": mid, "error": f"unknown action: {action}"}
        return {"type": "error", "id": mid, "error": f"unknown type: {t}"}

    def _in_scope(self, url: str) -> bool:
        try:
            return bool(self.scope_allows(url))
        except Exception:
            return False   # fail closed

    # --- TCP server -------------------------------------------------------

    def start(self) -> "RelayNode":
        node = self

        class _Handler(socketserver.StreamRequestHandler):
            def handle(self):
                line = self.rfile.readline()
                if not line:
                    return
                payload = verify(line, node.secret)   # None if HMAC invalid
                resp = node.handle_payload(payload)
                self.wfile.write(sign(resp, node.secret))

        class _Server(socketserver.ThreadingTCPServer):
            allow_reuse_address = True

        self._srv = _Server((self._host, self._port), _Handler)
        self._port = self._srv.server_address[1]
        self._thread = threading.Thread(target=self._srv.serve_forever, daemon=True)
        self._thread.start()
        return self

    @property
    def port(self) -> int:
        return self._port

    def stop(self) -> None:
        if self._srv is not None:
            try:
                self._srv.shutdown()
                self._srv.server_close()
            except Exception:
                pass
        if self._thread is not None:
            self._thread.join(timeout=5.0)
        self._srv = self._thread = None
