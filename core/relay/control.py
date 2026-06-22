"""Relay controller — pairs with a node (PSK) and dispatches scoped tasks."""
from __future__ import annotations

import socket
from typing import Optional

from .protocol import sign, verify


class RelayError(Exception):
    pass


class RelayControl:
    def __init__(self, host: str, port: int, secret, *, timeout: float = 10.0):
        self.host, self.port, self.secret, self.timeout = host, port, secret, timeout
        self._id = 0

    def _rpc(self, payload: dict) -> dict:
        self._id += 1
        payload = {"id": self._id, **payload}
        try:
            with socket.create_connection((self.host, self.port), self.timeout) as s:
                s.settimeout(self.timeout)
                s.sendall(sign(payload, self.secret))
                buf = b""
                while b"\n" not in buf:
                    chunk = s.recv(4096)
                    if not chunk:
                        break
                    buf += chunk
        except Exception as exc:   # noqa: BLE001
            raise RelayError(f"relay connection failed: {exc}") from exc
        resp = verify(buf, self.secret)
        if resp is None:
            raise RelayError("node response failed authentication (wrong key / tampered)")
        return resp

    def ping(self) -> dict:
        return self._rpc({"type": "ping"})

    def dispatch(self, action: str, **params) -> dict:
        """Dispatch one task to the node; returns its (scope-checked) result."""
        return self._rpc({"type": "task", "action": action, **params})

    def paired(self) -> bool:
        """True iff the node answers an authenticated ping (PSK handshake works)."""
        try:
            return self.ping().get("type") == "pong"
        except RelayError:
            return False
