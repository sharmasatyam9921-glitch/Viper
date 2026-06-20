"""OOB listeners: an HTTP server and a minimal DNS UDP responder.

Both extract the canary token from any interaction (HTTP Host/path, DNS qname)
and record it in a shared :class:`InteractionStore`. Bind to ephemeral ports for
tests; in a real engagement run them on a public host the target can reach
(DNS on 53, HTTP on 80/8080).
"""
from __future__ import annotations

import logging
import socket
import socketserver
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Optional

from .canary import token_from_host, token_from_path
from .store import InteractionStore

logger = logging.getLogger("viper.oob")


# --- HTTP -----------------------------------------------------------------

def _make_http_handler(store: InteractionStore):
    class _Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *a):           # silence default stderr logging
            pass

        def _record(self):
            host = self.headers.get("Host", "")
            token = token_from_host(host) or token_from_path(self.path)
            if token:
                store.record(token, "http", self.client_address[0],
                             detail=f"{self.command} {self.path} Host={host}",
                             headers={k: v for k, v in self.headers.items()})
            body = b"ok\n"
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        do_GET = _record
        do_POST = _record
        do_PUT = _record
        do_HEAD = _record
    return _Handler


# --- DNS ------------------------------------------------------------------

def _parse_qname(data: bytes, offset: int = 12):
    labels, i = [], offset
    try:
        while i < len(data):
            ln = data[i]
            if ln == 0:
                i += 1
                break
            if ln & 0xC0:                    # compression pointer — not in a query
                i += 2
                break
            labels.append(data[i + 1:i + 1 + ln].decode("ascii", "ignore"))
            i += 1 + ln
    except IndexError:
        return "", offset
    return ".".join(labels), i


def _dns_response(query: bytes, qend: int) -> bytes:
    # echo id, set QR + RD-copied, no error, qdcount=1, ancount=0
    txid = (query[0:2] if len(query) >= 2 else b"\x00\x00")
    qend = max(12, min(qend, len(query)))    # clamp so we never slice past the packet
    question = query[12:qend + 4]            # qname + qtype + qclass
    return (txid + b"\x81\x80" + b"\x00\x01" + b"\x00\x00"
            + b"\x00\x00\x00\x00" + question)


def _make_dns_handler(store: InteractionStore):
    class _DNSHandler(socketserver.BaseRequestHandler):
        def handle(self):
            data, sock = self.request
            try:
                qname, qend = _parse_qname(data, 12)
                token = token_from_host(qname)
                if token:
                    store.record(token, "dns", self.client_address[0],
                                 detail=qname)
                sock.sendto(_dns_response(data, qend), self.client_address)
            except Exception as exc:         # never let one packet kill the server
                logger.debug("dns handler error: %s", exc)
    return _DNSHandler


class _UDPServer(socketserver.ThreadingUDPServer):
    allow_reuse_address = True


# --- facade ---------------------------------------------------------------

class OOBListeners:
    """Starts/stops the HTTP and (optional) DNS listeners on background threads."""

    def __init__(self, store: InteractionStore, *, http_host: str = "127.0.0.1",
                 http_port: int = 0, dns_host: str = "127.0.0.1",
                 dns_port: int = 0, enable_dns: bool = True):
        self.store = store
        self._http_host, self._http_port = http_host, http_port
        self._dns_host, self._dns_port = dns_host, dns_port
        self._enable_dns = enable_dns
        self._http: Optional[ThreadingHTTPServer] = None
        self._dns: Optional[_UDPServer] = None
        self._threads = []

    def start(self) -> "OOBListeners":
        self._http = ThreadingHTTPServer((self._http_host, self._http_port),
                                         _make_http_handler(self.store))
        self._http_port = self._http.server_address[1]
        t = threading.Thread(target=self._http.serve_forever, daemon=True)
        t.start()
        self._threads.append(t)
        if self._enable_dns:
            try:
                self._dns = _UDPServer((self._dns_host, self._dns_port),
                                       _make_dns_handler(self.store))
                self._dns_port = self._dns.server_address[1]
                td = threading.Thread(target=self._dns.serve_forever, daemon=True)
                td.start()
                self._threads.append(td)
            except (OSError, socket.error) as exc:   # e.g. port 53 needs privilege
                logger.warning("DNS listener disabled: %s", exc)
                self._dns = None
        return self

    @property
    def http_port(self) -> int:
        return self._http_port

    @property
    def dns_port(self) -> int:
        return self._dns_port if self._dns else 0

    def stop(self) -> None:
        for srv in (self._http, self._dns):
            if srv is not None:
                try:
                    srv.shutdown()
                    srv.server_close()
                except Exception as exc:   # noqa: BLE001
                    logger.warning("oob listener shutdown error: %s", exc)
        # Wait for the serve_forever threads to actually exit (no lingering
        # request handling after stop() returns).
        for t in self._threads:
            t.join(timeout=5.0)
        self._threads = []
        self._http = self._dns = None
