"""#7(a) feed-forward object-ID pool: an object ID leaked in one response ("harvest an
ID here") becomes an IDOR test value on an ID-shaped param elsewhere ("replay it there").
Read-only, still anonymous, still a lead (0.55) for manual review."""
from __future__ import annotations

import asyncio
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.swarm_engine import SwarmAgent  # noqa: E402
from core.swarm_workers.vuln import idor as idor_mod  # noqa: E402
from core.payload_library import (  # noqa: E402
    add_object_refs, clear_object_refs)


def _agent(target: str) -> SwarmAgent:
    return SwarmAgent(agent_id="t", objective="x", target=target,
                      technique="idor", payload={}, timeout_s=6.0)


def _serve(handler_cls):
    srv = ThreadingHTTPServer(("127.0.0.1", 0), handler_cls)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, f"http://127.0.0.1:{srv.server_address[1]}"


class _Handler(BaseHTTPRequestHandler):
    # id 9987 is a "real" object with unique content; everything else is a shared page,
    # so the ADJACENT value (101) reveals nothing but the REPLAYED 9987 does.
    def log_message(self, *a):
        pass

    def do_GET(self):
        idv = parse_qs(urlsplit(self.path).query).get("id", [""])[0]
        body = (f"<html>unique object {idv}</html>" if idv == "9987"
                else "<html>shared generic page</html>").encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def test_idor_replays_harvested_object_id():
    clear_object_refs()
    add_object_refs('{"order_id": 9987}')     # harvested elsewhere this hunt
    srv, base = _serve(_Handler)
    try:
        out = asyncio.run(idor_mod.run(_agent(base + "/item?id=100")))
        assert out, "replaying the harvested id 9987 must surface an IDOR candidate"
        f = out[0]
        assert f["payload"] == "9987"
        assert "replayed from another response" in f["evidence"]
    finally:
        clear_object_refs()
        srv.shutdown()


def test_idor_empty_pool_is_adjacent_only():
    # With no harvested ids, behavior is unchanged: the shared page makes id=100 vs 101
    # identical, so nothing is flagged (no feed-forward, no regression).
    clear_object_refs()
    srv, base = _serve(_Handler)
    try:
        out = asyncio.run(idor_mod.run(_agent(base + "/item?id=100")))
        assert out == [], "adjacent-only on a shared page yields no candidate"
    finally:
        srv.shutdown()
