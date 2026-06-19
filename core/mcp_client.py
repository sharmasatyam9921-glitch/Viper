"""Dependency-free MCP client over stdio (newline-delimited JSON-RPC 2.0).

Spawns an MCP server as a subprocess, performs the ``initialize`` handshake, and
exposes ``list_tools`` / ``call_tool``. Works with any spec-compliant stdio MCP
server — including VIPER's own (``core.mcp.servers.*``) and third-party ones.

Synchronous core (simple + robust for subprocess pipes); an ``acall_tool`` async
wrapper runs calls off the event loop so a swarm worker can await them.
"""
from __future__ import annotations

import asyncio
import logging
import subprocess
import threading
import time
from typing import Any, Dict, List, Optional

from core.mcp import protocol as P

logger = logging.getLogger("viper.mcp.client")


class MCPError(Exception):
    pass


class MCPClient:
    """A connection to one stdio MCP server."""

    def __init__(self, command: List[str], *, cwd: Optional[str] = None,
                 env: Optional[dict] = None, timeout: float = 20.0):
        self.command = command
        self.cwd = cwd
        self.env = env
        self.timeout = timeout
        self._proc: Optional[subprocess.Popen] = None
        self._id = 0
        self._lock = threading.Lock()
        self._server_info: dict = {}

    # --- lifecycle ---------------------------------------------------------

    def start(self) -> "MCPClient":
        if self._proc is not None:
            return self
        self._proc = subprocess.Popen(
            self.command, cwd=self.cwd, env=self.env,
            stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, text=True, encoding="utf-8",
            bufsize=1,
        )
        # If the handshake fails (server died / not MCP), reap the child rather
        # than leaking it.
        try:
            init = self._rpc("initialize", {
                "protocolVersion": P.PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": {"name": "viper", "version": "1.0"},
            })
            self._server_info = init.get("serverInfo", {})
            self._notify("notifications/initialized")
        except Exception:
            self.close()
            raise
        return self

    def close(self) -> None:
        if self._proc is None:
            return
        try:
            if self._proc.stdin:
                self._proc.stdin.close()
            self._proc.terminate()
            try:
                self._proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self._proc.kill()
        except Exception:
            pass
        finally:
            self._proc = None

    def __enter__(self) -> "MCPClient":
        return self.start()

    def __exit__(self, *exc) -> None:
        self.close()

    def __del__(self):
        # Safety net for callers who forget to close()/use `with`.
        try:
            self.close()
        except Exception:
            pass

    @property
    def server_info(self) -> dict:
        return dict(self._server_info)

    # --- API ---------------------------------------------------------------

    def list_tools(self) -> List[dict]:
        return self._rpc("tools/list", {}).get("tools", [])

    def call_tool(self, name: str, arguments: Optional[dict] = None) -> dict:
        """Call a tool; returns {text, is_error, raw}. Never raises on a tool
        error — the failure is reported in the result."""
        res = self._rpc("tools/call", {"name": name, "arguments": arguments or {}})
        content = res.get("content") or []
        text = "\n".join(c.get("text", "") for c in content
                         if isinstance(c, dict) and c.get("type") == "text")
        return {"text": text, "is_error": bool(res.get("isError")), "raw": res}

    async def acall_tool(self, name: str, arguments: Optional[dict] = None) -> dict:
        return await asyncio.to_thread(self.call_tool, name, arguments)

    # --- transport ---------------------------------------------------------

    def _next_id(self) -> int:
        self._id += 1
        return self._id

    def _send(self, msg: dict) -> None:
        if self._proc is None or self._proc.stdin is None:
            raise MCPError("client not started")
        try:
            self._proc.stdin.write(P.encode(msg))
            self._proc.stdin.flush()
        except (BrokenPipeError, ValueError, OSError) as exc:
            raise MCPError(f"failed to send to server: {exc}") from exc

    def _notify(self, method: str, params: Optional[dict] = None) -> None:
        with self._lock:
            self._send(P.notification(method, params))

    def _rpc(self, method: str, params: Optional[dict] = None) -> dict:
        if self._proc is None:
            raise MCPError("client not started")
        with self._lock:
            msg_id = self._next_id()
            self._send(P.request(msg_id, method, params))
            # Read until the matching id arrives. A wall-clock deadline (not a
            # frame count) bounds the wait, so a chatty server that interleaves
            # notifications can't either hang us forever or silently eat the reply.
            deadline = time.monotonic() + max(self.timeout, 1.0)
            skipped = 0
            while time.monotonic() < deadline:
                line = self._readline()
                if not line:
                    raise MCPError(f"server closed during {method}")
                try:
                    resp = P.decode(line)
                except ValueError:
                    continue
                if resp.get("id") != msg_id:
                    skipped += 1
                    if skipped <= 20 or skipped % 100 == 0:
                        logger.debug("mcp: skipped frame id=%r while awaiting %s",
                                     resp.get("id"), method)
                    continue
                if "error" in resp:
                    err = resp["error"]
                    raise MCPError(f"{method}: {err.get('message')} ({err.get('code')})")
                return resp.get("result") or {}
        raise MCPError(f"timed out awaiting response to {method} "
                       f"(skipped {skipped} unrelated frame(s))")

    def _readline(self) -> str:
        """Read one line from the server with a timeout (kills on hang)."""
        result: Dict[str, Any] = {}

        def _r():
            try:
                result["line"] = self._proc.stdout.readline()
            except Exception as exc:   # noqa: BLE001
                result["err"] = exc
        t = threading.Thread(target=_r, daemon=True)
        t.start()
        t.join(self.timeout)
        if t.is_alive():
            self.close()
            raise MCPError("server read timed out")
        if "err" in result:
            raise MCPError(str(result["err"]))
        return result.get("line", "")
