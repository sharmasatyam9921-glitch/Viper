#!/usr/bin/env python3
"""
VIPER 4.0 — WebSocket server for real-time dashboard streaming.

Provides two transport modes:
  1. Native WebSocket via `websockets` library (preferred)
  2. SSE fallback via the existing HTTP server EventBus (zero-dep)

Usage:
    from dashboard.ws_server import DashboardWSServer
    ws = DashboardWSServer(port=8081)
    await ws.start()
    await ws.broadcast("finding", {"severity": "critical", ...})
"""

import asyncio
import json
import logging
import time
import uuid
from typing import Dict, Optional, Set

logger = logging.getLogger("viper.ws")

try:
    import websockets
    import websockets.server
    HAS_WEBSOCKETS = True
except ImportError:
    HAS_WEBSOCKETS = False
    logger.info("websockets not installed — using SSE fallback")


# ══════════════════════════════════════════════════════════════════════
# EVENT TYPES
# ══════════════════════════════════════════════════════════════════════

EVENT_THINKING = "thinking"
EVENT_TOOL_START = "tool_start"
EVENT_TOOL_COMPLETE = "tool_complete"
EVENT_FINDING = "finding"
EVENT_PHASE_UPDATE = "phase_update"
EVENT_SCAN_PROGRESS = "scan_progress"
EVENT_CHAIN_UPDATE = "chain_update"
EVENT_SESSION_UPDATE = "session_update"
EVENT_LOG = "log"
EVENT_ERROR = "error"
EVENT_HEARTBEAT = "heartbeat"


# ══════════════════════════════════════════════════════════════════════
# WEBSOCKET SERVER (requires `websockets` library)
# ══════════════════════════════════════════════════════════════════════

class DashboardWSServer:
    """WebSocket server for real-time dashboard updates.

    Falls back to SSE via EventBus if websockets is not installed.
    """

    def __init__(self, host: str = "0.0.0.0", port: int = 8081):
        self.host = host
        self.port = port
        self._clients: Set = set()
        self._session_clients: Dict[str, Set] = {}  # session_id -> set of ws
        self._server = None
        self._heartbeat_task: Optional[asyncio.Task] = None
        self._event_history: list = []
        self._max_history = 200
        self._running = False

        # SSE fallback bus (always available)
        self._sse_bus: Optional[object] = None

    # ── Lifecycle ────────────────────────────────────────────────────

    async def start(self):
        """Start WebSocket server."""
        if HAS_WEBSOCKETS:
            self._server = await websockets.server.serve(
                self._handler,
                self.host,
                self.port,
                ping_interval=20,
                ping_timeout=10,
                max_size=2**20,  # 1MB
                origins=None,  # Allow all origins
            )
            self._running = True
            self._heartbeat_task = asyncio.create_task(self._heartbeat_loop())
            logger.info(f"WebSocket server started on ws://{self.host}:{self.port}")
        else:
            # SSE fallback — import from sibling server module
            self._running = True
            try:
                from dashboard.server import event_bus
                self._sse_bus = event_bus
                logger.info("SSE fallback mode — events route through HTTP EventBus")
            except ImportError:
                logger.warning("Neither websockets nor dashboard.server available")

    async def stop(self):
        """Stop server and disconnect all clients."""
        self._running = False
        if self._heartbeat_task:
            self._heartbeat_task.cancel()
            try:
                await self._heartbeat_task
            except asyncio.CancelledError:
                pass

        if self._server:
            self._server.close()
            await self._server.wait_closed()
            logger.info("WebSocket server stopped")

        # Close all client connections
        if self._clients:
            await asyncio.gather(
                *[ws.close(1001, "Server shutting down") for ws in self._clients],
                return_exceptions=True,
            )
            self._clients.clear()
            self._session_clients.clear()

    # ── Connection handler ───────────────────────────────────────────

    async def _handler(self, websocket):
        """Handle a single WebSocket connection."""
        client_id = str(uuid.uuid4())[:8]
        session_id = None

        self._clients.add(websocket)
        logger.debug(f"Client {client_id} connected ({len(self._clients)} total)")

        try:
            # Send recent history on connect
            await self._send_history(websocket)

            async for message in websocket:
                try:
                    msg = json.loads(message)
                    action = msg.get("action", "")

                    if action == "subscribe_session":
                        # Subscribe to a specific session's events
                        session_id = msg.get("session_id")
                        if session_id:
                            if session_id not in self._session_clients:
                                self._session_clients[session_id] = set()
                            self._session_clients[session_id].add(websocket)
                            await websocket.send(json.dumps({
                                "type": "subscribed",
                                "payload": {"session_id": session_id},
                            }))

                    elif action == "unsubscribe_session":
                        old_sid = msg.get("session_id", session_id)
                        if old_sid and old_sid in self._session_clients:
                            self._session_clients[old_sid].discard(websocket)
                        session_id = None

                    elif action == "get_history":
                        await self._send_history(websocket, msg.get("limit", 50))

                    elif action == "ping":
                        await websocket.send(json.dumps({
                            "type": "pong",
                            "payload": {"ts": time.time()},
                        }))

                except json.JSONDecodeError:
                    await websocket.send(json.dumps({
                        "type": "error",
                        "payload": {"message": "Invalid JSON"},
                    }))

        except Exception as e:
            logger.debug(f"Client {client_id} error: {e}")
        finally:
            self._clients.discard(websocket)
            # Remove from all session subscriptions
            for subs in self._session_clients.values():
                subs.discard(websocket)
            logger.debug(f"Client {client_id} disconnected ({len(self._clients)} total)")

    # ── Broadcasting ─────────────────────────────────────────────────

    async def broadcast(self, event_type: str, data: dict):
        """Broadcast event to all connected clients."""
        event = {
            "type": event_type,
            "payload": data,
            "ts": time.time(),
        }

        # Store in history
        self._event_history.append(event)
        if len(self._event_history) > self._max_history:
            self._event_history = self._event_history[-self._max_history:]

        if HAS_WEBSOCKETS and self._clients:
            msg = json.dumps(event, default=str)
            dead = set()
            for ws in self._clients.copy():
                try:
                    await ws.send(msg)
                except Exception:
                    dead.add(ws)
            self._clients -= dead

        # Also push to SSE bus if available
        if self._sse_bus:
            try:
                self._sse_bus.publish(event_type, data)
            except Exception:
                pass

    async def send_to_session(self, session_id: str, event_type: str, data: dict):
        """Send event to clients subscribed to a specific session."""
        event = {
            "type": event_type,
            "payload": {**data, "session_id": session_id},
            "ts": time.time(),
        }

        # Store in history
        self._event_history.append(event)
        if len(self._event_history) > self._max_history:
            self._event_history = self._event_history[-self._max_history:]

        targets = self._session_clients.get(session_id, set())
        if not targets:
            return

        msg = json.dumps(event, default=str)
        dead = set()
        for ws in targets.copy():
            try:
                await ws.send(msg)
            except Exception:
                dead.add(ws)
        targets -= dead

        # SSE fallback
        if self._sse_bus:
            try:
                self._sse_bus.publish(event_type, {**data, "session_id": session_id})
            except Exception:
                pass

    # ── Convenience emitters ─────────────────────────────────────────

    async def emit_thinking(self, thought: str, iteration: int = 0,
                            phase: str = "", session_id: str = None):
        data = {"thought": thought, "iteration": iteration, "phase": phase}
        if session_id:
            await self.send_to_session(session_id, EVENT_THINKING, data)
        else:
            await self.broadcast(EVENT_THINKING, data)

    async def emit_tool_start(self, tool_name: str, tool_args: dict = None,
                              session_id: str = None):
        data = {"tool_name": tool_name, "tool_args": tool_args or {}}
        if session_id:
            await self.send_to_session(session_id, EVENT_TOOL_START, data)
        else:
            await self.broadcast(EVENT_TOOL_START, data)

    async def emit_tool_complete(self, tool_name: str, output: str = "",
                                 success: bool = True, session_id: str = None):
        data = {"tool_name": tool_name, "output": output[:2000], "success": success}
        if session_id:
            await self.send_to_session(session_id, EVENT_TOOL_COMPLETE, data)
        else:
            await self.broadcast(EVENT_TOOL_COMPLETE, data)

    async def emit_finding(self, finding_type: str, severity: str, url: str = "",
                           title: str = "", session_id: str = None):
        data = {
            "type": finding_type, "severity": severity,
            "url": url, "title": title,
        }
        if session_id:
            await self.send_to_session(session_id, EVENT_FINDING, data)
        else:
            await self.broadcast(EVENT_FINDING, data)

    async def emit_phase_update(self, phase: str, iteration: int = 0,
                                session_id: str = None):
        data = {"phase": phase, "iteration": iteration}
        if session_id:
            await self.send_to_session(session_id, EVENT_PHASE_UPDATE, data)
        else:
            await self.broadcast(EVENT_PHASE_UPDATE, data)

    async def emit_scan_progress(self, phase: str, progress_pct: float,
                                 session_id: str = None):
        data = {"phase": phase, "progress_pct": round(progress_pct, 1)}
        if session_id:
            await self.send_to_session(session_id, EVENT_SCAN_PROGRESS, data)
        else:
            await self.broadcast(EVENT_SCAN_PROGRESS, data)

    async def emit_chain_update(self, chain_id: str, steps: list,
                                findings: list = None, session_id: str = None):
        data = {"chain_id": chain_id, "steps": steps, "findings": findings or []}
        if session_id:
            await self.send_to_session(session_id, EVENT_CHAIN_UPDATE, data)
        else:
            await self.broadcast(EVENT_CHAIN_UPDATE, data)

    # ── Internal ─────────────────────────────────────────────────────

    async def _send_history(self, websocket, limit: int = 50):
        """Send recent event history to a newly connected client."""
        history = self._event_history[-limit:]
        if history:
            try:
                await websocket.send(json.dumps({
                    "type": "history",
                    "payload": {"events": history},
                }))
            except Exception:
                pass

    async def _heartbeat_loop(self):
        """Send periodic heartbeat to keep connections alive."""
        while self._running:
            try:
                await asyncio.sleep(15)
                if self._clients:
                    await self.broadcast(EVENT_HEARTBEAT, {
                        "ts": time.time(),
                        "clients": len(self._clients),
                    })
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.debug(f"Heartbeat error: {e}")

    @property
    def client_count(self) -> int:
        return len(self._clients)


# ══════════════════════════════════════════════════════════════════════
# SSE FALLBACK ADAPTER
# ══════════════════════════════════════════════════════════════════════

class SSEFallbackServer:
    """Thin adapter that routes all events through the HTTP EventBus.

    Use this when `websockets` is not installed. The dashboard HTML pages
    fall back to EventSource (SSE) at /api/stream automatically.
    """

    def __init__(self):
        self._bus = None
        self._running = False

    async def start(self):
        try:
            from dashboard.server import event_bus
            self._bus = event_bus
            self._running = True
            logger.info("SSE fallback server ready — events via /api/stream")
        except ImportError:
            logger.error("Cannot import EventBus from dashboard.server")

    async def stop(self):
        self._running = False

    async def broadcast(self, event_type: str, data: dict):
        if self._bus:
            self._bus.publish(event_type, data)

    async def send_to_session(self, session_id: str, event_type: str, data: dict):
        if self._bus:
            self._bus.publish(event_type, {**data, "session_id": session_id})

    @property
    def client_count(self) -> int:
        if self._bus:
            return self._bus.subscriber_count
        return 0


# ══════════════════════════════════════════════════════════════════════
# FACTORY
# ══════════════════════════════════════════════════════════════════════

def create_ws_server(host: str = "0.0.0.0", port: int = 8081):
    """Create the best available real-time server."""
    if HAS_WEBSOCKETS:
        return DashboardWSServer(host=host, port=port)
    else:
        logger.info("Using SSE fallback (pip install websockets for WebSocket support)")
        return SSEFallbackServer()


# ── Standalone launch ──

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="VIPER WebSocket Server")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=8081)
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(name)s] %(message)s")

    async def main():
        srv = create_ws_server(args.host, args.port)
        await srv.start()
        logger.info(f"Press Ctrl+C to stop")
        try:
            await asyncio.Future()  # run forever
        except (KeyboardInterrupt, asyncio.CancelledError):
            pass
        finally:
            await srv.stop()

    asyncio.run(main())
