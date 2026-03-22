"""
VIPER 4.0 Phase 7 — Tunnel Manager

Manage ngrok and chisel tunnels for reverse shells and C2 callbacks.
Async multi-tunnel management inspired by open-source pentesting frameworks.

No external dependencies — stdlib + asyncio only.
"""

import asyncio
import json
import logging
import os
import shutil
import socket
import subprocess
import time
import uuid
from typing import Dict, Optional

logger = logging.getLogger("viper.tunnel_manager")


def get_local_ip() -> str:
    """Get the machine's local (LAN) IP address."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(2)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


def get_public_ip() -> str:
    """Get the machine's public IP address (via httpbin)."""
    try:
        import urllib.request
        resp = urllib.request.urlopen("https://httpbin.org/ip", timeout=5)
        data = json.loads(resp.read().decode())
        return data.get("origin", "unknown")
    except Exception:
        return "unknown"


class TunnelManager:
    """Manage reverse shell tunnels via ngrok or chisel."""

    def __init__(self):
        self._tunnels: Dict[str, dict] = {}  # tunnel_id -> info
        self._processes: Dict[str, asyncio.subprocess.Process] = {}

    # ------------------------------------------------------------------
    # ngrok
    # ------------------------------------------------------------------

    async def create_ngrok_tunnel(
        self, port: int, proto: str = "tcp", authtoken: Optional[str] = None
    ) -> dict:
        """Create an ngrok tunnel. Returns {url, port, tunnel_id} or error."""
        if not shutil.which("ngrok"):
            return {"error": "ngrok not found in PATH"}

        tunnel_id = f"ngrok-{uuid.uuid4().hex[:8]}"

        # Optional: set authtoken via config
        if authtoken:
            cfg_dir = os.path.expanduser("~/.config/ngrok")
            os.makedirs(cfg_dir, exist_ok=True)
            cfg_path = os.path.join(cfg_dir, "ngrok.yml")
            with open(cfg_path, "w") as f:
                f.write(
                    f'version: "3"\nagent:\n  authtoken: {authtoken}\n'
                )

        cmd = ["ngrok", proto, str(port), "--log=stdout", "--log-level=info"]

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
            )
            self._processes[tunnel_id] = proc

            # Parse ngrok output for the public URL (wait up to 15s)
            url = await self._parse_ngrok_url(proc, timeout=15)

            info = {
                "tunnel_id": tunnel_id,
                "type": "ngrok",
                "proto": proto,
                "local_port": port,
                "url": url or "pending (check ngrok API at localhost:4040)",
                "pid": proc.pid,
                "created": time.time(),
            }
            self._tunnels[tunnel_id] = info
            logger.info("ngrok tunnel %s created -> %s", tunnel_id, url)
            return info

        except Exception as exc:
            return {"error": str(exc)}

    async def _parse_ngrok_url(
        self, proc: asyncio.subprocess.Process, timeout: int = 15
    ) -> Optional[str]:
        """Read ngrok stdout for the tunnel URL."""
        deadline = asyncio.get_event_loop().time() + timeout
        try:
            while asyncio.get_event_loop().time() < deadline:
                line = await asyncio.wait_for(
                    proc.stdout.readline(), timeout=2
                )
                if not line:
                    break
                text = line.decode("utf-8", errors="replace")
                # ngrok log: msg="started tunnel" ... url=tcp://X.tcp.ngrok.io:PORT
                if "url=" in text:
                    for part in text.split():
                        if part.startswith("url="):
                            return part[4:]
        except (asyncio.TimeoutError, Exception):
            pass
        return None

    # ------------------------------------------------------------------
    # chisel
    # ------------------------------------------------------------------

    async def create_chisel_tunnel(
        self,
        remote_port: int,
        local_port: int,
        server_url: str,
        auth: Optional[str] = None,
    ) -> dict:
        """Create a chisel reverse tunnel. Returns {url, tunnel_id} or error."""
        if not shutil.which("chisel"):
            return {"error": "chisel not found in PATH"}

        tunnel_id = f"chisel-{uuid.uuid4().hex[:8]}"

        cmd = ["chisel", "client"]
        if auth:
            cmd += ["--auth", auth]
        cmd += [server_url, f"R:{remote_port}:localhost:{local_port}"]

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
            )
            self._processes[tunnel_id] = proc

            info = {
                "tunnel_id": tunnel_id,
                "type": "chisel",
                "server_url": server_url,
                "remote_port": remote_port,
                "local_port": local_port,
                "pid": proc.pid,
                "created": time.time(),
            }
            self._tunnels[tunnel_id] = info
            logger.info(
                "chisel tunnel %s: %s R:%d->localhost:%d",
                tunnel_id, server_url, remote_port, local_port,
            )
            return info

        except Exception as exc:
            return {"error": str(exc)}

    # ------------------------------------------------------------------
    # Management
    # ------------------------------------------------------------------

    def get_tunnel(self, tunnel_id: str) -> Optional[dict]:
        """Get tunnel info by ID."""
        info = self._tunnels.get(tunnel_id)
        if info:
            proc = self._processes.get(tunnel_id)
            info["alive"] = proc is not None and proc.returncode is None
        return info

    def list_tunnels(self) -> list:
        """List all tunnels with current status."""
        result = []
        for tid, info in self._tunnels.items():
            proc = self._processes.get(tid)
            entry = dict(info)
            entry["alive"] = proc is not None and proc.returncode is None
            result.append(entry)
        return result

    async def close_tunnel(self, tunnel_id: str) -> bool:
        """Close a specific tunnel."""
        proc = self._processes.pop(tunnel_id, None)
        self._tunnels.pop(tunnel_id, None)
        if proc is None:
            return False
        return await self._kill_proc(proc, tunnel_id)

    async def close_all(self):
        """Close all tunnels."""
        for tid in list(self._tunnels.keys()):
            await self.close_tunnel(tid)
        logger.info("All tunnels closed")

    @staticmethod
    async def _kill_proc(proc: asyncio.subprocess.Process, name: str) -> bool:
        """Terminate a subprocess gracefully, then kill if needed."""
        if proc.returncode is not None:
            return True
        try:
            proc.terminate()
            try:
                await asyncio.wait_for(proc.wait(), timeout=5)
            except asyncio.TimeoutError:
                proc.kill()
                await proc.wait()
            logger.info("Stopped %s (pid %d)", name, proc.pid)
            return True
        except Exception as exc:
            logger.error("Error stopping %s: %s", name, exc)
            return False
