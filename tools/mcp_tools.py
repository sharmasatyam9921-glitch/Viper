"""
VIPER 4.0 Phase 7 — Unified MCP Tool Interface

Provides the same API whether running locally (subprocess) or via a
Docker-based MCP Kali sandbox (SSE transport). Auto-detects mode.

No external MCP library — MCP mode uses plain HTTP/SSE calls via urllib.
No external dependencies — stdlib + asyncio only.
"""

import asyncio
import json
import logging
import shutil
import urllib.request
import urllib.error
from typing import Any, Callable, Coroutine, Dict, List, Optional

from . import kali_tools
from .msf_persistent import PersistentMsfConsole
from .tunnel_manager import TunnelManager

logger = logging.getLogger("viper.mcp_tools")

# Default MCP server URL when running in Docker mode
_MCP_BASE_URL = "http://localhost:8000"


# =====================================================================
# Tool registry — maps tool names to local async callables
# =====================================================================

# Singletons (created lazily)
_msf_console: Optional[PersistentMsfConsole] = None
_tunnel_mgr: Optional[TunnelManager] = None


def _get_msf() -> PersistentMsfConsole:
    global _msf_console
    if _msf_console is None:
        _msf_console = PersistentMsfConsole()
    return _msf_console


def _get_tunnels() -> TunnelManager:
    global _tunnel_mgr
    if _tunnel_mgr is None:
        _tunnel_mgr = TunnelManager()
    return _tunnel_mgr


async def _msf_execute(args: dict) -> dict:
    """Execute a Metasploit console command."""
    msf = _get_msf()
    command = args.get("command", "")
    timeout = args.get("timeout", 120)
    output = await msf.execute(command, timeout=timeout)
    return {"output": output, "success": True, "sessions": msf.get_sessions()}


async def _tunnel_create_ngrok(args: dict) -> dict:
    mgr = _get_tunnels()
    return await mgr.create_ngrok_tunnel(
        port=args.get("port", 4444),
        proto=args.get("proto", "tcp"),
        authtoken=args.get("authtoken"),
    )


async def _tunnel_create_chisel(args: dict) -> dict:
    mgr = _get_tunnels()
    return await mgr.create_chisel_tunnel(
        remote_port=args.get("remote_port", 4444),
        local_port=args.get("local_port", 4444),
        server_url=args.get("server_url", ""),
        auth=args.get("auth"),
    )


async def _tunnel_list(args: dict) -> dict:
    return {"tunnels": _get_tunnels().list_tunnels()}


async def _tunnel_close(args: dict) -> dict:
    tid = args.get("tunnel_id", "")
    ok = await _get_tunnels().close_tunnel(tid)
    return {"closed": ok}


# Wrap kali_tools functions to accept dict args and return dict
async def _wrap_kali_shell(args: dict) -> dict:
    out = await kali_tools.kali_shell(args.get("command", ""), args.get("timeout", 60))
    return {"output": out, "success": "[ERROR]" not in out and "[BLOCKED]" not in out}


async def _wrap_execute_code(args: dict) -> dict:
    out = await kali_tools.execute_code(
        language=args.get("language", "python"),
        code=args.get("code", ""),
        timeout=args.get("timeout", 30),
    )
    return {"output": out, "success": "[ERROR]" not in out}


async def _wrap_hydra(args: dict) -> dict:
    out = await kali_tools.execute_hydra(args.get("args", ""), args.get("timeout", 1800))
    return {"output": out, "success": "[ERROR]" not in out}


async def _wrap_nmap(args: dict) -> dict:
    out = await kali_tools.execute_nmap(args.get("args", ""), args.get("timeout", 600))
    return {"output": out, "success": "[ERROR]" not in out}


async def _wrap_naabu(args: dict) -> dict:
    out = await kali_tools.execute_naabu(args.get("args", ""), args.get("timeout", 300))
    return {"output": out, "success": "[ERROR]" not in out}


async def _wrap_curl(args: dict) -> dict:
    out = await kali_tools.execute_curl(args.get("args", ""), args.get("timeout", 60))
    return {"output": out, "success": "[ERROR]" not in out}


# Full registry
TOOL_REGISTRY: Dict[str, dict] = {
    "kali_shell": {
        "fn": _wrap_kali_shell,
        "description": "Execute a shell command in the Kali environment",
        "params": ["command", "timeout"],
    },
    "execute_code": {
        "fn": _wrap_execute_code,
        "description": "Write code to file and execute (python, bash, ruby, perl, c, cpp)",
        "params": ["language", "code", "timeout"],
    },
    "execute_hydra": {
        "fn": _wrap_hydra,
        "description": "Run THC Hydra credential testing",
        "params": ["args", "timeout"],
    },
    "execute_nmap": {
        "fn": _wrap_nmap,
        "description": "Run nmap port/service scanner",
        "params": ["args", "timeout"],
    },
    "execute_naabu": {
        "fn": _wrap_naabu,
        "description": "Run naabu fast port scanner",
        "params": ["args", "timeout"],
    },
    "execute_curl": {
        "fn": _wrap_curl,
        "description": "Run curl HTTP client",
        "params": ["args", "timeout"],
    },
    "metasploit_console": {
        "fn": _msf_execute,
        "description": "Execute a command in persistent Metasploit console",
        "params": ["command", "timeout"],
    },
    "tunnel_ngrok": {
        "fn": _tunnel_create_ngrok,
        "description": "Create ngrok TCP tunnel for reverse shells",
        "params": ["port", "proto", "authtoken"],
    },
    "tunnel_chisel": {
        "fn": _tunnel_create_chisel,
        "description": "Create chisel reverse tunnel",
        "params": ["remote_port", "local_port", "server_url", "auth"],
    },
    "tunnel_list": {
        "fn": _tunnel_list,
        "description": "List all active tunnels",
        "params": [],
    },
    "tunnel_close": {
        "fn": _tunnel_close,
        "description": "Close a tunnel by ID",
        "params": ["tunnel_id"],
    },
}


# =====================================================================
# MCPToolInterface
# =====================================================================

class MCPToolInterface:
    """Unified tool interface — local subprocess or Docker MCP backend."""

    def __init__(self, mode: str = "auto", mcp_url: str = _MCP_BASE_URL):
        """
        Args:
            mode: 'auto' (detect Docker), 'local' (subprocess), 'mcp' (Docker).
            mcp_url: Base URL of the MCP server when in mcp mode.
        """
        self._mode = mode
        self._mcp_url = mcp_url.rstrip("/")
        self._tools = dict(TOOL_REGISTRY)

        if mode == "auto":
            self._detect_mode()

    def _detect_mode(self):
        """Auto-detect: if Docker is available and kali-sandbox running, use MCP; else local."""
        if not shutil.which("docker"):
            self._mode = "local"
            return

        try:
            import subprocess as sp
            result = sp.run(
                ["docker", "ps", "--filter", "name=kali-sandbox", "--format", "{{.Names}}"],
                capture_output=True, text=True, timeout=5,
            )
            if "kali-sandbox" in result.stdout:
                # Verify MCP server is reachable
                try:
                    req = urllib.request.urlopen(f"{self._mcp_url}/health", timeout=3)
                    if req.status == 200:
                        self._mode = "mcp"
                        logger.info("MCP mode: kali-sandbox Docker container detected")
                        return
                except Exception:
                    pass
        except Exception:
            pass

        self._mode = "local"
        logger.info("Local mode: no Docker MCP sandbox detected")

    @property
    def mode(self) -> str:
        return self._mode

    async def execute(self, tool_name: str, args: dict, max_retries: int = 3, timeout: int = 60) -> dict:
        """Execute a tool with retry logic. Returns {output, success, error?}."""
        if tool_name not in self._tools:
            return {"output": "", "success": False, "error": f"Unknown tool: {tool_name}"}

        if self._mode == "mcp":
            return await self._call_with_retry(tool_name, args, max_retries=max_retries, timeout=timeout)
        return await self._execute_local(tool_name, args)

    async def _call_with_retry(self, tool_name: str, args: dict, max_retries: int = 3, timeout: int = 60) -> dict:
        """Execute MCP call with exponential backoff retry on connection/timeout errors."""
        for attempt in range(max_retries):
            try:
                result = await asyncio.wait_for(
                    self._execute_mcp(tool_name, args), timeout=timeout
                )
                # If the result indicates a connection-level failure, treat it as retryable
                if not result.get("success") and result.get("error", "").startswith("MCP server unreachable"):
                    raise ConnectionError(result["error"])
                return result
            except (ConnectionError, asyncio.TimeoutError, OSError) as e:
                if attempt < max_retries - 1:
                    wait = 2 ** attempt
                    logger.warning(
                        "MCP %s attempt %d/%d failed: %s, retrying in %ds",
                        tool_name, attempt + 1, max_retries, e, wait,
                    )
                    await asyncio.sleep(wait)
                else:
                    logger.error(
                        "MCP %s failed after %d attempts: %s",
                        tool_name, max_retries, e,
                    )
                    return {
                        "output": "",
                        "success": False,
                        "error": f"MCP {tool_name} failed after {max_retries} attempts: {e}",
                        "tool": tool_name,
                    }
        # Should not reach here, but safety fallback
        return {"output": "", "success": False, "error": f"MCP {tool_name}: retry loop exhausted"}

    async def _execute_local(self, tool_name: str, args: dict) -> dict:
        """Execute tool as local subprocess via registered function."""
        entry = self._tools[tool_name]
        fn = entry["fn"]
        try:
            result = await fn(args)
            if isinstance(result, dict):
                result.setdefault("success", True)
                return result
            return {"output": str(result), "success": True}
        except Exception as exc:
            logger.error("Local tool %s failed: %s", tool_name, exc)
            return {"output": "", "success": False, "error": str(exc)}

    async def _execute_mcp(self, tool_name: str, args: dict) -> dict:
        """Execute tool via MCP server using JSON-RPC over HTTP."""
        payload = json.dumps({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": tool_name, "arguments": args},
        }).encode("utf-8")

        try:
            req = urllib.request.Request(
                f"{self._mcp_url}/mcp",
                data=payload,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            # Run blocking urllib in thread pool to stay async
            loop = asyncio.get_event_loop()
            resp = await loop.run_in_executor(None, lambda: urllib.request.urlopen(req, timeout=300))
            body = json.loads(resp.read().decode("utf-8"))

            if "result" in body:
                content = body["result"]
                # MCP tool result: {content: [{type: "text", text: "..."}]}
                if isinstance(content, dict) and "content" in content:
                    texts = [
                        c.get("text", "") for c in content["content"]
                        if c.get("type") == "text"
                    ]
                    return {"output": "\n".join(texts), "success": True}
                return {"output": str(content), "success": True}
            elif "error" in body:
                return {
                    "output": "",
                    "success": False,
                    "error": body["error"].get("message", str(body["error"])),
                }
            return {"output": str(body), "success": True}

        except urllib.error.URLError as exc:
            return {"output": "", "success": False, "error": f"MCP server unreachable: {exc}"}
        except Exception as exc:
            return {"output": "", "success": False, "error": f"MCP call failed: {exc}"}

    def get_available_tools(self) -> list:
        """List available tools with descriptions."""
        result = []
        for name, entry in self._tools.items():
            available = True
            # For local mode, check if the underlying binary exists
            if self._mode == "local":
                # Tools that need specific binaries
                bin_map = {
                    "execute_nmap": "nmap",
                    "execute_naabu": "naabu",
                    "execute_hydra": "hydra",
                    "execute_curl": "curl",
                    "metasploit_console": "msfconsole",
                    "tunnel_ngrok": "ngrok",
                    "tunnel_chisel": "chisel",
                }
                if name in bin_map:
                    available = shutil.which(bin_map[name]) is not None

            result.append({
                "name": name,
                "description": entry["description"],
                "params": entry["params"],
                "available": available,
            })
        return result

    def is_tool_available(self, tool_name: str) -> bool:
        """Check if a specific tool is available."""
        if tool_name not in self._tools:
            return False
        if self._mode == "mcp":
            return True  # MCP server handles availability
        # Local: check binary
        bin_map = {
            "execute_nmap": "nmap",
            "execute_naabu": "naabu",
            "execute_hydra": "hydra",
            "execute_curl": "curl",
            "metasploit_console": "msfconsole",
            "tunnel_ngrok": "ngrok",
            "tunnel_chisel": "chisel",
        }
        if tool_name in bin_map:
            return shutil.which(bin_map[tool_name]) is not None
        return True

    def register_tool(
        self, name: str, fn: Callable, description: str = "", params: list = None
    ):
        """Register a custom tool at runtime."""
        self._tools[name] = {
            "fn": fn,
            "description": description,
            "params": params or [],
        }
        logger.info("Registered custom tool: %s", name)
