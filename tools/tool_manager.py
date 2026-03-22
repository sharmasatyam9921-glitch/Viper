#!/usr/bin/env python3
"""
External Tool Manager for VIPER

Centralized registry for external security tools (nuclei, httpx, subfinder, etc.)
with auto-detection, version checking, and unified subprocess execution.
"""

import asyncio
import json
import shutil
import subprocess
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple


@dataclass
class ExternalTool:
    name: str
    binary: str
    install_cmd: str
    min_version: str = ""
    found_path: Optional[str] = None
    version: Optional[str] = None
    available: bool = False


# Tool definitions
TOOL_REGISTRY = {
    "nuclei": ExternalTool(
        name="Nuclei",
        binary="nuclei",
        install_cmd="go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
        min_version="3.0.0",
    ),
    "httpx": ExternalTool(
        name="httpx",
        binary="httpx",
        install_cmd="go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest",
    ),
    "subfinder": ExternalTool(
        name="Subfinder",
        binary="subfinder",
        install_cmd="go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
    ),
    "katana": ExternalTool(
        name="Katana",
        binary="katana",
        install_cmd="go install -v github.com/projectdiscovery/katana/cmd/katana@latest",
    ),
    "gau": ExternalTool(
        name="GAU",
        binary="gau",
        install_cmd="go install github.com/lc/gau/v2/cmd/gau@latest",
    ),
    "nmap": ExternalTool(
        name="Nmap",
        binary="nmap",
        install_cmd="Download from https://nmap.org/download",
    ),
    "curl": ExternalTool(
        name="cURL",
        binary="curl",
        install_cmd="Built into most systems",
    ),
}


class ToolManager:
    """Manages external security tools."""

    def __init__(self, auto_detect: bool = True):
        self.tools: Dict[str, ExternalTool] = {}
        for name, template in TOOL_REGISTRY.items():
            self.tools[name] = ExternalTool(
                name=template.name,
                binary=template.binary,
                install_cmd=template.install_cmd,
                min_version=template.min_version,
            )
        # Load any cached tool paths
        self._cache_path = Path(__file__).parent.parent / "data" / "tools-installed.json"
        self._load_cache()
        if auto_detect:
            self.detect_all()

    def _load_cache(self):
        if self._cache_path.exists():
            try:
                data = json.loads(self._cache_path.read_text())
                for name, info in data.items():
                    if name in self.tools and isinstance(info, dict):
                        self.tools[name].found_path = info.get("path")
                        self.tools[name].version = info.get("version")
            except (json.JSONDecodeError, KeyError):
                pass

    def _save_cache(self):
        self._cache_path.parent.mkdir(parents=True, exist_ok=True)
        data = {}
        for name, tool in self.tools.items():
            if tool.available:
                data[name] = {"path": tool.found_path, "version": tool.version}
        self._cache_path.write_text(json.dumps(data, indent=2))

    def detect_all(self) -> Dict[str, bool]:
        """Detect all tools. Returns {name: available}."""
        results = {}
        for name in self.tools:
            results[name] = self.detect(name)
        self._save_cache()
        return results

    def detect(self, name: str) -> bool:
        """Detect a single tool."""
        tool = self.tools.get(name)
        if not tool:
            return False

        path = shutil.which(tool.binary)
        if path:
            tool.found_path = path
            tool.available = True
            # Try to get version
            try:
                result = subprocess.run(
                    [path, "--version"],
                    capture_output=True, text=True, timeout=10,
                    creationflags=subprocess.CREATE_NO_WINDOW if hasattr(subprocess, 'CREATE_NO_WINDOW') else 0,
                )
                output = result.stdout + result.stderr
                # Extract version pattern like x.y.z
                match = re.search(r"(\d+\.\d+\.?\d*)", output)
                if match:
                    tool.version = match.group(1)
            except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
                pass
        else:
            tool.available = False
        return tool.available

    def check_tool(self, name: str) -> bool:
        """Check if a tool is available."""
        tool = self.tools.get(name)
        return tool.available if tool else False

    def get_path(self, name: str) -> Optional[str]:
        """Get path to a tool binary, or None if not found."""
        tool = self.tools.get(name)
        if tool and tool.available:
            return tool.found_path
        return None

    def install_hint(self, name: str) -> str:
        """Get install instructions for a tool."""
        tool = self.tools.get(name)
        if not tool:
            return f"Unknown tool: {name}"
        if tool.available:
            return f"{tool.name} is already installed at {tool.found_path}"
        return f"Install {tool.name}: {tool.install_cmd}"

    def check_all(self) -> Dict[str, bool]:
        """Return availability status of all tools."""
        return {name: tool.available for name, tool in self.tools.items()}

    def summary(self) -> str:
        """Human-readable summary of tool status."""
        lines = ["External Tools:"]
        for name, tool in self.tools.items():
            status = f"OK ({tool.version})" if tool.available else "MISSING"
            lines.append(f"  {tool.name:12s} [{status}]")
        return "\n".join(lines)

    async def run_tool(
        self,
        name: str,
        args: List[str],
        timeout: int = 300,
        stdin_data: Optional[str] = None,
    ) -> Tuple[int, str, str]:
        """
        Run an external tool asynchronously.

        Returns: (return_code, stdout, stderr)
        Raises: RuntimeError if tool not available.
        """
        tool = self.tools.get(name)
        if not tool or not tool.available:
            raise RuntimeError(
                f"Tool '{name}' not available. {self.install_hint(name)}"
            )

        cmd = [tool.found_path] + args
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                stdin=asyncio.subprocess.PIPE if stdin_data else None,
            )
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(input=stdin_data.encode() if stdin_data else None),
                timeout=timeout,
            )
            return (
                proc.returncode or 0,
                stdout.decode(errors="replace"),
                stderr.decode(errors="replace"),
            )
        except asyncio.TimeoutError:
            proc.kill()
            return (-1, "", f"Tool '{name}' timed out after {timeout}s")
        except FileNotFoundError:
            tool.available = False
            return (-1, "", f"Tool '{name}' binary not found at {tool.found_path}")

    def run_tool_sync(
        self,
        name: str,
        args: List[str],
        timeout: int = 300,
        stdin_data: Optional[str] = None,
    ) -> Tuple[int, str, str]:
        """Synchronous version of run_tool."""
        tool = self.tools.get(name)
        if not tool or not tool.available:
            raise RuntimeError(
                f"Tool '{name}' not available. {self.install_hint(name)}"
            )

        cmd = [tool.found_path] + args
        try:
            result = subprocess.run(
                cmd,
                capture_output=True, text=True, timeout=timeout,
                input=stdin_data,
                creationflags=subprocess.CREATE_NO_WINDOW if hasattr(subprocess, 'CREATE_NO_WINDOW') else 0,
            )
            return (result.returncode, result.stdout, result.stderr)
        except subprocess.TimeoutExpired:
            return (-1, "", f"Tool '{name}' timed out after {timeout}s")
        except FileNotFoundError:
            tool.available = False
            return (-1, "", f"Tool '{name}' binary not found at {tool.found_path}")


if __name__ == "__main__":
    tm = ToolManager()
    print(tm.summary())
