#!/usr/bin/env python3
"""
External Tool Manager for VIPER

Centralized registry for external security tools (nuclei, httpx, subfinder, etc.)
with auto-detection, version checking, and unified subprocess execution.
"""

import asyncio
import json
import logging
import os
import platform
import shutil
import subprocess
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger("viper.tool_manager")


@dataclass
class ExternalTool:
    name: str
    binary: str
    install_cmd: str
    min_version: str = ""
    found_path: Optional[str] = None
    version: Optional[str] = None
    available: bool = False
    # Verify marker that must appear in `--version`/`--help` output for
    # this to be considered the correct tool (disambiguates name
    # collisions like Python httpx vs ProjectDiscovery httpx).
    verify_marker: Optional[str] = None


# Common locations to search before falling back to $PATH. Go install
# tools land in $GOPATH/bin (default ~/go/bin) on every platform.
def _candidate_dirs() -> List[Path]:
    home = Path.home()
    dirs: List[Path] = []
    gopath = os.environ.get("GOPATH")
    if gopath:
        dirs.append(Path(gopath) / "bin")
    dirs.append(home / "go" / "bin")
    if platform.system() == "Windows":
        dirs.extend([
            Path("C:/tools"),
            Path("C:/tools/nuclei"),
            Path("C:/tools/subfinder"),
            Path("C:/tools/httpx"),
            Path("C:/tools/katana"),
            Path("C:/Program Files/Nmap"),
            Path("C:/Program Files (x86)/Nmap"),
        ])
    else:
        dirs.extend([
            Path("/usr/local/bin"),
            Path("/opt/go-tools/bin"),
            Path("/opt/tools/bin"),
        ])
    return [d for d in dirs if d.exists()]


def _binary_names(binary: str) -> List[str]:
    if platform.system() == "Windows":
        return [f"{binary}.exe", binary]
    return [binary]


# Tool definitions
TOOL_REGISTRY = {
    "nuclei": ExternalTool(
        name="Nuclei",
        binary="nuclei",
        install_cmd="go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
        min_version="3.0.0",
        verify_marker="nuclei",
    ),
    "httpx": ExternalTool(
        name="httpx",
        binary="httpx",
        install_cmd="go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest",
        # ProjectDiscovery httpx prints "Current Version: …" — Python httpx
        # cli doesn't, so this catches the collision.
        verify_marker="projectdiscovery",
    ),
    "subfinder": ExternalTool(
        name="Subfinder",
        binary="subfinder",
        install_cmd="go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
        verify_marker="subfinder",
    ),
    "katana": ExternalTool(
        name="Katana",
        binary="katana",
        install_cmd="go install -v github.com/projectdiscovery/katana/cmd/katana@latest",
        verify_marker="katana",
    ),
    "naabu": ExternalTool(
        name="Naabu",
        binary="naabu",
        install_cmd="go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest",
        verify_marker="naabu",
    ),
    "dnsx": ExternalTool(
        name="dnsx",
        binary="dnsx",
        install_cmd="go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest",
        verify_marker="dnsx",
    ),
    "amass": ExternalTool(
        name="Amass",
        binary="amass",
        install_cmd="go install -v github.com/owasp-amass/amass/v4/...@master",
        verify_marker="amass",
    ),
    "gau": ExternalTool(
        name="GAU",
        binary="gau",
        install_cmd="go install github.com/lc/gau/v2/cmd/gau@latest",
    ),
    "ffuf": ExternalTool(
        name="ffuf",
        binary="ffuf",
        install_cmd="go install github.com/ffuf/ffuf/v2@latest",
        verify_marker="ffuf",
    ),
    "dalfox": ExternalTool(
        name="Dalfox",
        binary="dalfox",
        install_cmd="go install github.com/hahwul/dalfox/v2@latest",
        verify_marker="dalfox",
    ),
    "gobuster": ExternalTool(
        name="Gobuster",
        binary="gobuster",
        install_cmd="go install github.com/OJ/gobuster/v3@latest",
        verify_marker="gobuster",
    ),
    "hakrawler": ExternalTool(
        name="hakrawler",
        binary="hakrawler",
        install_cmd="go install github.com/hakluke/hakrawler@latest",
    ),
    "gospider": ExternalTool(
        name="gospider",
        binary="gospider",
        install_cmd="go install github.com/jaeles-project/gospider@latest",
    ),
    "qsreplace": ExternalTool(
        name="qsreplace",
        binary="qsreplace",
        install_cmd="go install github.com/tomnomnom/qsreplace@latest",
    ),
    "anew": ExternalTool(
        name="anew",
        binary="anew",
        install_cmd="go install github.com/tomnomnom/anew@latest",
    ),
    "gf": ExternalTool(
        name="gf",
        binary="gf",
        install_cmd="go install github.com/tomnomnom/gf@latest",
    ),
    "nmap": ExternalTool(
        name="Nmap",
        binary="nmap",
        install_cmd="Download from https://nmap.org/download",
    ),
    "sqlmap": ExternalTool(
        name="sqlmap",
        binary="sqlmap",
        install_cmd="pip install sqlmap",
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
            except (json.JSONDecodeError, KeyError) as e:
                logger.debug("Ignoring corrupt tool cache %s: %s", self._cache_path, e)

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

    def _candidate_paths(self, tool: ExternalTool) -> List[str]:
        """Build search order: well-known install dirs first, then PATH.

        Putting Go-install dirs first matters on Windows where Python's
        ``httpx`` CLI shadows ProjectDiscovery's ``httpx.exe`` in $PATH.
        """
        out: List[str] = []
        for d in _candidate_dirs():
            for name in _binary_names(tool.binary):
                p = d / name
                if p.is_file():
                    out.append(str(p))
        for name in _binary_names(tool.binary):
            p = shutil.which(name)
            if p and p not in out:
                out.append(p)
        return out

    def _verify(self, path: str, marker: Optional[str]) -> Tuple[bool, Optional[str]]:
        """Run --version and (a) extract a version, (b) confirm marker
        appears in output if the tool has one. Returns (ok, version).
        """
        try:
            result = subprocess.run(
                [path, "--version"],
                capture_output=True, text=True, timeout=10,
                creationflags=subprocess.CREATE_NO_WINDOW
                    if hasattr(subprocess, "CREATE_NO_WINDOW") else 0,
            )
            output = (result.stdout + result.stderr).lower()
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            return (marker is None, None)
        if marker and marker.lower() not in output:
            # Wrong binary (e.g. Python httpx shadows ProjectDiscovery httpx)
            return (False, None)
        ver = None
        m = re.search(r"(\d+\.\d+(?:\.\d+)?)", output)
        if m:
            ver = m.group(1)
        return (True, ver)

    def detect(self, name: str) -> bool:
        """Detect a single tool. Tries every candidate path and picks the
        first one whose --version output matches the verify_marker (if
        any). This disambiguates same-name tools across PATH dirs.
        """
        tool = self.tools.get(name)
        if not tool:
            return False

        for path in self._candidate_paths(tool):
            ok, ver = self._verify(path, tool.verify_marker)
            if ok:
                tool.found_path = path
                tool.version = ver
                tool.available = True
                return True

        tool.available = False
        tool.found_path = None
        return False

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
            await proc.wait()  # reap the killed child so it doesn't linger as a zombie
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
