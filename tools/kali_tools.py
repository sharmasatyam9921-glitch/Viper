"""
VIPER 4.0 Phase 7 — Kali Tool Wrappers

Async wrappers for common pentest tools: shell, code execution, hydra,
nmap, naabu, curl. Works as local subprocess calls. Each function checks
if the binary is installed, executes via asyncio.subprocess, and returns
stdout + stderr.

Network recon tool signatures inspired by open-source pentesting frameworks.
No external dependencies — stdlib + asyncio only.
"""

import asyncio
import logging
import os
import re
import shlex
import shutil
import tempfile
from typing import Optional

logger = logging.getLogger("viper.kali_tools")

# ANSI escape stripper
_ANSI_RE = re.compile(r'\x1b\[[0-9;]*[a-zA-Z]')

# Dangerous commands that must never be executed
_BLOCKED_PATTERNS = [
    r'\brm\s+-rf\s+/',
    r'\bmkfs\b',
    r'\bformat\b',
    r'\bdd\s+if=.*of=/dev/',
    r':\(\)\s*\{\s*:\|:&\s*\};\s*:',  # fork bomb
    r'\bshutdown\b',
    r'\breboot\b',
    r'\binit\s+0\b',
]
_BLOCKED_RE = re.compile("|".join(_BLOCKED_PATTERNS), re.IGNORECASE)

# Language map for execute_code
_LANG_MAP = {
    "python": ("py",  "python3"),
    "py":     ("py",  "python3"),
    "bash":   ("sh",  "bash"),
    "sh":     ("sh",  "bash"),
    "shell":  ("sh",  "bash"),
    "ruby":   ("rb",  "ruby"),
    "rb":     ("rb",  "ruby"),
    "perl":   ("pl",  "perl"),
    "pl":     ("pl",  "perl"),
    "c":      ("c",   None),
    "cpp":    ("cpp", None),
    "c++":    ("cpp", None),
}


def _check_tool(name: str) -> Optional[str]:
    """Return full path if tool exists, else None."""
    return shutil.which(name)


async def _run_subprocess(
    cmd: list, timeout: int, stdin_data: Optional[bytes] = None
) -> str:
    """Run a command via asyncio subprocess and return combined output."""
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdin=asyncio.subprocess.PIPE if stdin_data else asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(
            proc.communicate(input=stdin_data), timeout=timeout
        )
        output = stdout.decode("utf-8", errors="replace")
        if stderr:
            err_text = stderr.decode("utf-8", errors="replace").strip()
            if err_text:
                output += f"\n[STDERR]: {err_text}"
        if not output.strip():
            if proc.returncode != 0:
                return f"[ERROR] Command exited with code {proc.returncode}"
            return "[INFO] Command completed with no output"
        return output
    except asyncio.TimeoutError:
        # Try to kill the process
        try:
            proc.kill()
        except Exception:
            pass
        return f"[ERROR] Command timed out after {timeout} seconds"
    except FileNotFoundError:
        return f"[ERROR] {cmd[0]} not found in PATH"
    except Exception as exc:
        return f"[ERROR] {exc}"


# =====================================================================
# Tool functions
# =====================================================================

async def kali_shell(command: str, timeout: int = 60) -> str:
    """Execute a shell command. Safety: blocks destructive patterns."""
    if _BLOCKED_RE.search(command):
        return "[BLOCKED] Dangerous command pattern detected. Aborting."

    logger.info("kali_shell: %s", command[:120])
    return await _run_subprocess(["bash", "-c", command], timeout=timeout)


async def execute_code(
    language: str, code: str, timeout: int = 30, filename: str = "viper_exec"
) -> str:
    """Write code to a temp file and execute it.

    Supported languages: python, bash, ruby, perl, c, cpp.
    """
    if not code or not code.strip():
        return "[ERROR] No code provided"

    lang_key = language.lower().strip()
    if lang_key not in _LANG_MAP:
        supported = sorted(set(_LANG_MAP.keys()))
        return f"[ERROR] Unsupported language '{language}'. Supported: {', '.join(supported)}"

    ext, interpreter = _LANG_MAP[lang_key]
    safe_name = re.sub(r'[^a-zA-Z0-9_-]', '_', filename)
    filepath = os.path.join(tempfile.gettempdir(), f"{safe_name}.{ext}")
    binary_path = os.path.join(tempfile.gettempdir(), safe_name)

    # Write code to file
    try:
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(code)
    except Exception as exc:
        return f"[ERROR] Failed to write code file: {exc}"

    logger.info("execute_code: %s (%s)", filepath, language)

    if interpreter:
        if not _check_tool(interpreter):
            return f"[ERROR] {interpreter} not found in PATH"
        return await _run_subprocess([interpreter, filepath], timeout=timeout)
    else:
        # Compiled: gcc / g++
        compiler = "gcc" if ext == "c" else "g++"
        if not _check_tool(compiler):
            return f"[ERROR] {compiler} not found in PATH"

        # Compile
        compile_out = await _run_subprocess(
            [compiler, filepath, "-o", binary_path], timeout=60
        )
        if "[ERROR]" in compile_out:
            return f"[ERROR] Compilation failed:\n{compile_out}"

        # Run binary
        return await _run_subprocess([binary_path], timeout=timeout)


async def execute_hydra(args: str, timeout: int = 1800) -> str:
    """Run THC Hydra for credential testing. Parses successful credentials."""
    if not _check_tool("hydra"):
        return "[ERROR] hydra not found in PATH"

    logger.info("execute_hydra: hydra %s", args[:120])
    cmd = ["hydra"] + shlex.split(args)
    output = await _run_subprocess(cmd, timeout=timeout)

    # Extract successful logins
    creds = []
    for line in output.splitlines():
        # Hydra success format: [PORT][SERVICE] host:IP   login:USER   password:PASS
        if "login:" in line.lower() and "password:" in line.lower():
            creds.append(line.strip())
    if creds:
        output += "\n\n[VIPER] Successful credentials found:\n" + "\n".join(creds)

    return output


async def execute_nmap(args: str, timeout: int = 600) -> str:
    """Run nmap with given arguments."""
    if not _check_tool("nmap"):
        return "[ERROR] nmap not found in PATH"

    logger.info("execute_nmap: nmap %s", args[:120])
    cmd = ["nmap"] + shlex.split(args)
    return await _run_subprocess(cmd, timeout=timeout)


async def execute_naabu(args: str, timeout: int = 300) -> str:
    """Run naabu port scanner."""
    if not _check_tool("naabu"):
        return "[ERROR] naabu not found in PATH"

    logger.info("execute_naabu: naabu %s", args[:120])
    cmd = ["naabu"] + shlex.split(args)
    output = await _run_subprocess(cmd, timeout=timeout)
    # Strip ANSI codes and info lines from naabu stderr
    output = _ANSI_RE.sub("", output)
    return output


async def execute_curl(args: str, timeout: int = 60) -> str:
    """Run curl with given arguments."""
    if not _check_tool("curl"):
        return "[ERROR] curl not found in PATH"

    logger.info("execute_curl: curl %s", args[:120])
    cmd = ["curl"] + shlex.split(args)
    return await _run_subprocess(cmd, timeout=timeout)
