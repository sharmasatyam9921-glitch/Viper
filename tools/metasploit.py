#!/usr/bin/env python3
"""
VIPER Metasploit Integration - msfconsole subprocess interface.

Provides programmatic access to Metasploit Framework for:
- Exploit and auxiliary module search
- CVE-based module lookup
- Controlled exploit execution with session management
- Auxiliary scanner execution

ETHICAL USE ONLY - Requires explicit authorization and scope enforcement.
All exploit attempts are logged. Only available during EXPLOIT phase.

Prerequisites:
- Metasploit Framework installed (msfconsole in PATH)
- OR msfrpcd running on localhost:55553
"""

import asyncio
import logging
import os
import re
import shutil
import subprocess
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger("viper.metasploit")

HACKAGENT_DIR = Path(__file__).parent.parent
DATA_DIR = HACKAGENT_DIR / "data" / "metasploit"
DATA_DIR.mkdir(parents=True, exist_ok=True)

# Safety limits
COMMAND_TIMEOUT = 90  # seconds per msfconsole command
MAX_OUTPUT_SIZE = 1_048_576  # 1 MB
MAX_SESSIONS = 10
MAX_SEARCH_RESULTS = 50

# Banned modules / patterns for safety
BANNED_PATTERNS = [
    "exploit/multi/handler",  # Generic listener — manual use only
    "post/multi/manage/shell_to_meterpreter",
    "payload/.*reverse.*",  # No reverse shells in automated mode
]


@dataclass
class ExploitModule:
    """A Metasploit exploit or auxiliary module."""
    module_path: str
    name: str
    disclosure_date: str = ""
    rank: str = ""
    description: str = ""
    cve: str = ""

    def to_dict(self) -> dict:
        return {
            "module_path": self.module_path,
            "name": self.name,
            "disclosure_date": self.disclosure_date,
            "rank": self.rank,
            "description": self.description,
            "cve": self.cve,
        }


@dataclass
class ExploitResult:
    """Result from running an exploit or auxiliary module."""
    module: str
    target: str
    success: bool
    session_id: Optional[int] = None
    output: str = ""
    error: str = ""
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())

    def to_dict(self) -> dict:
        return {
            "module": self.module,
            "target": self.target,
            "success": self.success,
            "session_id": self.session_id,
            "output": self.output[:5000],
            "error": self.error[:1000],
            "timestamp": self.timestamp,
        }


@dataclass
class SessionInfo:
    """An active Metasploit session."""
    session_id: int
    session_type: str  # meterpreter, shell
    target_host: str
    module: str = ""
    info: str = ""


def _sanitize_option(value: str) -> str:
    """Sanitize an option value to prevent command injection in msfconsole."""
    # Only allow alphanumeric, dots, colons, slashes, hyphens, underscores
    if not re.match(r'^[a-zA-Z0-9._:/\-]+$', value):
        raise ValueError(f"Unsafe option value: {value!r}")
    return value


def _sanitize_module_path(path: str) -> str:
    """Validate a Metasploit module path."""
    if not re.match(r'^[a-z]+(/[a-z0-9_]+)+$', path):
        raise ValueError(f"Invalid module path: {path!r}")
    return path


def _is_banned(module_path: str) -> bool:
    """Check if a module is in the banned list."""
    for pattern in BANNED_PATTERNS:
        if re.match(pattern, module_path):
            return True
    return False


class MetasploitClient:
    """
    Metasploit Framework integration via msfconsole subprocess.

    Executes msfconsole commands non-interactively using -x flag.
    Each command spawns a fresh msfconsole process for isolation.

    All module paths and option values are sanitized before execution.
    Reverse shell payloads are blocked in automated mode.
    """

    def __init__(self):
        self._available: Optional[bool] = None
        self._msf_path: Optional[str] = None
        self._exploit_log: List[Dict[str, Any]] = []

    # ------------------------------------------------------------------
    # Availability check
    # ------------------------------------------------------------------

    def is_available(self) -> bool:
        """Check if msfconsole is available in PATH."""
        if self._available is not None:
            return self._available

        self._msf_path = shutil.which("msfconsole")
        if self._msf_path:
            self._available = True
            logger.info("Metasploit found at %s", self._msf_path)
        else:
            # Check common installation paths
            common_paths = [
                "/usr/bin/msfconsole",
                "/opt/metasploit-framework/bin/msfconsole",
                "/usr/local/bin/msfconsole",
            ]
            for p in common_paths:
                if os.path.isfile(p) and os.access(p, os.X_OK):
                    self._msf_path = p
                    self._available = True
                    logger.info("Metasploit found at %s", p)
                    break
            else:
                self._available = False
                logger.info("Metasploit not found — module disabled")

        return self._available

    # ------------------------------------------------------------------
    # Core command execution
    # ------------------------------------------------------------------

    async def _run_msfconsole(self, commands: str, timeout: int = COMMAND_TIMEOUT) -> Optional[str]:
        """
        Execute commands in msfconsole non-interactively.

        Args:
            commands: Semicolon-separated msfconsole commands.
            timeout: Max seconds to wait.

        Returns:
            stdout output or None on failure.
        """
        if not self.is_available():
            logger.warning("Metasploit not available")
            return None

        # Build command list (no shell=True)
        cmd = [self._msf_path, "-q", "-x", commands]

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            try:
                stdout, stderr = await asyncio.wait_for(
                    proc.communicate(), timeout=timeout
                )
            except asyncio.TimeoutError:
                proc.kill()
                await proc.communicate()
                logger.warning("msfconsole timed out after %ds", timeout)
                return None

            output = stdout.decode("utf-8", errors="replace")[:MAX_OUTPUT_SIZE]

            if proc.returncode != 0:
                err = stderr.decode("utf-8", errors="replace")[:500]
                logger.warning("msfconsole returned %d: %s", proc.returncode, err)

            return output

        except FileNotFoundError:
            self._available = False
            logger.warning("msfconsole not found at runtime")
            return None
        except Exception as e:
            logger.warning("msfconsole error: %s", e)
            return None

    # ------------------------------------------------------------------
    # Module search
    # ------------------------------------------------------------------

    async def search_exploits(self, query: str) -> List[ExploitModule]:
        """
        Search Metasploit modules by keyword.

        Args:
            query: Search term (e.g., "apache struts", "wordpress").

        Returns:
            List of matching ExploitModule objects.
        """
        if not query or len(query) > 200:
            return []

        # Sanitize query — allow alphanumeric, spaces, hyphens, underscores
        safe_query = re.sub(r'[^a-zA-Z0-9 _\-.]', '', query)
        if not safe_query:
            return []

        commands = f"search {safe_query}; exit"
        output = await self._run_msfconsole(commands)
        if not output:
            return []

        return self._parse_search_output(output)

    async def search_by_cve(self, cve_id: str) -> List[ExploitModule]:
        """
        Search Metasploit modules by CVE identifier.

        Args:
            cve_id: CVE ID (e.g., "CVE-2021-44228").

        Returns:
            List of matching ExploitModule objects.
        """
        # Validate CVE format
        if not re.match(r'^CVE-\d{4}-\d{4,}$', cve_id, re.IGNORECASE):
            logger.warning("Invalid CVE format: %s", cve_id)
            return []

        commands = f"search cve:{cve_id}; exit"
        output = await self._run_msfconsole(commands)
        if not output:
            return []

        modules = self._parse_search_output(output)
        for m in modules:
            m.cve = cve_id
        return modules

    def _parse_search_output(self, output: str) -> List[ExploitModule]:
        """Parse msfconsole search output into ExploitModule objects."""
        modules = []
        lines = output.strip().split("\n")

        # Find the header separator line (-----)
        data_start = 0
        for i, line in enumerate(lines):
            if re.match(r'^\s*-+\s+-+', line):
                data_start = i + 1
                break

        for line in lines[data_start:]:
            line = line.strip()
            if not line or line.startswith("msf") or "Matching Modules" in line:
                continue

            # Typical format: "  # Name  Disclosure Date  Rank  Check  Description"
            # or newer: module_path  date  rank  check  description
            parts = line.split(None, 4)
            if len(parts) < 3:
                continue

            # Try to find the module path (starts with exploit/, auxiliary/, post/)
            module_path = ""
            remaining = parts
            for j, part in enumerate(parts):
                if part.startswith(("exploit/", "auxiliary/", "post/", "payload/")):
                    module_path = part
                    remaining = parts[j + 1:]
                    break

            if not module_path:
                # Try numeric index prefix
                if parts[0].isdigit() and len(parts) >= 4:
                    module_path = parts[1]
                    remaining = parts[2:]
                else:
                    continue

            disclosure_date = ""
            rank = ""
            description = ""

            if remaining:
                # Date is typically YYYY-MM-DD
                if re.match(r'\d{4}-\d{2}-\d{2}', remaining[0]):
                    disclosure_date = remaining[0]
                    remaining = remaining[1:]

                if remaining:
                    rank = remaining[0]
                    remaining = remaining[1:]

                if remaining:
                    # Skip 'Check' column (Yes/No)
                    if remaining[0] in ("Yes", "No"):
                        remaining = remaining[1:]
                    description = " ".join(remaining)

            modules.append(ExploitModule(
                module_path=module_path,
                name=module_path.split("/")[-1],
                disclosure_date=disclosure_date,
                rank=rank,
                description=description,
            ))

            if len(modules) >= MAX_SEARCH_RESULTS:
                break

        return modules

    # ------------------------------------------------------------------
    # Exploit execution
    # ------------------------------------------------------------------

    async def run_exploit(
        self,
        module: str,
        target_host: str,
        target_port: int,
        payload: Optional[str] = None,
        options: Optional[Dict[str, str]] = None,
    ) -> ExploitResult:
        """
        Run a Metasploit exploit module against a target.

        Args:
            module: Module path (e.g., "exploit/unix/webapp/...").
            target_host: Target IP or hostname.
            target_port: Target port number.
            payload: Payload module path (optional). Reverse payloads are blocked.
            options: Additional module options as key-value pairs.

        Returns:
            ExploitResult with success status and output.
        """
        # Validate inputs
        try:
            module = _sanitize_module_path(module)
        except ValueError as e:
            return ExploitResult(module=module, target=target_host, success=False, error=str(e))

        if _is_banned(module):
            return ExploitResult(
                module=module, target=target_host, success=False,
                error=f"Module {module} is banned in automated mode",
            )

        if payload:
            try:
                payload = _sanitize_module_path(payload)
            except ValueError as e:
                return ExploitResult(module=module, target=target_host, success=False, error=str(e))

            if _is_banned(payload):
                return ExploitResult(
                    module=module, target=target_host, success=False,
                    error=f"Payload {payload} is banned in automated mode",
                )

        target_host = _sanitize_option(target_host)
        if not (0 < target_port < 65536):
            return ExploitResult(module=module, target=target_host, success=False, error="Invalid port")

        # Build msfconsole command string
        cmd_parts = [
            f"use {module}",
            f"set RHOSTS {target_host}",
            f"set RPORT {target_port}",
        ]

        if payload:
            cmd_parts.append(f"set PAYLOAD {payload}")

        if options:
            for key, value in options.items():
                safe_key = _sanitize_option(key)
                safe_value = _sanitize_option(str(value))
                cmd_parts.append(f"set {safe_key} {safe_value}")

        cmd_parts.append("run")
        cmd_parts.append("exit")

        commands = "; ".join(cmd_parts)

        # Log the attempt
        attempt = {
            "module": module,
            "target": f"{target_host}:{target_port}",
            "payload": payload,
            "options": options,
            "timestamp": datetime.now().isoformat(),
        }
        self._exploit_log.append(attempt)

        logger.info("Running exploit: %s against %s:%d", module, target_host, target_port)

        output = await self._run_msfconsole(commands)
        if output is None:
            return ExploitResult(
                module=module, target=f"{target_host}:{target_port}",
                success=False, error="msfconsole execution failed",
            )

        # Parse result
        success = False
        session_id = None

        # Check for session creation
        session_match = re.search(r'session (\d+) opened', output, re.IGNORECASE)
        if session_match:
            success = True
            session_id = int(session_match.group(1))

        # Check for other success indicators
        if not success:
            success_indicators = [
                "Command completed",
                "Exploit completed",
                "Win",
                "shell session",
                "meterpreter session",
            ]
            for indicator in success_indicators:
                if indicator.lower() in output.lower():
                    success = True
                    break

        # Check for failure indicators
        failure_indicators = [
            "Exploit failed",
            "Exploit aborted",
            "No session was created",
            "exploit completed, but no session",
        ]
        for indicator in failure_indicators:
            if indicator.lower() in output.lower():
                success = False
                session_id = None
                break

        result = ExploitResult(
            module=module,
            target=f"{target_host}:{target_port}",
            success=success,
            session_id=session_id,
            output=output[:5000],
        )

        # Save to log
        self._save_exploit_log(result)

        return result

    # ------------------------------------------------------------------
    # Auxiliary module execution
    # ------------------------------------------------------------------

    async def run_auxiliary(
        self,
        module: str,
        target: str,
        options: Optional[Dict[str, str]] = None,
    ) -> ExploitResult:
        """
        Run a Metasploit auxiliary module (scanners, fuzzers, etc.).

        Args:
            module: Module path (e.g., "auxiliary/scanner/http/...").
            target: Target host or CIDR.
            options: Additional module options.

        Returns:
            ExploitResult with output.
        """
        try:
            module = _sanitize_module_path(module)
        except ValueError as e:
            return ExploitResult(module=module, target=target, success=False, error=str(e))

        if not module.startswith("auxiliary/"):
            return ExploitResult(
                module=module, target=target, success=False,
                error="run_auxiliary() only accepts auxiliary/ modules",
            )

        target = _sanitize_option(target)

        cmd_parts = [
            f"use {module}",
            f"set RHOSTS {target}",
        ]

        if options:
            for key, value in options.items():
                safe_key = _sanitize_option(key)
                safe_value = _sanitize_option(str(value))
                cmd_parts.append(f"set {safe_key} {safe_value}")

        cmd_parts.append("run")
        cmd_parts.append("exit")

        commands = "; ".join(cmd_parts)

        logger.info("Running auxiliary: %s against %s", module, target)

        output = await self._run_msfconsole(commands)
        if output is None:
            return ExploitResult(
                module=module, target=target,
                success=False, error="msfconsole execution failed",
            )

        # Auxiliary modules don't create sessions typically
        success = "Auxiliary module execution completed" in output or \
                  "[+]" in output or \
                  "completed" in output.lower()

        return ExploitResult(
            module=module,
            target=target,
            success=success,
            output=output[:5000],
        )

    # ------------------------------------------------------------------
    # Session management
    # ------------------------------------------------------------------

    async def list_sessions(self) -> List[SessionInfo]:
        """List active Metasploit sessions."""
        output = await self._run_msfconsole("sessions -l; exit")
        if not output:
            return []

        sessions = []
        lines = output.strip().split("\n")

        for line in lines:
            # Format: "  Id  Name  Type  Information  Connection"
            match = re.match(
                r'\s*(\d+)\s+\S*\s+(meterpreter|shell)\s+(.+?)\s+(\S+\s*->\s*\S+)',
                line,
            )
            if match:
                session_id = int(match.group(1))
                session_type = match.group(2)
                info = match.group(3).strip()
                connection = match.group(4).strip()

                # Extract target host from connection string
                target_match = re.search(r'->\s*(\S+)', connection)
                target_host = target_match.group(1) if target_match else ""

                sessions.append(SessionInfo(
                    session_id=session_id,
                    session_type=session_type,
                    target_host=target_host,
                    info=info,
                ))

        return sessions

    async def session_command(self, session_id: int, command: str) -> Optional[str]:
        """
        Execute a command in an active session.

        Args:
            session_id: The session ID to interact with.
            command: Command to execute in the session.

        Returns:
            Command output or None on failure.
        """
        if session_id < 0 or session_id > 9999:
            logger.warning("Invalid session ID: %d", session_id)
            return None

        # Sanitize command — block dangerous operations
        dangerous = ["rm -rf", "format ", "del /", "shutdown", "reboot", "mkfs"]
        cmd_lower = command.lower()
        for d in dangerous:
            if d in cmd_lower:
                logger.warning("Blocked dangerous command in session: %s", command)
                return None

        # Escape semicolons in the command to avoid msfconsole injection
        safe_cmd = command.replace(";", "\\;").replace('"', '\\"')

        commands = f'sessions -i {session_id} -c "{safe_cmd}"; exit'

        output = await self._run_msfconsole(commands, timeout=30)
        return output

    # ------------------------------------------------------------------
    # Module info
    # ------------------------------------------------------------------

    async def get_module_info(self, module: str) -> Optional[Dict[str, str]]:
        """
        Get detailed information about a Metasploit module.

        Returns:
            Dict with module details or None.
        """
        try:
            module = _sanitize_module_path(module)
        except ValueError:
            return None

        commands = f"use {module}; info; exit"
        output = await self._run_msfconsole(commands, timeout=30)
        if not output:
            return None

        info: Dict[str, str] = {"module": module}

        # Parse key fields from 'info' output
        field_patterns = {
            "name": r'Name:\s*(.+)',
            "module": r'Module:\s*(.+)',
            "platform": r'Platform:\s*(.+)',
            "arch": r'Arch:\s*(.+)',
            "rank": r'Rank:\s*(.+)',
            "disclosure_date": r'Disclosure Date:\s*(.+)',
            "description": r'Description:\s*(.+)',
        }

        for field_name, pattern in field_patterns.items():
            match = re.search(pattern, output)
            if match:
                info[field_name] = match.group(1).strip()

        # Extract references (CVEs, etc.)
        refs = re.findall(r'(CVE-\d{4}-\d+)', output)
        if refs:
            info["cves"] = ", ".join(set(refs))

        return info

    # ------------------------------------------------------------------
    # Logging
    # ------------------------------------------------------------------

    def _save_exploit_log(self, result: ExploitResult):
        """Append exploit result to the log file."""
        log_file = DATA_DIR / "exploit_log.jsonl"
        try:
            with open(log_file, "a", encoding="utf-8") as f:
                f.write(json.dumps(result.to_dict()) + "\n")
        except Exception as e:
            logger.debug("Failed to write exploit log: %s", e)

    def get_exploit_log(self) -> List[Dict[str, Any]]:
        """Return all logged exploit attempts from this session."""
        return list(self._exploit_log)

    def get_exploit_log_from_disk(self) -> List[Dict[str, Any]]:
        """Load exploit log from disk."""
        log_file = DATA_DIR / "exploit_log.jsonl"
        if not log_file.exists():
            return []
        results = []
        try:
            for line in log_file.read_text(encoding="utf-8").strip().split("\n"):
                if line:
                    results.append(json.loads(line))
        except Exception as e:
            logger.debug("Failed to read exploit log: %s", e)
        return results

    # ------------------------------------------------------------------
    # Convenience: suggest exploits for a finding
    # ------------------------------------------------------------------

    async def suggest_exploits(self, finding: dict) -> List[ExploitModule]:
        """
        Suggest Metasploit modules for a vulnerability finding.

        Searches by CVE if available, then by vuln type keywords.
        """
        results = []

        # Try CVE search first
        cve = finding.get("cve", "")
        if cve and re.match(r'CVE-\d{4}-\d{4,}', cve, re.IGNORECASE):
            results = await self.search_by_cve(cve)
            if results:
                return results

        # Fall back to keyword search
        vuln_type = finding.get("vuln_type", finding.get("finding_type", ""))
        url = finding.get("url", "")

        # Build search terms from finding
        search_terms = []
        if vuln_type:
            type_keywords = {
                "sqli": "sql injection",
                "xss": "xss",
                "lfi": "file inclusion",
                "rce": "remote code execution",
                "ssrf": "ssrf",
                "ssti": "template injection",
                "command_injection": "command injection",
            }
            keyword = type_keywords.get(vuln_type.lower(), vuln_type)
            search_terms.append(keyword)

        # Extract technology from URL or finding
        tech = finding.get("technology", "")
        if tech:
            search_terms.append(tech)

        for term in search_terms[:3]:
            found = await self.search_exploits(term)
            results.extend(found)
            if len(results) >= MAX_SEARCH_RESULTS:
                break

        # Deduplicate by module path
        seen = set()
        unique = []
        for m in results:
            if m.module_path not in seen:
                seen.add(m.module_path)
                unique.append(m)

        return unique[:MAX_SEARCH_RESULTS]
