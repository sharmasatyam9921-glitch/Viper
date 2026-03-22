"""
VIPER 4.0 Phase 7 — Persistent Metasploit Console

Persistent Metasploit Console. Maintains a long-running
msfconsole subprocess so sessions, module context, and variables survive
across commands. Uses timing-based output detection (no prompt regex).

Fully async (asyncio.subprocess). No external dependencies.
"""

import asyncio
import logging
import re
import shutil
import time
from typing import Optional, Set, List, Dict

logger = logging.getLogger("viper.msf_persistent")

# Strip ANSI escape codes
_ANSI_RE = re.compile(r'\x1b\[[\?]?[0-9;]*[a-zA-Z]')
_OSC_RE = re.compile(r'\x1b\][^\x07]*\x07')
_CHARSET_RE = re.compile(r'\x1b[()][AB012]')

# Timing presets (seconds) — (timeout, quiet_period)
_TIMING = {
    "run":        (1800, 20.0),   # brute force / aux modules
    "exploit":    (600,  20.0),   # CVE exploits
    "bruteforce": (1800, 20.0),
    "default":    (120,   2.0),
}


def _clean_ansi(text: str) -> str:
    text = _ANSI_RE.sub("", text)
    text = _OSC_RE.sub("", text)
    text = _CHARSET_RE.sub("", text)
    return text


def _is_meaningful_output(line: str) -> bool:
    """Filter prompt redraws and cursor noise — only meaningful lines reset the quiet timer."""
    clean = _clean_ansi(line).strip()
    if not clean:
        return False
    # msf prompt noise
    if re.match(r'^msf\d?\s*([\w\(\)/]+\s*)?>?\s*$', clean, re.IGNORECASE):
        return False
    if re.match(r'^[\$#>]\s*$', clean):
        return False
    if clean in ['>', '']:
        return False
    return True


class PersistentMsfConsole:
    """Persistent Metasploit console — sessions survive across commands."""

    def __init__(self, msfconsole_path: str = "msfconsole"):
        self._msfconsole_path = msfconsole_path
        self._process: Optional[asyncio.subprocess.Process] = None
        self._lock = asyncio.Lock()
        self._session_ids: Set[int] = set()
        self._initialized = False
        self._reader_task: Optional[asyncio.Task] = None
        self._output_queue: asyncio.Queue = asyncio.Queue()
        self._current_output: List[str] = []

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def start(self) -> bool:
        """Start msfconsole subprocess. Returns True if successful."""
        if self.is_running():
            return True

        if not shutil.which(self._msfconsole_path):
            logger.error("msfconsole not found in PATH")
            return False

        try:
            logger.info("Starting msfconsole process...")
            self._process = await asyncio.create_subprocess_exec(
                self._msfconsole_path, "-q", "-x", "",
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
            )
            logger.info("msfconsole PID: %d", self._process.pid)

            # Background reader
            self._reader_task = asyncio.create_task(self._read_output_loop())

            # Wait for initial prompt (can take 60-120s on first start)
            await self._wait_for_output(timeout=120, quiet_period=5.0)
            self._initialized = True
            logger.info("msfconsole ready (PID %d)", self._process.pid)
            return True

        except Exception as exc:
            logger.error("Failed to start msfconsole: %s", exc)
            return False

    async def restart(self) -> bool:
        """Kill and restart msfconsole."""
        logger.info("Restarting msfconsole...")
        await self.close()
        # Drain leftover queue items
        while not self._output_queue.empty():
            try:
                self._output_queue.get_nowait()
            except asyncio.QueueEmpty:
                break
        self._current_output.clear()
        self._session_ids.clear()
        return await self.start()

    def is_running(self) -> bool:
        """Check if msfconsole process is alive."""
        return self._process is not None and self._process.returncode is None

    async def close(self):
        """Terminate msfconsole."""
        if self._reader_task and not self._reader_task.done():
            self._reader_task.cancel()
            try:
                await self._reader_task
            except asyncio.CancelledError:
                pass

        if self._process and self._process.returncode is None:
            try:
                self._process.stdin.write(b"exit -y\n")
                await self._process.stdin.drain()
                try:
                    await asyncio.wait_for(self._process.wait(), timeout=5)
                except asyncio.TimeoutError:
                    self._process.kill()
                    await self._process.wait()
            except Exception:
                try:
                    self._process.kill()
                except ProcessLookupError:
                    pass
            logger.info("msfconsole stopped")

        self._process = None
        self._initialized = False
        self._session_ids.clear()

    # ------------------------------------------------------------------
    # Command execution
    # ------------------------------------------------------------------

    async def execute(self, command: str, timeout: int = 120) -> str:
        """Execute a command and return output.

        Uses timing-based output detection:
        - Read output until no new meaningful data for quiet_period seconds.
        - Special timeouts for run/exploit/brute force commands.
        """
        async with self._lock:
            if not self.is_running():
                if not await self.start():
                    return "[ERROR] Failed to start msfconsole"

            # Pick timing based on command keyword
            cmd_lower = command.strip().lower().split()[0] if command.strip() else ""
            if cmd_lower in ("run",):
                t, q = _TIMING["run"]
            elif cmd_lower in ("exploit",):
                t, q = _TIMING["exploit"]
            else:
                t, q = _TIMING["default"]

            # Caller override
            if timeout and timeout != 120:
                t = timeout

            # Drain pending output
            while not self._output_queue.empty():
                try:
                    self._output_queue.get_nowait()
                except asyncio.QueueEmpty:
                    break

            # Send command (split semicolons — msfconsole doesn't parse them on stdin)
            try:
                if ";" in command:
                    for part in command.split(";"):
                        part = part.strip()
                        if part:
                            self._process.stdin.write((part + "\n").encode())
                else:
                    self._process.stdin.write((command + "\n").encode())
                await self._process.stdin.drain()
            except Exception as exc:
                return f"[ERROR] Failed to send command: {exc}"

            output = await self._wait_for_output(timeout=t, quiet_period=q)
            return output if output else "(no output)"

    def get_sessions(self) -> list:
        """List active Metasploit session IDs detected so far."""
        return sorted(self._session_ids)

    # ------------------------------------------------------------------
    # Internal I/O
    # ------------------------------------------------------------------

    async def _read_output_loop(self):
        """Background task: continuously read stdout and push to queue."""
        try:
            while self.is_running():
                line = await self._process.stdout.readline()
                if not line:
                    break
                decoded = line.decode("utf-8", errors="replace")
                await self._output_queue.put(decoded)
                self._detect_session_events(decoded)
        except asyncio.CancelledError:
            pass
        except Exception as exc:
            logger.debug("Reader loop error: %s", exc)

    async def _wait_for_output(self, timeout: float, quiet_period: float) -> str:
        """Collect output until no new meaningful data for quiet_period seconds."""
        output_lines: List[str] = []
        self._current_output = []
        deadline = asyncio.get_event_loop().time() + timeout
        last_meaningful = asyncio.get_event_loop().time()
        min_wait = min(3.0, timeout / 2)
        start = asyncio.get_event_loop().time()

        while asyncio.get_event_loop().time() < deadline:
            remaining = deadline - asyncio.get_event_loop().time()
            try:
                line = await asyncio.wait_for(
                    self._output_queue.get(), timeout=min(0.1, remaining)
                )
                stripped = line.rstrip()
                output_lines.append(stripped)
                self._current_output.append(stripped)
                if _is_meaningful_output(stripped):
                    last_meaningful = asyncio.get_event_loop().time()
            except (asyncio.TimeoutError, asyncio.QueueEmpty):
                now = asyncio.get_event_loop().time()
                elapsed = now - start
                since_last = now - last_meaningful
                if output_lines and since_last >= quiet_period:
                    break
                if not output_lines and elapsed < min_wait:
                    continue

        return "\n".join(output_lines)

    def _detect_session_events(self, line: str):
        """Track session open/close events via simple string matching."""
        lower = line.lower()
        if "session" in lower and "opened" in lower:
            self._parse_session_id(lower, "opened", add=True)
        elif "session" in lower and "closed" in lower:
            self._parse_session_id(lower, "closed", add=False)

    def _parse_session_id(self, line: str, keyword: str, add: bool):
        try:
            idx = line.index("session")
            rest = line[idx + 7:].strip()
            parts = rest.split()
            if parts and parts[0].isdigit():
                sid = int(parts[0])
                if add:
                    self._session_ids.add(sid)
                    logger.info("Session %d opened", sid)
                else:
                    self._session_ids.discard(sid)
                    logger.info("Session %d closed", sid)
        except (ValueError, IndexError):
            pass
