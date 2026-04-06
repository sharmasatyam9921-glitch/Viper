#!/usr/bin/env python3
"""
VIPER Autopilot — Configurable autonomous hunting safety controller.

Three operating modes control how much human approval is required:

    PARANOID: Every tool execution requires human approval before running.
    NORMAL:   Only dangerous tools (exploit, bruteforce, metasploit, etc.) need approval.
    YOLO:     Full autonomous mode — no human in the loop.

Usage:
    autopilot = Autopilot(mode=AutopilotMode.NORMAL)
    result = await autopilot.execute_with_safety(
        "nuclei_scan", nuclei_fn, {"target": "http://example.com"}, approval_fn=cli_approve
    )

Wire into viper.py via --autopilot flag:
    python viper.py http://target.com --autopilot yolo
    python viper.py http://target.com --autopilot paranoid
"""

import asyncio
import logging
import sys
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

logger = logging.getLogger("viper.autopilot")

# ── ANSI colors ──────────────────────────────────────────────────────────

_COLORS = hasattr(sys.stdout, "isatty") and sys.stdout.isatty()


def _c(code: str, text: str) -> str:
    return f"\033[{code}m{text}\033[0m" if _COLORS else text


def _red(t: str) -> str: return _c("91", t)
def _yellow(t: str) -> str: return _c("93", t)
def _green(t: str) -> str: return _c("92", t)
def _cyan(t: str) -> str: return _c("96", t)
def _bold(t: str) -> str: return _c("1", t)
def _dim(t: str) -> str: return _c("2", t)


class AutopilotMode(str, Enum):
    """Autopilot safety levels."""
    PARANOID = "paranoid"   # Every action requires human approval
    NORMAL = "normal"       # Only dangerous actions need approval
    YOLO = "yolo"           # Full autonomous — no approvals needed


@dataclass
class AutopilotAction:
    """Record of a single autopilot action."""
    tool_name: str
    args: Dict[str, Any]
    approved: bool
    auto_approved: bool
    timestamp: float
    result: Optional[Any] = None
    error: Optional[str] = None
    elapsed_ms: float = 0.0


@dataclass
class AutopilotStats:
    """Aggregate statistics for the autopilot session."""
    actions_taken: int = 0
    actions_approved: int = 0
    actions_blocked: int = 0
    actions_auto_approved: int = 0
    actions_human_approved: int = 0
    actions_failed: int = 0
    dangerous_tools_blocked: int = 0
    total_elapsed_ms: float = 0.0

    def to_dict(self) -> dict:
        return {
            "actions_taken": self.actions_taken,
            "actions_approved": self.actions_approved,
            "actions_blocked": self.actions_blocked,
            "actions_auto_approved": self.actions_auto_approved,
            "actions_human_approved": self.actions_human_approved,
            "actions_failed": self.actions_failed,
            "dangerous_tools_blocked": self.dangerous_tools_blocked,
            "total_elapsed_ms": round(self.total_elapsed_ms, 1),
        }


class Autopilot:
    """Autonomous hunting with configurable safety levels.

    PARANOID: Every tool execution requires human approval.
    NORMAL:   Only dangerous tools need approval — safe tools auto-execute.
    YOLO:     Full autonomous mode, no human in the loop.

    The autopilot wraps tool execution and intercepts calls based on the
    configured mode. It maintains an action log and statistics for auditing.
    """

    # Tools that require human approval in NORMAL mode.
    # In PARANOID mode, ALL tools require approval.
    # In YOLO mode, NO tools require approval.
    DANGEROUS_TOOLS: Set[str] = {
        # Exploitation
        "metasploit", "metasploit_console", "msf_restart",
        "exploit", "exploit_cve", "exploit_chain",
        "reverse_shell", "webshell", "file_upload",
        # Credential attacks
        "bruteforce", "brute_force", "hydra", "execute_hydra",
        # Injection
        "sqlmap", "sqlmap_scan",
        # Active scanning with side effects
        "execute_code", "kali_shell",
        # Post-exploitation
        "post_exploit", "pivot", "lateral_move",
        # Destructive
        "delete", "modify", "overwrite",
    }

    # Tools that are always safe (never need approval even in NORMAL mode)
    SAFE_TOOLS: Set[str] = {
        # Passive recon
        "whois", "dns_lookup", "crt_sh", "subfinder",
        "shodan_lookup", "urlscan", "wayback",
        # Read-only analysis
        "analyze", "classify", "triage", "summarize",
        "report", "graph_query",
        # Information gathering
        "httpx", "wappalyzer", "tech_detect",
        "screenshot", "crawl",
    }

    # Argument patterns that make otherwise-safe tools dangerous
    DANGEROUS_ARG_PATTERNS: Dict[str, List[str]] = {
        "nmap": ["-sU", "--script=exploit", "--script=vuln", "-sC"],
        "nuclei": ["-severity critical", "-tags cve", "-tags rce"],
        "curl": ["-X DELETE", "-X PUT", "-d", "--data"],
        "http_request": ["DELETE", "PUT", "PATCH"],
    }

    def __init__(self, mode: AutopilotMode = AutopilotMode.NORMAL):
        self.mode = mode
        self.stats = AutopilotStats()
        self.action_log: List[AutopilotAction] = []
        self._session_start = time.monotonic()
        logger.info(f"Autopilot initialized: mode={mode.value}")

    def should_approve(self, tool_name: str, args: Optional[Dict] = None) -> bool:
        """Check if an action should be auto-approved based on the current mode.

        Returns:
            True if the action can proceed without human approval.
            False if human approval is required.
        """
        if self.mode == AutopilotMode.YOLO:
            return True

        if self.mode == AutopilotMode.PARANOID:
            return False

        # NORMAL mode: check if tool is dangerous
        tool_lower = tool_name.lower().strip()

        # Explicit dangerous tool match
        if tool_lower in self.DANGEROUS_TOOLS:
            return False

        # Partial match for tool variants (e.g., "nuclei_scan" matches "nuclei")
        for dangerous in self.DANGEROUS_TOOLS:
            if dangerous in tool_lower or tool_lower in dangerous:
                return False

        # Check argument patterns that make safe tools dangerous
        if args and tool_lower in self.DANGEROUS_ARG_PATTERNS:
            patterns = self.DANGEROUS_ARG_PATTERNS[tool_lower]
            args_str = str(args).lower()
            for pattern in patterns:
                if pattern.lower() in args_str:
                    return False

        return True

    def is_dangerous(self, tool_name: str, args: Optional[Dict] = None) -> Tuple[bool, str]:
        """Check if a tool is classified as dangerous, with reason.

        Returns:
            (is_dangerous, reason) tuple.
        """
        tool_lower = tool_name.lower().strip()

        # Direct match
        if tool_lower in self.DANGEROUS_TOOLS:
            return True, f"Tool '{tool_name}' is in the dangerous tools list"

        # Partial match
        for dangerous in self.DANGEROUS_TOOLS:
            if dangerous in tool_lower:
                return True, f"Tool '{tool_name}' matches dangerous tool '{dangerous}'"

        # Arg pattern match
        if args and tool_lower in self.DANGEROUS_ARG_PATTERNS:
            patterns = self.DANGEROUS_ARG_PATTERNS[tool_lower]
            args_str = str(args).lower()
            for pattern in patterns:
                if pattern.lower() in args_str:
                    return True, f"Tool '{tool_name}' with args matching dangerous pattern '{pattern}'"

        return False, ""

    async def request_approval(
        self,
        tool_name: str,
        args: Optional[Dict] = None,
        approval_fn: Optional[Callable] = None,
    ) -> bool:
        """Request human approval for a tool execution.

        Args:
            tool_name: Name of the tool to execute.
            args: Tool arguments.
            approval_fn: Custom approval function. If None, uses stdin prompt.

        Returns:
            True if approved, False if denied.
        """
        if approval_fn:
            # Custom approval function (e.g., from dashboard, Telegram)
            if asyncio.iscoroutinefunction(approval_fn):
                return await approval_fn(tool_name, args)
            return approval_fn(tool_name, args)

        # Default: CLI stdin prompt
        return self._cli_approve(tool_name, args)

    def _cli_approve(self, tool_name: str, args: Optional[Dict] = None) -> bool:
        """Prompt for approval via CLI stdin."""
        dangerous, reason = self.is_dangerous(tool_name, args)

        print(f"\n{'='*60}")
        if dangerous:
            print(_red(f"  DANGEROUS TOOL: {tool_name}"))
            print(_dim(f"  Reason: {reason}"))
        else:
            print(_yellow(f"  APPROVAL REQUIRED: {tool_name}"))

        if args:
            # Truncate long args for display
            args_display = {k: (str(v)[:100] + "..." if len(str(v)) > 100 else v)
                           for k, v in args.items()}
            print(_dim(f"  Args: {args_display}"))

        print(f"{'='*60}")

        try:
            response = input(_bold("  Approve? [y/N/skip] ")).strip().lower()
            if response in ("y", "yes"):
                print(_green("  Approved"))
                return True
            elif response in ("s", "skip"):
                print(_yellow("  Skipped"))
                return False
            else:
                print(_red("  Denied"))
                return False
        except (EOFError, KeyboardInterrupt):
            print(_red("\n  Denied (no TTY or interrupted)"))
            return False

    async def execute_with_safety(
        self,
        tool_name: str,
        tool_fn: Callable,
        args: Optional[Dict] = None,
        approval_fn: Optional[Callable] = None,
    ) -> Optional[Any]:
        """Execute a tool with safety checks based on the autopilot mode.

        Args:
            tool_name: Name of the tool to execute.
            tool_fn: Async or sync callable to execute.
            args: Arguments to pass to tool_fn.
            approval_fn: Custom approval function for interactive mode.

        Returns:
            Tool result if approved and successful, None if blocked or failed.
        """
        args = args or {}
        self.stats.actions_taken += 1

        auto_approved = self.should_approve(tool_name, args)

        if auto_approved:
            approved = True
            self.stats.actions_auto_approved += 1
            logger.debug(f"Auto-approved: {tool_name}")
        else:
            # Need human approval
            approved = await self.request_approval(tool_name, args, approval_fn)
            if approved:
                self.stats.actions_human_approved += 1
                logger.info(f"Human-approved: {tool_name}")
            else:
                self.stats.actions_blocked += 1
                dangerous, _ = self.is_dangerous(tool_name, args)
                if dangerous:
                    self.stats.dangerous_tools_blocked += 1
                logger.info(f"Blocked: {tool_name}")

        action = AutopilotAction(
            tool_name=tool_name,
            args=args,
            approved=approved,
            auto_approved=auto_approved,
            timestamp=time.monotonic(),
        )

        if not approved:
            self.action_log.append(action)
            return None

        # Execute the tool
        self.stats.actions_approved += 1
        start = time.monotonic()
        try:
            if asyncio.iscoroutinefunction(tool_fn):
                result = await tool_fn(**args)
            else:
                loop = asyncio.get_event_loop()
                result = await loop.run_in_executor(None, lambda: tool_fn(**args))

            elapsed = (time.monotonic() - start) * 1000
            action.result = result
            action.elapsed_ms = elapsed
            self.stats.total_elapsed_ms += elapsed
            self.action_log.append(action)
            return result

        except Exception as e:
            elapsed = (time.monotonic() - start) * 1000
            action.error = str(e)
            action.elapsed_ms = elapsed
            self.stats.actions_failed += 1
            self.stats.total_elapsed_ms += elapsed
            self.action_log.append(action)
            logger.error(f"Tool {tool_name} failed: {e}")
            return None

    def add_dangerous_tool(self, tool_name: str):
        """Add a tool to the dangerous tools set at runtime."""
        self.DANGEROUS_TOOLS.add(tool_name.lower())

    def remove_dangerous_tool(self, tool_name: str):
        """Remove a tool from the dangerous tools set."""
        self.DANGEROUS_TOOLS.discard(tool_name.lower())

    def set_mode(self, mode: AutopilotMode):
        """Change the autopilot mode at runtime."""
        old = self.mode
        self.mode = mode
        logger.info(f"Autopilot mode changed: {old.value} -> {mode.value}")

    def summary(self) -> Dict[str, Any]:
        """Return session summary with stats and recent actions."""
        elapsed = time.monotonic() - self._session_start
        return {
            "mode": self.mode.value,
            "session_seconds": round(elapsed, 1),
            "stats": self.stats.to_dict(),
            "recent_actions": [
                {
                    "tool": a.tool_name,
                    "approved": a.approved,
                    "auto": a.auto_approved,
                    "error": a.error,
                    "elapsed_ms": round(a.elapsed_ms, 1),
                }
                for a in self.action_log[-20:]
            ],
        }

    def print_summary(self):
        """Print a formatted summary to stdout."""
        s = self.stats
        mode_colors = {
            AutopilotMode.PARANOID: _red,
            AutopilotMode.NORMAL: _yellow,
            AutopilotMode.YOLO: _green,
        }
        mode_fn = mode_colors.get(self.mode, str)

        print(f"\n{'='*50}")
        print(f"  Autopilot Summary — Mode: {mode_fn(self.mode.value.upper())}")
        print(f"{'='*50}")
        print(f"  Actions taken:        {s.actions_taken}")
        print(f"  Auto-approved:        {_green(str(s.actions_auto_approved))}")
        print(f"  Human-approved:       {_yellow(str(s.actions_human_approved))}")
        print(f"  Blocked:              {_red(str(s.actions_blocked))}")
        print(f"  Failed:               {_red(str(s.actions_failed))}")
        print(f"  Dangerous blocked:    {_red(str(s.dangerous_tools_blocked))}")
        print(f"  Total time:           {s.total_elapsed_ms/1000:.1f}s")
        print(f"{'='*50}")
