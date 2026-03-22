#!/usr/bin/env python3
"""
VIPER Phase Engine — Phase-aware execution engine for structured attack workflows.

Enforces a sequential phase model (RECON → SURFACE → SCAN → EXPLOIT → POST_EXPLOIT)
where each phase has a defined set of allowed tools. Prevents premature exploitation
and ensures thorough reconnaissance before attacking.
"""

import logging
import time
from enum import Enum
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger("viper.phase_engine")


class Phase(str, Enum):
    """Attack workflow phases in execution order."""
    RECON = "RECON"
    SURFACE = "SURFACE"
    SCAN = "SCAN"
    EXPLOIT = "EXPLOIT"
    POST_EXPLOIT = "POST_EXPLOIT"


# Phase ordering for comparison
_PHASE_ORDER: Dict[str, int] = {p.value: i for i, p in enumerate(Phase)}


class PhaseTransition:
    """Record of a phase transition."""
    __slots__ = ("from_phase", "to_phase", "reason", "timestamp", "findings_count")

    def __init__(self, from_phase: str, to_phase: str, reason: str,
                 findings_count: int = 0):
        self.from_phase = from_phase
        self.to_phase = to_phase
        self.reason = reason
        self.timestamp = time.time()
        self.findings_count = findings_count

    def to_dict(self) -> Dict:
        return {
            "from": self.from_phase,
            "to": self.to_phase,
            "reason": self.reason,
            "timestamp": self.timestamp,
            "findings_count": self.findings_count,
        }


class PhaseEngine:
    """Controls tool access based on the current attack phase.

    Phases execute in order: RECON → SURFACE → SCAN → EXPLOIT → POST_EXPLOIT.
    Each phase unlocks a specific set of tools. Tools from earlier phases
    remain available; tools from later phases are blocked until that phase
    is reached.
    """

    PHASES: List[str] = [p.value for p in Phase]

    PHASE_TOOLS: Dict[str, List[str]] = {
        "RECON": [
            "subfinder", "amass", "httpx", "nmap", "whois",
            "shodan", "urlscan", "crtsh", "gau", "dnsx",
            "waybackurls", "assetfinder", "massdns",
        ],
        "SURFACE": [
            "crawler", "js_analyzer", "parameter_discovery",
            "form_detector", "graphql_detect", "api_discovery",
            "wappalyzer", "tech_detect", "sitemap_parser",
        ],
        "SCAN": [
            "nuclei", "fuzzer", "secret_scanner", "gvm",
            "nikto", "wpscan", "sqlmap_detect", "xss_scan",
            "cors_scan", "header_scan", "ssl_scan",
        ],
        "EXPLOIT": [
            "sqli", "xss", "ssti", "lfi", "cmdi", "xxe",
            "ssrf", "idor", "jwt", "brute_force", "metasploit",
            "deserialization", "file_upload", "prototype_pollution",
            "race_condition", "open_redirect", "csrf",
        ],
        "POST_EXPLOIT": [
            "privilege_escalation", "lateral_movement",
            "persistence", "data_exfil", "credential_dump",
            "webshell", "backdoor", "pivot",
        ],
    }

    # Minimum conditions to auto-advance (can be overridden)
    PHASE_AUTO_ADVANCE: Dict[str, Dict] = {
        "RECON": {"min_targets": 1},
        "SURFACE": {"min_endpoints": 5},
        "SCAN": {"min_scan_results": 1},
        "EXPLOIT": {"min_findings": 1},
    }

    def __init__(self, start_phase: str = "RECON",
                 allow_phase_skip: bool = False):
        """Initialize the phase engine.

        Args:
            start_phase: Phase to start in (default RECON)
            allow_phase_skip: If True, allow jumping forward multiple phases
        """
        if start_phase not in _PHASE_ORDER:
            raise ValueError(f"Invalid phase: {start_phase}")
        self.current_phase: str = start_phase
        self.allow_phase_skip: bool = allow_phase_skip
        self.phase_history: List[PhaseTransition] = []
        self._phase_start_time: float = time.time()
        self._phase_stats: Dict[str, Dict] = {
            p: {"tools_used": [], "duration": 0.0, "findings": 0}
            for p in self.PHASES
        }
        logger.info("Phase engine initialized at phase: %s", start_phase)

    def can_use_tool(self, tool_name: str) -> Tuple[bool, str]:
        """Check if a tool is allowed in the current phase.

        Tools from the current phase and all earlier phases are allowed.
        Tools from future phases are blocked.

        Args:
            tool_name: Name of the tool to check

        Returns:
            Tuple of (allowed: bool, reason: str)
        """
        tool_lower = tool_name.lower()
        current_idx = _PHASE_ORDER[self.current_phase]

        # Check current and all previous phases
        for phase_name in self.PHASES[:current_idx + 1]:
            if tool_lower in self.PHASE_TOOLS.get(phase_name, []):
                return True, f"Tool '{tool_name}' allowed in phase {phase_name}"

        # Check if tool exists in a future phase
        for phase_name in self.PHASES[current_idx + 1:]:
            if tool_lower in self.PHASE_TOOLS.get(phase_name, []):
                return False, (
                    f"Tool '{tool_name}' requires phase {phase_name}, "
                    f"current phase is {self.current_phase}. "
                    f"Advance to {phase_name} first."
                )

        # Tool not in any phase — allow by default (custom/external tools)
        return True, f"Tool '{tool_name}' not phase-restricted"

    def advance_phase(self, reason: str = "",
                      findings_count: int = 0) -> str:
        """Advance to the next phase.

        Args:
            reason: Why the phase is advancing
            findings_count: Number of findings in the current phase

        Returns:
            The new phase name

        Raises:
            ValueError: If already at the final phase
        """
        current_idx = _PHASE_ORDER[self.current_phase]
        if current_idx >= len(self.PHASES) - 1:
            raise ValueError(
                f"Already at final phase: {self.current_phase}"
            )

        old_phase = self.current_phase
        new_phase = self.PHASES[current_idx + 1]

        # Record stats for the phase we're leaving
        elapsed = time.time() - self._phase_start_time
        self._phase_stats[old_phase]["duration"] = elapsed
        self._phase_stats[old_phase]["findings"] = findings_count

        # Record transition
        transition = PhaseTransition(
            from_phase=old_phase,
            to_phase=new_phase,
            reason=reason or "Manual advance",
            findings_count=findings_count,
        )
        self.phase_history.append(transition)

        self.current_phase = new_phase
        self._phase_start_time = time.time()

        logger.info("Phase advanced: %s -> %s (reason: %s)",
                     old_phase, new_phase, reason)
        return new_phase

    def advance_to_phase(self, target_phase: str,
                         reason: str = "") -> str:
        """Advance directly to a specific phase.

        Args:
            target_phase: Phase to advance to
            reason: Why we're jumping to this phase

        Returns:
            The new phase name

        Raises:
            ValueError: If target is behind current phase or invalid
        """
        if target_phase not in _PHASE_ORDER:
            raise ValueError(f"Invalid phase: {target_phase}")

        target_idx = _PHASE_ORDER[target_phase]
        current_idx = _PHASE_ORDER[self.current_phase]

        if target_idx <= current_idx:
            raise ValueError(
                f"Cannot go backwards: {self.current_phase} -> {target_phase}"
            )

        if not self.allow_phase_skip and target_idx > current_idx + 1:
            raise ValueError(
                f"Phase skipping not allowed. Advance one phase at a time."
            )

        # Advance through intermediate phases
        while self.current_phase != target_phase:
            self.advance_phase(reason=reason)

        return self.current_phase

    def get_available_tools(self) -> List[str]:
        """Return all tools available in the current phase and earlier."""
        current_idx = _PHASE_ORDER[self.current_phase]
        tools = []
        for phase_name in self.PHASES[:current_idx + 1]:
            tools.extend(self.PHASE_TOOLS.get(phase_name, []))
        return tools

    def get_phase_summary(self) -> Dict:
        """Return a summary of the current phase state."""
        current_idx = _PHASE_ORDER[self.current_phase]
        elapsed = time.time() - self._phase_start_time

        return {
            "current_phase": self.current_phase,
            "phase_index": current_idx,
            "total_phases": len(self.PHASES),
            "progress_pct": round(
                (current_idx / (len(self.PHASES) - 1)) * 100
            ) if len(self.PHASES) > 1 else 100,
            "elapsed_seconds": round(elapsed, 1),
            "available_tools": self.get_available_tools(),
            "transitions": [t.to_dict() for t in self.phase_history],
            "phase_stats": dict(self._phase_stats),
            "remaining_phases": self.PHASES[current_idx + 1:],
        }

    def record_tool_use(self, tool_name: str):
        """Record that a tool was used in the current phase."""
        stats = self._phase_stats[self.current_phase]
        if tool_name not in stats["tools_used"]:
            stats["tools_used"].append(tool_name)

    def should_auto_advance(self, metrics: Dict) -> Tuple[bool, str]:
        """Check if the current phase should auto-advance based on metrics.

        Args:
            metrics: Dict with keys like 'targets', 'endpoints',
                     'scan_results', 'findings'

        Returns:
            Tuple of (should_advance: bool, reason: str)
        """
        conditions = self.PHASE_AUTO_ADVANCE.get(self.current_phase)
        if not conditions:
            return False, "No auto-advance conditions for this phase"

        if self.current_phase == "RECON":
            if metrics.get("targets", 0) >= conditions.get("min_targets", 1):
                return True, (
                    f"RECON complete: {metrics['targets']} targets discovered"
                )
        elif self.current_phase == "SURFACE":
            if metrics.get("endpoints", 0) >= conditions.get("min_endpoints", 5):
                return True, (
                    f"SURFACE complete: {metrics['endpoints']} endpoints found"
                )
        elif self.current_phase == "SCAN":
            if metrics.get("scan_results", 0) >= conditions.get("min_scan_results", 1):
                return True, (
                    f"SCAN complete: {metrics['scan_results']} scan results"
                )
        elif self.current_phase == "EXPLOIT":
            if metrics.get("findings", 0) >= conditions.get("min_findings", 1):
                return True, (
                    f"EXPLOIT complete: {metrics['findings']} findings confirmed"
                )

        return False, f"Phase {self.current_phase} conditions not met"

    def __repr__(self) -> str:
        idx = _PHASE_ORDER[self.current_phase]
        return (f"PhaseEngine(phase={self.current_phase}, "
                f"progress={idx}/{len(self.PHASES) - 1})")
