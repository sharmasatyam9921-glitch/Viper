"""VIPER Tool Registry — standardized tool registration and execution.

Provides a clean interface for registering, discovering, and executing
tools by type and phase.
"""

import logging
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, List, Optional

logger = logging.getLogger("viper.tool_registry")


class ToolType(str, Enum):
    """Tool categories for filtering and phase enforcement."""
    RECON = "recon"
    SCAN = "scan"
    EXPLOIT = "exploit"
    SEARCH = "search"
    REPORT = "report"
    UTILITY = "utility"
    BROWSER = "browser"


@dataclass
class ToolDefinition:
    """Metadata and handler for a registered tool."""
    name: str
    description: str
    tool_type: ToolType
    handler: Callable
    is_dangerous: bool = False
    requires_approval: bool = False
    phases_allowed: List[str] = field(default_factory=lambda: ["RECON", "SURFACE", "SCAN", "EXPLOIT", "POST_EXPLOIT"])
    timeout: int = 60  # seconds

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "description": self.description,
            "type": self.tool_type.value,
            "dangerous": self.is_dangerous,
            "requires_approval": self.requires_approval,
            "phases": self.phases_allowed,
        }


class ToolRegistry:
    """Standardized tool registration, discovery, and execution.

    Usage::

        registry = ToolRegistry()
        registry.register("nuclei", nuclei_scan, ToolType.SCAN,
                          "Template-based vulnerability scanner")

        # Get tools available in current phase
        scan_tools = registry.get_for_phase("SCAN")

        # Execute with observability
        result = registry.execute("nuclei", target="https://example.com")
    """

    def __init__(self):
        self._tools: Dict[str, ToolDefinition] = {}
        self._stats: Dict[str, Dict[str, Any]] = {}

    def register(self, name: str, handler: Callable, tool_type: ToolType,
                 description: str = "", dangerous: bool = False,
                 requires_approval: bool = False,
                 phases: Optional[List[str]] = None,
                 timeout: int = 60):
        """Register a tool with the registry."""
        td = ToolDefinition(
            name=name,
            description=description or f"{name} tool",
            tool_type=tool_type,
            handler=handler,
            is_dangerous=dangerous,
            requires_approval=requires_approval or dangerous,
            phases_allowed=phases or ["RECON", "SURFACE", "SCAN", "EXPLOIT", "POST_EXPLOIT"],
            timeout=timeout,
        )
        self._tools[name] = td
        self._stats[name] = {"calls": 0, "errors": 0, "total_ms": 0}
        logger.debug("Registered tool: %s (%s)", name, tool_type.value)

    def get(self, name: str) -> Optional[ToolDefinition]:
        """Get a tool definition by name."""
        return self._tools.get(name)

    def get_by_type(self, tool_type: ToolType) -> List[ToolDefinition]:
        """Get all tools of a given type."""
        return [t for t in self._tools.values() if t.tool_type == tool_type]

    def get_for_phase(self, phase: str) -> List[ToolDefinition]:
        """Get all tools allowed in a given phase."""
        phase = phase.upper()
        return [t for t in self._tools.values() if phase in t.phases_allowed]

    def get_dangerous(self) -> List[ToolDefinition]:
        """Get tools that require approval before execution."""
        return [t for t in self._tools.values() if t.requires_approval]

    def list_all(self) -> List[ToolDefinition]:
        """List all registered tools."""
        return list(self._tools.values())

    def list_names(self) -> List[str]:
        """List all registered tool names."""
        return list(self._tools.keys())

    def is_available(self, name: str) -> bool:
        """Check if a tool is registered."""
        return name in self._tools

    def execute(self, name: str, **kwargs) -> Any:
        """Execute a tool by name with stats tracking."""
        td = self._tools.get(name)
        if not td:
            raise KeyError(f"Tool '{name}' not registered")

        start = time.monotonic()
        try:
            result = td.handler(**kwargs)
            elapsed_ms = int((time.monotonic() - start) * 1000)
            self._stats[name]["calls"] += 1
            self._stats[name]["total_ms"] += elapsed_ms
            return result
        except Exception as e:
            self._stats[name]["calls"] += 1
            self._stats[name]["errors"] += 1
            raise

    def get_stats(self) -> Dict[str, dict]:
        """Get execution stats for all tools."""
        result = {}
        for name, stats in self._stats.items():
            calls = stats["calls"]
            result[name] = {
                **stats,
                "avg_ms": stats["total_ms"] // max(calls, 1),
                "error_rate": stats["errors"] / max(calls, 1),
            }
        return result

    def to_llm_description(self, phase: str = "") -> str:
        """Generate tool descriptions for LLM prompt injection."""
        tools = self.get_for_phase(phase) if phase else self.list_all()
        lines = []
        for t in tools:
            danger = " [DANGEROUS]" if t.is_dangerous else ""
            lines.append(f"- {t.name}: {t.description}{danger}")
        return "\n".join(lines)

    def __len__(self) -> int:
        return len(self._tools)

    def __contains__(self, name: str) -> bool:
        return name in self._tools
