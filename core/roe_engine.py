"""
VIPER 4.0 Rules of Engagement Engine (F5)

Machine-enforceable RoE that gates every tool execution and target interaction.
Inspired by RedAmon's ``build_roe_prompt_section`` but adapted for VIPER's
standalone architecture (no project_settings dependency).

Supports loading from JSON / YAML / dict, runtime enforcement, and LLM
system-prompt injection.
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from fnmatch import fnmatch
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

logger = logging.getLogger("viper.roe")

# ---------------------------------------------------------------------------
# Phase ordering (used for severity-cap enforcement)
# ---------------------------------------------------------------------------
PHASE_ORDER = {
    "informational": 0,
    "exploitation": 1,
    "post_exploitation": 2,
}

# ---------------------------------------------------------------------------
# Tools implicitly forbidden unless explicitly allowed
# ---------------------------------------------------------------------------
DEFAULT_FORBIDDEN_TOOLS = {
    "rm", "del", "format", "mkfs",
    "shutdown", "reboot", "halt",
    "dd",
}

# DoS-category tools
DOS_TOOLS = {
    "slowloris", "hping3", "goldeneye", "torshammer",
    "siege", "ab",  # when intent is DoS
}


@dataclass
class RulesOfEngagement:
    """Declarative rules parsed from an engagement document or config."""

    # -- Target scope --
    client_name: str = ""
    engagement_start: str = ""            # ISO date or human-readable
    engagement_end: str = ""
    in_scope_targets: List[str] = field(default_factory=list)    # domains, IPs, CIDRs, wildcards
    excluded_hosts: List[dict] = field(default_factory=list)     # [{host, reason}]

    # -- Time restrictions --
    testing_hours: dict = field(default_factory=dict)            # {start: "09:00", end: "17:00", timezone: "UTC"}
    blackout_dates: List[str] = field(default_factory=list)      # ["2026-04-01", ...]

    # -- Permission toggles --
    allow_dos: bool = False
    allow_social_engineering: bool = False
    allow_physical: bool = False
    allow_data_exfiltration: bool = False
    allow_brute_force: bool = True
    allow_exploitation: bool = True
    max_severity_phase: str = "exploitation"   # informational | exploitation | post_exploitation

    # -- Rate limits --
    global_rate_limit_rps: float = 10.0

    # -- Tool restrictions --
    forbidden_tools: List[str] = field(default_factory=list)
    forbidden_categories: List[str] = field(default_factory=list)

    # -- Sensitive data handling --
    sensitive_data_policy: str = "prove_only"  # no_access | prove_only | limited | full

    # -- Compliance --
    compliance_frameworks: List[str] = field(default_factory=list)

    # -- Incident procedures --
    incident_contact: str = ""
    escalation_email: str = ""
    notes: str = ""


# ---------------------------------------------------------------------------
# RoE Engine
# ---------------------------------------------------------------------------

class RoEEngine:
    """Runtime enforcement of Rules of Engagement."""

    def __init__(self, roe: Optional[RulesOfEngagement] = None):
        self.roe = roe or RulesOfEngagement()

    # -- Loaders ---------------------------------------------------------------

    def load_from_file(self, path: str) -> None:
        """Load RoE from a JSON or YAML file."""
        p = Path(path)
        if not p.exists():
            raise FileNotFoundError(f"RoE file not found: {path}")

        text = p.read_text(encoding="utf-8")

        if p.suffix in (".yaml", ".yml"):
            try:
                import yaml  # type: ignore
                data = yaml.safe_load(text)
            except ImportError:
                raise ImportError("PyYAML is required to load .yaml RoE files")
        else:
            data = json.loads(text)

        self.load_from_dict(data)

    def load_from_dict(self, data: dict) -> None:
        """Populate the RoE dataclass from a flat or nested dict."""
        roe = self.roe
        for key, val in data.items():
            # Normalise keys: ROE_CLIENT_NAME -> client_name
            norm = key.lower().removeprefix("roe_")
            if hasattr(roe, norm):
                setattr(roe, norm, val)
            else:
                logger.debug("Unknown RoE key ignored: %s", key)

    # -- Target checks ---------------------------------------------------------

    def check_target_allowed(self, target: str) -> Tuple[bool, str]:
        """Check if *target* is in scope and not excluded.

        Returns ``(allowed, reason)``.
        """
        # Normalise target to just the hostname / IP
        host = self._extract_host(target)

        # 1. Check exclusion list first (takes priority)
        for exc in self.roe.excluded_hosts:
            exc_host = exc.get("host", "") if isinstance(exc, dict) else str(exc)
            if self._host_matches(host, exc_host):
                reason = exc.get("reason", "excluded") if isinstance(exc, dict) else "excluded"
                return False, f"Target '{host}' is excluded: {reason}"

        # 2. If there is an explicit in-scope list, target must match
        if self.roe.in_scope_targets:
            for scope_entry in self.roe.in_scope_targets:
                if self._host_matches(host, scope_entry):
                    return True, "in scope"
            return False, f"Target '{host}' is not in the in-scope list"

        # No scope defined -> permissive (warn)
        return True, "no scope defined (permissive)"

    # -- Tool checks -----------------------------------------------------------

    def check_tool_allowed(self, tool: str, args: Optional[dict] = None) -> Tuple[bool, str]:
        """Check if a tool/action is allowed by the RoE.

        Returns ``(allowed, reason)``.
        """
        tool_lower = tool.lower()

        # Forbidden tools (explicit)
        for ft in self.roe.forbidden_tools:
            if ft.lower() in tool_lower or tool_lower in ft.lower():
                return False, f"Tool '{tool}' is forbidden by RoE"

        # Forbidden categories
        for cat in self.roe.forbidden_categories:
            if cat.lower() in tool_lower:
                return False, f"Tool '{tool}' matches forbidden category '{cat}'"

        # Default forbidden tools
        if tool_lower in DEFAULT_FORBIDDEN_TOOLS:
            return False, f"Tool '{tool}' is in the default-forbidden list"

        # DoS permission
        if not self.roe.allow_dos and tool_lower in DOS_TOOLS:
            return False, f"DoS tool '{tool}' is prohibited by RoE"

        # Brute force permission
        if not self.roe.allow_brute_force and "brute" in tool_lower:
            return False, "Brute-force tools are prohibited by RoE"

        # Social engineering
        if not self.roe.allow_social_engineering and "social" in tool_lower:
            return False, "Social engineering is prohibited by RoE"

        # Data exfiltration
        if not self.roe.allow_data_exfiltration and "exfil" in tool_lower:
            return False, "Data exfiltration is prohibited by RoE"

        return True, "allowed"

    # -- Time checks -----------------------------------------------------------

    def check_time_window(self) -> Tuple[bool, str]:
        """Check if the current time is within allowed testing hours.

        Returns ``(allowed, reason)``.
        """
        now = datetime.now(timezone.utc)

        # Blackout dates
        today_str = now.strftime("%Y-%m-%d")
        if today_str in self.roe.blackout_dates:
            return False, f"Today ({today_str}) is a blackout date"

        # Testing hours
        hours = self.roe.testing_hours
        if not hours or not hours.get("start") or not hours.get("end"):
            return True, "no time restriction"

        tz_name = hours.get("timezone", "UTC")
        try:
            import zoneinfo
            tz = zoneinfo.ZoneInfo(tz_name)
            local_now = now.astimezone(tz)
        except Exception:
            local_now = now  # Fallback to UTC

        start_parts = hours["start"].split(":")
        end_parts = hours["end"].split(":")
        start_h, start_m = int(start_parts[0]), int(start_parts[1]) if len(start_parts) > 1 else 0
        end_h, end_m = int(end_parts[0]), int(end_parts[1]) if len(end_parts) > 1 else 0

        current_minutes = local_now.hour * 60 + local_now.minute
        start_minutes = start_h * 60 + start_m
        end_minutes = end_h * 60 + end_m

        if start_minutes <= end_minutes:
            allowed = start_minutes <= current_minutes < end_minutes
        else:
            # Wraps midnight
            allowed = current_minutes >= start_minutes or current_minutes < end_minutes

        if not allowed:
            return False, (
                f"Current time {local_now.strftime('%H:%M')} ({tz_name}) "
                f"is outside allowed window {hours['start']}-{hours['end']}"
            )
        return True, "within testing hours"

    # -- Phase cap -------------------------------------------------------------

    def check_phase_allowed(self, phase: str) -> Tuple[bool, str]:
        """Check if the requested phase is within the severity cap."""
        max_ord = PHASE_ORDER.get(self.roe.max_severity_phase, 2)
        req_ord = PHASE_ORDER.get(phase, 0)
        if req_ord > max_ord:
            return False, (
                f"Phase '{phase}' exceeds max allowed phase "
                f"'{self.roe.max_severity_phase}'"
            )
        return True, "phase allowed"

    # -- Combined enforcement --------------------------------------------------

    def enforce(
        self,
        tool: str,
        target: str,
        args: Optional[dict] = None,
        phase: Optional[str] = None,
    ) -> Tuple[bool, str]:
        """Combined check: target + tool + time + phase.

        Returns ``(allowed, reason)``.  Any failing check short-circuits.
        """
        # Time window
        ok, reason = self.check_time_window()
        if not ok:
            return False, reason

        # Target scope
        ok, reason = self.check_target_allowed(target)
        if not ok:
            return False, reason

        # Tool permission
        ok, reason = self.check_tool_allowed(tool, args)
        if not ok:
            return False, reason

        # Phase cap
        if phase:
            ok, reason = self.check_phase_allowed(phase)
            if not ok:
                return False, reason

        return True, "all RoE checks passed"

    # -- LLM prompt injection --------------------------------------------------

    def to_prompt_section(self) -> str:
        """Generate a prompt section for LLM system-prompt injection.

        Mirrors RedAmon's ``build_roe_prompt_section`` but reads directly
        from the ``RulesOfEngagement`` dataclass instead of project settings.
        """
        roe = self.roe

        # If nothing configured, skip
        if not roe.client_name and not roe.in_scope_targets and not roe.excluded_hosts:
            return ""

        sections: List[str] = ["## RULES OF ENGAGEMENT (MANDATORY)"]

        # Client & engagement
        if roe.client_name:
            line = f"**Client:** {roe.client_name}"
            if roe.incident_contact:
                line += f" | Contact: {roe.incident_contact}"
            sections.append(line)

        if roe.engagement_start or roe.engagement_end:
            sections.append(
                f"**Engagement:** {roe.engagement_start} to {roe.engagement_end}"
            )

        if roe.escalation_email:
            sections.append(f"**Escalation Email:** {roe.escalation_email}")

        # In-scope targets
        if roe.in_scope_targets:
            lines = "\n".join(f"  - {t}" for t in roe.in_scope_targets)
            sections.append(f"**In-Scope Targets:**\n{lines}")

        # Excluded hosts
        if roe.excluded_hosts:
            host_lines = []
            for exc in roe.excluded_hosts:
                if isinstance(exc, dict):
                    h = exc.get("host", "?")
                    r = exc.get("reason", "")
                    host_lines.append(f"  - {h}" + (f" ({r})" if r else ""))
                else:
                    host_lines.append(f"  - {exc}")
            sections.append("**EXCLUDED HOSTS (NEVER TOUCH):**\n" + "\n".join(host_lines))

        # Time window
        if roe.testing_hours:
            tz = roe.testing_hours.get("timezone", "UTC")
            sections.append(
                f"**Allowed Time Window:** "
                f"{roe.testing_hours.get('start', '?')}-{roe.testing_hours.get('end', '?')} {tz}"
            )

        # Blackout dates
        if roe.blackout_dates:
            sections.append(f"**Blackout Dates:** {', '.join(roe.blackout_dates)}")

        # Permission flags
        perm_flags = [
            ("DoS", roe.allow_dos),
            ("Social Engineering", roe.allow_social_engineering),
            ("Physical Access", roe.allow_physical),
            ("Data Exfiltration", roe.allow_data_exfiltration),
            ("Brute Force", roe.allow_brute_force),
            ("Exploitation", roe.allow_exploitation),
        ]
        perm_lines = [f"  - {label}: {'ALLOWED' if val else 'PROHIBITED'}" for label, val in perm_flags]
        sections.append("**Testing Permissions:**\n" + "\n".join(perm_lines))

        # Phase cap
        phase_labels = {
            "informational": "Informational only (recon/scanning)",
            "exploitation": "Up to exploitation",
            "post_exploitation": "All phases (no restriction)",
        }
        sections.append(
            f"**Max Allowed Phase:** {phase_labels.get(roe.max_severity_phase, roe.max_severity_phase)}"
        )

        # Rate limit
        if roe.global_rate_limit_rps > 0:
            sections.append(f"**Global Rate Limit:** {roe.global_rate_limit_rps} requests/sec")

        # Forbidden tools
        if roe.forbidden_tools:
            sections.append(f"**Forbidden Tools:** {', '.join(roe.forbidden_tools)}")
        if roe.forbidden_categories:
            sections.append(f"**Forbidden Categories:** {', '.join(roe.forbidden_categories)}")

        # Data handling
        data_labels = {
            "no_access": "Do NOT access, copy, or display any sensitive data",
            "prove_only": "Note existence of sensitive data but do NOT copy or display it",
            "limited": "Limited collection allowed — minimize data captured",
            "full": "Full access — collect as needed for proof",
        }
        sections.append(
            f"**Data Handling:** {data_labels.get(roe.sensitive_data_policy, roe.sensitive_data_policy)}"
        )

        # Compliance
        if roe.compliance_frameworks:
            sections.append(
                f"**Compliance:** {', '.join(roe.compliance_frameworks)} "
                "— testing must respect these frameworks"
            )

        # Notes
        if roe.notes:
            sections.append(f"**Additional Rules:** {roe.notes}")

        # Enforcement reminder
        sections.append(
            "\nYou MUST respect ALL rules above. Never target excluded hosts. "
            "Never use forbidden tools or techniques. Stay within the allowed phase. "
            "If you discover a critical vulnerability, flag it immediately."
        )

        return "\n\n".join(sections)

    # -- Helpers ---------------------------------------------------------------

    @staticmethod
    def _extract_host(target: str) -> str:
        """Extract hostname/IP from a URL or bare target string."""
        if "://" in target:
            parsed = urlparse(target)
            host = parsed.netloc
        else:
            host = target
        # Remove port
        if ":" in host:
            host = host.split(":")[0]
        return host.lower().strip()

    @staticmethod
    def _host_matches(host: str, pattern: str) -> bool:
        """Check if *host* matches a scope pattern (exact, wildcard, CIDR prefix)."""
        host = host.lower().strip()
        pattern = pattern.lower().strip()

        if host == pattern:
            return True

        # Wildcard: *.example.com
        if pattern.startswith("*."):
            suffix = pattern[1:]  # ".example.com"
            return host.endswith(suffix) or host == pattern[2:]

        # fnmatch fallback
        return fnmatch(host, pattern)
