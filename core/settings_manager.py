#!/usr/bin/env python3
"""
VIPER 4.0 Settings Manager

JSON-based configuration management. Loads/saves viper_settings.json.
Supports global defaults, per-project overrides, and runtime modifications.

Pure stdlib -- no external dependencies.
"""

import json
import logging
import os
import copy
from typing import Any, Dict, List, Optional

logger = logging.getLogger("viper.settings")

# ---------------------------------------------------------------------------
# Default settings (50+ keys)
# ---------------------------------------------------------------------------

DEFAULT_SETTINGS: Dict[str, Any] = {
    # =====================================================================
    # LLM Configuration
    # =====================================================================
    "llm_model": "anthropic/claude-sonnet-4-20250514",
    "llm_triage_model": "ollama/deepseek-r1:14b",
    "llm_reasoning_model": "anthropic/claude-sonnet-4-20250514",
    "llm_fallback_models": ["ollama/deepseek-r1:14b", "openai/gpt-4o"],
    "llm_max_tokens": 4096,
    "llm_temperature": 0.3,
    "llm_rate_limit_rpm": 30,
    "llm_parse_max_retries": 3,
    "llm_api_base": "",

    # =====================================================================
    # Stealth Mode
    # =====================================================================
    "stealth_mode": False,
    "stealth_max_rps": 2,
    "stealth_realistic_ua": True,

    # =====================================================================
    # Guardrails
    # =====================================================================
    "guardrail_enabled": True,
    "guardrail_hard_enabled": True,
    "guardrail_llm_enabled": True,
    "guardrail_fail_open": True,

    # =====================================================================
    # Phase Configuration
    # =====================================================================
    "phase_auto_transition": False,
    "phase_max_iterations": 100,
    "phase_post_exploitation_enabled": True,
    "phase_post_exploitation_type": "statefull",
    "phase_approval_exploitation": True,
    "phase_approval_post_exploitation": True,

    # =====================================================================
    # Attack Skills Enable/Disable
    # =====================================================================
    "skill_cve_exploit_enabled": True,
    "skill_brute_force_enabled": True,
    "skill_phishing_enabled": False,
    "skill_dos_enabled": False,
    "skill_unclassified_enabled": True,

    # =====================================================================
    # Hydra / Brute Force Configuration
    # =====================================================================
    "hydra_threads": 16,
    "hydra_wait_between_connections": 0,
    "hydra_connection_timeout": 32,
    "hydra_stop_on_first_found": True,
    "hydra_extra_checks": "nsr",
    "hydra_verbose": True,
    "hydra_max_attempts": 3,

    # =====================================================================
    # DoS Configuration
    # =====================================================================
    "dos_max_duration": 60,
    "dos_max_attempts": 3,
    "dos_concurrent_connections": 1000,
    "dos_assessment_only": False,

    # =====================================================================
    # Payload / Session Configuration
    # =====================================================================
    "payload_lhost": "",
    "payload_lport": None,
    "payload_bind_port": None,
    "payload_use_https": False,
    "payload_tunnel_type": "none",

    # =====================================================================
    # Tool Phase Restrictions
    # =====================================================================
    "tool_phase_map": {
        "graph_query": ["informational", "exploitation", "post_exploitation"],
        "web_search": ["informational", "exploitation", "post_exploitation"],
        "curl_request": ["informational", "exploitation", "post_exploitation"],
        "port_scan": ["informational", "exploitation"],
        "nmap_scan": ["informational", "exploitation", "post_exploitation"],
        "nuclei_scan": ["informational", "exploitation"],
        "shell_exec": ["informational", "exploitation", "post_exploitation"],
        "code_exec": ["exploitation", "post_exploitation"],
        "hydra_attack": ["exploitation"],
        "metasploit": ["exploitation", "post_exploitation"],
        "sqlmap_scan": ["exploitation"],
        "shodan_lookup": ["informational", "exploitation"],
        "google_dork": ["informational"],
    },

    # =====================================================================
    # Tool Restrictions
    # =====================================================================
    "tool_confirmation_required": True,
    "tool_output_max_chars": 20000,
    "tool_timeout_seconds": 120,
    "tool_dangerous_tools": [
        "nmap_scan", "port_scan", "nuclei_scan", "curl_request",
        "shell_exec", "code_exec", "hydra_attack", "metasploit",
    ],

    # =====================================================================
    # Rules of Engagement (RoE)
    # =====================================================================
    "roe_enabled": False,
    "roe_raw_text": "",
    "roe_client_name": "",
    "roe_client_contact_name": "",
    "roe_client_contact_email": "",
    "roe_client_contact_phone": "",
    "roe_emergency_contact": "",
    "roe_engagement_start_date": "",
    "roe_engagement_end_date": "",
    "roe_engagement_type": "external",
    "roe_excluded_hosts": [],
    "roe_excluded_host_reasons": [],
    "roe_time_window_enabled": False,
    "roe_time_window_timezone": "UTC",
    "roe_time_window_days": ["monday", "tuesday", "wednesday", "thursday", "friday"],
    "roe_time_window_start_time": "09:00",
    "roe_time_window_end_time": "18:00",
    "roe_forbidden_tools": [],
    "roe_forbidden_categories": [],
    "roe_max_severity_phase": "post_exploitation",
    "roe_allow_dos": False,
    "roe_allow_social_engineering": False,
    "roe_allow_physical_access": False,
    "roe_allow_data_exfiltration": False,
    "roe_allow_account_lockout": False,
    "roe_allow_production_testing": True,
    "roe_global_max_rps": 0,
    "roe_sensitive_data_handling": "no_access",
    "roe_data_retention_days": 90,
    "roe_require_data_encryption": True,
    "roe_status_update_frequency": "daily",
    "roe_critical_finding_notify": True,
    "roe_incident_procedure": "",
    "roe_third_party_providers": [],
    "roe_compliance_frameworks": [],
    "roe_notes": "",

    # =====================================================================
    # Reporting
    # =====================================================================
    "report_format": "html",
    "report_include_evidence": True,
    "report_include_remediation": True,
    "report_severity_threshold": "low",

    # =====================================================================
    # Logging
    # =====================================================================
    "log_level": "INFO",
    "log_max_mb": 10,
    "log_backup_count": 5,

    # =====================================================================
    # Graph / Knowledge Base
    # =====================================================================
    "graph_backend": "sqlite",
    "graph_auto_persist": True,
    "graph_max_nodes": 50000,

    # =====================================================================
    # Agent Behavior
    # =====================================================================
    "agent_deep_think_enabled": True,
    "agent_execution_trace_steps": 100,
    "agent_q_learning_enabled": True,
    "agent_behavioral_validation": True,
}


class SettingsManager:
    """JSON-based settings manager with per-project override support.

    Usage:
        settings = SettingsManager()                    # loads defaults
        settings = SettingsManager("path/to/config.json")  # loads from file

        value = settings.get("stealth_mode", False)
        settings.set("stealth_mode", True)
        settings.save()
    """

    def __init__(self, config_path: Optional[str] = None):
        """Initialize settings manager.

        Args:
            config_path: Path to JSON config file. If None, uses
                         viper_settings.json in the hackagent directory.
        """
        if config_path is None:
            base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            config_path = os.path.join(base_dir, "viper_settings.json")

        self._config_path = config_path
        self._settings: Dict[str, Any] = copy.deepcopy(DEFAULT_SETTINGS)
        self._project_overrides: Dict[str, Dict[str, Any]] = {}
        self._current_project: Optional[str] = None
        self._dirty = False

        self.load()

    @property
    def config_path(self) -> str:
        return self._config_path

    def load(self) -> None:
        """Load settings from JSON file. Missing keys get defaults."""
        if not os.path.exists(self._config_path):
            logger.info("No config file at %s, using defaults", self._config_path)
            return

        try:
            with open(self._config_path, "r", encoding="utf-8") as f:
                data = json.load(f)

            if not isinstance(data, dict):
                logger.warning("Config file is not a dict, using defaults")
                return

            # Merge top-level settings
            global_settings = data.get("settings", data)
            if "settings" in data:
                global_settings = data["settings"]

            for key, value in global_settings.items():
                if key in ("projects", "project_overrides"):
                    continue
                self._settings[key] = value

            # Load project overrides
            self._project_overrides = data.get("projects", data.get("project_overrides", {}))

            self._dirty = False
            logger.info("Loaded settings from %s (%d keys)", self._config_path, len(self._settings))

        except json.JSONDecodeError as e:
            logger.error("Failed to parse config file %s: %s", self._config_path, e)
        except OSError as e:
            logger.error("Failed to read config file %s: %s", self._config_path, e)

    def save(self) -> None:
        """Save current settings to JSON file."""
        data = {
            "settings": self._settings,
            "projects": self._project_overrides,
        }

        try:
            os.makedirs(os.path.dirname(self._config_path) or ".", exist_ok=True)
            with open(self._config_path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, sort_keys=False, default=str)
            self._dirty = False
            logger.info("Saved settings to %s", self._config_path)
        except OSError as e:
            logger.error("Failed to save config file %s: %s", self._config_path, e)

    def get(self, key: str, default: Any = None) -> Any:
        """Get a setting value with optional default.

        Checks project overrides first, then global settings, then provided default.
        """
        # Check project overrides
        if self._current_project and self._current_project in self._project_overrides:
            project_settings = self._project_overrides[self._current_project]
            if key in project_settings:
                return project_settings[key]

        # Global settings
        if key in self._settings:
            return self._settings[key]

        # Default from DEFAULT_SETTINGS
        if key in DEFAULT_SETTINGS:
            return DEFAULT_SETTINGS[key]

        return default

    def set(self, key: str, value: Any) -> None:
        """Set a global setting value."""
        self._settings[key] = value
        self._dirty = True

    def set_project(self, project_id: str, key: str, value: Any) -> None:
        """Set a project-specific override."""
        if project_id not in self._project_overrides:
            self._project_overrides[project_id] = {}
        self._project_overrides[project_id][key] = value
        self._dirty = True

    def get_project_settings(self, project_id: str) -> Dict[str, Any]:
        """Get merged settings for a specific project.

        Returns global settings with project-specific overrides applied.
        """
        merged = copy.deepcopy(self._settings)
        if project_id in self._project_overrides:
            merged.update(self._project_overrides[project_id])
        return merged

    def set_current_project(self, project_id: Optional[str]) -> None:
        """Set the active project for get() lookups."""
        self._current_project = project_id

    def reset_to_defaults(self) -> None:
        """Reset all settings to defaults."""
        self._settings = copy.deepcopy(DEFAULT_SETTINGS)
        self._project_overrides = {}
        self._current_project = None
        self._dirty = True

    def get_all(self) -> Dict[str, Any]:
        """Get all current settings as a dict."""
        return copy.deepcopy(self._settings)

    @property
    def is_dirty(self) -> bool:
        """True if settings have been modified since last save/load."""
        return self._dirty

    # ----- Convenience helpers -----

    def get_enabled_skills(self) -> set:
        """Return set of enabled attack skill IDs."""
        skills = set()
        if self.get("skill_cve_exploit_enabled", True):
            skills.add("cve_exploit")
        if self.get("skill_brute_force_enabled", True):
            skills.add("brute_force_credential_guess")
        if self.get("skill_phishing_enabled", False):
            skills.add("phishing_social_engineering")
        if self.get("skill_dos_enabled", False):
            skills.add("denial_of_service")
        if self.get("skill_unclassified_enabled", True):
            skills.add("unclassified")
        return skills

    def is_tool_allowed_in_phase(self, tool_name: str, phase: str) -> bool:
        """Check if a tool is allowed in the given phase."""
        tool_phase_map = self.get("tool_phase_map", {})
        allowed_phases = tool_phase_map.get(tool_name, [])
        return phase in allowed_phases

    def get_allowed_tools_for_phase(self, phase: str) -> List[str]:
        """Get list of tool names allowed in the given phase."""
        tool_phase_map = self.get("tool_phase_map", {})
        return [
            tool_name
            for tool_name, allowed_phases in tool_phase_map.items()
            if phase in allowed_phases
        ]

    def get_hydra_flags(self) -> str:
        """Build Hydra CLI flags string from settings."""
        parts = []
        parts.append(f"-t {self.get('hydra_threads', 16)}")
        wait = self.get("hydra_wait_between_connections", 0)
        if wait > 0:
            parts.append(f"-W {wait}")
        timeout = self.get("hydra_connection_timeout", 32)
        if timeout != 32:
            parts.append(f"-w {timeout}")
        if self.get("hydra_stop_on_first_found", True):
            parts.append("-f")
        extra = self.get("hydra_extra_checks", "nsr")
        if extra:
            parts.append(f"-e {extra}")
        if self.get("hydra_verbose", True):
            parts.append("-V")
        return " ".join(parts)

    def get_dos_settings(self) -> Dict[str, Any]:
        """Get DoS settings dict for prompt template injection."""
        return {
            "dos_max_duration": self.get("dos_max_duration", 60),
            "dos_max_attempts": self.get("dos_max_attempts", 3),
            "dos_connections": self.get("dos_concurrent_connections", 1000),
        }

    def is_stealth_mode(self) -> bool:
        """Check if stealth mode is active."""
        return bool(self.get("stealth_mode", False))

    def is_roe_active(self) -> bool:
        """Check if Rules of Engagement are active."""
        return bool(self.get("roe_enabled", False))


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

_instance: Optional[SettingsManager] = None


def get_settings_manager(config_path: Optional[str] = None) -> SettingsManager:
    """Get or create the global SettingsManager singleton."""
    global _instance
    if _instance is None or (config_path and _instance.config_path != config_path):
        _instance = SettingsManager(config_path)
    return _instance


def get_setting(key: str, default: Any = None) -> Any:
    """Convenience: get a setting from the global manager."""
    return get_settings_manager().get(key, default)
