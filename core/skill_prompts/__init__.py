#!/usr/bin/env python3
"""
VIPER 5.0 Skill Prompts Package

Provides attack-skill-specific system prompts and phase guidance.
"""

from typing import Optional

# Re-export content libraries so they're reachable as
# ``core.skill_prompts.tool_registry`` / ``core.skill_prompts.stealth_rules``
# even though they're not part of the get_skill_prompt() dispatch table.
from . import tool_registry, stealth_rules  # noqa: F401


def get_skill_prompt(attack_path_type: str, phase: str = "exploitation") -> str:
    """Get the combined prompt for an attack skill type and phase.

    Args:
        attack_path_type: The classified attack skill type
            (e.g., "cve_exploit", "brute_force_credential_guess", "sql_injection-unclassified")
        phase: The current phase ("informational", "exploitation", "post_exploitation")

    Returns:
        Combined system prompt + phase guidance text for the skill.
    """
    # Import lazily to avoid circular imports. Each import is best-effort
    # so a single broken skill module doesn't poison the whole registry.
    _SKILL_MODULES: dict = {}

    def _maybe_import(name):
        try:
            return __import__(f"core.skill_prompts.{name}",
                              fromlist=[name])
        except Exception:  # noqa: BLE001
            return None

    # Always-present built-ins
    from . import (
        cve_exploit, brute_force, phishing, dos, sql_injection,
        api_security, xss_exploitation, ssrf_exploitation, unclassified,
    )
    _SKILL_MODULES.update({
        "cve_exploit": cve_exploit,
        "brute_force_credential_guess": brute_force,
        "phishing_social_engineering": phishing,
        "denial_of_service": dos,
        "sql_injection": sql_injection,
        "api_security": api_security,
        "jwt_exploitation": api_security,
        "graphql_exploitation": api_security,
        "api_testing": api_security,
        "xss": xss_exploitation,
        "xss_exploitation": xss_exploitation,
        "cross_site_scripting": xss_exploitation,
        "ssrf": ssrf_exploitation,
        "ssrf_exploitation": ssrf_exploitation,
        "server_side_request_forgery": ssrf_exploitation,
    })

    # Vertical / lateral skills — optional, registered if present
    _OPTIONAL_BINDINGS = {
        "active_directory":   ("active_directory",
                               ["active_directory", "ad", "ldap_exploit"]),
        "ctf_web":            ("ctf_web",
                               ["ctf_web", "ctf", "ctf_challenge"]),
        "linux_privesc":      ("linux_privesc",
                               ["linux_privesc", "privesc_linux",
                                "post_exploit_linux"]),
        "windows_privesc":    ("windows_privesc",
                               ["windows_privesc", "privesc_windows",
                                "post_exploit_windows"]),
        "ai_security":        ("ai_security",
                               ["ai_security", "llm_security",
                                "prompt_injection", "ai_red_team"]),
    }
    for mod_name, (file_basename, aliases) in _OPTIONAL_BINDINGS.items():
        mod = _maybe_import(file_basename)
        if mod is None:
            continue
        for alias in aliases:
            _SKILL_MODULES.setdefault(alias, mod)

    # Check if it's a known built-in skill
    module = _SKILL_MODULES.get(attack_path_type)

    # If unclassified (e.g., "sql_injection-unclassified"), use unclassified module
    if module is None:
        if attack_path_type.endswith("-unclassified") or attack_path_type not in _SKILL_MODULES:
            module = unclassified

    if module is None:
        module = unclassified

    parts = []

    # System prompt
    if hasattr(module, "SYSTEM_PROMPT"):
        parts.append(module.SYSTEM_PROMPT)

    # Phase-specific guidance
    if hasattr(module, "get_phase_guidance"):
        guidance = module.get_phase_guidance(phase)
        if guidance:
            parts.append(guidance)

    return "\n\n".join(parts) if parts else ""


# ---------------------------------------------------------------------------
# Compatibility exports for Phase 3 API consumers
# ---------------------------------------------------------------------------

SKILL_CATEGORIES = [
    "cve_exploit",
    "brute_force_credential_guess",
    "phishing_social_engineering",
    "denial_of_service",
    "sql_injection",
    "api_security",
    "xss_exploitation",
    "ssrf_exploitation",
    "active_directory",
    "linux_privesc",
    "windows_privesc",
    "ctf_web",
    "ai_security",
    "unclassified",
]
