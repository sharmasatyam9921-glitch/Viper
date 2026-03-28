#!/usr/bin/env python3
"""
VIPER 4.0 Skill Prompts Package

Provides attack-skill-specific system prompts and phase guidance.
"""

from typing import Optional


def get_skill_prompt(attack_path_type: str, phase: str = "exploitation") -> str:
    """Get the combined prompt for an attack skill type and phase.

    Args:
        attack_path_type: The classified attack skill type
            (e.g., "cve_exploit", "brute_force_credential_guess", "sql_injection-unclassified")
        phase: The current phase ("informational", "exploitation", "post_exploitation")

    Returns:
        Combined system prompt + phase guidance text for the skill.
    """
    # Import lazily to avoid circular imports
    from . import cve_exploit, brute_force, phishing, dos, sql_injection, unclassified

    _SKILL_MODULES = {
        "cve_exploit": cve_exploit,
        "brute_force_credential_guess": brute_force,
        "phishing_social_engineering": phishing,
        "denial_of_service": dos,
        "sql_injection": sql_injection,
    }

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
    "unclassified",
]
