"""Swarm worker registry — phase + technique → runner function.

A "worker" is a short-lived coroutine that takes one
:class:`core.swarm_engine.SwarmAgent` and returns a list of finding
dicts. The coordinator wraps each runner with audit + bus plumbing.

Workers are grouped by phase:

    core.swarm_workers.recon     — RECON_WORKERS    (subdomain, port_scan, ...)
    core.swarm_workers.vuln      — VULN_WORKERS     (Phase 2)
    core.swarm_workers.exploit   — EXPLOIT_WORKERS  (Phase 3, gated)
    core.swarm_workers.post      — POST_WORKERS     (Phase 3, gated)

Public API:
    get_worker_runner(phase, technique) -> AgentRunner
    list_workers(phase) -> list[str]
    register_worker(phase, technique, runner)  # for tests / plugins
"""

from __future__ import annotations

from typing import Awaitable, Callable, Dict, List


# Each registered worker: (phase, technique) -> async runner
_REGISTRY: Dict[str, Dict[str, Callable[..., Awaitable[list]]]] = {
    "recon": {},
    "vuln": {},
    "exploit": {},
    "post": {},
}


def register_worker(phase: str, technique: str, runner) -> None:
    """Register a runner. Overwrites if (phase, technique) already exists."""
    if phase not in _REGISTRY:
        _REGISTRY[phase] = {}
    _REGISTRY[phase][technique] = runner


def get_worker_runner(phase: str, technique: str):
    """Look up a registered runner. Raises KeyError if missing."""
    try:
        return _REGISTRY[phase][technique]
    except KeyError:
        raise KeyError(f"no worker registered for phase={phase!r} technique={technique!r}")


def list_workers(phase: str) -> List[str]:
    """All known techniques for a phase."""
    return sorted(_REGISTRY.get(phase, {}).keys())


def list_all_phases() -> List[str]:
    return list(_REGISTRY.keys())


def clear_phase(phase: str) -> None:
    """Wipe a phase's registry (used by tests)."""
    _REGISTRY[phase] = {}


# Auto-register all phase modules on import. Import errors are tolerated so
# the registry remains usable even if one worker file is broken — the broken
# technique is just unavailable.
def _safe_import(modname: str) -> None:
    try:
        __import__(modname)
    except Exception:  # noqa: BLE001
        # Log but don't crash — workers are optional.
        import logging
        logging.getLogger("viper.swarm_workers").warning(
            "skipped importing %s due to error", modname, exc_info=True,
        )


_safe_import("core.swarm_workers.recon")
_safe_import("core.swarm_workers.vuln")
_safe_import("core.swarm_workers.exploit")
_safe_import("core.swarm_workers.post")
