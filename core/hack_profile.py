"""Hack profiles — `viper hack <target>` behavior presets.

A `Profile` bundles the policy a hack run obeys: which phases to enable,
which workers to spawn, how long to keep working, what success looks
like, and whether the persistence loop should keep iterating.

Three built-in profiles:

  - **CTFProfile**       Loop until a flag is found. 30-min cap. All
                         workers including exploit + post enabled.
                         No scope reasoner (CTF boxes are owned).

  - **BugBountyProfile** Scope-aware deep exploration. 60-min cap.
                         Recon + vuln-discovery workers run by default;
                         exploit + post workers are gated behind `--go`.
                         Stops when 3 consecutive iterations produce no
                         new findings.

  - **LabProfile**       Operator-owned box, no ROE rails. All workers.
                         15-min cap. Stops after one full pass.

Auto-detection:
  `Profile.detect(target, scope_file=...)` returns the best profile for
  a target string. Heuristics:
    - `*.htb`, `*.thm`, `picoctf.*`, `tryhackme.*`, `hackthebox.*` → CTF
    - explicit `--scope` argument → BugBountyProfile
    - private IPs / localhost → LabProfile
    - everything else → BugBountyProfile (safest default)
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from typing import Optional, Sequence
from urllib.parse import urlparse


# ----- Stop-condition signal --------------------------------------------------


@dataclass
class StopCondition:
    """A single rule for terminating the persistence loop."""
    name: str
    description: str
    # When True, loop stops. Called once per iteration with the cumulative
    # state.
    check: object = None    # Callable[[dict], bool]


def _stop_when_flag(state: dict) -> bool:
    """CTF stop: any finding with type=flag_captured / FLAG_CAPTURED."""
    for f in state.get("findings", []):
        t = str(f.get("type", "")).lower()
        if t in ("flag_captured", "flag", "ctf_flag"):
            return True
        title = str(f.get("title", ""))
        # Common CTF flag patterns in titles
        if any(p in title for p in ("flag{", "FLAG{", "HTB{", "picoCTF{",
                                     "THM{", "CTF{")):
            return True
    return False


def _stop_when_exhausted(state: dict) -> bool:
    """Bug-bounty stop: 3 consecutive iterations with zero new findings."""
    history = state.get("findings_per_iteration", [])
    return len(history) >= 3 and sum(history[-3:]) == 0


def _stop_after_one(state: dict) -> bool:
    """Lab stop: terminate after ONE COMPLETED phase sweep.

    `findings_per_iteration` is only appended AFTER all phases of an
    iteration have run, so this check fires between iterations, not
    between phases (which would skip vuln after only recon ran).
    """
    return len(state.get("findings_per_iteration", [])) >= 1


# ----- Profile dataclass ------------------------------------------------------


@dataclass
class Profile:
    """Bundle of policy choices for a hack run."""
    name: str
    description: str

    # Which phases to run, in order. Recognised values:
    #   "recon", "vuln", "exploit", "post", "report"
    phases: list[str] = field(default_factory=list)

    # Per-phase worker manifests (subset of registered techniques).
    # Empty list = "use all registered workers for that phase".
    workers: dict[str, list[str]] = field(default_factory=dict)

    # Hard cap on the whole run, in seconds. The HackMode loop enforces
    # this via `asyncio.wait_for`.
    time_budget_s: float = 900.0  # 15 min default

    # How many recon→vuln→exploit cycles to allow before forcing stop.
    max_iterations: int = 10

    # Whether destructive workers may run (exploit + post). Always False
    # for scout. The `--go` flag flips this on for BugBountyProfile.
    allow_destructive: bool = False

    # Use scope reasoner? CTF + Lab profiles disable it; bug-bounty mandates it.
    use_scope_reasoner: bool = True

    # Persistence loop stop conditions. The loop stops when ANY returns True.
    stop_conditions: list[StopCondition] = field(default_factory=list)

    # Max concurrent workers per phase. Higher = faster but louder.
    max_concurrent: int = 12

    # Per-worker timeout. Set lower for CTFs (boxes are smaller).
    per_worker_timeout: float = 60.0

    def should_stop(self, state: dict) -> tuple[bool, Optional[str]]:
        """Run every stop condition. Returns (stop?, reason)."""
        for cond in self.stop_conditions:
            try:
                if cond.check and cond.check(state):
                    return True, cond.name
            except Exception:
                continue
        if state.get("iteration", 0) >= self.max_iterations:
            return True, f"max_iterations ({self.max_iterations})"
        return False, None

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "description": self.description,
            "phases": list(self.phases),
            "workers": {k: list(v) for k, v in self.workers.items()},
            "time_budget_s": self.time_budget_s,
            "max_iterations": self.max_iterations,
            "allow_destructive": self.allow_destructive,
            "use_scope_reasoner": self.use_scope_reasoner,
            "max_concurrent": self.max_concurrent,
            "per_worker_timeout": self.per_worker_timeout,
            "stop_conditions": [c.name for c in self.stop_conditions],
        }


# ----- Built-in factories -----------------------------------------------------


def CTFProfile(*, time_budget_s: float = 1800.0, allow_destructive: bool = True) -> Profile:
    """30-min CTF run that loops until a flag is found."""
    return Profile(
        name="CTFProfile",
        description="Loop-until-flag CTF run. All workers enabled.",
        phases=["recon", "vuln", "exploit", "post", "report"],
        workers={
            "recon": ["subdomain", "port_scan", "wappalyzer", "dns", "wayback"],
            "vuln": [],     # all
            "exploit": [],  # all (gated by allow_destructive)
            "post": ["flag_hunter", "linpeas", "gtfobins"],
        },
        time_budget_s=time_budget_s,
        max_iterations=20,
        allow_destructive=allow_destructive,
        use_scope_reasoner=False,
        stop_conditions=[
            StopCondition("flag_found", "CTF flag detected", _stop_when_flag),
        ],
        max_concurrent=16,
        per_worker_timeout=90.0,
    )


def BugBountyProfile(*, time_budget_s: float = 3600.0,
                     allow_destructive: bool = False) -> Profile:
    """60-min scope-aware bug-bounty exploration."""
    return Profile(
        name="BugBountyProfile",
        description=(
            "Scope-aware deep exploration. Loops recon→vuln→exploit until "
            "3 consecutive iterations produce zero new findings."
        ),
        phases=["recon", "vuln"] + (
            ["exploit", "post"] if allow_destructive else []
        ) + ["report"],
        workers={
            "recon": [],   # all registered
            "vuln": [],    # all registered
            "exploit": [], # gated
            "post": [],
        },
        time_budget_s=time_budget_s,
        max_iterations=10,
        allow_destructive=allow_destructive,
        use_scope_reasoner=True,
        stop_conditions=[
            StopCondition("exhausted", "3 iterations with zero new findings",
                          _stop_when_exhausted),
        ],
        max_concurrent=12,
        per_worker_timeout=60.0,
    )


def LabProfile(*, time_budget_s: float = 900.0, allow_destructive: bool = True) -> Profile:
    """Owned-box test profile. No ROE rails."""
    return Profile(
        name="LabProfile",
        description=(
            "Owned box / lab target. No scope reasoner, all workers enabled, "
            "single full pass."
        ),
        phases=["recon", "vuln"] + (
            ["exploit", "post"] if allow_destructive else []
        ) + ["report"],
        workers={},
        time_budget_s=time_budget_s,
        max_iterations=1,
        allow_destructive=allow_destructive,
        use_scope_reasoner=False,
        stop_conditions=[
            StopCondition("one_pass", "after one full sweep", _stop_after_one),
        ],
        max_concurrent=12,
        per_worker_timeout=60.0,
    )


# ----- Auto-detection ---------------------------------------------------------


_CTF_PATTERNS = re.compile(
    r"\.(htb|thm)(:\d+)?$"           # HTB / TryHackMe
    r"|^(picoctf|tryhackme|hackthebox|pwn\.college|ctf\.)",
    re.IGNORECASE,
)


def _is_private_ip(host: str) -> bool:
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False
    return ip.is_private or ip.is_loopback or ip.is_link_local


def detect_profile(
    target: str,
    *,
    scope_file: Optional[str] = None,
    explicit: Optional[str] = None,
    go: bool = False,
) -> Profile:
    """Pick a profile for `target`.

    Resolution order:
      1. `explicit` arg ("ctf" / "bugbounty" / "lab") wins.
      2. `scope_file` set → BugBounty.
      3. Target hostname matches a known CTF pattern → CTF.
      4. Target is private IP / localhost → Lab.
      5. Default → BugBounty (safest — scope-aware).
    """
    if explicit:
        key = explicit.lower()
        if key in ("ctf", "ctfprofile"):
            return CTFProfile(allow_destructive=True)
        if key in ("bugbounty", "bug-bounty", "bb", "bugbountyprofile"):
            return BugBountyProfile(allow_destructive=go)
        if key in ("lab", "labprofile"):
            return LabProfile(allow_destructive=go)
        raise ValueError(f"unknown profile: {explicit!r}")

    if scope_file:
        return BugBountyProfile(allow_destructive=go)

    host = target.strip().lower()
    if "://" in host:
        host = urlparse(host).hostname or host
    host = host.split(":", 1)[0].strip().rstrip(".")

    if _CTF_PATTERNS.search(host):
        return CTFProfile(allow_destructive=True)

    if _is_private_ip(host) or host in ("localhost", "127.0.0.1", "0.0.0.0"):
        return LabProfile(allow_destructive=go)

    return BugBountyProfile(allow_destructive=go)


# ----- Public registry --------------------------------------------------------


BUILTIN_PROFILES = {
    "ctf": CTFProfile,
    "bugbounty": BugBountyProfile,
    "lab": LabProfile,
}


def list_profiles() -> Sequence[str]:
    return tuple(BUILTIN_PROFILES.keys())
