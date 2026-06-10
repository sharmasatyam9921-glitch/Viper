"""Dataclasses for the VIPER benchmark harness.

Three records flow through the pipeline:
  Challenge  — a spec loaded from a suite JSON file (what to attack, how to score).
  RunResult  — the raw outcome of running VIPER once against a challenge.
  Score      — the graded verdict (solved / not), with the reason and evidence.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Optional


# Severity ladder used for `min_severity` gating in vuln_class scoring.
SEVERITY_ORDER = {
    "info": 0,
    "informational": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}


def severity_rank(sev: Optional[str]) -> int:
    """Map a severity label to its rank; unknown/None sorts to the bottom."""
    if not sev:
        return -1
    return SEVERITY_ORDER.get(str(sev).strip().lower(), -1)


@dataclass
class Target:
    """How to stand up (or reach) the system-under-test for one challenge.

    type:
      external        — already running; just use `url`.
      docker_image    — `docker run` a single image, map `container_port`->`host_port`.
      docker_compose  — `docker compose up` a compose file in `compose_dir`.
    """

    type: str = "external"
    url: str = ""
    # docker_image
    image: str = ""
    container_port: int = 0
    host_port: int = 0
    env: dict[str, str] = field(default_factory=dict)
    run_args: list[str] = field(default_factory=list)
    # docker_compose
    compose_dir: str = ""
    compose_file: str = ""
    service: str = ""
    # health
    health_path: str = "/"
    health_timeout: int = 120

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "Target":
        known = {f for f in cls.__dataclass_fields__}  # type: ignore[attr-defined]
        return cls(**{k: v for k, v in d.items() if k in known})


@dataclass
class Expect:
    """Grading criteria for vuln_class mode."""

    vuln_types: list[str] = field(default_factory=list)
    url_contains: str = ""
    min_severity: str = ""

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "Expect":
        return cls(
            vuln_types=[str(v) for v in d.get("vuln_types", [])],
            url_contains=str(d.get("url_contains", "")),
            min_severity=str(d.get("min_severity", "")),
        )


@dataclass
class Challenge:
    """One benchmark item parsed from a suite spec file."""

    id: str
    name: str = ""
    category: str = ""
    difficulty: str = ""
    # "flag" → XBOW-comparable capture-the-flag scoring.
    # "vuln_class" → graded on whether VIPER reported a matching vuln class.
    mode: str = "vuln_class"
    target: Target = field(default_factory=Target)
    expect: Expect = field(default_factory=Expect)
    flag: str = ""
    flag_regex: str = ""
    viper_args: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "Challenge":
        return cls(
            id=str(d["id"]),
            name=str(d.get("name", d["id"])),
            category=str(d.get("category", "")),
            difficulty=str(d.get("difficulty", "")),
            mode=str(d.get("mode", "vuln_class")),
            target=Target.from_dict(d.get("target", {})),
            expect=Expect.from_dict(d.get("expect", {})),
            flag=str(d.get("flag", "")),
            flag_regex=str(d.get("flag_regex", "")),
            viper_args=[str(a) for a in d.get("viper_args", [])],
            tags=[str(t) for t in d.get("tags", [])],
        )


@dataclass
class RunResult:
    """Raw outcome of one VIPER subprocess run against one challenge."""

    challenge_id: str
    target_url: str
    started_at: float = field(default_factory=time.time)
    duration_s: float = 0.0
    exit_code: Optional[int] = None
    timed_out: bool = False
    output_json_path: str = ""
    # Parsed findings (normalized list of dicts) from the --output JSON, if any.
    findings: list[dict[str, Any]] = field(default_factory=list)
    stdout_tail: str = ""
    stderr_tail: str = ""
    error: str = ""


@dataclass
class Score:
    """Graded verdict for one challenge."""

    challenge_id: str
    name: str = ""
    category: str = ""
    mode: str = ""
    solved: bool = False
    reason: str = ""
    matched: list[dict[str, Any]] = field(default_factory=list)
    duration_s: float = 0.0
    timed_out: bool = False
    error: str = ""

    def to_row(self) -> dict[str, Any]:
        return {
            "challenge_id": self.challenge_id,
            "name": self.name,
            "category": self.category,
            "mode": self.mode,
            "solved": self.solved,
            "reason": self.reason,
            "duration_s": round(self.duration_s, 1),
            "timed_out": self.timed_out,
            "error": self.error,
        }
