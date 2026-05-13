"""Novice-friendly progress narrator.

Translates VIPER's internal events (port scan results, nuclei findings,
exploit attempts, privesc paths) into plain-English step messages a
non-technical operator can follow in real time. Modeled loosely on how
an OSCP exam taker narrates their own progress.

Usage:
    n = Narrator()
    n.stage("RECON", total_stages=7, current=1)
    n.step("Scanning ports on target.com...")
    n.found(f"{len(open_ports)} open ports: {', '.join(map(str, open_ports))}")
    n.next_stage("VULN_DISCOVERY")
    ...
    n.summary(findings=18, foothold=True, privesc=True, time_min=23)
"""

from __future__ import annotations

import sys
import time
from dataclasses import dataclass, field
from typing import Optional, TextIO


# ANSI color codes (degrade gracefully on Windows cmd / piped output)
class _C:
    RESET = "\x1b[0m"
    BOLD = "\x1b[1m"
    DIM = "\x1b[2m"
    GREEN = "\x1b[32m"
    YELLOW = "\x1b[33m"
    RED = "\x1b[31m"
    BLUE = "\x1b[34m"
    CYAN = "\x1b[36m"
    MAGENTA = "\x1b[35m"


@dataclass
class StageProgress:
    name: str
    index: int       # 1-based
    total: int
    started_at: float = field(default_factory=time.time)
    finished_at: Optional[float] = None
    status: str = "running"  # running / success / failed / skipped
    findings: list[str] = field(default_factory=list)

    @property
    def elapsed_s(self) -> float:
        end = self.finished_at or time.time()
        return end - self.started_at


# Map of pretty-Unicode → ASCII fallback for terminals that can't encode it
# (cp1252 on Windows console). Applied lazily when the stream encoding is
# detected as ASCII-only.
_ASCII_FALLBACK = str.maketrans({
    "═": "=", "║": "|", "╔": "+", "╗": "+", "╚": "+", "╝": "+",
    "─": "-", "│": "|", "┌": "+", "┐": "+", "└": "+", "┘": "+",
    "✓": "OK", "✗": "X", "○": "o", "·": ".",
    "→": "->", "←": "<-", "▶": ">",
    "█": "#", "░": ".", "▒": ":",
    "—": "--", "–": "-", "…": "...", "•": "*",
    "“": '"', "”": '"', "‘": "'", "’": "'",
})


def _stream_supports_unicode(stream) -> bool:
    """Detect whether the stream can encode common Unicode chars without error."""
    enc = (getattr(stream, "encoding", None) or "").lower()
    if not enc:
        return True
    # cp1252 / cp437 / ascii — the common Windows console encodings
    return enc not in ("cp1252", "cp437", "ascii", "us-ascii", "windows-1252")


class Narrator:
    """Single-operator pretty printer with optional plain-text fallback."""

    def __init__(self, *, stream: TextIO = None, use_color: bool = None,
                 quiet: bool = False, ascii_only: bool = None) -> None:
        self.stream = stream or sys.stdout
        if use_color is None:
            use_color = self.stream.isatty()
        self.use_color = use_color
        # ascii_only defaults to "auto-detect" — True when the stream can't
        # encode unicode box-drawing characters (e.g. Windows cmd.exe).
        if ascii_only is None:
            ascii_only = not _stream_supports_unicode(self.stream)
        self.ascii_only = ascii_only
        self.quiet = quiet
        self.stages: list[StageProgress] = []
        self.current: Optional[StageProgress] = None
        self.t0 = time.time()

    # ------------------------------------------------------------------
    # Low-level write
    # ------------------------------------------------------------------

    def _w(self, msg: str) -> None:
        if self.quiet:
            return
        if self.ascii_only:
            msg = msg.translate(_ASCII_FALLBACK)
        if not self.use_color:
            # Strip ANSI codes
            import re
            msg = re.sub(r"\x1b\[[0-9;]*[a-zA-Z]", "", msg)
        try:
            self.stream.write(msg + "\n")
            self.stream.flush()
        except UnicodeEncodeError:
            # Last-resort fallback — encode with replacement
            enc = getattr(self.stream, "encoding", "ascii") or "ascii"
            safe = msg.encode(enc, errors="replace").decode(enc, errors="replace")
            self.stream.write(safe + "\n")
            self.stream.flush()

    def _color(self, text: str, color: str) -> str:
        if not self.use_color:
            return text
        return f"{color}{text}{_C.RESET}"

    # ------------------------------------------------------------------
    # Public narration API
    # ------------------------------------------------------------------

    def banner(self, target: str, mode: str = "safe") -> None:
        """Print the opening banner the operator sees before any stages run."""
        bar = "═" * 60
        self._w("")
        self._w(self._color(bar, _C.CYAN))
        self._w(self._color("  VIPER — autonomous pentest", _C.BOLD))
        self._w(self._color(bar, _C.CYAN))
        self._w(f"  Target:    {self._color(target, _C.YELLOW)}")
        self._w(f"  Mode:      {self._color(mode, _C.MAGENTA)}")
        self._w(f"  Started:   {time.strftime('%Y-%m-%d %H:%M:%S')}")
        self._w("")
        self._w(self._color("  REMINDER", _C.RED) + ": run this only on systems you")
        self._w("  own or have explicit written authorization to test.")
        self._w(self._color(bar, _C.CYAN))
        self._w("")

    def stage(self, name: str, *, current: int, total: int) -> StageProgress:
        """Start a new stage. Closes any in-progress stage as success."""
        if self.current and self.current.status == "running":
            self.finish_stage("success")
        self._w("")
        bar = "═" * 25
        title = f" STAGE {current}/{total}: {name} "
        self._w(self._color(f"{bar}{title}{bar}", _C.BLUE + _C.BOLD))
        sp = StageProgress(name=name, index=current, total=total)
        self.stages.append(sp)
        self.current = sp
        return sp

    def step(self, msg: str, *, substep: Optional[str] = None) -> None:
        """A neutral 'now doing X' line."""
        prefix = self._color(f"[{substep}] ", _C.DIM) if substep else "  "
        self._w(f"{prefix}{msg}")

    def found(self, msg: str, *, severity: str = "info") -> None:
        """A positive finding."""
        color_map = {
            "critical": _C.RED + _C.BOLD,
            "high": _C.RED,
            "medium": _C.YELLOW,
            "low": _C.GREEN,
            "info": _C.GREEN,
        }
        color = color_map.get(severity, _C.GREEN)
        check = self._color("    ✓", color)
        self._w(f"{check} {msg}")
        if self.current:
            self.current.findings.append(f"[{severity}] {msg}")

    def warn(self, msg: str) -> None:
        self._w(self._color(f"    ! {msg}", _C.YELLOW))

    def fail(self, msg: str) -> None:
        self._w(self._color(f"    ✗ {msg}", _C.RED))

    def info(self, msg: str) -> None:
        self._w(self._color(f"    · {msg}", _C.DIM))

    def gate(self, what: str, *, required_flag: str) -> None:
        """Loud message when an approval-gated action is skipped by default."""
        self._w("")
        self._w(self._color(f"    [GATED] {what}", _C.MAGENTA + _C.BOLD))
        self._w(self._color(
            f"             Skipped because {required_flag} is not set.",
            _C.DIM,
        ))
        self._w(self._color(
            f"             Add {required_flag} to opt in.", _C.DIM,
        ))

    def finish_stage(self, status: str = "success") -> None:
        if self.current is None:
            return
        self.current.status = status
        self.current.finished_at = time.time()
        elapsed = self.current.elapsed_s
        color = {"success": _C.GREEN, "failed": _C.RED, "skipped": _C.YELLOW}.get(
            status, _C.DIM,
        )
        self._w("")
        self._w(self._color(
            f"  -> stage {self.current.index}/{self.current.total} "
            f"{self.current.name}: {status} ({elapsed:.1f}s, "
            f"{len(self.current.findings)} findings)",
            color,
        ))
        self.current = None

    def summary(self, **kw) -> None:
        """Final summary block. Accepts arbitrary key=value pairs."""
        if self.current and self.current.status == "running":
            self.finish_stage("success")
        bar = "═" * 60
        elapsed = time.time() - self.t0
        self._w("")
        self._w(self._color(bar, _C.CYAN))
        self._w(self._color("  SUMMARY", _C.BOLD))
        self._w(self._color(bar, _C.CYAN))
        # Default keys we always show
        defaults = {
            "total_time": f"{elapsed/60:.1f} minutes",
            "stages_completed": sum(1 for s in self.stages if s.status == "success"),
            "stages_failed": sum(1 for s in self.stages if s.status == "failed"),
            "total_findings": sum(len(s.findings) for s in self.stages),
        }
        for k, v in defaults.items():
            self._w(f"  {k.replace('_', ' ').capitalize():<25}: {v}")
        # Per-stage finding counts
        self._w("")
        self._w(self._color("  Per-stage findings:", _C.BOLD))
        for s in self.stages:
            tick = {
                "success": self._color("✓", _C.GREEN),
                "failed":  self._color("✗", _C.RED),
                "skipped": self._color("○", _C.YELLOW),
            }.get(s.status, "·")
            self._w(f"    {tick} {s.name:<24} {len(s.findings):>3} findings   {s.elapsed_s:>5.1f}s")
        # User-supplied extras
        if kw:
            self._w("")
            self._w(self._color("  Output:", _C.BOLD))
            for k, v in kw.items():
                self._w(f"    {k.replace('_', ' ').capitalize():<25}: {v}")
        self._w(self._color(bar, _C.CYAN))

    # ------------------------------------------------------------------
    # Convenience: emit one event from a finding dict
    # ------------------------------------------------------------------

    def emit_finding(self, finding: dict) -> None:
        """Take a structured finding (from finding_validator / scanners /
        agents) and narrate it appropriately."""
        title = finding.get("title") or finding.get("type") or finding.get("vuln_type")
        sev = (finding.get("severity") or "info").lower()
        url = finding.get("url") or finding.get("target") or ""
        msg = f"{title}"
        if url:
            msg += f" — {url}"
        self.found(msg, severity=sev)

    # ------------------------------------------------------------------
    # Serializable snapshot (used by master_agent for /api integration)
    # ------------------------------------------------------------------

    def snapshot(self) -> dict:
        return {
            "started_at": self.t0,
            "elapsed_s": time.time() - self.t0,
            "stages": [
                {
                    "name": s.name,
                    "index": s.index,
                    "total": s.total,
                    "status": s.status,
                    "elapsed_s": s.elapsed_s,
                    "finding_count": len(s.findings),
                    "findings": s.findings,
                }
                for s in self.stages
            ],
        }
