"""LinPEAS runner — download, deploy, execute, parse.

LinPEAS is a Linux privesc enumeration script (carlospolop/PEASS-ng).
This module:
  1. Downloads the latest linpeas.sh to a local cache (one-time)
  2. Deploys it to a target via SSH/SCP, HTTP serve, or local file copy
  3. Executes it on the target
  4. Parses the colored output into structured findings ranked by severity
  5. Cross-references findings with gtfobins_db / kernel_exploits_db

No third-party deps — stdlib only (urllib, asyncio, subprocess).
SSH transport requires `ssh` + `scp` binaries on PATH.

Approval gating: deployment + execution leave a binary on the target.
This is read-only enumeration but logged. Caller decides whether to gate.
"""

from __future__ import annotations

import asyncio
import logging
import os
import re
import shutil
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

logger = logging.getLogger("viper.linpeas")

LINPEAS_URL = "https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh"
DEFAULT_CACHE = Path.home() / ".cache" / "viper" / "linpeas.sh"

# ANSI escape stripper
_ANSI_RE = re.compile(r"\x1b\[[0-9;]*[a-zA-Z]")
# linpeas color hints — red = high (95-99% PE), yellow = interesting
_RED = re.compile(r"\x1b\[1;31m|\x1b\[31;1m|\x1b\[91m")
_YELLOW = re.compile(r"\x1b\[1;33m|\x1b\[33;1m|\x1b\[93m")
_GREEN = re.compile(r"\x1b\[1;32m|\x1b\[32;1m|\x1b\[92m")


# ---------------------------------------------------------------------------
# Result types
# ---------------------------------------------------------------------------


@dataclass
class LinpeasFinding:
    section: str
    line: str  # ANSI-stripped
    severity: str  # "high" / "medium" / "low" / "info"
    raw_color: Optional[str] = None  # "red" / "yellow" / "green"


@dataclass
class LinpeasReport:
    target: str = ""
    findings: list[LinpeasFinding] = field(default_factory=list)
    sections_seen: list[str] = field(default_factory=list)
    output_lines: int = 0
    error: Optional[str] = None
    cross_refs: dict = field(default_factory=dict)  # gtfobins / kernel correlations

    @property
    def high(self) -> list[LinpeasFinding]:
        return [f for f in self.findings if f.severity == "high"]

    @property
    def medium(self) -> list[LinpeasFinding]:
        return [f for f in self.findings if f.severity == "medium"]


# ---------------------------------------------------------------------------
# Section detection — linpeas uses these section markers
# ---------------------------------------------------------------------------

# Each entry is a substring linpeas prints when entering a section.
# Used to classify findings by area.
LINPEAS_SECTIONS: list[tuple[str, str]] = [
    # marker substring                          friendly section name
    ("Operative system",                        "OS Info"),
    ("Sudo version",                            "Sudo Version"),
    ("CVEs Check",                              "Kernel CVEs"),
    ("Searching Important Linux Files",         "Important Files"),
    ("Sudo permissions",                        "Sudo Privesc"),
    ("Sudo tokens",                             "Sudo Tokens"),
    ("LD_PRELOAD",                              "LD_PRELOAD env_keep"),
    ("Capabilities",                            "Linux Capabilities"),
    ("SUID - Check easy privesc",               "SUID Files"),
    ("SGID",                                    "SGID Files"),
    ("Files with ACLs",                         "POSIX ACLs"),
    ("NFS exports",                             "NFS Exports"),
    ("Cron jobs",                               "Cron Jobs"),
    ("Systemd",                                 "Systemd Services"),
    ("Init",                                    "Init Scripts"),
    ("PATH",                                    "PATH Hijack"),
    ("Searching ssl/ssh files",                 "SSH/SSL Keys"),
    ("Sudo group",                              "Sudo Group"),
    ("Docker",                                  "Docker"),
    ("LXC",                                     "LXC/LXD"),
    ("Kerberos",                                "Kerberos"),
    ("Searching passwords",                     "Password Files"),
    ("Bash history",                            "Bash History"),
    ("Mounted",                                 "Mounted FS"),
    ("Wifi creds",                              "WiFi Credentials"),
    ("Cloud",                                   "Cloud Metadata"),
    ("Containers",                              "Container Escapes"),
    ("Procs running",                           "Process List"),
]


def _classify_section(line: str, current: str) -> str:
    for marker, section_name in LINPEAS_SECTIONS:
        if marker in line:
            return section_name
    return current


def _classify_severity(raw: str) -> tuple[str, Optional[str]]:
    """Use ANSI color codes to estimate severity."""
    if _RED.search(raw):
        return "high", "red"
    if _YELLOW.search(raw):
        return "medium", "yellow"
    if _GREEN.search(raw):
        return "low", "green"
    return "info", None


# ---------------------------------------------------------------------------
# Local script management
# ---------------------------------------------------------------------------


async def ensure_local(cache_path: Path = DEFAULT_CACHE, *, force: bool = False) -> Path:
    """Download linpeas.sh to local cache if not present (or force=True)."""
    if cache_path.exists() and not force:
        return cache_path
    cache_path.parent.mkdir(parents=True, exist_ok=True)

    # Use stdlib urllib — no requests dependency
    import urllib.request

    logger.info("downloading linpeas to %s", cache_path)

    def _download():
        with urllib.request.urlopen(LINPEAS_URL, timeout=60) as r:
            data = r.read()
        cache_path.write_bytes(data)
        os.chmod(cache_path, 0o755)
        return cache_path

    return await asyncio.to_thread(_download)


# ---------------------------------------------------------------------------
# Execution transports
# ---------------------------------------------------------------------------


async def run_local(
    script_path: Optional[Path] = None,
    *,
    extra_args: tuple[str, ...] = (),
    timeout: float = 600.0,
) -> str:
    """Run linpeas on the local box (testing / WSL / standalone).

    Returns the raw colored output (ANSI preserved for parser).
    """
    script = script_path or await ensure_local()
    if not shutil.which("bash"):
        raise RuntimeError("bash not found — required to run linpeas locally")

    cmd = ["bash", str(script), *extra_args]
    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        env={**os.environ, "TERM": "xterm-256color"},  # preserve colors
    )
    out, err = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    if err and proc.returncode != 0:
        logger.warning("linpeas stderr: %s", err.decode("utf-8", errors="replace")[:500])
    return out.decode("utf-8", errors="replace")


async def run_via_ssh(
    host: str,
    user: str,
    *,
    password: Optional[str] = None,
    key_path: Optional[Path] = None,
    port: int = 22,
    script_path: Optional[Path] = None,
    extra_args: tuple[str, ...] = (),
    timeout: float = 600.0,
) -> str:
    """SCP linpeas to /tmp on target, exec it, retrieve output, clean up.

    Requires `ssh` + `scp` on PATH. Either password (via sshpass) or key auth.
    Caller is responsible for scope/approval check before calling this.
    """
    script = script_path or await ensure_local()
    remote_path = f"/tmp/.lp_{os.urandom(4).hex()}.sh"

    if not shutil.which("ssh") or not shutil.which("scp"):
        raise RuntimeError("ssh/scp not installed")

    base_args = []
    if key_path:
        base_args += ["-i", str(key_path)]
    base_args += [
        "-o", "StrictHostKeyChecking=no",
        "-o", "UserKnownHostsFile=/dev/null",
        "-o", "LogLevel=ERROR",
    ]

    # SECURITY (fix #8): use sshpass -e (reads from $SSHPASS env var)
    # instead of -p PASSWORD argv. Argv-mode passwords leak to `ps`.
    sshpass_env = None
    if password and shutil.which("sshpass"):
        sshpass_env = {**os.environ, "SSHPASS": password}

    def _wrap(cmd: list[str]) -> list[str]:
        if password and shutil.which("sshpass"):
            return ["sshpass", "-e", *cmd]
        return cmd

    # 1. Upload
    scp_cmd = _wrap(["scp", "-P", str(port), *base_args, str(script), f"{user}@{host}:{remote_path}"])
    proc = await asyncio.create_subprocess_exec(
        *scp_cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        env=sshpass_env,
    )
    _, err = await asyncio.wait_for(proc.communicate(), timeout=60.0)
    if proc.returncode != 0:
        raise RuntimeError(f"scp failed: {err.decode()[:500]}")

    # 2. Execute
    args_str = " ".join(extra_args)
    remote_cmd = (
        f"chmod +x {remote_path} && TERM=xterm-256color bash {remote_path} {args_str}; "
        f"rm -f {remote_path}"
    )
    ssh_cmd = _wrap(["ssh", "-p", str(port), *base_args, f"{user}@{host}", remote_cmd])
    proc = await asyncio.create_subprocess_exec(
        *ssh_cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        env=sshpass_env,
    )
    out, err = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    if err:
        logger.debug("ssh stderr: %s", err.decode()[:500])

    return out.decode("utf-8", errors="replace")


# ---------------------------------------------------------------------------
# Output parser
# ---------------------------------------------------------------------------


def parse(output: str, target: str = "") -> LinpeasReport:
    """Parse ANSI-colored linpeas output into ranked findings."""
    report = LinpeasReport(target=target)
    if not output:
        report.error = "empty output"
        return report

    current_section = "Header"
    sections_seen: set[str] = set()
    lines = output.splitlines()
    report.output_lines = len(lines)

    for raw in lines:
        if not raw.strip():
            continue
        # Update section
        section = _classify_section(raw, current_section)
        if section != current_section:
            current_section = section
            sections_seen.add(section)

        # Severity from color
        severity, color = _classify_severity(raw)
        # Only keep findings that are notable: red, yellow, or contain
        # known-interesting markers.
        is_interesting = (
            severity in ("high", "medium")
            or "PE]" in raw
            or "[CVE-" in raw
            or "rwx" in raw
            or "PASSWORD" in raw.upper()
            or "ssh" in raw.lower() and "id_rsa" in raw.lower()
        )
        if not is_interesting:
            continue

        clean = _ANSI_RE.sub("", raw).strip()
        if not clean or len(clean) < 5:
            continue

        report.findings.append(LinpeasFinding(
            section=current_section,
            line=clean[:500],  # cap each line
            severity=severity if severity != "info" else "low",
            raw_color=color,
        ))

    report.sections_seen = sorted(sections_seen)
    report.cross_refs = _cross_reference(report.findings, output)
    return report


def _cross_reference(findings: list[LinpeasFinding], raw_output: str = "") -> dict:
    """Run findings through gtfobins_db + kernel_exploits_db for actionability."""
    from pentest import gtfobins_db, kernel_exploits_db

    refs: dict = {"gtfobins": [], "kernel": []}

    sudo_lines = [f.line for f in findings if "Sudo" in f.section]
    suid_lines = [f.line for f in findings if "SUID" in f.section]
    cap_lines = [f.line for f in findings if "Capabilities" in f.section]
    # Kernel version can appear in OS Info banner or Kernel CVE section
    kernel_lines = [
        f.line for f in findings
        if "Kernel" in f.section or "OS" in f.section or "CVE-" in f.line
        or "Linux" in f.line
    ]

    for line in sudo_lines:
        for bin_name in re.findall(r"/[^\s]+/(\w[\w.-]*)", line):
            vectors = gtfobins_db.lookup(bin_name)
            if vectors and "sudo" in vectors:
                refs["gtfobins"].append({
                    "binary": bin_name, "context": "sudo",
                    "command": vectors["sudo"],
                })

    for line in suid_lines:
        for bin_name in re.findall(r"/[^\s]+/(\w[\w.-]*)", line):
            if bin_name in gtfobins_db.known_safe_suids():
                continue
            vectors = gtfobins_db.lookup(bin_name)
            if vectors:
                vec_key = "suid" if "suid" in vectors else next(iter(vectors))
                refs["gtfobins"].append({
                    "binary": bin_name, "context": "suid",
                    "command": vectors[vec_key],
                })

    for line in cap_lines:
        # cap entries look like: "/usr/bin/python = cap_setuid+ep"
        m = re.match(r"(/[^\s=]+)\s*=\s*(\w+\+\w+)", line)
        if m:
            refs["gtfobins"].append({
                "binary": m.group(1).rsplit("/", 1)[-1],
                "context": "capabilities",
                "capability": m.group(2),
            })

    # Kernel: look for "Linux X.Y.Z" or version markers
    kver = ""
    # First check the filtered kernel-context lines
    for line in kernel_lines:
        m = re.search(r"(\d+\.\d+\.\d+(?:[-\w]*)?)", line)
        if m:
            kver = m.group(1)
            break
    # Fall back: search raw output for "Linux X.Y.Z" pattern
    if not kver and raw_output:
        clean_raw = _ANSI_RE.sub("", raw_output)
        m = re.search(r"Linux\s+\S+\s+(\d+\.\d+\.\d+(?:[-\w]*)?)", clean_raw)
        if m:
            kver = m.group(1)
    if kver:
        for exp in kernel_exploits_db.lookup_linux(kver):
            refs["kernel"].append({
                "cve": exp.cve, "name": exp.name,
                "url": exp.exploit_url, "reliability": exp.reliability,
            })

    # Dedupe
    seen = set()
    refs["gtfobins"] = [
        x for x in refs["gtfobins"]
        if (k := f"{x['context']}:{x.get('binary')}") not in seen and not seen.add(k)
    ]
    return refs
