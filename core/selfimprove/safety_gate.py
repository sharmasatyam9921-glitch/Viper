"""Safety gate: the ingestion boundary that blocks weaponization.

VIPER is an authorized bug-bounty / pentest tool. Knowledge that flows into the
learning/ingestion layer (evograph, knowledge base, skill prompts) must stay
DETECTION-GRADE: the read-only, non-destructive proof-of-concept payloads a
bug-bounty hunter uses to CONFIRM a vulnerability — exactly what appears in
disclosed HackerOne reports.

This module is a hard boundary. It REJECTS text carrying weaponization
signatures (reverse/bind shells, persistence, C2/beacon, destructive commands,
ransomware/wipers, cryptominers, mass credential exfil) and ALLOWS the benign
detection-grade PoCs used to prove a finding.

Public API:
    classify_payload(text: str) -> dict   {"allowed": bool, "reason": str, "category": str}
    is_allowed(text: str) -> bool

The classifier is conservative by design: when a weaponization signature
matches, the text is rejected even if it also contains benign markers. A
detection PoC never needs a reverse shell next to it.
"""

from __future__ import annotations

import re
from typing import Dict, List, Pattern, Tuple

__all__ = ["classify_payload", "is_allowed", "WEAPONIZATION_SIGNATURES"]

# Category constants -----------------------------------------------------------

CAT_CLEAN = "clean"
CAT_SHELL = "reverse_bind_shell"
CAT_PERSISTENCE = "persistence"
CAT_C2 = "c2_beacon"
CAT_DESTRUCTIVE = "destructive"
CAT_RANSOMWARE = "ransomware_wiper"
CAT_MINER = "cryptominer"
CAT_EXFIL = "mass_credential_exfil"

# Weaponization signatures -----------------------------------------------------
#
# Each entry is (category, compiled regex). All patterns are matched
# case-insensitively against the raw text. Patterns are intentionally specific
# so that benign detection markers (e.g. ";id", "${7*7}") do not trip them.

_RAW_SIGNATURES: List[Tuple[str, str]] = [
    # --- Reverse / bind shells -------------------------------------------------
    # bash interactive reverse shell + /dev/tcp redirection
    (CAT_SHELL, r"bash\s+-i\b"),
    (CAT_SHELL, r"/dev/(?:tcp|udp)/"),
    # netcat / ncat exec-style shells
    (CAT_SHELL, r"\bn(?:c|cat)\b[^\n]*\s-[a-z]*e\b"),
    (CAT_SHELL, r"\bn(?:c|cat)\b[^\n]*\s-[a-z]*c\b"),
    # mkfifo named-pipe shell pattern
    (CAT_SHELL, r"\bmkfifo\b"),
    # socket+exec style reverse shells (python/perl/ruby/php one-liners)
    (CAT_SHELL, r"socket\.socket\([^\n]*\)[\s\S]{0,200}?(?:exec|/bin/sh|/bin/bash|pty\.spawn)"),
    (CAT_SHELL, r"(?:os\.dup2|subprocess\.(?:call|Popen))[\s\S]{0,200}?(?:/bin/sh|/bin/bash)"),
    (CAT_SHELL, r"pty\.spawn\("),
    (CAT_SHELL, r"fsockopen\([\s\S]{0,120}?\)"),
    (CAT_SHELL, r"\bIO\.popen\b"),
    # PowerShell encoded / download-and-run payloads
    (CAT_SHELL, r"powershell[^\n]*\s-e(?:nc|ncodedcommand)?\b\s*[A-Za-z0-9+/=]{16,}"),
    (CAT_SHELL, r"(?:downloadstring|downloadfile)\s*\("),
    (CAT_SHELL, r"new-object\s+(?:system\.)?net\.(?:webclient|sockets\.tcpclient)"),
    (CAT_SHELL, r"invoke-expression|\biex\b\s*\("),
    # generic remote fetch piped straight into a shell
    (CAT_SHELL, r"(?:curl|wget)\s+[^\n|]*\|\s*(?:ba)?sh\b"),

    # --- Persistence -----------------------------------------------------------
    (CAT_PERSISTENCE, r"\bcrontab\s+-"),
    (CAT_PERSISTENCE, r"/etc/cron\.(?:d|daily|hourly|weekly|monthly)\b"),
    (CAT_PERSISTENCE, r"systemctl\s+(?:enable|start)\b"),
    (CAT_PERSISTENCE, r"/etc/systemd/system/"),
    (CAT_PERSISTENCE, r"\.ssh/authorized_keys"),
    (CAT_PERSISTENCE, r"reg\s+add\b[^\n]*\\(?:run|runonce)\b"),
    (CAT_PERSISTENCE, r"currentversion\\(?:run|runonce)\b"),
    (CAT_PERSISTENCE, r"\bschtasks\b[^\n]*/create\b"),
    (CAT_PERSISTENCE, r"(?:hklm|hkcu)\\[^\n]*\\run\b"),
    (CAT_PERSISTENCE, r"\\start menu\\programs\\startup\\"),
    (CAT_PERSISTENCE, r"launchctl\s+load\b"),

    # --- C2 / beacon -----------------------------------------------------------
    (CAT_C2, r"\bcobalt\s*strike\b|\bbeacon\.(?:dll|exe|bin|x64)\b"),
    (CAT_C2, r"\bmeterpreter\b"),
    (CAT_C2, r"\bmsfvenom\b"),
    (CAT_C2, r"\b(?:empire|covenant|sliver|mythic)\b[^\n]*(?:agent|implant|stager|beacon)"),
    (CAT_C2, r"\b(?:c2|command[\s-]?and[\s-]?control)\b[^\n]*(?:beacon|callback|implant)"),
    (CAT_C2, r"\bstager\b[^\n]*\b(?:payload|listener)\b"),
    (CAT_C2, r"\breverse_(?:tcp|https?)\b"),

    # --- Destructive commands --------------------------------------------------
    (CAT_DESTRUCTIVE, r"\brm\s+-[a-z]*r[a-z]*f?[a-z]*\s+(?:/|--no-preserve-root|~|\*)"),
    (CAT_DESTRUCTIVE, r"\brm\s+-[a-z]*f[a-z]*r[a-z]*\s+(?:/|~|\*)"),
    (CAT_DESTRUCTIVE, r"--no-preserve-root"),
    (CAT_DESTRUCTIVE, r"\bdrop\s+(?:table|database)\b"),
    (CAT_DESTRUCTIVE, r"\btruncate\s+table\b"),
    (CAT_DESTRUCTIVE, r"\bdelete\s+from\b[^\n]*?(?:;|--)\s*$"),
    (CAT_DESTRUCTIVE, r"\bmkfs(?:\.\w+)?\b"),
    (CAT_DESTRUCTIVE, r"\bdd\s+if=/dev/(?:zero|random|urandom)\s+of=/dev/"),
    (CAT_DESTRUCTIVE, r">\s*/dev/sd[a-z]\b"),
    (CAT_DESTRUCTIVE, r"\bformat\s+[a-z]:"),
    (CAT_DESTRUCTIVE, r"\bdel\s+/[a-z]\s+/[a-z]\b|\bdel\s+/[fqs]"),
    (CAT_DESTRUCTIVE, r"rmdir\s+/s\b"),
    # classic fork bomb :(){ :|:& };:
    (CAT_DESTRUCTIVE, r":\s*\(\s*\)\s*\{\s*:\s*\|\s*:&?\s*\}"),
    (CAT_DESTRUCTIVE, r"\bshutdown\s+(?:/s|/r|-h|-r)\b"),
    (CAT_DESTRUCTIVE, r"\bwevtutil\s+cl\b"),

    # --- Ransomware / wiper ----------------------------------------------------
    (CAT_RANSOMWARE, r"\bransom(?:ware|note)?\b"),
    (CAT_RANSOMWARE, r"\bvssadmin\b[^\n]*\bdelete\s+shadows\b"),
    (CAT_RANSOMWARE, r"\bcipher\s+/w:"),
    (CAT_RANSOMWARE, r"encrypt[\s\S]{0,80}?(?:all\s+files|every\s+file|\.(?:locked|crypt|enc)\b)"),
    (CAT_RANSOMWARE, r"\bbcdedit\b[^\n]*recoveryenabled\s+no\b"),
    (CAT_RANSOMWARE, r"\bwbadmin\b[^\n]*delete\b"),
    (CAT_RANSOMWARE, r"your\s+files\s+have\s+been\s+encrypted"),

    # --- Cryptominer -----------------------------------------------------------
    (CAT_MINER, r"\bxmrig\b"),
    (CAT_MINER, r"stratum\+(?:tcp|ssl|tls)://"),
    (CAT_MINER, r"\b(?:minerd|cgminer|cpuminer|ethminer|nbminer|phoenixminer)\b"),
    (CAT_MINER, r"--donate-level\b"),
    (CAT_MINER, r"\bmonero\b[^\n]*(?:wallet|pool|mine)"),

    # --- Mass credential exfiltration -----------------------------------------
    (CAT_EXFIL, r"\b(?:cat|type|copy)\b[^\n]*/etc/shadow\b"),
    (CAT_EXFIL, r"\bmimikatz\b|sekurlsa::logonpasswords"),
    (CAT_EXFIL, r"\blsass\.(?:dmp|exe)\b|procdump[^\n]*lsass"),
    (CAT_EXFIL, r"reg\s+save\b[^\n]*\b(?:sam|security|system)\b"),
    (CAT_EXFIL, r"\bntds\.dit\b"),
    (CAT_EXFIL, r"dump[\s\S]{0,40}?(?:all\s+)?(?:passwords|credentials|hashes)\b"),
    (CAT_EXFIL, r"(?:tar|zip)\b[^\n]*(?:\.aws|\.ssh|\.gnupg|/etc/passwd)[\s\S]{0,80}?(?:curl|wget|nc)\b"),
    (CAT_EXFIL, r"(?:cat|grep)\b[^\n]*(?:id_rsa|\.aws/credentials|\.env)[\s\S]{0,80}?(?:curl|wget|nc|>\s*/dev/tcp)"),
]

WEAPONIZATION_SIGNATURES: List[Tuple[str, Pattern[str]]] = [
    (category, re.compile(pattern, re.IGNORECASE)) for category, pattern in _RAW_SIGNATURES
]

# Human-readable category descriptions for the rejection reason.
_CATEGORY_REASON: Dict[str, str] = {
    CAT_SHELL: "reverse/bind shell signature (remote interactive shell)",
    CAT_PERSISTENCE: "persistence mechanism (autostart/cron/registry/ssh keys)",
    CAT_C2: "command-and-control / beacon signature",
    CAT_DESTRUCTIVE: "destructive command (data/disk/process destruction)",
    CAT_RANSOMWARE: "ransomware/wiper signature",
    CAT_MINER: "cryptominer signature",
    CAT_EXFIL: "mass credential exfiltration signature",
}


def classify_payload(text: str) -> Dict[str, object]:
    """Classify a piece of candidate knowledge for ingestion.

    Returns a dict ``{"allowed": bool, "reason": str, "category": str}``.

    ``allowed`` is ``False`` only when a weaponization signature matches; in
    that case ``category`` names the matched class and ``reason`` explains the
    block. Detection-grade PoCs and ordinary text return ``allowed=True`` with
    ``category="clean"``.
    """
    if not isinstance(text, str):
        # Non-string input is never valid knowledge; fail closed but explain.
        return {
            "allowed": False,
            "reason": "input is not text",
            "category": CAT_CLEAN,
        }

    if not text.strip():
        # Empty / whitespace-only text carries no weaponization; allow it.
        return {"allowed": True, "reason": "empty input", "category": CAT_CLEAN}

    for category, pattern in WEAPONIZATION_SIGNATURES:
        match = pattern.search(text)
        if match:
            snippet = match.group(0).strip()
            if len(snippet) > 60:
                snippet = snippet[:57] + "..."
            reason = _CATEGORY_REASON.get(category, "weaponization signature")
            return {
                "allowed": False,
                "reason": f"blocked: {reason} (matched {snippet!r})",
                "category": category,
            }

    return {
        "allowed": True,
        "reason": "detection-grade content; no weaponization signature",
        "category": CAT_CLEAN,
    }


def is_allowed(text: str) -> bool:
    """Return ``True`` if ``text`` may be ingested/learned, ``False`` otherwise."""
    return bool(classify_payload(text)["allowed"])
