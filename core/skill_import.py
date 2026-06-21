"""Absorb external Agent-Skills (SKILL.md) into VIPER's lazy skill catalog.

Point this at a local clone of an Agent-Skills-format library (YAML frontmatter +
``## Workflow`` / ``## Verification`` markdown) and it normalizes every SKILL.md
into a catalog entry — carrying the procedure AND the tools its workflow invokes,
so VIPER both *knows the procedure* and *learns which tools to use, and how*.

Nothing third-party is vendored into the repo: import writes a local, gitignored
JSON index (``data/imported_skills.json``) that ``build_registry`` loads on
startup. Run ``viper.py skills import <dir>`` to absorb a clone.

Frontmatter is parsed without a YAML dependency (handles scalars, folded
continuations, and ``- item`` lists — the Agent-Skills shape).
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Dict, List, Optional, Tuple

_ROOT = Path(__file__).resolve().parents[1]
IMPORTED_JSON = _ROOT / "data" / "imported_skills.json"

_FM = re.compile(r"^---\s*\n(.*?)\n---\s*\n?(.*)$", re.S)
_SECTION = re.compile(r"^##\s+(.+?)\s*$", re.M)
_CODE_BLOCK = re.compile(r"```(?:bash|sh|shell|console|text)?\s*\n(.*?)```", re.S)
_TID = re.compile(r"^T\d{3,4}(?:\.\d{3})?$")

# Shell builtins / coreutils that are NOT "security tools" worth indexing.
_NOT_TOOLS = {
    "cd", "echo", "for", "in", "do", "done", "while", "if", "then", "fi", "else",
    "elif", "case", "esac", "cat", "ls", "cp", "mv", "rm", "mkdir", "rmdir",
    "export", "set", "unset", "source", "exit", "return", "sleep", "grep", "egrep",
    "awk", "sed", "cut", "head", "tail", "sort", "uniq", "wc", "tr", "tee", "read",
    "printf", "true", "false", "test", "chmod", "chown", "touch", "find", "xargs",
    "kill", "ps", "df", "du", "wget", "tar", "gzip", "gunzip", "unzip", "git",
    "pip", "pip3", "apt", "apt-get", "brew", "yum", "dnf", "go", "npm", "make",
    "cmake", "gcc", "g++", "sudo", "env", "bash", "sh", "zsh", "function", "local",
}


def _parse_frontmatter(fm_text: str) -> Dict[str, object]:
    data: Dict[str, object] = {}
    key: Optional[str] = None
    for raw in fm_text.splitlines():
        if not raw.strip():
            continue
        if raw.lstrip().startswith("- ") and key is not None:
            data.setdefault(key, [])
            if isinstance(data[key], list):
                data[key].append(raw.strip()[2:].strip().strip("'\""))
            continue
        if raw[0] not in " \t" and ":" in raw:
            k, _, v = raw.partition(":")
            key = k.strip()
            v = v.strip()
            data[key] = v.strip("'\"") if v else []
        elif raw[0] in " \t" and key is not None and isinstance(data.get(key), str):
            data[key] = (str(data[key]) + " " + raw.strip()).strip()
    # keys that opened a list ([]) but never got items -> drop to empty string
    return data


def _split_sections(body: str) -> Dict[str, str]:
    out: Dict[str, str] = {}
    parts = _SECTION.split(body)
    # parts: [pre, header1, content1, header2, content2, ...]
    for i in range(1, len(parts), 2):
        out[parts[i].strip().lower()] = parts[i + 1].strip()
    return out


def extract_tools(body: str) -> List[str]:
    """Tool names invoked in the workflow's code blocks (e.g. nmap, volatility3)."""
    tools: set = set()
    for block in _CODE_BLOCK.findall(body):
        for line in block.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            toks = line.split()
            first = toks[0]
            # peel a leading sudo / env VAR=val
            while first in ("sudo", "env") and len(toks) > 1:
                toks = toks[1:]
                first = toks[0]
            first = first.strip("`$();|&<>\"'")
            # python -m <tool> -> take the module
            if first in ("python", "python3") and "-m" in toks:
                mi = toks.index("-m")
                if mi + 1 < len(toks):
                    first = toks[mi + 1].split(".")[0]
            if re.fullmatch(r"[a-z][a-z0-9_.\-]{1,30}", first) and first not in _NOT_TOOLS:
                tools.add(first)
    return sorted(tools)


def _techniques(name: str, tags: List[str], subdomain: str) -> List[str]:
    toks = set(re.findall(r"[a-z0-9]+", (name + " " + subdomain).lower()))
    toks.update(t.lower() for t in tags)
    # drop noise words
    toks -= {"with", "and", "the", "for", "a", "an", "of", "to", "using", "via"}
    return sorted(toks)


def _phases(subdomain: str, tags: List[str]) -> List[str]:
    s = (subdomain + " " + " ".join(tags)).lower()
    if any(w in s for w in ("forensic", "incident", "malware", "threat-hunt",
                            "detection", "response", "dfir")):
        return ["post_exploitation", "reconnaissance"]
    if any(w in s for w in ("recon", "osint", "enumeration", "discovery")):
        return ["reconnaissance"]
    if any(w in s for w in ("privilege", "lateral", "persistence", "post-exploit")):
        return ["post_exploitation"]
    return ["exploitation"]


def skill_md_to_entry(text: str) -> Optional[dict]:
    """Normalize one SKILL.md into an import_external entry (or None if invalid)."""
    m = _FM.match(text.lstrip("﻿"))
    if not m:
        return None
    meta = _parse_frontmatter(m.group(1))
    body = m.group(2).strip()
    name = str(meta.get("name") or "").strip()
    if not name:
        return None
    tags = [str(t) for t in (meta.get("tags") or []) if isinstance(meta.get("tags"), list)]
    subdomain = str(meta.get("subdomain") or meta.get("domain") or "")
    attack = [str(t) for t in (meta.get("mitre_attack") or []) if _TID.match(str(t))]
    tools = extract_tools(body)
    return {
        "id": name,
        "name": name.replace("-", " ").title(),
        "summary": str(meta.get("description") or "")[:160],
        "body": body,
        "techniques": _techniques(name, tags, subdomain),
        "tags": sorted(set(tags) | {subdomain.lower()} | set(tools)) if subdomain
                else sorted(set(tags) | set(tools)),
        "phases": _phases(subdomain, tags),
        "severity": "info",
        "attack": attack,
        "tools": tools,
    }


def parse_skill_directory(root: str) -> List[dict]:
    """Walk `root` for SKILL.md files; return normalized entries."""
    entries: List[dict] = []
    for p in Path(root).rglob("SKILL.md"):
        try:
            e = skill_md_to_entry(p.read_text(encoding="utf-8"))
            if e:
                entries.append(e)
        except Exception:
            continue
    return entries


def import_skill_directory(root: str, *, out: Optional[Path] = None) -> Tuple[int, int]:
    """Absorb a SKILL.md library into the local catalog index.

    Returns (skills_imported, distinct_tools_learned). Writes a gitignored JSON
    index that build_registry() loads, so absorption persists across runs without
    vendoring the source files.
    """
    out = out or IMPORTED_JSON
    entries = parse_skill_directory(root)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(entries, indent=1), encoding="utf-8")
    tools = {t for e in entries for t in e.get("tools", [])}
    return len(entries), len(tools)


def load_imported_entries(path: Optional[Path] = None) -> List[dict]:
    path = path or IMPORTED_JSON
    if not path.exists():
        return []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return data if isinstance(data, list) else []
    except Exception:
        return []
