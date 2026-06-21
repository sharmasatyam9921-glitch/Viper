"""Absorbing external Agent-Skills (SKILL.md) into the catalog + tool learning."""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.skill_import import (  # noqa: E402
    extract_tools,
    import_skill_directory,
    load_imported_entries,
    parse_skill_directory,
    skill_md_to_entry,
)
from core.skill_registry import SkillRegistry  # noqa: E402
from core.skill_catalog import import_external, tool_index  # noqa: E402

_FIXTURE = """---
name: testing-for-sql-injection
description: Detect and exploit SQL injection in web parameters using sqlmap and
  manual payloads to confirm database access.
domain: cybersecurity
subdomain: web-application-security
tags:
- sqli
- injection
- web
version: '1.0'
author: tester
license: Apache-2.0
mitre_attack:
- T1190
- T1059
---

## When to Use
When a web parameter reflects database errors.

## Workflow
```bash
# enumerate first
sqlmap -u "http://t/?id=1" --batch --dbs
sudo nuclei -u http://t -t sqli/
python3 -m arjun -u http://t
```

## Verification
Confirm a database name is returned.
"""


def test_parse_frontmatter_and_sections():
    e = skill_md_to_entry(_FIXTURE)
    assert e["id"] == "testing-for-sql-injection"
    assert e["name"] == "Testing For Sql Injection"
    assert "SQL injection" in e["summary"]            # folded description joined
    assert "Workflow" in e["body"] and "Verification" in e["body"]
    assert e["attack"] == ["T1190", "T1059"]
    assert "sqli" in e["tags"] and "web-application-security" in e["tags"]


def test_extract_tools_from_workflow():
    e = skill_md_to_entry(_FIXTURE)
    # sqlmap + nuclei (sudo peeled) + arjun (python -m) ; shell builtins excluded
    assert set(e["tools"]) == {"sqlmap", "nuclei", "arjun"}


def test_extract_tools_handles_plain_block():
    tools = extract_tools("```\nnmap -sV t\necho hi\ngobuster dir -u t\n```")
    assert tools == ["gobuster", "nmap"]              # echo dropped


def test_malformed_skill_returns_none():
    assert skill_md_to_entry("no frontmatter here") is None
    assert skill_md_to_entry("---\ndescription: x\n---\nbody") is None   # no name


def test_directory_import_round_trip(tmp_path):
    d = tmp_path / "skills" / "testing-for-sql-injection"
    d.mkdir(parents=True)
    (d / "SKILL.md").write_text(_FIXTURE, encoding="utf-8")
    (tmp_path / "skills" / "notaskill").mkdir()
    (tmp_path / "skills" / "notaskill" / "README.md").write_text("ignore me")

    out = tmp_path / "imported.json"
    n, ntools = import_skill_directory(str(tmp_path), out=out)
    assert n == 1 and ntools == 3
    entries = load_imported_entries(out)
    assert entries[0]["id"] == "testing-for-sql-injection"


def test_imported_skill_is_selectable_and_tool_indexed():
    reg = SkillRegistry()
    import_external(reg, [skill_md_to_entry(_FIXTURE)])
    # selectable by an absorbed technique/tag
    sel = reg.select(intent="sql injection web", limit=3)
    assert sel and sel[0].id == "external:testing-for-sql-injection"
    assert "sqlmap" in sel[0].tools
    # tool index maps a learned tool -> the skill that uses it
    idx = tool_index(reg)
    assert "external:testing-for-sql-injection" in idx["sqlmap"]


def test_parse_directory_skips_unreadable(tmp_path):
    (tmp_path / "SKILL.md").write_text(_FIXTURE, encoding="utf-8")
    assert len(parse_skill_directory(str(tmp_path))) == 1
