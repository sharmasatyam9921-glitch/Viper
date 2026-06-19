"""Lazy skill registry + catalog: selection, flat token cost, ingestion."""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.skill_catalog import (  # noqa: E402
    build_registry,
    default_registry,
    import_external,
    mitre_available,
)
from core.skill_registry import Skill, SkillRegistry  # noqa: E402


def test_catalog_indexes_thousands_of_skills():
    reg = default_registry()
    st = reg.stats()
    # 13 curated prompts + ~969 CWE + ~559/615 CAPEC from the vendored DB.
    assert st["total"] >= 1000
    assert st["by_source"]["prompt"] >= 10
    if mitre_available():
        assert st["by_source"]["cwe"] >= 900
        assert st["by_source"]["capec"] >= 500


def test_bodies_are_lazy_until_selected():
    reg = default_registry()
    s = reg.get("cwe:79")
    assert s is not None
    assert s._body_cache is None            # not formatted at index time
    body = s.body()
    assert "CWE-79" in body and s._body_cache is not None   # loaded + cached now


def test_web_idor_intent_surfaces_the_api_playbook_first():
    reg = default_registry()
    sel = reg.select(technique="idor", phase="exploitation",
                     intent="web idor bola authorization", limit=5)
    assert sel and sel[0].id == "prompt:api_security"


def test_token_cost_is_flat_as_catalog_grows():
    # Selecting + rendering the same intent must stay bounded no matter how many
    # more skills are indexed — the core "no context pollution" property.
    base = build_registry()
    small = base.render(base.select(technique="sqli", limit=3), max_chars=1500)
    big = build_registry()
    big.add_many(Skill(id=f"junk:{i}", name=f"junk {i}", source="external",
                       tags=("junk",)) for i in range(5000))
    assert len(big) >= len(base) + 5000
    sel_big = big.select(technique="sqli", limit=3)
    assert len(sel_big) <= 3
    rendered = big.render(sel_big, max_chars=1500)
    assert len(rendered) <= 1500            # hard cap honored
    # the SQLi playbook is selected regardless of catalog size
    assert any(s.id == "prompt:sql_injection" for s in sel_big)


def test_render_hard_caps_length():
    reg = default_registry()
    sel = reg.select(intent="injection", limit=8)
    assert len(reg.render(sel, max_chars=500)) <= 500


def test_search_prefers_curated_playbook():
    reg = default_registry()
    hits = reg.search("sql injection", limit=5)
    assert hits and hits[0].id == "prompt:sql_injection"


def test_search_by_cwe_number():
    reg = default_registry()
    ids = [s.id for s in reg.search("CWE-89", limit=5)]
    assert "cwe:89" in ids or any(s == "prompt:sql_injection" for s in ids)


def test_select_returns_nothing_for_unmatched():
    reg = SkillRegistry()
    reg.add(Skill(id="prompt:x", name="X", source="prompt", techniques=("x",),
                  tags=("x",)))
    assert reg.select(technique="totally_unrelated_zzz") == []


def test_cwe_number_in_intent_matches_cwe_not_substring_capec():
    # GATE: select(intent='89') must surface CWE-89 / the SQLi playbook, NOT a
    # CAPEC whose number merely contains '89' (e.g. capec:189).
    reg = default_registry()
    ids = [s.id for s in reg.select(intent="89", limit=5)]
    # the curated SQLi playbook (cwe=89) leads; CWE-89 itself is selected. Before
    # the fix, an intent of "89" matched neither (cwe scoring was gated on the
    # explicit cwe= param) and substring-noise CAPECs dominated.
    assert set(ids[:2]) == {"cwe:89", "prompt:sql_injection"}


def test_short_technique_does_not_substring_match_everything():
    # GATE: a 1-char technique must NOT substring-match "sql_injection" etc.
    reg = default_registry()
    assert reg.select(technique="i") == []          # no phase/intent -> no matches


def test_phase_only_match_does_not_earn_prompt_bonus():
    reg = SkillRegistry()
    reg.add(Skill(id="prompt:p", name="P", source="prompt", phases=("exploitation",),
                  tags=("p",)))
    reg.add(Skill(id="cwe:1", name="real", source="cwe", phases=("exploitation",),
                  techniques=(), tags=("xyz",)))
    # technique hits the CWE's content; the prompt only matches on phase -> CWE wins
    sel = reg.select(technique="xyz", phase="exploitation", limit=2)
    assert sel[0].id == "cwe:1"


def test_render_never_exceeds_max_chars_for_any_cap():
    reg = default_registry()
    sel = reg.select(intent="injection sql xss", limit=8)
    for cap in (10, 50, 100, 500, 1500):
        assert len(reg.render(sel, max_chars=cap)) <= cap


def test_select_limit_zero_or_negative_returns_empty():
    reg = default_registry()
    assert reg.select(technique="sqli", limit=0) == []
    assert reg.select(technique="sqli", limit=-3) == []


def test_external_import_is_lazy_and_namespaced():
    reg = SkillRegistry()
    n = import_external(reg, [
        {"id": "wstg-athz-01", "name": "Testing for Bypassing Authorization",
         "body": "1. capture request as low-priv user ...",
         "techniques": ["idor", "bola"], "tags": ["authz", "idor"],
         "cwe": ["639"], "phases": ["exploitation"], "severity": "high"},
        {"name": "no id -> skipped"},
    ])
    assert n == 1
    s = reg.get("external:wstg-athz-01")
    assert s is not None and s.cwe == ("639",)
    assert "capture request" in s.body()
    # it now competes in selection like any other skill
    assert reg.select(technique="idor")[0].id == "external:wstg-athz-01"


def test_skill_to_dict_and_contains():
    reg = default_registry()
    assert "prompt:sql_injection" in reg
    d = reg.get("prompt:sql_injection").to_dict()
    assert d["id"] == "prompt:sql_injection" and d["source"] == "prompt"
    assert "89" in d["cwe"]


def test_body_loader_exception_returns_empty():
    def boom():
        raise RuntimeError("nope")
    s = Skill(id="x:1", name="X", source="external", _loader=boom)
    assert s.body() == ""            # swallowed, cached as ""
    assert s._body_cache == ""


def test_render_truncates_oversized_body():
    reg = SkillRegistry()
    reg.add(Skill(id="x:big", name="Big", source="external", techniques=("big",),
                  tags=("big",), _loader=lambda: "Z" * 500))
    out = reg.render(reg.select(technique="big"), max_chars=200)
    assert len(out) <= 200 and "[truncated]" in out


def test_select_and_render_convenience():
    reg = default_registry()
    out = reg.select_and_render(technique="sqli", limit=2, max_chars=900)
    assert isinstance(out, str) and len(out) <= 900


def test_capec_body_loads_lazily():
    reg = default_registry()
    if not mitre_available():
        return
    cap = next((s for s in reg.all() if s.source == "capec"), None)
    assert cap is not None and cap._body_cache is None
    assert cap.id.upper().replace("CAPEC:", "CAPEC-") in cap.body().upper()


def test_capec_skill_carries_attack_technique_ids():
    reg = default_registry()
    if not mitre_available():
        return
    # at least some CAPEC entries resolve to ATT&CK T-IDs
    with_attack = [s for s in reg.all()
                   if s.source == "capec" and s.attack]
    assert with_attack, "expected some CAPEC->ATT&CK technique links"
    assert all(t.startswith("T") for s in with_attack for t in s.attack)
