"""`viper.py skills` CLI + classifier/react integration of the skill catalog."""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.skill_classifier import AttackPathClassification  # noqa: E402
from core.skills_cli import run_skills_cli  # noqa: E402


def test_cli_stats(capsys):
    rc = run_skills_cli(["stats"])
    out = capsys.readouterr().out
    assert rc == 0 and "skill catalog" in out and "total indexed skills" in out


def test_cli_default_is_stats(capsys):
    rc = run_skills_cli([])
    assert rc == 0 and "total indexed skills" in capsys.readouterr().out


def test_cli_search(capsys):
    rc = run_skills_cli(["search", "sql", "injection"])
    out = capsys.readouterr().out
    assert rc == 0 and "prompt:sql_injection" in out


def test_cli_show(capsys):
    rc = run_skills_cli(["show", "prompt:sql_injection"])
    out = capsys.readouterr().out
    assert rc == 0 and "prompt:sql_injection" in out


def test_cli_show_unknown_returns_1(capsys):
    rc = run_skills_cli(["show", "nope:does-not-exist"])
    assert rc == 1 and "no such skill" in capsys.readouterr().out


def test_cli_select_render(capsys):
    rc = run_skills_cli(["select", "--technique", "idor",
                         "--phase", "exploitation", "--render", "--limit", "3"])
    out = capsys.readouterr().out
    assert rc == 0 and "prompt:api_security" in out


def test_cli_select_without_render(capsys):
    rc = run_skills_cli(["select", "--technique", "sqli", "--limit", "2"])
    out = capsys.readouterr().out
    assert rc == 0 and "selected skill(s)" in out and "-" * 60 not in out


def test_cli_search_no_results(capsys):
    rc = run_skills_cli(["search", "zzzznotaskillzzzz"])
    out = capsys.readouterr().out
    assert rc == 0 and "0 match" in out


def test_classification_maps_to_skills():
    c = AttackPathClassification(required_phase="exploitation",
                                 attack_path_type="sql_injection",
                                 reasoning="sqli in id parameter")
    skills = c.skills(limit=4)
    assert skills and skills[0].id == "prompt:sql_injection"


def test_classification_skills_is_safe_on_unknown_type():
    c = AttackPathClassification(attack_path_type="totally_made_up_zzz",
                                 reasoning="")
    # never raises; may return [] or loose matches, but must be a list
    assert isinstance(c.skills(), list)


def test_react_engine_render_active_skills_is_guarded():
    # The injection helper must be best-effort and bounded.
    from core.react_engine import ReACTEngine
    render = ReACTEngine._render_active_skills
    # call unbound with a minimal fake self (only needs the method body's imports)
    class _Fake:
        pass
    out = render(_Fake(), {"phase": "exploitation",
                           "attack_path_type": "xss",
                           "technologies": ["php"]})
    assert isinstance(out, str) and len(out) <= 1200   # hard cap
