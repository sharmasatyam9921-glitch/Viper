"""Cross-hunt attack priors: record outcomes + rank by learned success, all
best-effort (never break a hunt) and never touching the gate."""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.attack_priors import AttackPriors, tech_tokens_from_findings  # noqa: E402


def _priors(tmp_path):
    from core.evograph import EvoGraph
    eg = EvoGraph(db_path=tmp_path / "evo.db")
    p = AttackPriors(evograph=eg)
    p.start("http://t/", ["nginx", "php"])
    return p


def test_tech_tokens_extracts_product_not_version():
    findings = [
        {"type": "technology", "title": "nginx 1.18"},
        {"type": "technology", "title": "PHP"},
        {"type": "technology", "title": "Apache/2.4.41"},
        {"type": "xss", "title": "reflected"},          # not a technology finding
        {"type": "technology", "title": "1.2.3"},        # version-only -> skipped
    ]
    toks = tech_tokens_from_findings(findings)
    assert toks == ["nginx", "php", "apache"]
    assert tech_tokens_from_findings([]) == []
    assert tech_tokens_from_findings(None) == []


def test_rank_is_noop_without_history(tmp_path):
    p = _priors(tmp_path)
    techs = ["sqli", "xss", "lfi"]
    assert p.rank(techs, ["nginx", "php"]) == techs      # no data yet -> unchanged


def test_record_then_rank_promotes_successful_attack(tmp_path):
    p = _priors(tmp_path)
    tech = ["php", "nginx"]
    # sqli + lfi succeed repeatedly against php stacks; xss keeps failing.
    # (evograph's ranking needs >= 2 attempts before an attack is counted.)
    for _ in range(3):
        p.record("sqli", tech, success=True)
        p.record("xss", tech, success=False)
    for _ in range(2):
        p.record("lfi", tech, success=True)
    ranked = p.rank(["xss", "lfi", "sqli"], ["php"])
    # both proven-successful attacks come before the failing one; xss (0 successes)
    # sinks to the end.
    assert ranked[-1] == "xss"
    assert set(ranked[:2]) == {"sqli", "lfi"}
    assert set(ranked) == {"xss", "lfi", "sqli"}          # set is preserved


def test_rank_never_changes_the_set(tmp_path):
    p = _priors(tmp_path)
    p.record("sqli", ["php"], success=True)
    for techs in ([], ["only"], ["a", "b", "c", "sqli"]):
        out = p.rank(techs, ["php"])
        assert set(out) == set(techs) and len(out) == len(techs)


def test_all_methods_are_noop_when_evograph_disabled():
    p = AttackPriors(enabled=False)
    assert not p.active
    p.start("http://t/", ["php"])                 # no raise
    assert p.rank(["a", "b"], ["php"]) == ["a", "b"]
    p.record("sqli", ["php"], success=True)       # no raise


def _hackmode(tmp_path):
    from core.audit_logger import AuditLogger
    from core.hack_mode import HackMode
    from core.hack_profile import LabProfile
    from core.narrator import Narrator
    audit = AuditLogger.for_hunt("example.com", hunts_dir=tmp_path / "hunts",
                                 db_path=tmp_path / "v.db")
    return HackMode(target="example.com", profile=LabProfile(),
                    narrator=Narrator(quiet=True), audit=audit)


class _Res:
    def __init__(self, findings):
        self.findings = findings


def test_hackmode_extracts_tech_and_records_outcomes(tmp_path):
    from core.attack_priors import AttackPriors
    from core.evograph import EvoGraph
    hm = _hackmode(tmp_path)
    hm._priors = AttackPriors(evograph=EvoGraph(db_path=tmp_path / "evo.db"))
    hm._priors.start("example.com", ["php"])
    # a recon technology finding drives tech-token extraction for ranking
    hm._state["findings"] = [{"type": "technology", "title": "nginx 1.18"},
                             {"type": "sqli", "title": "x"}]
    assert hm._priors_tech_tokens() == ["nginx"]
    # sqli produced a finding (success), xss ran but produced nothing (fail)
    res = _Res([{"technique": "sqli", "vuln_type": "sqli:id"}])
    hm._record_priors(["sqli", "xss"], res, ["php"])
    hm._record_priors(["sqli", "xss"], res, ["php"])   # >=2 attempts to be counted
    ranked = hm._priors.rank(["xss", "sqli"], ["php"])
    assert ranked[0] == "sqli"                          # proven success ranks first


def test_hackmode_priors_none_is_safe(tmp_path):
    hm = _hackmode(tmp_path)
    hm._priors = None
    assert hm._priors_tech_tokens() == []
    hm._record_priors(["sqli"], _Res([]), ["php"])      # no raise


def test_record_survives_a_broken_evograph(tmp_path):
    class _Boom:
        def start_session(self, *a, **k):
            return 1

        def record_attack(self, *a, **k):
            raise RuntimeError("db locked")

        def get_best_attacks_for_tech(self, *a, **k):
            raise RuntimeError("db locked")

    p = AttackPriors(evograph=_Boom())
    p.start("http://t/", ["php"])
    p.record("sqli", ["php"], success=True)       # swallowed, no raise
    assert p.rank(["a", "b"], ["php"]) == ["a", "b"]   # query error -> input order
