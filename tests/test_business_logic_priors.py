"""Class impact priors (derived from a disclosed-report corpus) + the PII-free
extractor + their effect on prioritization."""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.prioritization import _class_prior, priority_score  # noqa: E402
from core.selfimprove.derive_business_logic_priors import derive  # noqa: E402

_PRIORS = Path(__file__).resolve().parents[1] / "core" / "selfimprove" / "business_logic_priors.json"


def test_priors_file_is_clean_aggregates():
    d = json.loads(_PRIORS.read_text(encoding="utf-8"))
    assert d["total_cases"] > 1000 and d["classes"]
    blob = json.dumps(d).lower()
    # aggregates only — no disclosed-case ids, urls, or payload material
    import re as _re
    assert not _re.search(r"[a-z]+-20\d\d-\d", blob) and "http" not in blob.replace("https", "")
    for cls, info in d["classes"].items():
        assert {"cases", "prevalence", "criticality", "impact_prior"} <= set(info)
        assert 0 <= info["impact_prior"] <= 1


def test_sqli_outranks_rare_classes():
    d = json.loads(_PRIORS.read_text(encoding="utf-8"))["classes"]
    assert d["sqli"]["impact_prior"] >= d["xxe"]["impact_prior"]   # 24k vs 33 cases


def test_class_prior_maps_aliases():
    assert _class_prior("idor:user_id") == _class_prior("bola")    # -> access_control
    assert _class_prior("sqli:error") > 0
    assert _class_prior("clickjacking") == 0.0                     # not in corpus
    assert _class_prior(None) == 0.0


def test_prior_nudges_ranking_without_changing_base_semantics():
    # no vuln_type -> prior 0 -> exact legacy scores preserved
    assert priority_score({"severity": "medium"}) == 20.0
    # access-control finding ranks above an equal-grade no-prior finding
    base = {"severity": "high", "submittable": True, "validation_confidence": 0.8}
    assert priority_score({**base, "vuln_type": "idor"}) > \
        priority_score({**base, "vuln_type": "clickjacking"})
    # capped at 100
    assert priority_score({"vuln_type": "sqli", "severity": "critical",
                           "submittable": True, "validation_confidence": 1.0}) == 100.0


def test_extractor_is_pii_free(tmp_path):
    # a tiny fixture corpus with a leaked-cred payload that must NOT survive
    cat = tmp_path / "sql-injection.md"
    cat.write_text(
        "# SQL\n## 高频参数\n```\n  uid: 5次\n```\n"
        "### 攻击模式分布\n```\n  注入: 3次\n```\n"
        "### 案例 1: rep-2015-000001\n**Payload片段**:\n```\nadmin:SuperSecret123\n```\n"
        "### 案例 2: rep-2015-000002\n",
        encoding="utf-8")
    out = derive(str(tmp_path))
    blob = json.dumps(out)
    assert "SuperSecret123" not in blob and "rep-2015" not in blob      # no PII/case ids
    assert out["classes"]["sqli"]["cases"] == 2                         # counted cases
    assert "injection" in out["classes"]["sqli"]["attack_patterns"]
