"""Cross-hunt reasoning recall: read back prior high-reward Deep-Think steps by tech
stack (the react-loop complement to the evograph attack-priors loop). Best-effort;
shapes exploration only, never the gate."""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.evograph import EvoGraph  # noqa: E402
from core.react_engine import ReACTEngine  # noqa: E402


def _eg(tmp_path):
    eg = EvoGraph(db_path=tmp_path / "e.db")
    php = eg.start_session("http://t/", ["php", "apache"])
    eg.record_reasoning_step(php, 1, "try sqli", "sqli_probe", "500 DB error near quote", 1.0)
    eg.record_reasoning_step(php, 2, "try xss", "xss_probe", "no reflection", 0.0)  # low reward
    nginx = eg.start_session("http://o/", ["nginx"])
    eg.record_reasoning_step(nginx, 1, "try lfi", "lfi_probe", "read /etc/passwd", 1.0)
    return eg


def test_recall_filters_by_tech_and_reward(tmp_path):
    eg = _eg(tmp_path)
    rec = eg.get_reasoning_recall(["php"], top_n=5)
    acts = [r["action"] for r in rec]
    assert "sqli_probe" in acts             # php stack, high reward
    assert "xss_probe" not in acts          # reward below min_reward (0.5)
    assert "lfi_probe" not in acts          # different tech stack
    assert eg.get_reasoning_recall([]) == []          # no tech -> nothing
    assert eg.get_reasoning_recall(["cobol"]) == []   # unseen tech -> nothing


def test_recall_honours_min_reward_and_limit(tmp_path):
    eg = _eg(tmp_path)
    # lowering min_reward surfaces the previously-excluded low-reward step
    acts = [r["action"] for r in eg.get_reasoning_recall(["php"], min_reward=0.0)]
    assert {"sqli_probe", "xss_probe"} <= set(acts)
    assert len(eg.get_reasoning_recall(["php"], top_n=1, min_reward=0.0)) == 1


def test_react_helper_formats_recall(tmp_path):
    eng = ReACTEngine(brain=None, verbose=False)
    eng.evograph = _eg(tmp_path)
    hint = eng._reasoning_recall(["php", "apache"])
    assert "sqli_probe" in hint and "500 DB error" in hint
    assert "xss_probe" not in hint          # low-reward step filtered out


def test_react_helper_is_safe_without_evograph_or_history(tmp_path):
    eng = ReACTEngine(brain=None, verbose=False)
    eng.evograph = None
    assert eng._reasoning_recall(["php"]) == ""      # no evograph -> empty, no raise
    eng.evograph = EvoGraph(db_path=tmp_path / "empty.db")
    assert eng._reasoning_recall(["php"]) == ""      # no history -> empty


def test_react_helper_survives_broken_evograph():
    class _Boom:
        def get_reasoning_recall(self, *a, **k):
            raise RuntimeError("db locked")

    eng = ReACTEngine(brain=None, verbose=False)
    eng.evograph = _Boom()
    assert eng._reasoning_recall(["php"]) == ""      # swallowed -> empty
