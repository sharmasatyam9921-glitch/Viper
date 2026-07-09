"""Coverage-critic follow-up: after the loop, VIPER re-probes discovered-but-untested
surface in one bounded round (exploration only — new findings still pass the gate)."""
from __future__ import annotations

import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


def _hackmode(tmp_path):
    from core.audit_logger import AuditLogger
    from core.hack_mode import HackMode
    from core.hack_profile import LabProfile
    from core.narrator import Narrator
    audit = AuditLogger.for_hunt("t", hunts_dir=tmp_path / "h", db_path=tmp_path / "v.db")
    return HackMode(target="http://t/", profile=LabProfile(),
                    narrator=Narrator(quiet=True), audit=audit)


class _Res:
    def __init__(self):
        self.findings = []
        self.surface = []


def _phase_result(findings):
    return type("PR", (), {"findings": findings, "findings_count": len(findings)})()


def test_coverage_targets_flags_only_unprobed_param_endpoints(tmp_path):
    hm = _hackmode(tmp_path)
    hm._state["findings"] = [
        {"type": "endpoint", "url": "http://t/api?id=1"},           # param endpoint, no finding
        {"type": "endpoint", "url": "http://t/done?q=1"},           # param endpoint...
        {"type": "xss", "vuln_type": "xss:q", "url": "http://t/done?q=2"},  # ...that WAS probed
    ]
    targets = hm._coverage_targets()
    assert "http://t/api?id=1" in targets
    assert not any("/done" in t for t in targets)     # a finding exists at that path


def test_coverage_round_probes_targets_and_folds_results(tmp_path, monkeypatch):
    hm = _hackmode(tmp_path)
    hm._state["findings"] = [{"type": "endpoint", "url": "http://t/api?id=1"}]
    seen = {}

    async def fake_phase(phase, *, assets=None, **kw):
        seen["phase"], seen["assets"] = phase, assets
        return _phase_result([{"type": "xss", "vuln_type": "xss:id",
                               "url": "http://t/api?id=1"}])
    monkeypatch.setattr(hm, "_run_phase", fake_phase)
    result = _Res()
    n = asyncio.run(hm._run_coverage_round(result))
    assert n == 1
    assert seen["phase"] == "vuln" and "http://t/api?id=1" in seen["assets"]
    assert any(f["vuln_type"] == "xss:id" for f in result.findings)   # folded in


def test_coverage_round_noop_when_nothing_unprobed(tmp_path, monkeypatch):
    hm = _hackmode(tmp_path)
    hm._state["findings"] = [{"type": "xss", "vuln_type": "xss:q", "url": "http://t/x?q=1"}]

    async def boom(*a, **k):
        raise AssertionError("_run_phase must not be called when there are no gaps")
    monkeypatch.setattr(hm, "_run_phase", boom)
    assert asyncio.run(hm._run_coverage_round(_Res())) == 0


def test_coverage_followup_opt_out(tmp_path, monkeypatch):
    hm = _hackmode(tmp_path)
    hm.profile.coverage_followup = False
    hm._state["findings"] = [{"type": "endpoint", "url": "http://t/api?id=1"}]

    async def boom(*a, **k):
        raise AssertionError("disabled follow-up must not dispatch a phase")
    monkeypatch.setattr(hm, "_run_phase", boom)
    assert asyncio.run(hm._run_coverage_round(_Res())) == 0
