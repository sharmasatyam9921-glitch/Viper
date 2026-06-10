"""Tests for core.chain_planner — verdict logic + bounded follow-up planning."""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.chain_planner import (  # noqa: E402
    CHAIN_REQUIRED,
    DOWNGRADE,
    KILL,
    PASS,
    ChainPlanner,
)


class TestVerdict:
    def test_confirmed_exploit_chains(self):
        p = ChainPlanner()
        f = {"type": "sqli_exploited", "severity": "critical",
             "url": "http://t/x?id=1"}
        assert p.verdict(f) == CHAIN_REQUIRED

    def test_foothold_chains(self):
        p = ChainPlanner()
        assert p.verdict({"type": "cmdi_exploited", "foothold": True,
                          "url": "http://t/p"}) == CHAIN_REQUIRED

    def test_high_sev_with_url_chains(self):
        p = ChainPlanner()
        assert p.verdict({"type": "sqli", "severity": "high",
                          "url": "http://t/a"}) == CHAIN_REQUIRED

    def test_skipped_is_killed(self):
        p = ChainPlanner()
        assert p.verdict({"type": "exploit_skipped",
                          "severity": "info"}) == KILL

    def test_info_is_downgraded(self):
        p = ChainPlanner()
        assert p.verdict({"type": "subdomain", "severity": "info",
                          "url": "http://t"}) == DOWNGRADE

    def test_medium_without_url_passes(self):
        p = ChainPlanner()
        assert p.verdict({"type": "cors", "severity": "medium"}) == PASS


class TestPlan:
    def test_chain_required_emits_task(self):
        p = ChainPlanner(max_depth=3)
        d = p.plan([{"type": "sqli_exploited", "severity": "critical",
                     "url": "http://t/x?id=1"}], depth=0)
        assert len(d.new_tasks) == 1
        assert d.new_tasks[0].asset_url == "http://t/x?id=1"
        assert d.new_tasks[0].depth == 1
        assert not d.converged

    def test_cycle_detection_blocks_repeat(self):
        p = ChainPlanner(max_depth=3)
        f = {"type": "sqli_exploited", "severity": "critical", "url": "http://t/x"}
        first = p.plan([f], depth=0)
        assert len(first.new_tasks) == 1
        # Same finding again → already seen → no new task → converged.
        second = p.plan([f], depth=1)
        assert second.new_tasks == []
        assert second.converged

    def test_depth_budget_stops_tasks(self):
        p = ChainPlanner(max_depth=2)
        f = {"type": "sqli_exploited", "severity": "critical", "url": "http://t/x"}
        # At depth == max_depth, classify but emit nothing.
        d = p.plan([f], depth=2)
        assert d.new_tasks == []
        assert d.converged

    def test_max_tasks_cap(self):
        p = ChainPlanner(max_depth=3, max_tasks=2)
        findings = [
            {"type": "sqli_exploited", "severity": "critical",
             "url": f"http://t/{i}"} for i in range(5)
        ]
        d = p.plan(findings, depth=0)
        assert len(d.new_tasks) == 2

    def test_downgrade_and_kill_never_chain(self):
        p = ChainPlanner(max_depth=3)
        d = p.plan([
            {"type": "subdomain", "severity": "info", "url": "http://t/a"},
            {"type": "exploit_skipped", "severity": "info", "url": "http://t/b"},
        ], depth=0)
        assert d.new_tasks == []
        assert d.converged
