"""Tests for RoEEngine — Rules of Engagement enforcement."""
import pytest
from core.roe_engine import RoEEngine, RulesOfEngagement, DEFAULT_FORBIDDEN_TOOLS


class TestRoETargetScope:
    def test_in_scope_target_allowed(self, roe_engine):
        ok, reason = roe_engine.check_target_allowed("testphp.vulnweb.com")
        assert ok is True
        assert "in scope" in reason.lower()

    def test_wildcard_scope_subdomain_allowed(self, roe_engine):
        ok, _ = roe_engine.check_target_allowed("sub.example.com")
        assert ok is True

    def test_out_of_scope_target_denied(self, roe_engine):
        ok, reason = roe_engine.check_target_allowed("evil.com")
        assert ok is False
        assert "not in" in reason.lower() or "scope" in reason.lower()

    def test_excluded_host_denied(self, roe_engine):
        ok, reason = roe_engine.check_target_allowed("admin.example.com")
        assert ok is False
        assert "excluded" in reason.lower()

    def test_excluded_takes_priority_over_scope(self):
        """An excluded host within in-scope wildcard should be denied."""
        roe = RulesOfEngagement(
            in_scope_targets=["*.example.com"],
            excluded_hosts=[{"host": "admin.example.com", "reason": "prod"}],
        )
        engine = RoEEngine(roe)
        ok, reason = engine.check_target_allowed("admin.example.com")
        assert ok is False
        assert "excluded" in reason.lower()

    def test_permissive_when_no_scope_defined(self):
        """If in_scope_targets is empty, any target is allowed."""
        engine = RoEEngine(RulesOfEngagement())
        ok, reason = engine.check_target_allowed("anything.com")
        assert ok is True
        assert "permissive" in reason.lower()

    def test_url_with_scheme_normalised(self, roe_engine):
        ok, _ = roe_engine.check_target_allowed("https://testphp.vulnweb.com/path")
        assert ok is True

    def test_load_from_dict_updates_scope(self):
        engine = RoEEngine()
        engine.load_from_dict({"in_scope_targets": ["mytest.com"]})
        ok, _ = engine.check_target_allowed("mytest.com")
        assert ok is True


class TestRoEToolChecks:
    def test_safe_tool_allowed(self, roe_engine):
        ok, reason = roe_engine.check_tool_allowed("nmap")
        assert ok is True

    def test_forbidden_tool_denied(self, roe_engine):
        """metasploit is in the forbidden_tools list from fixture."""
        ok, reason = roe_engine.check_tool_allowed("metasploit")
        assert ok is False
        assert "forbidden" in reason.lower()

    def test_default_forbidden_rm_denied(self, roe_engine):
        ok, reason = roe_engine.check_tool_allowed("rm")
        assert ok is False
        assert "forbidden" in reason.lower()

    def test_default_forbidden_del_denied(self, roe_engine):
        ok, _ = roe_engine.check_tool_allowed("del")
        assert ok is False

    def test_default_forbidden_format_denied(self, roe_engine):
        ok, _ = roe_engine.check_tool_allowed("format")
        assert ok is False

    def test_default_forbidden_shutdown_denied(self, roe_engine):
        ok, _ = roe_engine.check_tool_allowed("shutdown")
        assert ok is False

    def test_dos_tool_denied_when_not_allowed(self, roe_engine):
        ok, reason = roe_engine.check_tool_allowed("slowloris")
        assert ok is False
        assert "dos" in reason.lower() or "prohibited" in reason.lower()

    def test_social_tool_denied_when_not_allowed(self, roe_engine):
        ok, _ = roe_engine.check_tool_allowed("social_phishing")
        assert ok is False

    def test_exfil_tool_denied_when_not_allowed(self, roe_engine):
        ok, _ = roe_engine.check_tool_allowed("data_exfil_tool")
        assert ok is False

    def test_forbidden_category_denied(self, roe_engine):
        """'destructive' category is forbidden in fixture."""
        ok, reason = roe_engine.check_tool_allowed("destructive_payload")
        assert ok is False

    def test_brute_force_allowed_when_enabled(self, roe_engine):
        ok, _ = roe_engine.check_tool_allowed("brute_force_login")
        assert ok is True

    def test_sqlmap_allowed_by_default(self, roe_engine):
        ok, _ = roe_engine.check_tool_allowed("sqlmap")
        assert ok is True

    def test_default_forbidden_tools_set_nonempty(self):
        assert len(DEFAULT_FORBIDDEN_TOOLS) > 0
        assert "rm" in DEFAULT_FORBIDDEN_TOOLS


class TestRoETimeWindow:
    def test_no_restriction_always_allowed(self, roe_engine):
        ok, reason = roe_engine.check_time_window()
        assert ok is True
        assert "no time restriction" in reason.lower()

    def test_blackout_date_denied(self):
        from datetime import datetime, timezone
        today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        engine = RoEEngine(RulesOfEngagement(blackout_dates=[today]))
        ok, reason = engine.check_time_window()
        assert ok is False
        assert "blackout" in reason.lower()

    def test_future_blackout_not_triggered(self):
        engine = RoEEngine(RulesOfEngagement(blackout_dates=["2099-01-01"]))
        ok, _ = engine.check_time_window()
        assert ok is True


class TestRoEPhaseChecks:
    def test_exploitation_phase_allowed(self, roe_engine):
        ok, reason = roe_engine.check_phase_allowed("exploitation")
        assert ok is True

    def test_informational_phase_always_allowed(self, roe_engine):
        ok, _ = roe_engine.check_phase_allowed("informational")
        assert ok is True

    def test_post_exploitation_denied_by_default(self, roe_engine):
        """Fixture sets max_severity_phase=exploitation, so post_exploitation denied."""
        ok, reason = roe_engine.check_phase_allowed("post_exploitation")
        assert ok is False
        assert "exceeds" in reason.lower() or "phase" in reason.lower()

    def test_post_exploitation_allowed_when_permitted(self):
        engine = RoEEngine(RulesOfEngagement(max_severity_phase="post_exploitation"))
        ok, _ = engine.check_phase_allowed("post_exploitation")
        assert ok is True


class TestRoEEnforce:
    def test_valid_combo_returns_allowed(self, roe_engine):
        ok, reason = roe_engine.enforce(
            tool="nmap",
            target="testphp.vulnweb.com",
            phase="exploitation",
        )
        assert ok is True

    def test_excluded_target_short_circuits(self, roe_engine):
        ok, reason = roe_engine.enforce(
            tool="nmap",
            target="admin.example.com",
            phase="informational",
        )
        assert ok is False
        assert "excluded" in reason.lower()

    def test_forbidden_tool_short_circuits(self, roe_engine):
        ok, reason = roe_engine.enforce(
            tool="rm",
            target="testphp.vulnweb.com",
        )
        assert ok is False
        assert "forbidden" in reason.lower()

    def test_out_of_scope_denied(self, roe_engine):
        ok, _ = roe_engine.enforce(
            tool="nmap",
            target="outofscope.com",
        )
        assert ok is False

    def test_phase_cap_enforced_in_combined(self, roe_engine):
        ok, reason = roe_engine.enforce(
            tool="nmap",
            target="testphp.vulnweb.com",
            phase="post_exploitation",
        )
        assert ok is False
        assert "phase" in reason.lower() or "exceeds" in reason.lower()
