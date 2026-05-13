"""Tests for core/hack_profile.py — CTF / BugBounty / Lab profile policy."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.hack_profile import (  # noqa: E402
    BUILTIN_PROFILES,
    BugBountyProfile,
    CTFProfile,
    LabProfile,
    Profile,
    StopCondition,
    _is_private_ip,
    _stop_after_one,
    _stop_when_exhausted,
    _stop_when_flag,
    detect_profile,
    list_profiles,
)


# ---------------------------------------------------------------------------
# Built-in profiles
# ---------------------------------------------------------------------------


class TestBuiltinProfiles:
    def test_ctf_profile_loops_until_flag(self):
        p = CTFProfile()
        assert p.name == "CTFProfile"
        assert "flag_hunter" in p.workers["post"]
        assert any(c.name == "flag_found" for c in p.stop_conditions)
        assert p.allow_destructive is True
        assert p.use_scope_reasoner is False
        # CTF gets bigger iteration budget than other profiles
        assert p.max_iterations >= 10

    def test_bugbounty_profile_defaults_scout(self):
        p = BugBountyProfile()
        # Default = scout = no exploit/post
        assert "exploit" not in p.phases
        assert "post" not in p.phases
        assert "recon" in p.phases
        assert "vuln" in p.phases
        assert p.allow_destructive is False
        assert p.use_scope_reasoner is True
        assert any(c.name == "exhausted" for c in p.stop_conditions)

    def test_bugbounty_profile_go_mode_includes_exploit(self):
        p = BugBountyProfile(allow_destructive=True)
        assert "exploit" in p.phases
        assert "post" in p.phases
        assert p.allow_destructive is True

    def test_lab_profile_one_pass(self):
        p = LabProfile()
        assert p.max_iterations == 1
        assert p.use_scope_reasoner is False
        assert any(c.name == "one_pass" for c in p.stop_conditions)

    def test_lab_profile_go_mode_has_exploit(self):
        p = LabProfile(allow_destructive=True)
        assert "exploit" in p.phases

    def test_all_profiles_include_recon_vuln_report(self):
        for fact in (CTFProfile, BugBountyProfile, LabProfile):
            p = fact()
            assert "recon" in p.phases
            assert "vuln" in p.phases
            assert "report" in p.phases


# ---------------------------------------------------------------------------
# Stop conditions
# ---------------------------------------------------------------------------


class TestStopConditions:
    def test_flag_stop_recognizes_type(self):
        state = {"findings": [{"type": "flag_captured", "title": "x"}]}
        assert _stop_when_flag(state) is True

    @pytest.mark.parametrize("title", [
        "flag{some_flag}", "FLAG{capture}", "HTB{root_pwned}",
        "picoCTF{abc}", "THM{c}", "CTF{x}",
    ])
    def test_flag_stop_recognizes_title_patterns(self, title):
        state = {"findings": [{"type": "x", "title": title}]}
        assert _stop_when_flag(state) is True

    def test_flag_stop_no_match(self):
        state = {"findings": [{"type": "subdomain", "title": "api.example.com"}]}
        assert _stop_when_flag(state) is False

    def test_exhausted_after_three_zero_iterations(self):
        # Two zero-iterations is not enough
        assert _stop_when_exhausted({"findings_per_iteration": [1, 0, 0]}) is False
        # Three zeros in a row is
        assert _stop_when_exhausted({"findings_per_iteration": [1, 0, 0, 0]}) is True

    def test_exhausted_resets_after_finding(self):
        # Recent finding breaks the run
        assert _stop_when_exhausted(
            {"findings_per_iteration": [0, 0, 5]}
        ) is False

    def test_one_pass_after_one_iter(self):
        assert _stop_after_one({"iteration": 0}) is False
        assert _stop_after_one({"iteration": 1}) is True


# ---------------------------------------------------------------------------
# Profile.should_stop
# ---------------------------------------------------------------------------


class TestShouldStop:
    def test_returns_false_when_no_condition_met(self):
        p = BugBountyProfile()
        ok, reason = p.should_stop({"iteration": 1, "findings": [], "findings_per_iteration": [3]})
        assert ok is False
        assert reason is None

    def test_returns_true_with_reason_when_condition_met(self):
        p = CTFProfile()
        state = {"findings": [{"type": "flag_captured", "title": "FLAG{x}"}]}
        ok, reason = p.should_stop(state)
        assert ok is True
        assert reason == "flag_found"

    def test_max_iterations_caps(self):
        p = LabProfile()  # max_iterations=1
        ok, reason = p.should_stop({"iteration": 1, "findings": [], "findings_per_iteration": []})
        # The one_pass condition fires first
        assert ok is True

    def test_broken_condition_ignored(self):
        def bad(state): raise RuntimeError("boom")
        p = LabProfile()
        p.stop_conditions = [StopCondition(name="bad", description="x", check=bad)]
        ok, reason = p.should_stop({"iteration": 0})
        # Doesn't crash; falls through to max_iterations check
        assert ok is False


# ---------------------------------------------------------------------------
# _is_private_ip
# ---------------------------------------------------------------------------


class TestIsPrivateIp:
    @pytest.mark.parametrize("ip", [
        "10.0.0.1", "172.16.5.10", "192.168.1.100",
        "127.0.0.1", "169.254.169.254",
    ])
    def test_private_ips(self, ip):
        assert _is_private_ip(ip) is True

    @pytest.mark.parametrize("ip", [
        "8.8.8.8", "1.1.1.1", "example.com",
    ])
    def test_public_or_hostname(self, ip):
        assert _is_private_ip(ip) is False


# ---------------------------------------------------------------------------
# detect_profile
# ---------------------------------------------------------------------------


class TestDetectProfile:
    def test_explicit_ctf(self):
        p = detect_profile("anything.com", explicit="ctf")
        assert p.name == "CTFProfile"

    def test_explicit_bugbounty(self):
        p = detect_profile("anything.com", explicit="bugbounty")
        assert p.name == "BugBountyProfile"

    def test_explicit_lab(self):
        p = detect_profile("anything.com", explicit="lab")
        assert p.name == "LabProfile"

    def test_explicit_aliases(self):
        assert detect_profile("x", explicit="bb").name == "BugBountyProfile"
        assert detect_profile("x", explicit="LAB").name == "LabProfile"

    def test_unknown_explicit_raises(self):
        with pytest.raises(ValueError):
            detect_profile("x", explicit="unknown")

    def test_scope_file_triggers_bugbounty(self):
        p = detect_profile("anything.com", scope_file="scope.json")
        assert p.name == "BugBountyProfile"

    @pytest.mark.parametrize("target", [
        "challenge.htb", "https://box.thm",
        "https://picoctf.com/x", "tryhackme.com/box/1",
        "hackthebox.com/machine", "pwn.college/x",
    ])
    def test_ctf_pattern_detection(self, target):
        p = detect_profile(target)
        assert p.name == "CTFProfile"

    @pytest.mark.parametrize("target", [
        "10.10.10.5", "192.168.1.100",
        "https://10.0.0.5:8080", "localhost", "127.0.0.1",
    ])
    def test_private_ip_triggers_lab(self, target):
        p = detect_profile(target)
        assert p.name == "LabProfile"

    def test_public_hostname_defaults_to_bugbounty(self):
        p = detect_profile("example.com")
        assert p.name == "BugBountyProfile"

    def test_url_form_target_is_normalized(self):
        p = detect_profile("https://10.10.10.5:8443/path")
        assert p.name == "LabProfile"

    def test_go_flag_propagates(self):
        p = detect_profile("example.com", go=True)
        assert p.allow_destructive is True
        assert "exploit" in p.phases


# ---------------------------------------------------------------------------
# Public registry
# ---------------------------------------------------------------------------


class TestRegistry:
    def test_list_profiles_returns_three(self):
        profiles = list_profiles()
        assert set(profiles) == {"ctf", "bugbounty", "lab"}

    def test_builtin_factory_keys_match(self):
        for k, fact in BUILTIN_PROFILES.items():
            p = fact()
            assert isinstance(p, Profile)
            assert p.name.lower().startswith(k.replace("bug", "bug"))


# ---------------------------------------------------------------------------
# to_dict
# ---------------------------------------------------------------------------


class TestToDict:
    def test_to_dict_serializable(self):
        import json
        for fact in (CTFProfile, BugBountyProfile, LabProfile):
            d = fact().to_dict()
            json.dumps(d)
            assert "phases" in d
            assert "time_budget_s" in d
            assert "stop_conditions" in d
            assert isinstance(d["stop_conditions"], list)
