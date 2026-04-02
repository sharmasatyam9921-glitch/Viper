"""Tests for TargetGuardrail and InputSanitizer."""
import pytest
from core.guardrails import TargetGuardrail, InputSanitizer


# ── TargetGuardrail — allowlist ──────────────────────────────────────────────

class TestTargetGuardrailAllowlist:
    def test_hackthebox_allowed(self, guardrail):
        allowed, reason = guardrail.validate_target_sync("hackthebox.eu")
        assert allowed is True
        assert "allowlist" in reason.lower()

    def test_tryhackme_allowed(self, guardrail):
        allowed, _ = guardrail.validate_target_sync("tryhackme.com")
        assert allowed is True

    def test_localhost_allowed(self, guardrail):
        allowed, _ = guardrail.validate_target_sync("localhost")
        assert allowed is True

    def test_testphp_vulnweb_allowed(self, guardrail):
        allowed, _ = guardrail.validate_target_sync("testphp.vulnweb.com")
        assert allowed is True

    def test_demo_testfire_allowed(self, guardrail):
        allowed, _ = guardrail.validate_target_sync("demo.testfire.net")
        assert allowed is True

    def test_dvwa_allowed(self, guardrail):
        allowed, _ = guardrail.validate_target_sync("dvwa.local")
        assert allowed is True

    def test_juice_shop_allowed(self, guardrail):
        allowed, _ = guardrail.validate_target_sync("juice-shop.example.com")
        assert allowed is True

    def test_portswigger_allowed(self, guardrail):
        allowed, _ = guardrail.validate_target_sync("portswigger.net")
        assert allowed is True

    def test_url_with_path_hackthebox(self, guardrail):
        """URL parsing: domain extracted correctly from full URL."""
        allowed, _ = guardrail.validate_target_sync("https://hackthebox.eu/machines")
        assert allowed is True


# ── TargetGuardrail — blocklist ──────────────────────────────────────────────

class TestTargetGuardrailBlocklist:
    def test_gov_tld_blocked(self, guardrail):
        allowed, reason = guardrail.validate_target_sync("pentagon.gov")
        assert allowed is False
        assert "blocklist" in reason.lower() or "gov" in reason.lower()

    def test_mil_tld_blocked(self, guardrail):
        allowed, _ = guardrail.validate_target_sync("army.mil")
        assert allowed is False

    def test_edu_tld_blocked(self, guardrail):
        allowed, _ = guardrail.validate_target_sync("harvard.edu")
        assert allowed is False

    def test_nsa_blocked(self, guardrail):
        allowed, _ = guardrail.validate_target_sync("nsa.gov")
        assert allowed is False

    def test_cia_blocked(self, guardrail):
        allowed, _ = guardrail.validate_target_sync("cia.gov")
        assert allowed is False

    def test_fbi_blocked(self, guardrail):
        allowed, _ = guardrail.validate_target_sync("fbi.gov")
        assert allowed is False

    def test_nhs_blocked(self, guardrail):
        allowed, _ = guardrail.validate_target_sync("nhs.uk")
        # 'nhs' is in the blocklist as a label, not a TLD — check blocklist logic
        # nhs.uk: tld='uk' not in blocklist, but 'nhs' is checked differently
        # According to code: checks if blocked_l in f".{domain_lower}." as substring
        # ".nhs.uk." contains ".nhs." so it should be blocked
        assert allowed is False

    def test_army_subdomain_blocked(self, guardrail):
        allowed, _ = guardrail.validate_target_sync("www.army.mil")
        assert allowed is False


# ── TargetGuardrail — private IPs ────────────────────────────────────────────

class TestTargetGuardrailPrivateIPs:
    def test_192_168_allowed(self, guardrail):
        allowed, _ = guardrail.validate_target_sync("192.168.1.1")
        assert allowed is True

    def test_10_network_allowed(self, guardrail):
        allowed, _ = guardrail.validate_target_sync("10.0.0.1")
        assert allowed is True

    def test_172_16_allowed(self, guardrail):
        allowed, _ = guardrail.validate_target_sync("172.16.0.1")
        assert allowed is True

    def test_loopback_allowed(self, guardrail):
        allowed, _ = guardrail.validate_target_sync("127.0.0.1")
        assert allowed is True

    def test_loopback_url_allowed(self, guardrail):
        allowed, _ = guardrail.validate_target_sync("http://127.0.0.1:8080")
        assert allowed is True


# ── TargetGuardrail — edge cases ─────────────────────────────────────────────

class TestTargetGuardrailEdgeCases:
    def test_empty_string_denied(self, guardrail):
        allowed, reason = guardrail.validate_target_sync("")
        assert allowed is False

    def test_extra_blocklist_denies(self):
        g = TargetGuardrail(extra_blocklist=["evil"])
        allowed, _ = g.validate_target_sync("evil.com")
        # "evil" as TLD doesn't exist but as substring check: .evil.com. contains .evil.
        # Actually the TLD check: tld == "com" which is not "evil"
        # substring check: ".evil." in ".evil.com." -> True -> blocked
        assert allowed is False

    def test_extra_allowlist_permits(self):
        g = TargetGuardrail(extra_allowlist=["mytest.local"])
        allowed, _ = g.validate_target_sync("mytest.local")
        assert allowed is True

    def test_url_scheme_stripped(self, guardrail):
        """https:// scheme is stripped before validation."""
        allowed, _ = guardrail.validate_target_sync("https://testphp.vulnweb.com/path?a=1")
        assert allowed is True

    def test_get_validation_log_returns_list(self, guardrail):
        guardrail.validate_target_sync("hackthebox.eu")
        guardrail.validate_target_sync("pentagon.gov")
        log = guardrail.get_validation_log()
        assert isinstance(log, list)
        assert len(log) >= 2

    def test_get_validation_log_has_required_keys(self, guardrail):
        guardrail.validate_target_sync("hackthebox.eu")
        log = guardrail.get_validation_log()
        entry = log[-1]
        assert "target" in entry
        assert "allowed" in entry
        assert "reason" in entry
        assert "timestamp" in entry

    def test_validate_alias(self, guardrail):
        """validate() is backward-compat alias for validate_target_sync()."""
        r1 = guardrail.validate_target_sync("hackthebox.eu")
        g2 = TargetGuardrail()
        r2 = g2.validate("hackthebox.eu")
        assert r1[0] == r2[0]

    def test_unknown_domain_default_permit(self, guardrail):
        """Non-allowlisted, non-blocklisted domain defaults to allowed with warning."""
        allowed, reason = guardrail.validate_target_sync("somebugbountyprogram.com")
        assert allowed is True


# ── InputSanitizer ───────────────────────────────────────────────────────────

class TestInputSanitizer:
    @pytest.fixture(autouse=True)
    def setup(self):
        self.s = InputSanitizer()

    def test_empty_url_invalid(self):
        valid, msg = self.s.sanitize_url("")
        assert valid is False
        assert "empty" in msg.lower() or msg

    def test_url_too_long_invalid(self):
        valid, msg = self.s.sanitize_url("x" * 2049)
        assert valid is False
        assert "length" in msg.lower() or "max" in msg.lower()

    def test_plain_domain_gets_https_prefix(self):
        valid, url = self.s.sanitize_url("example.com")
        assert valid is True
        assert url.startswith("https://")

    def test_https_url_passes_through(self):
        valid, url = self.s.sanitize_url("https://example.com")
        assert valid is True
        assert "example.com" in url

    def test_http_url_passes_through(self):
        valid, url = self.s.sanitize_url("http://example.com/path?q=1")
        assert valid is True

    def test_url_at_max_length_ok(self):
        base = "https://example.com/" + "a" * (2048 - len("https://example.com/"))
        valid, _ = self.s.sanitize_url(base)
        assert valid is True

    def test_sanitize_header_crlf_in_value_invalid(self):
        valid, msg = self.s.sanitize_header("X-Test", "value\r\ninjected: header")
        assert valid is False
        assert "crlf" in msg.lower() or "header" in msg.lower()

    def test_sanitize_header_lf_in_value_invalid(self):
        valid, _ = self.s.sanitize_header("X-Test", "normal\ninjected")
        assert valid is False

    def test_sanitize_header_cr_in_name_invalid(self):
        valid, _ = self.s.sanitize_header("X-Te\rst", "value")
        assert valid is False

    def test_sanitize_header_normal_value_valid(self):
        valid, val = self.s.sanitize_header("X-Custom", "normal value")
        assert valid is True
        assert val == "normal value"

    def test_sanitize_header_long_value_invalid(self):
        valid, _ = self.s.sanitize_header("X-Test", "x" * 8193)
        assert valid is False

    def test_sanitize_header_max_length_ok(self):
        valid, _ = self.s.sanitize_header("X-Test", "x" * 8192)
        assert valid is True
