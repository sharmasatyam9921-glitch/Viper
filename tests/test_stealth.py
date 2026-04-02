"""Tests for StealthEngine — WAF evasion and fingerprint randomization."""
import pytest
from core.stealth import StealthEngine, StealthLevel, USER_AGENTS, WAF_SIGNATURES


class TestStealthLevels:
    def test_level_none_is_zero(self):
        engine = StealthEngine(level=0)
        assert engine.level == StealthLevel.NONE
        assert engine.level == 0

    def test_level_basic_is_one(self):
        engine = StealthEngine(level=1)
        assert engine.level == StealthLevel.BASIC

    def test_level_evasive_is_two(self):
        engine = StealthEngine(level=2)
        assert engine.level == StealthLevel.EVASIVE

    def test_level_paranoid_is_three(self):
        engine = StealthEngine(level=3)
        assert engine.level == StealthLevel.PARANOID

    def test_level_clamped_high(self):
        """Values above 3 are clamped to 3."""
        engine = StealthEngine(level=99)
        assert engine.level == StealthLevel.PARANOID

    def test_level_clamped_negative(self):
        """Negative values are clamped to 0."""
        engine = StealthEngine(level=-1)
        assert engine.level == StealthLevel.NONE


class TestStealthTiming:
    def test_level_none_zero_delays(self):
        engine = StealthEngine(level=0)
        assert engine.profile.min_delay == 0.0
        assert engine.profile.max_delay == 0.0

    def test_level_basic_has_nonzero_delay(self):
        engine = StealthEngine(level=1)
        assert engine.profile.min_delay > 0.0
        assert engine.profile.max_delay > engine.profile.min_delay

    def test_level_evasive_longer_than_basic(self):
        basic = StealthEngine(level=1)
        evasive = StealthEngine(level=2)
        assert evasive.profile.min_delay >= basic.profile.min_delay

    def test_level_paranoid_longest_delay(self):
        evasive = StealthEngine(level=2)
        paranoid = StealthEngine(level=3)
        assert paranoid.profile.min_delay >= evasive.profile.min_delay

    def test_level_basic_sticky_ua_set(self):
        engine = StealthEngine(level=1)
        assert engine.profile._ua_sticky is not None
        assert engine.profile._ua_sticky in USER_AGENTS


class TestGetHeaders:
    def test_level_none_returns_dict_with_user_agent(self):
        engine = StealthEngine(level=0)
        headers = engine.get_headers("http://example.com")
        assert isinstance(headers, dict)
        assert "User-Agent" in headers

    def test_level_basic_returns_dict_with_user_agent(self):
        engine = StealthEngine(level=1)
        headers = engine.get_headers("http://example.com")
        assert "User-Agent" in headers
        assert headers["User-Agent"] in USER_AGENTS

    def test_level_evasive_returns_dict_with_user_agent(self):
        engine = StealthEngine(level=2)
        headers = engine.get_headers("http://example.com")
        assert "User-Agent" in headers

    def test_level_paranoid_returns_dict_with_user_agent(self):
        engine = StealthEngine(level=3)
        headers = engine.get_headers("http://example.com")
        assert "User-Agent" in headers

    def test_custom_headers_merged(self):
        engine = StealthEngine(level=1)
        custom = {"X-Custom": "myval"}
        headers = engine.get_headers("http://example.com", custom_headers=custom)
        assert headers["X-Custom"] == "myval"

    def test_level_basic_sticky_ua_consistent(self):
        """At level 1, the same UA is used each call (sticky)."""
        engine = StealthEngine(level=1)
        h1 = engine.get_headers("http://example.com")
        h2 = engine.get_headers("http://example.com")
        assert h1["User-Agent"] == h2["User-Agent"]

    def test_user_agents_list_nonempty(self):
        assert len(USER_AGENTS) >= 10


class TestEncodePayload:
    def test_level_none_returns_raw(self):
        engine = StealthEngine(level=0)
        payload = "<script>alert(1)</script>"
        assert engine.encode_payload(payload) == payload

    def test_level_basic_returns_raw(self):
        engine = StealthEngine(level=1)
        payload = "<script>alert(1)</script>"
        assert engine.encode_payload(payload) == payload

    def test_level_evasive_may_encode(self):
        """At level 2, payload may be encoded (not guaranteed same)."""
        engine = StealthEngine(level=2)
        payload = "<script>alert(1)</script>"
        result = engine.encode_payload(payload)
        assert isinstance(result, str)
        assert len(result) > 0

    def test_level_paranoid_may_encode(self):
        engine = StealthEngine(level=3)
        payload = "' OR 1=1 --"
        result = engine.encode_payload(payload)
        assert isinstance(result, str)
        assert len(result) > 0

    def test_encode_returns_string_type(self):
        for level in range(4):
            engine = StealthEngine(level=level)
            result = engine.encode_payload("SELECT * FROM users")
            assert isinstance(result, str)


class TestWAFDetection:
    def test_detect_cloudflare_from_header(self):
        engine = StealthEngine(level=0)
        headers = {"cf-ray": "abc123", "Content-Type": "text/html"}
        waf = engine.detect_waf("example.com", headers, "")
        assert waf == "cloudflare"

    def test_detect_akamai_from_header(self):
        engine = StealthEngine(level=0)
        headers = {"x-akamai-transformed": "1"}
        waf = engine.detect_waf("example.com", headers, "")
        assert waf == "akamai"

    def test_detect_unknown_waf_from_body(self):
        engine = StealthEngine(level=0)
        headers = {}
        body = "Your request has been blocked by the web application firewall."
        waf = engine.detect_waf("example.com", headers, body)
        assert waf == "unknown_waf"

    def test_no_waf_returns_none(self):
        engine = StealthEngine(level=0)
        headers = {"Content-Type": "text/html"}
        waf = engine.detect_waf("example.com", headers, "<html>Hello</html>")
        assert waf is None

    def test_detect_waf_stores_in_profile(self):
        engine = StealthEngine(level=0)
        headers = {"cf-ray": "abc123"}
        engine.detect_waf("target.com", headers, "")
        assert "target.com" in engine.profile.detected_wafs

    def test_waf_signatures_dict_nonempty(self):
        assert len(WAF_SIGNATURES) > 0
        assert "cloudflare" in WAF_SIGNATURES

    def test_detect_imperva_from_cookie(self):
        engine = StealthEngine(level=0)
        headers = {"Set-Cookie": "incap_ses_12345=abc"}
        waf = engine.detect_waf("example.com", headers, "")
        assert waf == "imperva"


class TestProxyRotation:
    def test_no_proxies_returns_none_at_level_0(self):
        engine = StealthEngine(level=0)
        assert engine.get_proxy() is None

    def test_no_proxies_returns_none_at_level_2(self):
        engine = StealthEngine(level=2)
        assert engine.get_proxy() is None

    def test_proxies_returned_at_level_2(self):
        proxies = ["http://p1:8080", "http://p2:8080"]
        engine = StealthEngine(level=2, proxies=proxies)
        proxy = engine.get_proxy()
        assert proxy in proxies

    def test_proxy_rotation_cycles(self):
        proxies = ["http://p1:8080", "http://p2:8080"]
        engine = StealthEngine(level=2, proxies=proxies)
        p1 = engine.get_proxy()
        p2 = engine.get_proxy()
        assert p1 != p2

    def test_is_blocked_403_with_waf_keyword(self):
        engine = StealthEngine(level=0)
        assert engine.is_blocked(403, "Your request is blocked by our firewall") is True

    def test_is_blocked_200_is_false(self):
        engine = StealthEngine(level=0)
        assert engine.is_blocked(200, "Welcome") is False

    def test_on_blocked_adds_to_blocked_domains(self):
        engine = StealthEngine(level=0)
        engine.on_blocked("blocked.com")
        assert "blocked.com" in engine.profile.blocked_domains


class TestProfileSummary:
    def test_summary_returns_dict(self):
        engine = StealthEngine(level=2)
        summary = engine.profile.summary()
        assert isinstance(summary, dict)
        assert "level" in summary
        assert "proxies" in summary
        assert "detected_wafs" in summary
        assert "blocked_domains" in summary
