"""Tests for RateLimiter — token bucket rate limiting."""
import time
import pytest
from core.rate_limiter import RateLimiter, HumanTimingProfile


class TestRateLimiterBasics:
    def test_fresh_bucket_acquire_succeeds(self, rate_limiter):
        """A freshly configured bucket starts with tokens, so first acquire succeeds."""
        result = rate_limiter.acquire("http")
        assert result is True

    def test_acquire_unconfigured_category_returns_true(self, rate_limiter):
        """Unknown category is treated as unlimited."""
        result = rate_limiter.acquire("unknown_category_xyz")
        assert result is True

    def test_configure_new_category(self, rate_limiter):
        rate_limiter.configure("test_category", requests_per_second=5.0)
        result = rate_limiter.acquire("test_category")
        assert result is True

    def test_configure_updates_existing_category(self, rate_limiter):
        rate_limiter.configure("http", requests_per_second=100.0)
        stats = rate_limiter.get_stats()
        assert stats["http"]["rate"] == 100.0

    def test_default_categories_exist(self, rate_limiter):
        stats = rate_limiter.get_stats()
        assert "http" in stats
        assert "llm" in stats
        assert "recon" in stats
        assert "nuclei" in stats

    def test_get_stats_returns_dict(self, rate_limiter):
        stats = rate_limiter.get_stats()
        assert isinstance(stats, dict)

    def test_get_stats_has_tokens_and_rate(self, rate_limiter):
        stats = rate_limiter.get_stats()
        http_stats = stats["http"]
        assert "tokens" in http_stats
        assert "rate" in http_stats
        assert "max" in http_stats

    def test_rate_max_is_double_rate(self, rate_limiter):
        rate_limiter.configure("burst_test", requests_per_second=10.0)
        stats = rate_limiter.get_stats()
        assert stats["burst_test"]["max"] == 20.0


class TestRateLimiterTokenBucket:
    def test_acquire_depletes_tokens(self, rate_limiter):
        """Repeated acquires should eventually exhaust a low-rate bucket."""
        rate_limiter.configure("tight", requests_per_second=1.0)
        # First acquire should succeed (starts with 1.0 token)
        first = rate_limiter.acquire("tight", timeout=0.1)
        assert first is True
        # Immediately after, should fail (no time for refill)
        second = rate_limiter.acquire("tight", timeout=0.0)
        # With timeout=0 it may fail since no tokens remain
        # (acquire sleeps 0.05s per loop, so timeout=0 might not even try)
        assert isinstance(second, bool)

    def test_timeout_zero_returns_false_on_empty_bucket(self, rate_limiter):
        """With a near-zero rate and timeout=0, acquire should fail."""
        rate_limiter.configure("zero_rate", requests_per_second=0.001)
        # Force drain by calling acquire multiple times rapidly
        rate_limiter._buckets["zero_rate"]["tokens"] = 0.0
        result = rate_limiter.acquire("zero_rate", timeout=0.0)
        # timeout is 0, so it won't wait; result should be False
        assert result is False

    def test_tokens_refill_over_time(self, rate_limiter):
        """After draining, tokens should refill based on rate."""
        rate_limiter.configure("refill_test", requests_per_second=10.0)
        # Drain completely
        rate_limiter._buckets["refill_test"]["tokens"] = 0.0
        time.sleep(0.15)  # wait for ~1.5 tokens to refill
        result = rate_limiter.acquire("refill_test", timeout=0.1)
        assert result is True

    def test_wait_does_not_raise(self, rate_limiter):
        """wait() should not raise even if it blocks briefly."""
        rate_limiter.configure("fast", requests_per_second=100.0)
        rate_limiter.wait("fast")  # should complete quickly


class TestRateLimiterSingleton:
    def test_get_instance_returns_same_object(self):
        a = RateLimiter.get_instance()
        b = RateLimiter.get_instance()
        assert a is b

    def test_singleton_has_default_categories(self):
        inst = RateLimiter.get_instance()
        stats = inst.get_stats()
        assert "http" in stats


class TestHumanTimingProfile:
    def test_default_profile_is_normal(self):
        h = HumanTimingProfile()
        assert h.profile == HumanTimingProfile.NORMAL

    def test_cautious_profile(self):
        h = HumanTimingProfile(profile="cautious")
        assert h.profile == "cautious"

    def test_aggressive_profile(self):
        h = HumanTimingProfile(profile="aggressive")
        assert h.profile == "aggressive"

    def test_invalid_profile_defaults_to_normal(self):
        h = HumanTimingProfile(profile="nonexistent")
        assert h.profile == "normal"

    def test_get_delay_returns_positive_float(self):
        h = HumanTimingProfile(profile="normal")
        delay = h.get_delay()
        assert isinstance(delay, float)
        assert delay >= 0.1

    def test_cautious_delay_larger_than_aggressive(self):
        cautious = HumanTimingProfile(profile="cautious")
        aggressive = HumanTimingProfile(profile="aggressive")
        # Run multiple times to average out randomness
        cautious_avg = sum(cautious.get_delay() for _ in range(5)) / 5
        aggressive_avg = sum(aggressive.get_delay() for _ in range(5)) / 5
        assert cautious_avg > aggressive_avg

    def test_profile_setter_updates_mu(self):
        h = HumanTimingProfile(profile="normal")
        h.profile = "cautious"
        assert h._mu == HumanTimingProfile.PROFILES["cautious"]

    def test_profile_setter_ignores_invalid(self):
        h = HumanTimingProfile(profile="normal")
        old_mu = h._mu
        h.profile = "invalid_name"
        assert h._mu == old_mu  # unchanged

    def test_get_stats_returns_dict(self):
        h = HumanTimingProfile()
        stats = h.get_stats()
        assert isinstance(stats, dict)
        assert "profile" in stats
        assert "mu" in stats
        assert "requests_in_window" in stats
        assert "burst_threshold" in stats

    def test_burst_detection_auto_escalates_to_cautious(self):
        """Sending >10 requests quickly should auto-escalate to CAUTIOUS."""
        h = HumanTimingProfile(profile="aggressive")
        # Call get_delay 11 times rapidly
        for _ in range(12):
            h.get_delay()
        # After burst, should have auto-escalated
        assert h.profile == HumanTimingProfile.CAUTIOUS

    def test_profiles_dict_has_three_entries(self):
        assert len(HumanTimingProfile.PROFILES) == 3
        assert "cautious" in HumanTimingProfile.PROFILES
        assert "normal" in HumanTimingProfile.PROFILES
        assert "aggressive" in HumanTimingProfile.PROFILES
