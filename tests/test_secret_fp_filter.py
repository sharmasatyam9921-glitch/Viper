"""Tests for core.secret_scanner.is_likely_real_secret (FP filter)."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.secret_scanner import is_likely_real_secret  # noqa: E402


class TestRejectsFalsePositives:
    def test_dictionary_word_password(self):
        # The exact FP the benchmark produced on Juice Shop's main.js.
        assert is_likely_real_secret("password") is False

    def test_minified_js_code_blob(self):
        # The other benchmark FP: a greedy-regex catch of surrounding JS.
        blob = ")?{consumed:t}:null}function nD(t){return t.length===0?null:t[0]"
        assert is_likely_real_secret(blob) is False

    def test_placeholders_and_keywords(self):
        for v in ("username", "changeme", "your_api_key", "undefined", "null",
                  "secret", "token", "function"):
            assert is_likely_real_secret(v) is False, v

    def test_too_short(self):
        assert is_likely_real_secret("abc123") is False

    def test_empty_and_none(self):
        assert is_likely_real_secret("") is False
        assert is_likely_real_secret(None) is False

    def test_lowercase_identifier(self):
        assert is_likely_real_secret("apitokenvalue") is False  # var-name-like

    def test_value_with_code_punctuation(self):
        assert is_likely_real_secret("a={b:c}") is False
        assert is_likely_real_secret("foo bar baz qux") is False


class TestAcceptsRealSecrets:
    def test_high_entropy_api_key(self):
        assert is_likely_real_secret("sk-aB3xZ9qLmN7pR2tV8wY1cD4eF6gH0jK") is True

    def test_hex_token(self):
        assert is_likely_real_secret("9f8c2b1a7e4d6c3f0a5b8e2d1c4f7a9b") is True

    def test_jwt_like(self):
        jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abc123XYZ_def456"
        assert is_likely_real_secret(jwt) is True

    def test_aws_key_shape(self):
        assert is_likely_real_secret("AKIAIOSFODNN7EXAMPLE") is True
