"""Tests for the DVWA benchmark auth-setup adapter (parsing + error paths).

The happy-path login flow is proven by the live benchmark; here we lock the
CSRF-token extraction, the setups registry, and fail-closed error handling so a
DVWA layout change or an unreachable host surfaces clearly instead of silently
producing a bad cookie.
"""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "benchmark"))

from harness.dvwa import DvwaSetupError, SETUPS, _token, setup_dvwa  # noqa: E402


class TestTokenExtraction:
    def test_extracts_user_token(self):
        html = '<input type="hidden" name="user_token" value="0a1b2c3d4e5f6071" />'
        assert _token(html) == "0a1b2c3d4e5f6071"

    def test_missing_token_raises(self):
        with pytest.raises(DvwaSetupError):
            _token("<html>no token here</html>")


class TestRegistry:
    def test_dvwa_registered(self):
        assert "dvwa" in SETUPS
        assert SETUPS["dvwa"] is setup_dvwa


class TestErrorPaths:
    def test_unreachable_host_raises_setup_error(self):
        # Nothing is listening on this port → wrapped as DvwaSetupError, not a
        # raw URLError, so the orchestrator can report it cleanly.
        with pytest.raises(DvwaSetupError):
            setup_dvwa("http://127.0.0.1:1", timeout=2)
