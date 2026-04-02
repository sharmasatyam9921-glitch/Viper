"""Tests for preflight checker — startup validation."""
import os
import pytest
from unittest.mock import patch
from core.preflight import (
    run_preflight, check_python_version, check_tool,
    check_ai_provider, check_env_var, PreflightReport, CheckResult,
)


class TestPythonVersion:
    def test_current_version_passes(self):
        result = check_python_version()
        assert result.passed is True  # We're running >= 3.10

    def test_result_has_version_string(self):
        result = check_python_version()
        assert "." in result.message  # e.g., "3.12.0"


class TestToolCheck:
    def test_found_tool(self):
        # python should always be findable
        with patch("shutil.which", return_value="/usr/bin/python"):
            result = check_tool("python", "install python", required=True)
            assert result.passed is True
            assert "found" in result.message

    def test_missing_tool_required(self):
        with patch("shutil.which", return_value=None):
            result = check_tool("nonexistent", "install it", required=True)
            assert result.passed is False
            assert result.required is True

    def test_missing_tool_optional(self):
        with patch("shutil.which", return_value=None):
            result = check_tool("nonexistent", "install it", required=False)
            assert result.passed is False
            assert result.required is False


class TestAIProvider:
    def test_cli_mode(self):
        with patch.dict(os.environ, {"VIPER_USE_CLI": "true"}, clear=False):
            result = check_ai_provider()
            assert result.passed is True
            assert "Claude CLI" in result.message

    def test_anthropic_key(self):
        with patch.dict(os.environ, {"ANTHROPIC_API_KEY": "sk-test"}, clear=False):
            result = check_ai_provider()
            assert result.passed is True

    def test_no_provider(self):
        env = {k: v for k, v in os.environ.items()
               if k not in ("VIPER_USE_CLI", "ANTHROPIC_API_KEY", "OPENAI_API_KEY", "OLLAMA_HOST")}
        with patch.dict(os.environ, env, clear=True), \
             patch("core.preflight.shutil.which", return_value=None), \
             patch("pathlib.Path.exists", return_value=False):
            result = check_ai_provider()
            assert result.passed is False


class TestEnvVar:
    def test_set_var(self):
        with patch.dict(os.environ, {"TEST_KEY": "secret_value"}):
            result = check_env_var("TEST_KEY", "test key")
            assert result.passed is True
            assert "secr..." in result.message  # masked

    def test_unset_var(self):
        env = {k: v for k, v in os.environ.items() if k != "NONEXISTENT_KEY"}
        with patch.dict(os.environ, env, clear=True):
            result = check_env_var("NONEXISTENT_KEY", "test")
            assert result.passed is False


class TestPreflightReport:
    def test_all_pass(self):
        report = PreflightReport(checks=[
            CheckResult("a", True, "ok", required=True),
            CheckResult("b", True, "ok", required=True),
        ])
        assert report.passed is True
        assert len(report.failures) == 0

    def test_required_failure(self):
        report = PreflightReport(checks=[
            CheckResult("a", True, "ok", required=True),
            CheckResult("b", False, "fail", required=True),
        ])
        assert report.passed is False
        assert len(report.failures) == 1

    def test_optional_failure_still_passes(self):
        report = PreflightReport(checks=[
            CheckResult("a", True, "ok", required=True),
            CheckResult("b", False, "warn", required=False),
        ])
        assert report.passed is True
        assert len(report.warnings) == 1

    def test_format_output(self):
        report = PreflightReport(checks=[
            CheckResult("Python", True, "3.12", required=True),
        ])
        output = report.format()
        assert "Preflight" in output
        assert "Python" in output


class TestRunPreflight:
    def test_returns_tuple(self):
        ok, report = run_preflight()
        assert isinstance(ok, bool)
        assert isinstance(report, PreflightReport)

    def test_has_python_check(self):
        _, report = run_preflight()
        names = [c.name for c in report.checks]
        assert "Python version" in names

    def test_has_ai_provider_check(self):
        _, report = run_preflight()
        names = [c.name for c in report.checks]
        assert "AI Provider" in names
