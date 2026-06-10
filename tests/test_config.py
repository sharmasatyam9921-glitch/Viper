"""Tests for core.config — env coercion, validation, singleton."""

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core import config as cfgmod  # noqa: E402


@pytest.fixture(autouse=True)
def _clean_config():
    # Each test starts and ends with a fresh singleton so a reload doesn't leak.
    cfgmod.reset_config()
    yield
    cfgmod.reset_config()


def test_defaults(monkeypatch):
    for k in ("VIPER_PORT", "VIPER_BIND_HOST", "VIPER_DASHBOARD_TOKEN",
              "VIPER_UI_PORT", "VIPER_LOG_JSON"):
        monkeypatch.delenv(k, raising=False)
    c = cfgmod.get_config(reload=True)
    assert c.api_port == 8080
    assert c.ui_port == 3000
    assert c.dashboard_bind_localhost is True
    assert c.db_path.name == "viper.db"
    assert c.evograph_db_path.name == "evograph.db"
    assert c.db_path.is_absolute()


def test_env_override(monkeypatch):
    monkeypatch.setenv("VIPER_PORT", "9090")
    monkeypatch.setenv("VIPER_BIND_HOST", "0.0.0.0")
    monkeypatch.setenv("VIPER_DASHBOARD_TOKEN", "abc")
    monkeypatch.setenv("VIPER_LOG_JSON", "true")
    c = cfgmod.get_config(reload=True)
    assert c.api_port == 9090
    assert c.dashboard_bind_localhost is False
    assert c.dashboard_token == "abc"
    assert c.log_json is True


def test_invalid_port_raises(monkeypatch):
    monkeypatch.setenv("VIPER_PORT", "not-a-port")
    with pytest.raises(cfgmod.ConfigError):
        cfgmod.get_config(reload=True)


def test_out_of_range_port_raises(monkeypatch):
    monkeypatch.setenv("VIPER_PORT", "70000")
    with pytest.raises(cfgmod.ConfigError):
        cfgmod.get_config(reload=True)


def test_singleton_caches(monkeypatch):
    monkeypatch.delenv("VIPER_PORT", raising=False)
    a = cfgmod.get_config(reload=True)
    b = cfgmod.get_config()
    assert a is b
