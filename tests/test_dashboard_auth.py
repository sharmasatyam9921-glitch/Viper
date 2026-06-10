"""Tests for the dashboard authentication gate (dashboard/server.py)."""

import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "dashboard"))

import server  # noqa: E402  (dashboard/server.py)


class _Headers(dict):
    def get(self, k, default=""):
        return super().get(k, default)


class _Req:
    """Minimal stand-in exposing just `.headers` for _authorized()."""
    def __init__(self, headers=None):
        self.headers = _Headers(headers or {})


def _authorized(headers=None):
    return server.DashboardHandler._authorized(_Req(headers))


def test_localhost_no_token_is_open(monkeypatch):
    monkeypatch.delenv("VIPER_DASHBOARD_TOKEN", raising=False)
    monkeypatch.delenv("VIPER_BIND_HOST", raising=False)
    assert _authorized() is True


def test_public_bind_without_token_is_locked(monkeypatch):
    monkeypatch.delenv("VIPER_DASHBOARD_TOKEN", raising=False)
    monkeypatch.setenv("VIPER_BIND_HOST", "0.0.0.0")
    assert _authorized() is False


def test_token_requires_bearer(monkeypatch):
    monkeypatch.setenv("VIPER_DASHBOARD_TOKEN", "s3cr3t")
    assert _authorized({"Authorization": "Bearer s3cr3t"}) is True
    assert _authorized({"Authorization": "Bearer wrong"}) is False
    assert _authorized() is False  # no creds at all


def test_token_via_cookie(monkeypatch):
    monkeypatch.setenv("VIPER_DASHBOARD_TOKEN", "s3cr3t")
    assert _authorized({"Cookie": "theme=dark; viper_token=s3cr3t"}) is True
    assert _authorized({"Cookie": "viper_token=nope"}) is False


def test_health_path_is_exempt():
    assert "/api/health" in server.DashboardHandler._AUTH_EXEMPT_PATHS
