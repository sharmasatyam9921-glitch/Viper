"""Credential-hygiene env fallback for session auth: a session token/cookie can be supplied
via env var (VIPER_AUTH_BEARER / VIPER_SESSION_COOKIE and the *_B identity-B variants) so it
never appears on the command line, in shell history, or in `ps` output. An explicit CLI flag
always wins. Added so an authenticated hunt against a hardened target (where the real
IDOR/BOLA surface lives) can be run without ever pasting the token where a tool or operator
could capture it."""
from __future__ import annotations

import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import core.hack_cli as hc  # noqa: E402


class _Args:
    def __init__(self, **kw):
        self.cookie_b = kw.get("cookie_b")
        self.auth_bearer_b = kw.get("auth_bearer_b")
        self.auth_header_b = kw.get("auth_header_b", [])
        self.owner_marker = kw.get("owner_marker", [])


def _clear_env():
    for k in ("VIPER_AUTH_BEARER", "VIPER_SESSION_COOKIE",
              "VIPER_AUTH_BEARER_B", "VIPER_SESSION_COOKIE_B"):
        os.environ.pop(k, None)


def test_identity_b_from_env_when_no_cli_flag():
    _clear_env()
    os.environ["VIPER_SESSION_COOKIE_B"] = "sid=attackerB"
    try:
        cfg = hc._build_bola_config(
            _Args(owner_marker=["victim@example.com"]),
            {"Cookie": "sid=ownerA"},
        )
        assert cfg is not None
        assert (cfg.get("attacker_headers") or {}).get("Cookie") == "sid=attackerB"
    finally:
        _clear_env()


def test_cli_flag_wins_over_env_for_identity_b():
    _clear_env()
    os.environ["VIPER_SESSION_COOKIE_B"] = "sid=fromEnv"
    try:
        cfg = hc._build_bola_config(
            _Args(cookie_b="sid=fromCLI", owner_marker=["victim@example.com"]),
            {"Cookie": "sid=ownerA"},
        )
        assert (cfg.get("attacker_headers") or {}).get("Cookie") == "sid=fromCLI"
    finally:
        _clear_env()


def test_no_env_and_no_flag_leaves_bola_off():
    _clear_env()
    # No identity B anywhere and no markers -> BOLA not requested -> None (quiet).
    assert hc._build_bola_config(_Args(), {"Cookie": "sid=ownerA"}) is None


def test_bearer_b_from_env():
    _clear_env()
    os.environ["VIPER_AUTH_BEARER_B"] = "tokenB"
    try:
        cfg = hc._build_bola_config(
            _Args(owner_marker=["victim@example.com"]),
            {"Cookie": "sid=ownerA"},
        )
        assert cfg is not None
        assert (cfg.get("attacker_headers") or {}).get("Authorization") == "Bearer tokenB"
    finally:
        _clear_env()
