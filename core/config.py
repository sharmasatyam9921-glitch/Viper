"""Centralized, validated configuration for VIPER.

Single source of truth for ports, hosts, filesystem paths, timeouts, concurrency
limits and the dashboard token. Historically these were re-derived per module
(three separate copies of the DB path, hardcoded ports, scattered os.environ
reads). Load once via :func:`get_config`; prefer it over reading os.environ for
these values elsewhere.

The object is a frozen dataclass built from the process environment (with a
shared ``.env`` loader). Real environment variables always win over ``.env``.
"""

from __future__ import annotations

import os
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

# Repo root = parent of core/. Stable regardless of CWD.
_PROJECT_ROOT = Path(__file__).resolve().parent.parent


class ConfigError(ValueError):
    """Raised when configuration fails validation."""


# ----- .env loader (shared; supersedes the hand-rolled loop in viper.py) -----

def load_dotenv(path: Optional[Path] = None) -> None:
    """Populate os.environ from a .env file (setdefault — real env wins)."""
    path = path or (_PROJECT_ROOT / ".env")
    try:
        if not path.exists():
            return
        for raw in path.read_text(encoding="utf-8").splitlines():
            line = raw.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, v = line.split("=", 1)
            os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))
    except OSError:
        pass  # a missing/unreadable .env is not fatal


# ----- env coercion --------------------------------------------------------

def _s(key: str, default: str) -> str:
    v = os.environ.get(key)
    return v.strip() if v and v.strip() else default


def _i(key: str, default: int) -> int:
    v = os.environ.get(key)
    if not v or not v.strip():
        return default
    try:
        return int(v.strip())
    except ValueError as e:
        raise ConfigError(f"{key}={v!r} is not an integer") from e


def _f(key: str, default: float) -> float:
    v = os.environ.get(key)
    if not v or not v.strip():
        return default
    try:
        return float(v.strip())
    except ValueError as e:
        raise ConfigError(f"{key}={v!r} is not a number") from e


def _b(key: str, default: bool) -> bool:
    v = os.environ.get(key)
    if v is None or not v.strip():
        return default
    return v.strip().lower() in ("1", "true", "yes", "on")


def _p(key: str, default: Path) -> Path:
    v = os.environ.get(key)
    return Path(v).expanduser() if v and v.strip() else default


_LOOPBACK = {"127.0.0.1", "localhost", "::1", ""}


@dataclass(frozen=True)
class ViperConfig:
    # --- filesystem ---
    project_root: Path = _PROJECT_ROOT
    data_dir: Path = _PROJECT_ROOT / "data"
    state_dir: Path = _PROJECT_ROOT / "state"
    logs_dir: Path = _PROJECT_ROOT / "logs"
    reports_dir: Path = _PROJECT_ROOT / "reports"
    db_path: Path = _PROJECT_ROOT / "data" / "viper.db"
    evograph_db_path: Path = _PROJECT_ROOT / "data" / "evograph.db"
    hunts_dir: Path = _PROJECT_ROOT / "state" / "hunts"

    # --- network ---
    api_host: str = "127.0.0.1"          # VIPER_BIND_HOST
    api_port: int = 8080                  # VIPER_PORT
    ui_port: int = 3000                   # VIPER_UI_PORT
    dashboard_token: str = ""             # VIPER_DASHBOARD_TOKEN ("" = no auth)
    webapp_extra_origins: tuple = ()      # VIPER_WEBAPP_ORIGINS (csv)

    # --- timeouts (seconds) ---
    default_http_timeout_s: float = 30.0  # VIPER_HTTP_TIMEOUT
    db_timeout_s: float = 10.0

    # --- concurrency / rate ---
    max_concurrent_workers: int = 12      # VIPER_MAX_WORKERS
    http_max_concurrent: int = 10
    rate_limit_rps: float = 2.0           # VIPER_RATE_LIMIT_RPS

    # --- logging ---
    log_level: str = "INFO"               # VIPER_LOG_LEVEL
    log_json: bool = False                # VIPER_LOG_JSON

    @property
    def dashboard_bind_localhost(self) -> bool:
        return self.api_host in _LOOPBACK

    @classmethod
    def from_env(cls) -> "ViperConfig":
        root = _p("VIPER_PROJECT_ROOT", _PROJECT_ROOT)
        data = _p("VIPER_DATA_DIR", root / "data")
        state = _p("VIPER_STATE_DIR", root / "state")
        origins = tuple(
            o.strip().rstrip("/") for o in _s("VIPER_WEBAPP_ORIGINS", "").split(",")
            if o.strip()
        )
        cfg = cls(
            project_root=root,
            data_dir=data,
            state_dir=state,
            logs_dir=_p("VIPER_LOGS_DIR", root / "logs"),
            reports_dir=_p("VIPER_REPORTS_DIR", root / "reports"),
            db_path=_p("VIPER_DB_PATH", data / "viper.db"),
            evograph_db_path=_p("VIPER_EVOGRAPH_DB", data / "evograph.db"),
            hunts_dir=_p("VIPER_HUNTS_DIR", state / "hunts"),
            api_host=_s("VIPER_BIND_HOST", "127.0.0.1"),
            api_port=_i("VIPER_PORT", 8080),
            ui_port=_i("VIPER_UI_PORT", 3000),
            dashboard_token=_s("VIPER_DASHBOARD_TOKEN", ""),
            webapp_extra_origins=origins,
            default_http_timeout_s=_f("VIPER_HTTP_TIMEOUT", 30.0),
            db_timeout_s=_f("VIPER_DB_TIMEOUT", 10.0),
            max_concurrent_workers=_i("VIPER_MAX_WORKERS", 12),
            http_max_concurrent=_i("VIPER_HTTP_MAX_CONCURRENT", 10),
            rate_limit_rps=_f("VIPER_RATE_LIMIT_RPS", 2.0),
            log_level=_s("VIPER_LOG_LEVEL", "INFO"),
            log_json=_b("VIPER_LOG_JSON", False),
        )
        cfg.validate()
        return cfg

    def validate(self) -> None:
        for label, port in (("api_port", self.api_port), ("ui_port", self.ui_port)):
            if not (1 <= port <= 65535):
                raise ConfigError(f"{label}={port} is out of range 1..65535")
        if self.max_concurrent_workers < 1:
            raise ConfigError("max_concurrent_workers must be >= 1")
        if self.default_http_timeout_s <= 0:
            raise ConfigError("default_http_timeout_s must be > 0")
        # A public bind without a token is allowed to load (the dashboard then
        # locks itself down) but it is a misconfiguration worth flagging.
        # Validation stays non-fatal here; the server prints the loud warning.


# ----- singleton -----------------------------------------------------------

_lock = threading.Lock()
_config: Optional[ViperConfig] = None


def get_config(*, reload: bool = False) -> ViperConfig:
    """Return the process-wide config, building it once from env (+ .env)."""
    global _config
    if _config is not None and not reload:
        return _config
    with _lock:
        if _config is None or reload:
            load_dotenv()
            _config = ViperConfig.from_env()
    return _config


def reset_config() -> None:
    """Drop the cached config (tests that mutate the environment)."""
    global _config
    with _lock:
        _config = None
