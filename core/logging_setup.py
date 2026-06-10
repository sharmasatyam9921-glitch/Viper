"""Central logging + observability bootstrap for VIPER.

Until now VIPER had ~210 ``logging.getLogger("viper.*")`` call sites but no
entrypoint ever configured the root logger, so anything below WARNING was
silently dropped by Python's "last resort" handler. This module gives every
entrypoint one call -- ``configure_logging()`` -- that installs a single root
handler with either human-readable or JSON output.

It also threads a ``hunt_id`` through every log line emitted during a hunt,
via a :class:`contextvars.ContextVar`. The id is the SAME slug the audit log
uses (``AuditLogger.hunt_id`` / ``make_hunt_id``), so a JSON log line and an
``audit.jsonl`` row can be joined on ``hunt_id`` after the fact. Because it is
a ContextVar (not thread-local), the binding propagates correctly across
``asyncio`` tasks spawned inside a hunt and is naturally isolated between
concurrently-running hunts in the same process (e.g. the daemon, parallel
hunter).

Typical wiring
--------------
Entrypoint (once, very early)::

    from core.logging_setup import configure_logging
    configure_logging(level="INFO", json_output=bool(os.getenv("VIPER_LOG_JSON")))

Per hunt (wrap the run so every line carries the id)::

    from core.logging_setup import bind_hunt_id
    with bind_hunt_id(audit.hunt_id):
        result = await hm.run()

The filter is attached to the root handler, so EVERY ``viper.*`` logger
inherits the ``hunt_id`` field automatically -- no per-module changes needed
for the correlation id to appear. The "highest-value getLogger sites" listed
in the design are the ones whose *log calls* most benefit from the context
(coordinator, workers, react loop), not sites that need code changes.
"""

from __future__ import annotations

import contextlib
import contextvars
import json
import logging
import os
import sys
import time
from typing import Iterator, Optional

# --------------------------------------------------------------------------
# Correlation context
# --------------------------------------------------------------------------

# Holds the active hunt_id for the current execution context (task/thread).
# Empty string => no hunt bound (e.g. dashboard request handling, startup).
_hunt_id_var: contextvars.ContextVar[str] = contextvars.ContextVar(
    "viper_hunt_id", default=""
)

# Optional secondary correlation id: the worker / actor currently executing.
# Lets a JSON line be attributed to e.g. "sqli_probe_3" without the worker
# having to format it into every message. Set by the swarm coordinator.
_actor_var: contextvars.ContextVar[str] = contextvars.ContextVar(
    "viper_actor", default=""
)


def set_hunt_id(hunt_id: str) -> contextvars.Token:
    """Bind ``hunt_id`` for the current context. Returns a reset token."""
    return _hunt_id_var.set(hunt_id or "")


def reset_hunt_id(token: contextvars.Token) -> None:
    """Undo a previous :func:`set_hunt_id` using its token."""
    with contextlib.suppress(ValueError, LookupError):
        _hunt_id_var.reset(token)


def current_hunt_id() -> str:
    """Return the hunt_id bound to the current context (or '')."""
    return _hunt_id_var.get()


def set_actor(actor: str) -> contextvars.Token:
    """Bind the active worker/actor id for the current context."""
    return _actor_var.set(actor or "")


def reset_actor(token: contextvars.Token) -> None:
    with contextlib.suppress(ValueError, LookupError):
        _actor_var.reset(token)


@contextlib.contextmanager
def bind_hunt_id(hunt_id: str, *, actor: str = "") -> Iterator[str]:
    """Context manager that binds (and auto-resets) the hunt correlation ids.

    Usage::

        with bind_hunt_id(audit.hunt_id):
            await hm.run()

    Works across ``await`` boundaries: any ``asyncio.create_task`` started
    inside the ``with`` block copies the current context and therefore sees
    the same ``hunt_id``.
    """
    h_tok = set_hunt_id(hunt_id)
    a_tok = set_actor(actor) if actor else None
    try:
        yield hunt_id
    finally:
        if a_tok is not None:
            reset_actor(a_tok)
        reset_hunt_id(h_tok)


# --------------------------------------------------------------------------
# Filter: injects correlation ids onto every record
# --------------------------------------------------------------------------


class HuntContextFilter(logging.Filter):
    """Attaches ``hunt_id`` / ``actor`` from the ContextVars to each record.

    Attached to the root *handler* (not a single logger) so every ``viper.*``
    logger in the tree inherits it without per-module wiring. A ``filter``
    that always returns True is the canonical way to enrich records in stdlib
    logging.
    """

    def filter(self, record: logging.LogRecord) -> bool:  # noqa: A003
        # Don't clobber an explicitly-passed extra={"hunt_id": ...}.
        if not getattr(record, "hunt_id", ""):
            record.hunt_id = _hunt_id_var.get()
        if not getattr(record, "actor", ""):
            record.actor = _actor_var.get()
        return True


# --------------------------------------------------------------------------
# Formatters
# --------------------------------------------------------------------------


# Fields the stdlib LogRecord always carries -- everything NOT in here is
# treated as caller-supplied ``extra=`` and folded into the JSON line.
_RESERVED = frozenset(
    vars(logging.makeLogRecord({})).keys()
) | {"message", "asctime", "taskName"}


class JsonFormatter(logging.Formatter):
    """One JSON object per line. Stable key order; safe against bad payloads.

    Always includes: ts, level, logger, msg, hunt_id. Includes ``actor``,
    ``exc``, and any ``extra=`` keys when present. ``hunt_id`` is emitted even
    when empty so downstream log shippers can rely on the field existing.
    """

    def format(self, record: logging.LogRecord) -> str:
        rec = {
            "ts": time.strftime(
                "%Y-%m-%dT%H:%M:%S", time.gmtime(record.created)
            )
            + f".{int(record.msecs):03d}Z",
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
            "hunt_id": getattr(record, "hunt_id", ""),
        }
        actor = getattr(record, "actor", "")
        if actor:
            rec["actor"] = actor
        if record.exc_info:
            rec["exc"] = self.formatException(record.exc_info)
        # Fold caller-supplied extras (extra={...}) into the line.
        for k, v in record.__dict__.items():
            if k in _RESERVED or k in rec or k in ("hunt_id", "actor"):
                continue
            try:
                json.dumps(v)
                rec[k] = v
            except (TypeError, ValueError):
                rec[k] = str(v)
        return json.dumps(rec, default=str, separators=(",", ":"))


class HumanFormatter(logging.Formatter):
    """Console formatter that surfaces hunt_id inline when present.

    ``2026-06-09 12:00:00 INFO  [viper.swarm_coordinator] (h=acme_169..) msg``
    The ``(h=..)`` segment is omitted entirely outside a hunt to keep startup
    and dashboard logs uncluttered.
    """

    _BASE = "%(asctime)s %(levelname)-5s [%(name)s]%(hunt_seg)s %(message)s"

    def __init__(self) -> None:
        super().__init__(self._BASE, datefmt="%Y-%m-%d %H:%M:%S")

    def format(self, record: logging.LogRecord) -> str:
        hid = getattr(record, "hunt_id", "")
        actor = getattr(record, "actor", "")
        if hid and actor:
            record.hunt_seg = f" (h={hid} a={actor})"
        elif hid:
            record.hunt_seg = f" (h={hid})"
        else:
            record.hunt_seg = ""
        return super().format(record)


# --------------------------------------------------------------------------
# configure_logging
# --------------------------------------------------------------------------

# Set once configure_logging has installed handlers, so a second call is a
# cheap reconfigure rather than a duplicate-handler bug.
_CONFIGURED = False


def configure_logging(
    level: "str | int" = "INFO",
    json_output: Optional[bool] = None,
    *,
    stream=None,
    force: bool = False,
    quiet_loggers: Optional[dict] = None,
) -> logging.Logger:
    """Install VIPER's single root handler. Idempotent.

    Parameters
    ----------
    level:
        Root level. Accepts ``"DEBUG"`` etc. or an ``int``. Overridable at
        runtime by the ``VIPER_LOG_LEVEL`` env var (env wins only when the
        caller passes the default).
    json_output:
        ``True`` => one JSON object per line (for log shippers / files).
        ``False`` => human console format.
        ``None`` => auto: JSON when ``VIPER_LOG_JSON`` is truthy, else human.
    stream:
        Target stream (default ``sys.stderr`` so stdout stays clean for the
        narrator / piped report output).
    force:
        Re-apply even if already configured (e.g. flip to JSON mid-process).
    quiet_loggers:
        Optional ``{logger_name: level}`` to dial down noisy third parties.
        Sensible defaults applied for urllib3 / asyncio / aiohttp.

    Returns the configured ``"viper"`` parent logger for convenience.
    """
    global _CONFIGURED

    # Resolve level (env override when caller left the default).
    if level == "INFO":
        level = os.getenv("VIPER_LOG_LEVEL", "INFO")
    if isinstance(level, str):
        level = logging.getLevelName(level.upper())
        if not isinstance(level, int):
            level = logging.INFO

    if json_output is None:
        json_output = os.getenv("VIPER_LOG_JSON", "").strip().lower() in (
            "1", "true", "yes", "on", "json",
        )

    root = logging.getLogger()

    if _CONFIGURED and not force:
        root.setLevel(level)
        return logging.getLogger("viper")

    # Remove handlers we (or a stray basicConfig) previously installed so a
    # re-config or a library-level basicConfig doesn't double-emit lines.
    for h in list(root.handlers):
        root.removeHandler(h)
        with contextlib.suppress(Exception):
            h.close()

    handler = logging.StreamHandler(stream or sys.stderr)
    handler.setFormatter(JsonFormatter() if json_output else HumanFormatter())
    handler.addFilter(HuntContextFilter())  # enrich at the handler => global
    root.addHandler(handler)
    root.setLevel(level)

    # Tame chatty dependencies.
    defaults = {
        "urllib3": logging.WARNING,
        "asyncio": logging.WARNING,
        "aiohttp.access": logging.WARNING,
        "httpx": logging.WARNING,
        "websockets": logging.WARNING,
    }
    if quiet_loggers:
        defaults.update(quiet_loggers)
    for name, lvl in defaults.items():
        logging.getLogger(name).setLevel(lvl)

    _CONFIGURED = True
    logging.getLogger("viper").debug(
        "logging configured", extra={"json": json_output, "level": level}
    )
    return logging.getLogger("viper")


def is_configured() -> bool:
    """True once :func:`configure_logging` has run in this process."""
    return _CONFIGURED
