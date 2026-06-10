"""A single typed egress chokepoint for VIPER.

Every outbound action that touches a target — HTTP and subprocess (DNS rides on
HTTP/subprocess tools) — can be routed through this module so it is uniformly:

  * **scope-checked** (fail closed),
  * **rate-limited** (reusing the existing per-host token bucket — not a new one),
  * **timeout-bounded**, and
  * **audited**.

A hunt installs one :class:`EgressContext` (scope predicate + audit sink +
limits) via :func:`set_context`; every gateway call reads it from a ContextVar,
so concurrent hunts (daemon / dashboard) are isolated and async child-tasks
inherit it. **No context installed → permissive legacy mode**, mirroring the
worker HTTP helper, so lab/CTF runs and the existing test-suite are unaffected.

This is the architectural spine described in PLAN.md Section 7. It is adopted
incrementally: the module + tests land with zero call-site changes; HackMode
installs a context alongside its scope guard; individual call sites migrate to
``gateway.http`` / ``gateway.run_subprocess`` over time.
"""

from __future__ import annotations

import asyncio
import contextvars
import logging
import time
from dataclasses import dataclass, field
from typing import Callable, Optional, Sequence
from urllib.parse import urlparse

logger = logging.getLogger("viper.tool_gateway")

ScopePredicate = Callable[[str], bool]    # (url|host) -> True if in scope
AuditSink = Callable[[str, dict], None]   # (action, payload) -> None, never raises


@dataclass
class EgressLimits:
    http_timeout_s: float = 30.0
    subprocess_timeout_s: float = 300.0


@dataclass
class EgressContext:
    scope: Optional[ScopePredicate] = None     # None => unrestricted (legacy)
    audit: Optional[AuditSink] = None          # None => log only
    limits: EgressLimits = field(default_factory=EgressLimits)
    hunt_id: str = ""
    # OSINT/API hosts exempt from the target SCOPE check (still audited + rate
    # limited) — e.g. shodan, crt.sh. They are infrastructure, not the target.
    infra_hosts: frozenset = frozenset()


_ctx_var: contextvars.ContextVar = contextvars.ContextVar(
    "viper_egress_ctx", default=None
)


def set_context(ctx: EgressContext) -> contextvars.Token:
    return _ctx_var.set(ctx)


def reset_context(token: contextvars.Token) -> None:
    try:
        _ctx_var.reset(token)
    except (ValueError, LookupError):
        pass


def clear_context() -> None:
    _ctx_var.set(None)


def current() -> Optional[EgressContext]:
    return _ctx_var.get()


# ----- helpers --------------------------------------------------------------

def _host_of(url_or_host: str) -> str:
    if not url_or_host:
        return ""
    if "://" in url_or_host:
        return urlparse(url_or_host).hostname or ""
    return url_or_host.split("/", 1)[0].split(":", 1)[0]


def _audit(ctx: Optional[EgressContext], action: str, payload: dict) -> None:
    if ctx and ctx.audit:
        try:
            ctx.audit(action, payload)
            return
        except Exception:
            logger.debug("audit sink raised", exc_info=True)
    logger.info("egress %s %s", action, payload)


def _scope_ok(ctx: Optional[EgressContext], target: str, *, is_infra: bool) -> bool:
    """FAIL CLOSED: a predicate error denies. No ctx/predicate => allow (legacy)."""
    if ctx is None or ctx.scope is None:
        return True
    if is_infra or _host_of(target) in ctx.infra_hosts:
        return True
    try:
        return bool(ctx.scope(target))
    except Exception as e:  # noqa: BLE001
        logger.warning("scope predicate raised for %s (%s) -> deny", target, e)
        return False


async def _rate(target: str) -> bool:
    # Reuse the existing shared token bucket — do NOT introduce a 4th limiter.
    try:
        from core.swarm_workers.vuln._rate_limit import wait_for_token
        return await wait_for_token(target)
    except Exception:
        return True  # limiter unavailable → don't block


# ----- public API: HTTP -----------------------------------------------------

async def http(method: str, url: str, *, is_infra: bool = False,
               timeout: Optional[float] = None, rate_limit: bool = True, **kw):
    """Single HTTP egress point. Returns _http.HttpResp | None (None = denied/error)."""
    ctx = current()
    t0 = time.time()
    if not _scope_ok(ctx, url, is_infra=is_infra):
        _audit(ctx, "egress.blocked",
               {"kind": "http", "method": method, "url": url, "reason": "scope"})
        return None
    if rate_limit and not await _rate(url):
        _audit(ctx, "egress.blocked",
               {"kind": "http", "url": url, "reason": "rate_limit"})
        return None
    to = timeout if timeout is not None else (ctx.limits.http_timeout_s if ctx else 30.0)
    from core.swarm_workers.vuln._http import fetch
    resp = await fetch(method, url, timeout=to, rate_limit=False, **kw)
    _audit(ctx, "egress.http",
           {"method": method, "url": url,
            "status": getattr(resp, "status", None),
            "ms": int((time.time() - t0) * 1000)})
    return resp


# ----- public API: subprocess ----------------------------------------------

@dataclass
class ProcResult:
    returncode: int
    stdout: str
    stderr: str
    timed_out: bool = False


async def run_subprocess(argv: Sequence[str], *, scope_target: Optional[str] = None,
                         is_infra: bool = False, timeout: Optional[float] = None,
                         stdin: Optional[str] = None) -> Optional[ProcResult]:
    """Single subprocess egress point.

    `scope_target` is the host/url the tool will hit (e.g. ``nuclei -u <t>``);
    None means a local-only tool that needs no scope check. Returns a ProcResult,
    or None when the scope check denies the spawn.
    """
    ctx = current()
    t0 = time.time()
    if scope_target and not _scope_ok(ctx, scope_target, is_infra=is_infra):
        _audit(ctx, "egress.blocked",
               {"kind": "subprocess", "argv": list(argv)[:1], "target": scope_target,
                "reason": "scope"})
        return None

    to = timeout if timeout is not None else (ctx.limits.subprocess_timeout_s if ctx else 300.0)
    try:
        proc = await asyncio.create_subprocess_exec(
            *argv,
            stdin=asyncio.subprocess.PIPE if stdin else None,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
    except (OSError, FileNotFoundError) as e:
        _audit(ctx, "egress.subprocess",
               {"argv": list(argv)[:1], "target": scope_target, "error": repr(e)})
        return ProcResult(returncode=127, stdout="", stderr=repr(e))

    timed_out = False
    try:
        out, err = await asyncio.wait_for(
            proc.communicate(stdin.encode() if stdin else None), timeout=to)
    except asyncio.TimeoutError:
        timed_out = True
        try:
            proc.kill()
            out, err = await proc.communicate()
        except Exception:
            out, err = b"", b""
    res = ProcResult(
        returncode=proc.returncode if proc.returncode is not None else -1,
        stdout=(out or b"").decode("utf-8", "replace"),
        stderr=(err or b"").decode("utf-8", "replace"),
        timed_out=timed_out,
    )
    _audit(ctx, "egress.subprocess",
           {"argv": list(argv)[:1], "target": scope_target, "rc": res.returncode,
            "timed_out": timed_out, "ms": int((time.time() - t0) * 1000)})
    return res
