"""Shared HTTP plumbing for vuln workers.

stdlib-only — keeps swarm workers dependency-free. Workers can opt into
this helper or roll their own. Each request is timeboxed, follows
redirects optionally, and tolerates the usual network errors with `None`.
"""

from __future__ import annotations

import asyncio
import contextvars
import logging
import ssl
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Callable, Optional

logger = logging.getLogger("viper.swarm_workers.vuln._http")


# --- Scope gate -------------------------------------------------------------
# A hunt installs a predicate here so every worker request is checked against
# the engagement scope BEFORE it leaves the box. It lives in a ContextVar so
# concurrent hunts (daemon / dashboard) don't clobber each other's scope, and
# defaults to None → unrestricted (legacy behavior; lab/CTF run without a gate
# and the existing test-suite is unaffected). The gate FAILS CLOSED: any error
# evaluating the predicate denies the request.
_scope_guard_var: contextvars.ContextVar[Optional[Callable[[str], bool]]] = \
    contextvars.ContextVar("viper_scope_guard", default=None)


def set_scope_guard(fn: Optional[Callable[[str], bool]]) -> None:
    """Install a predicate `fn(url) -> bool` (True = in scope). None clears it."""
    _scope_guard_var.set(fn)


def clear_scope_guard() -> None:
    _scope_guard_var.set(None)


def get_scope_guard() -> Optional[Callable[[str], bool]]:
    """The currently-installed scope predicate (None if unrestricted)."""
    return _scope_guard_var.get()


def is_in_scope(url: str) -> bool:
    """True if `url` may be requested. No guard installed → unrestricted."""
    guard = _scope_guard_var.get()
    if guard is None:
        return True
    try:
        return bool(guard(url))
    except Exception as e:  # noqa: BLE001 — fail closed on any guard error
        logger.warning("scope guard raised for %s (%s) — denying", url, e)
        return False


# --- Session auth -----------------------------------------------------------
# A hunt may install session auth (a recovered/operator-supplied Bearer token or
# Cookie) here so EVERY worker tests the app as a logged-in user — that's where
# IDOR/BOLA/business-logic flaws live. Lives in a ContextVar (concurrent-hunt
# safe); default empty → unauthenticated (legacy behavior). Per-call `headers`
# always override the session auth, so a worker that needs a specific auth state
# (e.g. auth-bypass probes) can still set its own.
_auth_var: contextvars.ContextVar[dict] = contextvars.ContextVar(
    "viper_auth_headers", default={})


def set_auth(headers: Optional[dict[str, str]]) -> None:
    """Install session auth headers applied to every worker request.

    e.g. ``{"Authorization": "Bearer eyJ..."}`` or ``{"Cookie": "session=..."}``.
    None/empty clears it.
    """
    _auth_var.set(dict(headers) if headers else {})


def clear_auth() -> None:
    _auth_var.set({})


def get_auth() -> dict[str, str]:
    return _auth_var.get()


# --- Upstream proxy (Burp / ZAP) --------------------------------------------
# A hunt may route every worker request through an intercepting proxy so the
# operator can watch, log, and match-replace VIPER's traffic in Burp Suite (or
# ZAP). Lives in a ContextVar (concurrent-hunt safe); default None → direct.
# HTTPS through an intercepting proxy is a MITM, so the opener already disables
# cert verification (see _build_opener) — that's required for Burp to see TLS.
_proxy_var: contextvars.ContextVar[Optional[str]] = contextvars.ContextVar(
    "viper_upstream_proxy", default=None)


def set_proxy(url: Optional[str]) -> None:
    """Route every worker request through `url` (e.g. 'http://127.0.0.1:8080').

    None/empty clears it (direct connection).
    """
    _proxy_var.set(url.strip() if url and url.strip() else None)


def clear_proxy() -> None:
    _proxy_var.set(None)


def get_proxy() -> Optional[str]:
    return _proxy_var.get()


@dataclass
class HttpResp:
    status: int
    headers: dict[str, str]
    body: str
    final_url: str

    @property
    def ok(self) -> bool:
        return 200 <= self.status < 400


def _build_opener(*, follow_redirects: bool,
                  proxy: Optional[str] = None) -> urllib.request.OpenerDirector:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE  # bug-bounty / CTF targets often have bad certs
    handlers = [urllib.request.HTTPSHandler(context=ctx)]
    if proxy:
        # Route both schemes through the intercepting proxy (Burp/ZAP).
        handlers.append(urllib.request.ProxyHandler({"http": proxy, "https": proxy}))
    else:
        # Empty mapping = bypass any environment proxy (predictable direct path).
        handlers.append(urllib.request.ProxyHandler({}))
    if not follow_redirects:
        class _NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, *a, **kw): return None
        handlers.append(_NoRedirect())
    return urllib.request.build_opener(*handlers)


def _fetch_sync(
    method: str,
    url: str,
    *,
    headers: Optional[dict[str, str]] = None,
    body: Optional[bytes] = None,
    timeout: float = 10.0,
    follow_redirects: bool = True,
    proxy: Optional[str] = None,
) -> Optional[HttpResp]:
    if not url:
        return None
    # Defense-in-depth: the default urllib opener includes a FileHandler, so a
    # stray file:// (or ftp://, etc.) URL would read a local resource. Worker
    # traffic is HTTP only — refuse anything else regardless of where it came from.
    if urllib.parse.urlsplit(url).scheme.lower() not in ("http", "https"):
        logger.debug("refusing non-http(s) scheme: %s", url)
        return None
    h = {"User-Agent": "viper-swarm/1.0", **(headers or {})}
    req = urllib.request.Request(url, data=body, headers=h, method=method)
    opener = _build_opener(follow_redirects=follow_redirects, proxy=proxy)
    try:
        with opener.open(req, timeout=timeout) as r:
            data = r.read(256 * 1024)
            return HttpResp(
                status=getattr(r, "status", r.getcode()),
                headers={k.lower(): v for k, v in r.headers.items()},
                body=data.decode("utf-8", errors="replace"),
                final_url=r.geturl(),
            )
    except urllib.error.HTTPError as e:
        try:
            data = e.read(256 * 1024) if e.fp else b""
        except Exception:
            data = b""
        return HttpResp(
            status=e.code,
            headers={k.lower(): v for k, v in (e.headers or {}).items()},
            body=data.decode("utf-8", errors="replace") if data else "",
            final_url=url,
        )
    except (urllib.error.URLError, OSError, TimeoutError) as e:
        logger.debug("fetch error %s %s: %s", method, url, e)
        return None
    except Exception as e:  # noqa: BLE001
        logger.debug("unexpected fetch error %s %s: %s", method, url, e)
        return None


async def fetch(
    method: str,
    url: str,
    *,
    headers: Optional[dict[str, str]] = None,
    body: Optional[bytes] = None,
    timeout: float = 10.0,
    follow_redirects: bool = True,
    rate_limit: bool = True,
    use_session_auth: bool = True,
) -> Optional[HttpResp]:
    """Async wrapper around stdlib urllib via asyncio.to_thread.

    Token-bucket rate-limited per host by default (30 req/s, burst 60).
    Pass `rate_limit=False` to bypass — only useful for the rate-limiter
    own tests.

    Every request is checked against the installed scope guard first; an
    off-scope URL returns None without touching the network.

    use_session_auth: when True (default) the globally-installed session auth
    (see set_auth) is merged into the request, so every worker tests the app as
    the logged-in user. Workers that fully specify their own identities — the
    two-account BOLA worker especially — MUST pass False, otherwise the global
    session leaks into their "attacker" and "anonymous" probes and corrupts the
    result (a leftover owner cookie makes an anon control look public; a leftover
    owner Bearer makes the attacker look authorized). Per-call `headers` are then
    sent verbatim.
    """
    if url and not is_in_scope(url):
        logger.warning("scope gate blocked off-scope request: %s %s", method, url)
        return None
    # Merge session auth (if installed). Per-call headers win, so a worker can
    # still override (e.g. send no auth, or its own Authorization). Workers doing
    # identity-controlled testing opt out entirely via use_session_auth=False.
    if use_session_auth:
        auth = _auth_var.get()
        if auth:
            headers = {**auth, **(headers or {})}
    if rate_limit and url:
        # Lazy import to keep this module dependency-light at top of file
        from ._rate_limit import wait_for_token
        ok = await wait_for_token(url)
        if not ok:
            logger.debug("rate limit blocked %s %s", method, url)
            return None
    return await asyncio.to_thread(
        _fetch_sync, method, url,
        headers=headers, body=body, timeout=timeout,
        follow_redirects=follow_redirects, proxy=_proxy_var.get(),
    )


def normalize_target_url(target: str) -> str:
    """Treat bare hosts as https URLs."""
    s = target.strip()
    if not s:
        return s
    if "://" in s:
        return s.rstrip("/")
    return f"https://{s.split(':', 1)[0]}"


def add_query(url: str, key: str, value: str) -> str:
    """Append (or override) a query parameter in `url`."""
    parsed = urllib.parse.urlsplit(url)
    qs = dict(urllib.parse.parse_qsl(parsed.query))
    qs[key] = value
    new_q = urllib.parse.urlencode(qs)
    return urllib.parse.urlunsplit(
        (parsed.scheme, parsed.netloc, parsed.path, new_q, parsed.fragment)
    )
