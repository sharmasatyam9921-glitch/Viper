"""Optional Playwright-backed authenticated capture (graceful degradation).

If Playwright is installed, drive a real Chromium to load the target as each
supplied role and capture the authenticated traffic into a
:class:`SessionContext`. If Playwright is absent, :func:`available` returns False
and callers fall back to the pure-Python capture pipeline
(``proxy_pipeline`` + ``session_capture``) fed by a Burp/HAR export — so VIPER
never hard-depends on a browser.

Safety: capture is **read-only** — only navigations and the GET traffic they
trigger are recorded; state-mutating requests (POST/PUT/PATCH/DELETE) are never
issued by this module and are not recorded as reachable. Autonomous form
submission is intentionally out of scope here; that requires an explicit approval
gate elsewhere. Every navigation is checked against an optional ``scope_guard``.
"""
from __future__ import annotations

import logging
from typing import Callable, Dict, List, Optional

from core.session_context import SessionContext

logger = logging.getLogger("viper.browser")

_IDEMPOTENT = {"GET", "HEAD"}


def available() -> bool:
    """True iff Playwright's async API can be imported."""
    try:
        import playwright.async_api  # noqa: F401
        return True
    except Exception:
        return False


async def probe_proto_pollution(
    url: str,
    marker: str,
    *,
    scope_guard: Optional[Callable[[str], bool]] = None,
    timeout_ms: int = 15000,
) -> Optional[bool]:
    """DOM oracle for client-side prototype pollution (read-only).

    Navigate a headless browser to `url` with a ``__proto__`` payload carrying a unique
    `marker`, then read ``Object.prototype[marker]``. Returns:
      * ``True``  — the global prototype was ACTUALLY polluted (the marker landed on
        Object.prototype). Unforgeable: a random marker is ``undefined`` on any normal
        page, so this only happens if the page's own JS walked the URL into a prototype
        write — a definitive confirmation, never a false positive.
      * ``False`` — navigated but the prototype was not polluted.
      * ``None``  — Playwright unavailable, out of scope, or an error (caller keeps it a lead).

    Only GET navigations are issued; no form is submitted, no state is mutated."""
    if not available():
        return None
    if scope_guard is not None:
        try:
            if not scope_guard(url):
                return None
        except Exception:
            return None

    sep = "&" if "?" in url.split("#", 1)[0] else "?"
    # Common client-side PP entry points: query and hash __proto__ / constructor.prototype.
    targets = [
        f"{url}{sep}__proto__[{marker}]={marker}",
        f"{url}{sep}constructor[prototype][{marker}]={marker}",
        f"{url}#__proto__[{marker}]={marker}",
    ]
    from playwright.async_api import async_playwright
    try:
        async with async_playwright() as pw:
            browser = await pw.chromium.launch(headless=True)
            try:
                for target in targets:
                    ctx = await browser.new_context()
                    page = await ctx.new_page()
                    try:
                        await page.goto(target, timeout=timeout_ms, wait_until="load")
                        # A benign in-scope URL could 302 off-scope; the read-only GET is
                        # harmless, but don't evaluate/confirm against an off-scope page.
                        if scope_guard is not None:
                            try:
                                if not scope_guard(page.url):
                                    continue
                            except Exception:
                                continue
                        await page.wait_for_timeout(300)   # let a client router parse it
                        val = await page.evaluate("(m) => Object.prototype[m]", marker)
                        if val == marker:
                            return True
                    except Exception as exc:   # noqa: BLE001
                        logger.debug("proto-pollution probe %s failed: %s", target, exc)
                    finally:
                        await ctx.close()
                return False
            finally:
                await browser.close()
    except Exception as exc:   # noqa: BLE001 — never let the oracle raise into the gate
        logger.debug("proto-pollution browser probe errored: %s", exc)
        return None


async def capture_roles(
    seed_urls: List[str],
    accounts: Dict[str, dict],
    *,
    scope_guard: Optional[Callable[[str], bool]] = None,
    hunt_id: str = "",
    timeout_ms: int = 15000,
) -> SessionContext:
    """Load `seed_urls` as each role in `accounts`, capture GET traffic.

    ``accounts``: ``{role_name: {"headers": {...}, "markers": [...]}}``.
    Returns a populated SessionContext. Raises RuntimeError if Playwright is
    unavailable (check :func:`available` first and fall back to HAR import).
    """
    if not available():
        raise RuntimeError(
            "Playwright is not installed — install it, or feed a Burp/HAR export "
            "to session_capture.session_context_from_har() instead.")

    from playwright.async_api import async_playwright

    ctx = SessionContext(hunt_id=hunt_id)
    for role, bundle in accounts.items():
        ctx.add_role(role, bundle.get("headers"), bundle.get("markers"))

    def _in_scope(url: str) -> bool:
        if scope_guard is None:
            return True
        try:
            return bool(scope_guard(url))
        except Exception:
            return False   # fail closed

    async with async_playwright() as pw:
        browser = await pw.chromium.launch(headless=True)
        try:
            for role, bundle in accounts.items():
                context = await browser.new_context(
                    extra_http_headers=bundle.get("headers") or {})
                page = await context.new_page()

                def _on_response(response, _role=role):
                    try:
                        req = response.request
                        if req.method.upper() not in _IDEMPOTENT:
                            return   # read-only: never record mutating traffic
                        if not _in_scope(response.url):
                            return
                        ctx.record(_role, req.method, response.url, response.status)
                    except Exception:
                        pass

                page.on("response", _on_response)
                for url in seed_urls:
                    if not _in_scope(url):
                        continue
                    try:
                        await page.goto(url, timeout=timeout_ms,
                                        wait_until="networkidle")
                    except Exception as exc:
                        logger.debug("capture %s as %s failed: %s", url, role, exc)
                await context.close()
        finally:
            await browser.close()
    return ctx
