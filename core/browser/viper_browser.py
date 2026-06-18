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
