#!/usr/bin/env python3
"""
Playwright Browser Automation Tool for VIPER

Subprocess-based Playwright execution for safe browser automation.
Adapted from Redamon's approach: runs Playwright scripts in isolated
subprocesses with pre-initialized browser/context/page variables.

Features:
- Two modes: content extraction (url + selector) and custom script
- Subprocess isolation (no in-process browser)
- ANSI escape stripping from output
- Headless Chromium with Chrome user-agent
- Configurable browser args (Docker-friendly defaults)
- Max 15,000 chars output
- Convenience methods for XSS/CSRF/auth verification
"""

import asyncio
import importlib
import json
import re
import sys
import textwrap
from dataclasses import dataclass, field
from typing import Dict, List, Optional


# ANSI escape sequence pattern
_ANSI_RE = re.compile(r"\x1b\[[0-9;]*[a-zA-Z]")

# Default Chrome user-agent
_CHROME_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/124.0.0.0 Safari/537.36"
)

# Default browser launch args (Docker-friendly)
_DEFAULT_BROWSER_ARGS = [
    "--no-sandbox",
    "--disable-dev-shm-usage",
    "--disable-gpu",
    "--disable-setuid-sandbox",
    "--disable-software-rasterizer",
]


@dataclass
class PlaywrightResult:
    """Result of a Playwright operation."""

    success: bool
    output: str
    error: Optional[str] = None
    cookies: Optional[List[Dict]] = None
    url: Optional[str] = None


class PlaywrightTool:
    """Browser automation via Playwright subprocess execution.

    Runs Playwright scripts in isolated subprocesses with pre-initialized
    browser, context, and page variables. Supports content extraction
    (navigate to URL, optionally select elements) and custom script execution.

    Args:
        browser_args: Extra Chromium launch args. Merged with defaults.
        timeout: Default page timeout in milliseconds.
        max_output: Maximum characters returned from subprocess stdout.
        headless: Run browser in headless mode.
        user_agent: Override default Chrome user-agent string.
    """

    def __init__(
        self,
        browser_args: Optional[List[str]] = None,
        timeout: int = 30_000,
        max_output: int = 15_000,
        headless: bool = True,
        user_agent: Optional[str] = None,
    ):
        self._browser_args = list(_DEFAULT_BROWSER_ARGS)
        if browser_args:
            self._browser_args.extend(browser_args)
        self._timeout = timeout
        self._max_output = max_output
        self._headless = headless
        self._user_agent = user_agent or _CHROME_UA

    # ── Availability check ──────────────────────────────────────────

    @classmethod
    def is_available(cls) -> bool:
        """Check if playwright package is installed."""
        try:
            importlib.import_module("playwright")
            return True
        except ImportError:
            return False

    # ── Core methods ────────────────────────────────────────────────

    async def navigate(
        self,
        url: str,
        selector: Optional[str] = None,
        format: str = "text",
    ) -> PlaywrightResult:
        """Navigate to a URL and extract content.

        Args:
            url: Target URL to navigate to.
            selector: Optional CSS selector to extract specific content.
            format: Output format - "text" (inner_text) or "html" (inner_html).

        Returns:
            PlaywrightResult with extracted page content.
        """
        if not self.is_available():
            return PlaywrightResult(
                success=False,
                output="",
                error="playwright is not installed. Run: pip install playwright && python -m playwright install chromium",
            )

        extract_method = "inner_text" if format == "text" else "inner_html"

        if selector:
            body = textwrap.dedent(f"""\
                await page.goto({url!r}, wait_until="domcontentloaded", timeout={self._timeout})
                el = await page.query_selector({selector!r})
                if el:
                    content = await el.{extract_method}()
                    print(content)
                else:
                    print(f"PLAYWRIGHT_ERROR: selector {{repr({selector!r})}} not found")
            """)
        else:
            body = textwrap.dedent(f"""\
                await page.goto({url!r}, wait_until="domcontentloaded", timeout={self._timeout})
                content = await page.content()
                print(content)
            """)

        script = self._build_script(body)
        return await self._run_script(script, context_url=url)

    async def execute_script(self, script: str) -> PlaywrightResult:
        """Execute arbitrary Playwright code in a subprocess.

        The script receives pre-initialized variables:
        - ``browser``: launched Chromium instance
        - ``context``: browser context with Chrome user-agent
        - ``page``: new page ready for interaction

        Use ``print()`` to return output. The browser is closed automatically.

        Args:
            script: Python code using the Playwright async API.

        Returns:
            PlaywrightResult with script stdout.
        """
        if not self.is_available():
            return PlaywrightResult(
                success=False,
                output="",
                error="playwright is not installed. Run: pip install playwright && python -m playwright install chromium",
            )

        full_script = self._build_script(script)
        return await self._run_script(full_script)

    # ── VIPER convenience methods ───────────────────────────────────

    async def verify_xss(
        self,
        url: str,
        payload: str,
        input_selector: str,
    ) -> PlaywrightResult:
        """Verify reflected XSS by injecting payload into a form field.

        Fills the input identified by ``input_selector`` with ``payload``,
        submits the form, and checks whether the payload appears unencoded
        in the resulting page source.

        Args:
            url: Page containing the form.
            payload: XSS payload string (e.g. ``<script>alert(1)</script>``).
            input_selector: CSS selector for the input field.

        Returns:
            PlaywrightResult with verification details.
        """
        if not self.is_available():
            return PlaywrightResult(
                success=False, output="",
                error="playwright is not installed",
            )

        body = textwrap.dedent(f"""\
            import json as _json

            await page.goto({url!r}, wait_until="domcontentloaded", timeout={self._timeout})

            el = await page.query_selector({input_selector!r})
            if not el:
                print(_json.dumps({{"verified": False, "reason": "input selector not found"}}))
            else:
                await el.fill({payload!r})

                # Try submitting the closest form
                form = await page.query_selector({input_selector!r} + " >> xpath=ancestor::form")
                if form:
                    submit = await form.query_selector('[type="submit"], button')
                    if submit:
                        await submit.click()
                    else:
                        await page.keyboard.press("Enter")
                else:
                    await page.keyboard.press("Enter")

                await page.wait_for_load_state("domcontentloaded")
                source = await page.content()
                reflected = {payload!r} in source
                print(_json.dumps({{
                    "verified": reflected,
                    "payload": {payload!r},
                    "url": page.url,
                    "source_length": len(source),
                }}))
        """)

        script = self._build_script(body)
        return await self._run_script(script, context_url=url)

    async def verify_csrf(self, url: str) -> PlaywrightResult:
        """Check forms on a page for CSRF token presence.

        Navigates to ``url``, enumerates all ``<form>`` elements, and checks
        each for hidden inputs with names commonly used for CSRF protection
        (e.g. ``csrf_token``, ``_token``, ``authenticity_token``).

        Args:
            url: Page URL to inspect.

        Returns:
            PlaywrightResult with JSON listing forms and their CSRF status.
        """
        if not self.is_available():
            return PlaywrightResult(
                success=False, output="",
                error="playwright is not installed",
            )

        body = textwrap.dedent(f"""\
            import json as _json

            await page.goto({url!r}, wait_until="domcontentloaded", timeout={self._timeout})

            results = await page.evaluate('''() => {{
                const csrfNames = [
                    "csrf", "csrf_token", "csrftoken", "_csrf",
                    "_token", "token", "authenticity_token",
                    "xsrf", "xsrf_token", "_xsrf",
                    "__RequestVerificationToken",
                ];
                const forms = document.querySelectorAll("form");
                return Array.from(forms).map((form, i) => {{
                    const action = form.getAttribute("action") || "";
                    const method = (form.getAttribute("method") || "GET").toUpperCase();
                    const inputs = Array.from(form.querySelectorAll("input[type=hidden]"));
                    const names = inputs.map(inp => inp.name.toLowerCase());
                    const hasToken = csrfNames.some(cn => names.some(n => n.includes(cn)));
                    return {{
                        index: i,
                        action: action,
                        method: method,
                        has_csrf_token: hasToken,
                        hidden_inputs: inputs.map(inp => inp.name),
                    }};
                }});
            }}''')

            print(_json.dumps({{"url": {url!r}, "forms": results}}))
        """)

        script = self._build_script(body)
        return await self._run_script(script, context_url=url)

    async def capture_auth_flow(
        self,
        login_url: str,
        username: str,
        password: str,
        username_selector: str = 'input[name="username"], input[type="email"], input[name="email"]',
        password_selector: str = 'input[name="password"], input[type="password"]',
        submit_selector: str = 'button[type="submit"], input[type="submit"]',
    ) -> PlaywrightResult:
        """Perform login and capture resulting cookies/session.

        Args:
            login_url: Login page URL.
            username: Username or email to enter.
            password: Password to enter.
            username_selector: CSS selector for username field.
            password_selector: CSS selector for password field.
            submit_selector: CSS selector for submit button.

        Returns:
            PlaywrightResult with cookies in the ``cookies`` field.
        """
        if not self.is_available():
            return PlaywrightResult(
                success=False, output="",
                error="playwright is not installed",
            )

        body = textwrap.dedent(f"""\
            import json as _json

            await page.goto({login_url!r}, wait_until="domcontentloaded", timeout={self._timeout})

            # Fill username
            user_el = await page.query_selector({username_selector!r})
            if not user_el:
                print(_json.dumps({{"error": "username field not found"}}))
            else:
                await user_el.fill({username!r})

                # Fill password
                pass_el = await page.query_selector({password_selector!r})
                if pass_el:
                    await pass_el.fill({password!r})

                # Submit
                submit_el = await page.query_selector({submit_selector!r})
                if submit_el:
                    await submit_el.click()
                else:
                    await page.keyboard.press("Enter")

                await page.wait_for_load_state("networkidle", timeout={self._timeout})

                cookies = await context.cookies()
                cookie_list = [
                    {{
                        "name": c["name"],
                        "value": c["value"],
                        "domain": c.get("domain", ""),
                        "path": c.get("path", "/"),
                        "httpOnly": c.get("httpOnly", False),
                        "secure": c.get("secure", False),
                    }}
                    for c in cookies
                ]
                print(_json.dumps({{
                    "url": page.url,
                    "cookies": cookie_list,
                    "cookie_count": len(cookie_list),
                }}))
        """)

        script = self._build_script(body)
        result = await self._run_script(script, context_url=login_url)

        # Parse cookies into result field
        if result.success and result.output:
            try:
                data = json.loads(result.output)
                result.cookies = data.get("cookies")
                result.url = data.get("url")
            except (json.JSONDecodeError, KeyError):
                pass

        return result

    async def extract_spa_content(self, url: str) -> PlaywrightResult:
        """Wait for JS rendering and return full page text.

        Navigates to ``url``, waits for ``networkidle`` state (JS frameworks
        finished loading), then returns the full rendered text content.

        Args:
            url: SPA page URL.

        Returns:
            PlaywrightResult with rendered page text.
        """
        if not self.is_available():
            return PlaywrightResult(
                success=False, output="",
                error="playwright is not installed",
            )

        body = textwrap.dedent(f"""\
            await page.goto({url!r}, wait_until="networkidle", timeout={self._timeout})
            content = await page.evaluate("() => document.body.innerText")
            print(content)
        """)

        script = self._build_script(body)
        return await self._run_script(script, context_url=url)

    # ── Internal helpers ────────────────────────────────────────────

    def _build_script(self, code_body: str) -> str:
        """Wrap user code in a full Playwright async script.

        The generated script:
        1. Imports playwright and launches Chromium headless
        2. Creates a browser context with Chrome user-agent
        3. Opens a new page
        4. Runs the provided ``code_body``
        5. Closes the browser
        """
        args_str = repr(self._browser_args)
        indented_body = textwrap.indent(code_body, "        ")

        return textwrap.dedent(f"""\
            import asyncio
            from playwright.async_api import async_playwright

            async def main():
                async with async_playwright() as p:
                    browser = await p.chromium.launch(
                        headless={self._headless!r},
                        args={args_str},
                    )
                    context = await browser.new_context(
                        user_agent={self._user_agent!r},
                    )
                    page = await context.new_page()
                    page.set_default_timeout({self._timeout})
                    try:
            {indented_body}
                    finally:
                        await browser.close()

            asyncio.run(main())
        """)

    async def _run_script(
        self,
        script: str,
        context_url: Optional[str] = None,
    ) -> PlaywrightResult:
        """Execute a Playwright script in a subprocess.

        Args:
            script: Complete Python script to run.
            context_url: Optional URL for the result object.

        Returns:
            PlaywrightResult with stdout output (ANSI-stripped, truncated).
        """
        timeout_secs = (self._timeout / 1000) + 10  # script timeout + buffer

        try:
            proc = await asyncio.create_subprocess_exec(
                sys.executable, "-c", script,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            try:
                stdout, stderr = await asyncio.wait_for(
                    proc.communicate(),
                    timeout=timeout_secs,
                )
            except asyncio.TimeoutError:
                proc.kill()
                await proc.wait()
                return PlaywrightResult(
                    success=False,
                    output="",
                    error=f"Script timed out after {timeout_secs:.0f}s",
                    url=context_url,
                )

            # Decode and strip ANSI escapes
            out_text = _ANSI_RE.sub("", stdout.decode("utf-8", errors="replace")).strip()
            err_text = _ANSI_RE.sub("", stderr.decode("utf-8", errors="replace")).strip()

            # Truncate output
            if len(out_text) > self._max_output:
                out_text = out_text[: self._max_output] + f"\n... [truncated at {self._max_output} chars]"

            if proc.returncode != 0:
                return PlaywrightResult(
                    success=False,
                    output=out_text,
                    error=err_text or f"Process exited with code {proc.returncode}",
                    url=context_url,
                )

            return PlaywrightResult(
                success=True,
                output=out_text,
                error=err_text if err_text else None,
                url=context_url,
            )

        except FileNotFoundError:
            return PlaywrightResult(
                success=False,
                output="",
                error=f"Python interpreter not found: {sys.executable}",
                url=context_url,
            )
        except Exception as exc:
            return PlaywrightResult(
                success=False,
                output="",
                error=f"Subprocess error: {exc}",
                url=context_url,
            )
