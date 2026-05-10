"""
Playwright-driven auto-signup for VIPER.

Wraps a target's signup flow with:
  1. ROE check (refuses if program forbids automated account creation
     or temp emails — pulled from temp_account.get_program_rules).
  2. Inbox creation via the right TempEmailProvider.
  3. Form fill + submit using best-effort selector heuristics
     (id/name/placeholder/aria-label match against field hints).
  4. Email verification: polls inbox, extracts magic link, navigates.
  5. Cookie / storage_state capture, returned to caller.

Usage:
    plan = SignupPlan(
        program="circle-bbp",
        signup_url="https://app-sandbox.circle.com/signup",
        fields={
            "first_name": "viper_h1",  # rules will append _h1 if missing
            "last_name":  "ashborn_h1",
            "company":    "viper-research",
            "password":   "SOMEthing-strong-32+",
        },
        verify_subject_hint="verify",
    )
    result = AutoSignup().run(plan, label="circle_a")
    print(result.cookie_header)  # paste into CIRCLE_A_COOKIE
    print(result.storage_state_path)  # full Playwright auth state
"""
from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .temp_account import (
    Inbox,
    Message,
    ProgramRules,
    ProviderRegistry,
    TempEmailProvider,
    extract_first_link,
    get_program_rules,
)

UA = "viper-ashborn-h1 (Authorized Testing - VIPER auto-signup)"


@dataclass
class SignupPlan:
    program: str
    signup_url: str
    fields: dict[str, str] = field(default_factory=dict)
    submit_button_hints: tuple[str, ...] = ("Sign up", "Create account", "Continue", "Submit")
    verify_subject_hint: str = "verify"
    verify_link_contains: str = "verify"
    post_verify_url_contains: str = ""  # if non-empty, wait for nav to a URL containing this
    captcha_action: str = "abort"  # "abort" | "manual_pause"
    extra_steps: list[str] = field(default_factory=list)


@dataclass
class SignupResult:
    success: bool
    program: str
    label: str
    email: str
    cookie_header: str
    storage_state_path: str
    log: list[str] = field(default_factory=list)
    error: str | None = None


class AutoSignup:
    """Playwright-based signup driver. Lazy-imports playwright so the rest
    of VIPER can run without it installed."""

    def __init__(self, headless: bool = False, state_dir: Path | None = None,
                 force_provider: str | None = None) -> None:
        """
        force_provider: "temp" | "gmail" | None.
          "temp" overrides program ROE and uses mail.tm even on strict programs.
          Findings produced from such accounts may be ineligible — re-verify
          with a compliant account before reporting.
        """
        self.headless = headless
        self.state_dir = state_dir or Path("state/auto_signup")
        self.state_dir.mkdir(parents=True, exist_ok=True)
        self.force_provider = force_provider

    def _enforce_roe(self, plan: SignupPlan, rules: ProgramRules) -> None:
        # Ensure name fields carry the H1 marker if the program demands it.
        if rules.requires_h1_marker and rules.name_suffix:
            for field_key in ("first_name", "last_name"):
                value = plan.fields.get(field_key, "")
                if value and not value.endswith(rules.name_suffix):
                    plan.fields[field_key] = value + rules.name_suffix

    def run(self, plan: SignupPlan, *, label: str) -> SignupResult:
        rules = get_program_rules(plan.program)
        self._enforce_roe(plan, rules)
        provider = ProviderRegistry.pick(rules, force=self.force_provider)
        inbox = provider.create_inbox(label=label)
        log: list[str] = [f"[{plan.program}] using provider={provider.name}, "
                          f"inbox={inbox.address}"]

        try:
            from playwright.sync_api import sync_playwright  # type: ignore[import-not-found]
        except ImportError:
            return SignupResult(
                success=False, program=plan.program, label=label, email=inbox.address,
                cookie_header="", storage_state_path="",
                log=log, error="playwright not installed (pip install playwright)",
            )

        storage_path = self.state_dir / f"{plan.program}_{label}.json"

        try:
            with sync_playwright() as p:
                browser = p.chromium.launch(headless=self.headless)
                context = browser.new_context(user_agent=UA)
                page = context.new_page()

                log.append(f"goto {plan.signup_url}")
                page.goto(plan.signup_url, wait_until="domcontentloaded", timeout=30_000)

                # Fill each known field if a matching input is on the page.
                # Best-effort heuristic: try the obvious id/name/placeholder/label/aria.
                self._fill_form(page, plan, inbox.address, log)

                # Wait briefly for any async-loaded captcha widgets (reCAPTCHA,
                # hCaptcha, Turnstile) so we can detect them reliably.
                self._wait_for_async_widgets(page, log)
                captcha_present = self._detect_captcha(page, log)

                # Production signup flows almost always have a captcha or a TOS
                # checkbox. By default we never auto-submit — we hand the
                # browser to the human to solve captcha + click Sign Up. Caller
                # can opt into auto-submit with plan.captcha_action="auto".
                if plan.captcha_action == "auto" and not captcha_present:
                    self._click_submit(page, plan.submit_button_hints, log)
                    print(
                        f"\n[*] Form auto-submitted (captcha_action=auto, none detected). "
                        f"Email used: {inbox.address}\n"
                        f"    Polling inbox for verification email (3 min timeout)..."
                    )
                else:
                    detection_note = "captcha detected" if captcha_present else "manual submit mode"
                    print(
                        f"\n[HANDOFF] Browser is open with form pre-filled ({detection_note}).\n"
                        f"  Email used: {inbox.address}\n"
                        f"  --> Solve any captcha and click Sign Up in the browser.\n"
                        f"  --> I'll poll mail.tm for the verification email (5 min timeout)."
                    )

                # Wait for the verification email (longer timeout if human is solving captcha)
                wait_timeout = 300 if not (plan.captcha_action == "auto" and not captcha_present) else 180
                log.append(f"polling inbox for subject ~ {plan.verify_subject_hint!r} "
                           f"(timeout={wait_timeout}s)")
                msg = provider.wait_for_email(
                    inbox, subject_contains=plan.verify_subject_hint,
                    timeout=wait_timeout,
                )
                log.append(f"received: from={msg.from_addr!r}, subject={msg.subject!r}")

                link = extract_first_link(
                    msg.html or msg.text, contains=plan.verify_link_contains
                )
                log.append(f"verify link: {link[:120]}")

                page.goto(link, wait_until="domcontentloaded", timeout=30_000)
                if plan.post_verify_url_contains:
                    page.wait_for_url(f"**{plan.post_verify_url_contains}**", timeout=30_000)

                # Save full storage_state so we have cookies + localStorage
                state = context.storage_state(path=str(storage_path))
                cookie_header = self._cookies_to_header(state.get("cookies", []))

                browser.close()

                return SignupResult(
                    success=True, program=plan.program, label=label, email=inbox.address,
                    cookie_header=cookie_header,
                    storage_state_path=str(storage_path),
                    log=log,
                )
        except Exception as e:
            return SignupResult(
                success=False, program=plan.program, label=label, email=inbox.address,
                cookie_header="", storage_state_path=str(storage_path),
                log=log, error=f"{type(e).__name__}: {e}",
            )

    def _fill_form(self, page: Any, plan: SignupPlan, email: str, log: list[str]) -> None:
        """Try common selector patterns for each known field name."""
        # email always goes in
        plan.fields.setdefault("email", email)
        for field_key, value in plan.fields.items():
            value = value.replace("$EMAIL", email)
            selectors = self._selectors_for(field_key)
            placed = False
            for sel in selectors:
                try:
                    locator = page.locator(sel).first
                    if locator.count() > 0:
                        locator.fill(value, timeout=5_000)
                        log.append(f"filled {field_key} via {sel}")
                        placed = True
                        break
                except Exception:
                    continue
            if not placed:
                log.append(f"!! could not place {field_key} (no selector matched)")

    def _wait_for_async_widgets(self, page: Any, log: list[str], timeout_ms: int = 5000) -> None:
        """Wait briefly for async-loaded scripts (reCAPTCHA / hCaptcha / Turnstile)
        to inject their iframes. Non-fatal if they don't appear."""
        for sel in (
            'iframe[src*="recaptcha"]',
            'iframe[src*="hcaptcha"]',
            'iframe[src*="turnstile"]',
        ):
            try:
                page.wait_for_selector(sel, timeout=timeout_ms, state="attached")
                log.append(f"async widget appeared: {sel}")
                return  # one is enough
            except Exception:
                continue
        log.append("no async captcha widget within wait window")

    def _detect_captcha(self, page: Any, log: list[str]) -> bool:
        """Return True if a reCAPTCHA / hCaptcha / Turnstile widget is present."""
        selectors = [
            'iframe[src*="recaptcha"]',
            'iframe[src*="hcaptcha"]',
            'iframe[src*="turnstile"]',
            'div.g-recaptcha',
            'div.h-captcha',
            'div.cf-turnstile',
            '[data-sitekey]',
        ]
        for sel in selectors:
            try:
                if page.locator(sel).count() > 0:
                    log.append(f"captcha detected via {sel}")
                    return True
            except Exception:
                continue
        return False

    def _click_submit(self, page: Any, hints: tuple[str, ...], log: list[str]) -> None:
        # First try a button whose text contains any of the hints.
        for hint in hints:
            try:
                btn = page.get_by_role("button", name=hint, exact=False)
                if btn.count() > 0:
                    btn.first.click(timeout=5_000)
                    log.append(f"clicked submit button matching {hint!r}")
                    return
            except Exception:
                pass
        # Fallback: last submit-type input.
        try:
            page.locator("button[type=submit], input[type=submit]").last.click(timeout=5_000)
            log.append("clicked fallback submit button")
        except Exception as e:
            log.append(f"!! submit click failed: {e}")

    def _selectors_for(self, field_key: str) -> list[str]:
        # Map our canonical field names --> likely selectors on real signup forms.
        mapping = {
            "email": [
                'input[type=email]',
                'input[name=email]',
                'input[id*=email i]',
                'input[placeholder*=email i]',
                'input[placeholder*=work i]',
                'input[autocomplete=email]',
                'input[autocomplete=username]',
            ],
            "password": [
                'input[type=password]:not([name*=confirm i]):not([id*=confirm i])',
                'input[name=password]',
                'input[id*=password i]',
                'input[autocomplete=new-password]',
            ],
            "password_confirm": [
                'input[type=password][name*=confirm i]',
                'input[type=password][id*=confirm i]',
                'input[name*=password_confirmation]',
            ],
            "first_name": [
                'input[name=first_name]',
                'input[name=firstName]',
                'input[id*=first i]',
                'input[autocomplete=given-name]',
                'input[placeholder*=first i]',
            ],
            "last_name": [
                'input[name=last_name]',
                'input[name=lastName]',
                'input[id*=last i]',
                'input[autocomplete=family-name]',
                'input[placeholder*=last i]',
            ],
            "company": [
                'input[name=company]',
                'input[name=companyName]',
                'input[name*=business i]',
                'input[name*=entity i]',
                'input[id*=company i]',
                'input[id*=organization i]',
                'input[id*=business i]',
                'input[id*=entity i]',
                'input[placeholder*=company i]',
                'input[placeholder*=business i]',
                'input[placeholder*=entity i]',
                'input[placeholder*=organization i]',
            ],
            "phone": [
                'input[type=tel]',
                'input[name=phone]',
                'input[autocomplete=tel]',
            ],
        }
        return mapping.get(field_key, [f'input[name={field_key}]', f'input[id={field_key}]'])

    def _cookies_to_header(self, cookies: list[dict]) -> str:
        return "; ".join(f"{c['name']}={c['value']}" for c in cookies)
