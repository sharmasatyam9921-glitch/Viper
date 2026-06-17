"""Disposable mailbox provider for two-account testing (BOLA/IDOR + signup flows).

The two-account BOLA/IDOR capability (see ``bola_engine.py``) needs two accounts
the operator controls. On a real program that means registering two test users
and confirming them by email. This module supplies the *email* side: it creates
throwaway inboxes via a public API (no human signup, no CAPTCHA) and polls them
for the verification message, so the ``register -> confirm`` loop can be driven
programmatically during an authorized engagement.

Primary provider: **mail.tm** — free REST API, no API key, ~8 req/s per IP. The
mailbox is externally receivable, so it works for registering on third-party
targets that permit self-created test accounts (the bug-bounty norm). Creating a
mailbox is a single API call.

Scope / ethics note: nothing here registers on any target or solves a CAPTCHA.
It only provisions an inbox and reads what arrives. Registering the two test
accounts on the target remains the operator's authorized action, and CAPTCHA /
anti-bot gates must be handled by a human. The mailbox is throwaway and carries
no personal data.

Typical use::

    a = await new_mailbox()          # account A inbox
    b = await new_mailbox()          # account B inbox
    # ... operator registers A.address and B.address on the target ...
    msg = await MailTmProvider().wait_for(a, contains="confirm", timeout=120)
    link = verification_link(msg)    # visit to activate, then capture A's cookie
"""

from __future__ import annotations

import asyncio
import json as _json
import logging
import re
import secrets
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger("viper.specialist.temp_mail")

_BASE = "https://api.mail.tm"
_UA = "viper-temp-mail/1.0"

# URL keywords that mark a link as a verify/confirm/activate action.
_VERIFY_HINTS = (
    "verify", "verification", "confirm", "confirmation", "activate",
    "activation", "validate", "validation", "token", "signup", "register",
    "account/confirm", "auth/confirm", "email/confirm",
)
_URL_RE = re.compile(r"https?://[^\s\"'<>)\]]+", re.I)


@dataclass
class TempMailbox:
    """A provisioned throwaway inbox."""

    address: str
    password: str
    token: str = ""
    account_id: str = ""
    provider: str = "mail.tm"
    created: float = field(default_factory=time.time)


def _members(obj):
    """mail.tm sometimes returns a Hydra envelope, sometimes a bare list."""
    if isinstance(obj, dict) and "hydra:member" in obj:
        return obj["hydra:member"]
    return obj if isinstance(obj, list) else []


def _send(method: str, url: str, data: Optional[dict] = None,
          token: str = "", timeout: float = 15.0):
    """Blocking JSON HTTP call. (status, parsed_json | None). Patch point for tests."""
    headers = {"Accept": "application/json", "User-Agent": _UA}
    body = None
    if data is not None:
        headers["Content-Type"] = "application/json"
        body = _json.dumps(data).encode()
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(url, data=body, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            raw = r.read().decode("utf-8", "replace")
            return r.status, (_json.loads(raw) if raw else None)
    except urllib.error.HTTPError as e:
        raw = e.read().decode("utf-8", "replace") if e.fp else ""
        try:
            parsed = _json.loads(raw) if raw else None
        except ValueError:
            parsed = None
        return e.code, parsed
    except (urllib.error.URLError, OSError, TimeoutError) as e:
        logger.debug("temp_mail HTTP error %s %s: %s", method, url, e)
        return 0, None


class MailTmProvider:
    """Thin async wrapper over the mail.tm REST API."""

    base = _BASE

    async def _req(self, method, path, data=None, token=""):
        return await asyncio.to_thread(_send, method, self.base + path, data, token)

    async def domains(self) -> list[str]:
        status, body = await self._req("GET", "/domains")
        if status != 200 or body is None:
            return []
        return [d["domain"] for d in _members(body) if d.get("domain")]

    async def create(self) -> Optional[TempMailbox]:
        """Provision a fresh mailbox: pick a domain, create the account, get a token."""
        domains = await self.domains()
        if not domains:
            logger.warning("temp_mail: no mail.tm domains available")
            return None
        address = f"viper{secrets.token_hex(5)}@{domains[0]}"
        password = secrets.token_hex(10)
        status, acc = await self._req("POST", "/accounts",
                                      {"address": address, "password": password})
        if status not in (200, 201) or not isinstance(acc, dict):
            logger.warning("temp_mail: account creation failed (status %s)", status)
            return None
        mb = TempMailbox(address=address, password=password,
                         account_id=acc.get("id", ""))
        status, tok = await self._req("POST", "/token",
                                      {"address": address, "password": password})
        if status == 200 and isinstance(tok, dict):
            mb.token = tok.get("token", "")
        return mb

    async def messages(self, mb: TempMailbox) -> list[dict]:
        """Inbox message intros (id, from, subject, intro)."""
        status, body = await self._req("GET", "/messages", token=mb.token)
        return _members(body) if status == 200 else []

    async def message(self, mb: TempMailbox, mid: str) -> Optional[dict]:
        """Full message (text + html) by id."""
        status, body = await self._req("GET", f"/messages/{mid}", token=mb.token)
        return body if status == 200 and isinstance(body, dict) else None

    async def wait_for(self, mb: TempMailbox, *, sender: str = "",
                       contains: str = "", timeout: float = 120.0,
                       poll: float = 3.0) -> Optional[dict]:
        """Poll until a matching message arrives (or timeout). Returns the FULL message.

        sender   : substring matched against the message 'from' address (case-insensitive).
        contains : substring matched against subject + body (case-insensitive).
        """
        deadline = time.monotonic() + timeout
        seen: set[str] = set()
        while time.monotonic() < deadline:
            for intro in await self.messages(mb):
                mid = intro.get("id")
                if not mid or mid in seen:
                    continue
                seen.add(mid)
                frm = ((intro.get("from") or {}).get("address") or "").lower()
                if sender and sender.lower() not in frm:
                    continue
                full = await self.message(mb, mid)
                if full is None:
                    continue
                if contains and contains.lower() not in _message_text(full).lower():
                    continue
                return full
            await asyncio.sleep(poll)
        return None


def _message_text(msg: dict) -> str:
    """Flatten subject + text + html of a mail.tm message into one searchable string."""
    parts = [msg.get("subject", ""), msg.get("text", "")]
    html = msg.get("html")
    if isinstance(html, list):
        parts.extend(html)
    elif isinstance(html, str):
        parts.append(html)
    return "\n".join(p for p in parts if p)


def extract_links(msg: dict) -> list[str]:
    """All http(s) URLs found in a message, de-duplicated, order-preserved."""
    out: list[str] = []
    seen: set[str] = set()
    for u in _URL_RE.findall(_message_text(msg)):
        u = u.rstrip(".,)>\"'")
        if u not in seen:
            seen.add(u)
            out.append(u)
    return out


def verification_link(msg: dict) -> Optional[str]:
    """Best-guess account-verification URL: the first link whose URL looks like a
    verify/confirm/activate action, else the first link in the message."""
    links = extract_links(msg)
    for u in links:
        low = u.lower()
        if any(h in low for h in _VERIFY_HINTS):
            return u
    return links[0] if links else None


async def new_mailbox() -> Optional[TempMailbox]:
    """Convenience: provision one ready-to-use mailbox via mail.tm."""
    return await MailTmProvider().create()


if __name__ == "__main__":  # tiny smoke demo (creates two real inboxes)
    async def _demo():
        a = await new_mailbox()
        b = await new_mailbox()
        print("A:", a.address if a else "FAILED")
        print("B:", b.address if b else "FAILED")
    asyncio.run(_demo())
