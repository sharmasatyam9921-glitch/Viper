"""
VIPER auto-account module — burner email + verification-link harvesting.

Two providers, picked by the program's ROE:
  - GmailAliasProvider: real Gmail account + "+" aliases (RFC 5233 sub-addressing).
    Requires GMAIL_USER + GMAIL_APP_PASSWORD in env. Polls inbox via IMAP.
    Aliases legitimately *belong* to the account holder — usable on programs
    that require "email addresses you own and control" (Circle, Coinbase, etc).
  - MailTmProvider: public mail.tm API. No setup, but ephemeral and not
    "owned" by anyone. Only acceptable on programs whose ROE allows
    disposable inboxes.

Use ProviderRegistry.pick(program_rules) to get the right one.

Usage:
    inbox = provider.create_inbox(label="circle_a")
    print(inbox.address)  # use this in signup form
    msg = provider.wait_for_email(inbox, subject_contains="Verify", timeout=180)
    link = extract_first_link(msg.html or msg.text, contains="verify")
"""
from __future__ import annotations

import email
import imaplib
import json
import os
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Iterable, Protocol


@dataclass
class Inbox:
    """A handle to a temporary inbox we can poll."""
    label: str
    address: str
    provider_token: str | None = None  # API token if provider needs one
    metadata: dict = field(default_factory=dict)


@dataclass
class Message:
    """A received email."""
    from_addr: str
    subject: str
    text: str = ""
    html: str = ""
    received_at: float = 0.0


class TempEmailProvider(Protocol):
    """Common interface — every provider must support these three ops."""
    name: str

    def create_inbox(self, label: str) -> Inbox: ...
    def wait_for_email(
        self, inbox: Inbox, *, subject_contains: str = "", timeout: int = 120
    ) -> Message: ...
    def list_messages(self, inbox: Inbox) -> list[Message]: ...


# ---------------------------------------------------------------------------
# Mail.tm provider — public API, no auth needed
# ---------------------------------------------------------------------------

_MAILTM_BASE = "https://api.mail.tm"


def _http_json(url: str, *, method: str = "GET", body: dict | None = None,
               token: str | None = None, timeout: int = 15) -> tuple[int, dict]:
    headers = {"Accept": "application/json"}
    data = None
    if body is not None:
        headers["Content-Type"] = "application/json"
        data = json.dumps(body).encode()
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, json.loads(r.read().decode("utf-8", errors="replace"))
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read().decode("utf-8", errors="replace"))
        except json.JSONDecodeError:
            return e.code, {}
    except (urllib.error.URLError, json.JSONDecodeError) as e:
        return -1, {"_error": str(e)}


class MailTmProvider:
    """mail.tm public temp-email provider. Aliases NOT owned by user."""
    name = "mail.tm"

    def __init__(self) -> None:
        self._domain = self._fetch_domain()

    def _fetch_domain(self) -> str:
        status, body = _http_json(f"{_MAILTM_BASE}/domains")
        if status != 200:
            raise RuntimeError(f"mail.tm domain list failed: {status} {body}")
        # mail.tm returns either a bare list or a hydra-style {"hydra:member": [...]}
        if isinstance(body, list):
            members = body
        else:
            members = body.get("hydra:member") or body.get("member") or []
        if not members:
            raise RuntimeError(f"mail.tm returned no domains: {body}")
        return members[0]["domain"]

    def create_inbox(self, label: str) -> Inbox:
        local = f"viper-{label}-{int(time.time())}"
        address = f"{local}@{self._domain}"
        password = "V1per!" + os.urandom(8).hex()
        # Create account
        status, body = _http_json(
            f"{_MAILTM_BASE}/accounts",
            method="POST",
            body={"address": address, "password": password},
        )
        if status not in (200, 201):
            raise RuntimeError(f"mail.tm account create failed: {status} {body}")
        # Get auth token
        status, body = _http_json(
            f"{_MAILTM_BASE}/token",
            method="POST",
            body={"address": address, "password": password},
        )
        if status not in (200, 201):
            raise RuntimeError(f"mail.tm token failed: {status} {body}")
        return Inbox(
            label=label,
            address=address,
            provider_token=body["token"],
            metadata={"password": password},
        )

    def list_messages(self, inbox: Inbox) -> list[Message]:
        status, body = _http_json(
            f"{_MAILTM_BASE}/messages",
            token=inbox.provider_token,
        )
        if status != 200:
            return []
        if isinstance(body, list):
            members = body
        else:
            members = body.get("hydra:member") or body.get("member") or []
        out = []
        for m in members:
            # Fetch full body
            status2, full = _http_json(
                f"{_MAILTM_BASE}/messages/{m['id']}",
                token=inbox.provider_token,
            )
            if status2 != 200:
                continue
            out.append(Message(
                from_addr=(full.get("from") or {}).get("address", ""),
                subject=full.get("subject", ""),
                text=full.get("text", ""),
                html="\n".join(full.get("html") or []),
                received_at=time.time(),
            ))
        return out

    def wait_for_email(self, inbox: Inbox, *, subject_contains: str = "",
                       timeout: int = 120) -> Message:
        deadline = time.time() + timeout
        while time.time() < deadline:
            for msg in self.list_messages(inbox):
                if not subject_contains or subject_contains.lower() in msg.subject.lower():
                    return msg
            time.sleep(3)
        raise TimeoutError(
            f"No email matching subject={subject_contains!r} arrived in {timeout}s"
        )


# ---------------------------------------------------------------------------
# Gmail alias provider — uses YOUR real gmail with "+" aliases via IMAP
# ---------------------------------------------------------------------------

class GmailAliasProvider:
    """
    Uses Gmail "+" sub-addressing (RFC 5233). Each alias is a legitimate
    address you own — works on programs that require "owned" emails.

    Setup: enable IMAP in Gmail; create an App Password
    (myaccount.google.com → Security → 2-step → App passwords) and put it in
    GMAIL_USER + GMAIL_APP_PASSWORD env vars.
    """
    name = "gmail-alias"

    def __init__(self) -> None:
        self._user = os.environ.get("GMAIL_USER")
        self._app_pw = os.environ.get("GMAIL_APP_PASSWORD")
        if not self._user or not self._app_pw:
            raise RuntimeError(
                "GMAIL_USER + GMAIL_APP_PASSWORD must be set in .env. "
                "Generate at: https://myaccount.google.com/apppasswords"
            )

    def create_inbox(self, label: str) -> Inbox:
        local, _, domain = self._user.partition("@")
        # Use "+label-<rand>" so each test gets a unique alias.
        alias_local = f"{local}+{label}-{os.urandom(3).hex()}"
        return Inbox(
            label=label,
            address=f"{alias_local}@{domain}",
            metadata={"plus_tag": f"{label}-{alias_local.split('+', 1)[1].split('-')[1]}"},
        )

    def _connect(self) -> imaplib.IMAP4_SSL:
        m = imaplib.IMAP4_SSL("imap.gmail.com")
        assert self._user and self._app_pw  # narrowed by __init__
        m.login(self._user, self._app_pw)
        return m

    def list_messages(self, inbox: Inbox) -> list[Message]:
        m = self._connect()
        try:
            m.select("INBOX")
            # Search by To: header — Gmail honors the "+" alias here.
            _, data = m.search(None, f'(TO "{inbox.address}")')
            ids = data[0].split()
            out: list[Message] = []
            for mid in ids[-50:]:  # cap to last 50
                _, msg_data = m.fetch(mid, "(RFC822)")
                if not msg_data or not msg_data[0]:
                    continue
                raw = msg_data[0][1]
                if isinstance(raw, int):
                    continue
                msg = email.message_from_bytes(raw)
                text, html = "", ""
                if msg.is_multipart():
                    for part in msg.walk():
                        ctype = part.get_content_type()
                        try:
                            payload = part.get_payload(decode=True)
                        except (TypeError, ValueError):
                            payload = None
                        if not payload:
                            continue
                        body = payload.decode("utf-8", errors="replace")
                        if ctype == "text/plain":
                            text += body
                        elif ctype == "text/html":
                            html += body
                else:
                    payload = msg.get_payload(decode=True)
                    if payload:
                        text = payload.decode("utf-8", errors="replace")
                out.append(Message(
                    from_addr=msg.get("From", ""),
                    subject=msg.get("Subject", ""),
                    text=text,
                    html=html,
                ))
            return out
        finally:
            try:
                m.logout()
            except Exception:
                pass

    def wait_for_email(self, inbox: Inbox, *, subject_contains: str = "",
                       timeout: int = 180) -> Message:
        deadline = time.time() + timeout
        seen: set[tuple[str, str]] = set()
        # Snapshot of pre-existing messages so we don't return stale ones.
        for msg in self.list_messages(inbox):
            seen.add((msg.from_addr, msg.subject))
        while time.time() < deadline:
            for msg in self.list_messages(inbox):
                key = (msg.from_addr, msg.subject)
                if key in seen:
                    continue
                if not subject_contains or subject_contains.lower() in msg.subject.lower():
                    return msg
            time.sleep(8)  # IMAP is slow, don't hammer
        raise TimeoutError(
            f"No new email matching subject={subject_contains!r} for {inbox.address} in {timeout}s"
        )


# ---------------------------------------------------------------------------
# Provider registry — pick by program ROE
# ---------------------------------------------------------------------------

@dataclass
class ProgramRules:
    """Subset of program ROE relevant to account creation."""
    name: str
    requires_owned_email: bool = False
    requires_h1_marker: bool = False
    name_suffix: str | None = None  # e.g. "_h1" for Circle
    allowed_email_domains: tuple[str, ...] = ()  # empty = any


class ProviderRegistry:
    @staticmethod
    def pick(rules: ProgramRules, *, force: str | None = None) -> TempEmailProvider:
        """
        Pick the most ToS-compliant provider for the given program.

        Decision tree:
          - force="temp"      -> MailTmProvider (overrides program rules; logs warning)
          - force="gmail"     -> GmailAliasProvider
          - requires_owned_email -> GmailAliasProvider (if Gmail creds set)
          - else              -> MailTmProvider
        """
        if force == "temp":
            if rules.requires_owned_email:
                import sys
                print(
                    f"\n[!! ROE WARNING] Program {rules.name!r} requires owned emails. "
                    f"Forcing mail.tm anyway. Findings from this account may be "
                    f"rejected at triage on methodology grounds. Re-verify with a "
                    f"compliant account before submitting reports.\n",
                    file=sys.stderr,
                )
            return MailTmProvider()
        if force == "gmail":
            return GmailAliasProvider()
        if rules.requires_owned_email:
            try:
                return GmailAliasProvider()
            except RuntimeError as e:
                raise RuntimeError(
                    f"Program {rules.name!r} requires owned email addresses, "
                    f"but Gmail credentials are not configured. {e}"
                )
        return MailTmProvider()


# ---------------------------------------------------------------------------
# Hardcoded ROE table for known programs — extend as needed.
# ---------------------------------------------------------------------------

_KNOWN_PROGRAMS: dict[str, ProgramRules] = {
    "circle-bbp": ProgramRules(
        name="circle-bbp",
        requires_owned_email=True,
        requires_h1_marker=True,
        name_suffix="_h1",
    ),
    # Add more as they're encountered.
}


def get_program_rules(handle: str) -> ProgramRules:
    """Return rules for a known program, or a permissive default."""
    return _KNOWN_PROGRAMS.get(
        handle,
        ProgramRules(name=handle, requires_owned_email=False),
    )


# ---------------------------------------------------------------------------
# Helpers — link extraction
# ---------------------------------------------------------------------------

_LINK_RE = re.compile(r'https?://[^\s"<>\)]+', re.IGNORECASE)


def extract_first_link(text: str, *, contains: str = "") -> str:
    """Find the first http(s) link in text/html, optionally requiring substring."""
    for match in _LINK_RE.finditer(text):
        url = match.group(0)
        # Strip trailing punctuation that often gets glued to URLs.
        url = url.rstrip(".,;:>'\"")
        if not contains or contains.lower() in url.lower():
            return url
    raise ValueError(
        f"No link {('matching ' + repr(contains)) if contains else ''} found in message body."
    )


def extract_all_links(text: str, *, contains: str = "") -> list[str]:
    out: list[str] = []
    for match in _LINK_RE.finditer(text):
        url = match.group(0).rstrip(".,;:>'\"")
        if not contains or contains.lower() in url.lower():
            out.append(url)
    return out
