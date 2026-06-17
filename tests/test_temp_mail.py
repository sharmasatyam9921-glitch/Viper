"""Tests for the disposable-mailbox provider (hermetic — no real network)."""
from __future__ import annotations

import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.specialist import temp_mail  # noqa: E402
from core.specialist.temp_mail import (  # noqa: E402
    MailTmProvider,
    extract_links,
    new_mailbox,
    verification_link,
)


def _fake_transport(routes):
    """Build a _send replacement from a dict keyed by (METHOD, path-suffix)."""
    def _send(method, url, data=None, token="", timeout=15.0):
        for (m, suffix), resp in routes.items():
            if method == m and url.endswith(suffix):
                return resp
        return 404, None
    return _send


def test_create_mailbox(monkeypatch):
    routes = {
        ("GET", "/domains"): (200, {"hydra:member": [{"domain": "ex.test"}]}),
        ("POST", "/accounts"): (201, {"id": "acc123", "address": "x@ex.test"}),
        ("POST", "/token"): (200, {"token": "JWT.AAA.BBB"}),
    }
    monkeypatch.setattr(temp_mail, "_send", _fake_transport(routes))
    mb = asyncio.run(new_mailbox())
    assert mb is not None
    assert mb.address.endswith("@ex.test")
    assert mb.token == "JWT.AAA.BBB"
    assert mb.account_id == "acc123"


def test_create_handles_bare_list_domains(monkeypatch):
    # mail.tm has been seen returning a bare list instead of a Hydra envelope.
    routes = {
        ("GET", "/domains"): (200, [{"domain": "bare.test"}]),
        ("POST", "/accounts"): (201, {"id": "a", "address": "y@bare.test"}),
        ("POST", "/token"): (200, {"token": "T"}),
    }
    monkeypatch.setattr(temp_mail, "_send", _fake_transport(routes))
    mb = asyncio.run(new_mailbox())
    assert mb is not None and mb.address.endswith("@bare.test")


def test_create_returns_none_when_no_domains(monkeypatch):
    monkeypatch.setattr(temp_mail, "_send",
                        _fake_transport({("GET", "/domains"): (200, [])}))
    assert asyncio.run(new_mailbox()) is None


def test_wait_for_matches_sender_and_content(monkeypatch):
    from core.specialist.temp_mail import TempMailbox
    mb = TempMailbox(address="me@ex.test", password="p", token="T")
    full = {
        "id": "m1", "subject": "Confirm your account",
        "text": "Welcome! Visit https://target.test/auth/confirm?token=abc to verify.",
        "from": {"address": "no-reply@target.test"},
    }
    routes = {
        ("GET", "/messages"): (200, {"hydra:member": [
            {"id": "m1", "subject": "Confirm your account",
             "from": {"address": "no-reply@target.test"}},
        ]}),
        ("GET", "/messages/m1"): (200, full),
    }
    monkeypatch.setattr(temp_mail, "_send", _fake_transport(routes))
    msg = asyncio.run(MailTmProvider().wait_for(
        mb, sender="target.test", contains="confirm", timeout=2, poll=0.01))
    assert msg is not None and msg["id"] == "m1"


def test_wait_for_times_out_when_no_match(monkeypatch):
    from core.specialist.temp_mail import TempMailbox
    mb = TempMailbox(address="me@ex.test", password="p", token="T")
    routes = {("GET", "/messages"): (200, {"hydra:member": []})}
    monkeypatch.setattr(temp_mail, "_send", _fake_transport(routes))
    msg = asyncio.run(MailTmProvider().wait_for(mb, contains="confirm",
                                                timeout=0.2, poll=0.05))
    assert msg is None


def test_verification_link_prefers_confirm_url():
    msg = {
        "text": "Footer https://target.test/home and "
                "verify here https://target.test/email/confirm?token=xyz thanks",
    }
    assert verification_link(msg) == "https://target.test/email/confirm?token=xyz"


def test_verification_link_falls_back_to_first_link():
    msg = {"text": "Your dashboard: https://target.test/dash — enjoy"}
    assert verification_link(msg) == "https://target.test/dash"


def test_extract_links_dedupes_and_strips_punctuation():
    msg = {"text": "a https://t.test/x. b https://t.test/x) c https://t.test/y"}
    assert extract_links(msg) == ["https://t.test/x", "https://t.test/y"]


def test_verification_link_none_when_no_links():
    assert verification_link({"text": "no links here", "subject": "hi"}) is None
