"""Tests for the temp-account / auto-signup modules."""
from __future__ import annotations

import pytest

from core.temp_account import (
    GmailAliasProvider,
    Inbox,
    MailTmProvider,
    ProgramRules,
    ProviderRegistry,
    extract_all_links,
    extract_first_link,
    get_program_rules,
)


class TestProgramRules:
    def test_known_program_returns_circle(self) -> None:
        r = get_program_rules("circle-bbp")
        assert r.requires_owned_email is True
        assert r.requires_h1_marker is True
        assert r.name_suffix == "_h1"

    def test_unknown_program_returns_permissive(self) -> None:
        r = get_program_rules("xyz-not-a-program")
        assert r.requires_owned_email is False


class TestProviderRegistry:
    def test_strict_program_picks_gmail(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("GMAIL_USER", "test@gmail.com")
        monkeypatch.setenv("GMAIL_APP_PASSWORD", "abcd efgh ijkl mnop")
        rules = ProgramRules(name="x", requires_owned_email=True)
        provider = ProviderRegistry.pick(rules)
        assert provider.name == "gmail-alias"

    def test_strict_program_without_gmail_creds_raises(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.delenv("GMAIL_USER", raising=False)
        monkeypatch.delenv("GMAIL_APP_PASSWORD", raising=False)
        rules = ProgramRules(name="x", requires_owned_email=True)
        with pytest.raises(RuntimeError, match="requires owned email"):
            ProviderRegistry.pick(rules)

    def test_permissive_program_picks_mailtm(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # We don't actually want to hit the network here, so just ensure the
        # branch is taken and the right type is returned. Construction calls
        # _fetch_domain — patch it.
        monkeypatch.setattr(MailTmProvider, "_fetch_domain", lambda self: "test.local")
        rules = ProgramRules(name="x", requires_owned_email=False)
        provider = ProviderRegistry.pick(rules)
        assert provider.name == "mail.tm"


class TestGmailAlias:
    def test_create_inbox_uses_plus_aliasing(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("GMAIL_USER", "viper@gmail.com")
        monkeypatch.setenv("GMAIL_APP_PASSWORD", "x" * 16)
        provider = GmailAliasProvider()
        inbox = provider.create_inbox(label="circle_a")
        assert "+circle_a-" in inbox.address
        assert inbox.address.endswith("@gmail.com")
        assert inbox.address.startswith("viper+")


class TestExtractLinks:
    def test_extract_first_link_finds_https(self) -> None:
        body = "Hello, click https://example.com/verify?token=abc to confirm."
        assert extract_first_link(body) == "https://example.com/verify?token=abc"

    def test_extract_first_link_with_filter(self) -> None:
        body = "Visit https://other.com/x or https://example.com/verify"
        assert extract_first_link(body, contains="verify") == "https://example.com/verify"

    def test_extract_first_link_strips_trailing_punct(self) -> None:
        body = "go to https://example.com/x.html."
        assert extract_first_link(body) == "https://example.com/x.html"

    def test_extract_no_link_raises(self) -> None:
        with pytest.raises(ValueError):
            extract_first_link("no link here")

    def test_extract_all_links(self) -> None:
        body = "https://a.com and https://b.com/v"
        all_links = extract_all_links(body)
        assert len(all_links) == 2
