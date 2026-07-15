"""The hard guardrail blocks major/gov/mil/edu domains BY DEFAULT, but an authorized
operator can override it for a specific in-scope host — via a loaded program scope, the
VIPER_AUTHORIZED_TARGETS allowlist, or an explicit authorized=True. The safety net for an
un-authorized target must stay intact (a typo'd major domain is still refused)."""
from __future__ import annotations

import os
import sys
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.guardrail_hard import is_blocked, on_blocklist, validate_target  # noqa: E402


def _clean_env(**overrides):
    env = {k: v for k, v in os.environ.items() if k != "VIPER_AUTHORIZED_TARGETS"}
    env.update(overrides)
    return patch.dict(os.environ, env, clear=True)


# ── default behaviour is unchanged (safety net intact) ───────────────────────
def test_major_domain_blocked_by_default():
    with _clean_env():
        blocked, reason = is_blocked("x.com")
        assert blocked is True
        assert "protected major domain" in reason
        assert "VIPER_AUTHORIZED_TARGETS" in reason   # message points at the override


def test_gov_tld_blocked_by_default():
    with _clean_env():
        assert is_blocked("agency.gov")[0] is True


def test_subdomain_of_major_blocked_by_default():
    with _clean_env():
        assert is_blocked("api.google.com")[0] is True


def test_unrelated_typo_still_blocked_when_authorizing_something_else():
    # Authorizing x.com must NOT open google.com — the override is target-specific.
    with _clean_env(VIPER_AUTHORIZED_TARGETS="x.com"):
        assert is_blocked("google.com")[0] is True
        assert is_blocked("x.com")[0] is False


# ── env allowlist override ───────────────────────────────────────────────────
def test_env_authorizes_exact_host():
    with _clean_env(VIPER_AUTHORIZED_TARGETS="x.com"):
        assert is_blocked("x.com") == (False, "")


def test_env_bare_domain_covers_subdomains():
    with _clean_env(VIPER_AUTHORIZED_TARGETS="x.com"):
        assert is_blocked("sub.x.com")[0] is False


def test_env_wildcard_entry():
    with _clean_env(VIPER_AUTHORIZED_TARGETS="*.paypal.com"):
        assert is_blocked("api.paypal.com")[0] is False
        assert is_blocked("paypal.com")[0] is False


def test_env_list_and_semicolons():
    with _clean_env(VIPER_AUTHORIZED_TARGETS="foo.com; x.com , bar.org"):
        assert is_blocked("x.com")[0] is False


def test_env_authorizes_gov_tld():
    with _clean_env(VIPER_AUTHORIZED_TARGETS="agency.gov"):
        assert is_blocked("agency.gov")[0] is False


def test_env_blanket_star_allows_any_blocked():
    with _clean_env(VIPER_AUTHORIZED_TARGETS="*"):
        assert is_blocked("x.com")[0] is False
        assert is_blocked("agency.gov")[0] is False


# ── programmatic authorization sources ───────────────────────────────────────
def test_authorized_true_is_blanket():
    with _clean_env():
        assert is_blocked("x.com", authorized=True)[0] is False


def test_authorized_iterable_of_hosts():
    with _clean_env():
        assert is_blocked("x.com", authorized=["x.com", "paypal.com"])[0] is False
        # paypal.com IS a protected domain and is NOT in this allowlist -> still blocked
        assert is_blocked("paypal.com", authorized=["x.com", "netflix.com"])[0] is True


class _ScopeLike:
    """Mimics ScopeReasoner.decide(host).allowed; authoritative only when flagged."""
    def __init__(self, allowed_hosts, authoritative=True):
        self._allowed = set(allowed_hosts)
        self.viper_authoritative = authoritative

    def decide(self, host):
        class _D:
            pass
        d = _D()
        d.allowed = host in self._allowed
        return d


def test_authoritative_scope_object_in_scope_allows():
    with _clean_env():
        scope = _ScopeLike({"x.com"})
        assert is_blocked("x.com", authorized=scope)[0] is False
        # a protected host NOT in the loaded scope stays blocked (fail-closed)
        assert is_blocked("paypal.com", authorized=scope)[0] is True


def test_non_authoritative_scope_never_authorizes():
    # REGRESSION (auto-scope self-authorization): a scope NOT flagged authoritative — e.g.
    # the target-derived auto-scope — must NOT let a protected target authorize itself.
    with _clean_env():
        auto = _ScopeLike({"whitehouse.gov", "x.com"}, authoritative=False)
        assert is_blocked("whitehouse.gov", authorized=auto)[0] is True
        assert is_blocked("x.com", authorized=auto)[0] is True


def test_authoritative_scope_out_of_scope_stays_blocked_tuple_return():
    # REGRESSION (tuple truthiness): an is_in_scope() returning (bool, reason) must be
    # unwrapped — an OUT-of-scope protected host (False, ...) must NOT be authorized.
    class _MgrLike:
        def __init__(self):
            self.viper_authoritative = True

        def is_in_scope(self, host):
            return (host == "x.com", "reason string")   # always a truthy 2-tuple

    with _clean_env():
        mgr = _MgrLike()
        assert is_blocked("x.com", authorized=mgr)[0] is False        # in scope -> allowed
        assert is_blocked("paypal.com", authorized=mgr)[0] is True    # out of scope -> blocked


def test_scope_decide_raising_does_not_weaken_block():
    class _Boom:
        viper_authoritative = True

        def decide(self, host):
            raise RuntimeError("scope backend down")
    with _clean_env():
        assert is_blocked("x.com", authorized=_Boom())[0] is True


def test_safe_keyword_does_not_rescue_protected_host():
    # REGRESSION (keyword substring): a lab keyword must not unblock a protected subdomain
    # or a gov/mil host just by appearing in the string.
    with _clean_env():
        assert is_blocked("ctf.paypal.com")[0] is True
        assert is_blocked("dvwa.google.com")[0] is True
        assert is_blocked("hackthebox.mil")[0] is True
        # but a genuine lab label / safe suffix is still allowed
        assert is_blocked("ctf.local")[0] is False


def test_userinfo_prefix_does_not_bypass_blocklist():
    # REGRESSION (userinfo): the authority host is what matters, not the user@ prefix.
    with _clean_env():
        assert is_blocked("http://x@google.com")[0] is True
        assert is_blocked("http://admin:pw@paypal.com/path")[0] is True
        # userinfo host that IS the real connect target still resolves correctly
        assert is_blocked("http://google.com@my-app.com")[0] is False  # connects to my-app.com


def test_normalize_hardening_schemes_backslash_ipv6():
    # Hardening (pre-existing bypasses the review surfaced): any scheme is stripped, '\' is
    # folded to '/', bracketed IPv6 is unwrapped.
    with _clean_env():
        assert is_blocked("ftp://google.com")[0] is True          # non-http scheme
        assert is_blocked("ssh://admin@paypal.com")[0] is True
        assert is_blocked(r"http://google.com\@evil.com")[0] is True  # backslash authority -> google.com
        assert is_blocked("http://[::1]:8080")[0] is False         # loopback IPv6, allowed


# ── safe targets + wrapper still correct ─────────────────────────────────────
def test_safe_targets_unaffected():
    with _clean_env():
        assert is_blocked("localhost")[0] is False
        assert is_blocked("192.168.1.1")[0] is False
        assert is_blocked("juice-shop.local")[0] is False


def test_validate_target_forwards_authorization():
    with _clean_env():
        valid, _ = validate_target("x.com", authorized=True)
        assert valid is True
        assert validate_target("x.com")[0] is False


def test_on_blocklist_ignores_authorization_and_env():
    # on_blocklist reports the RAW blocklist verdict regardless of any override, so the
    # audit trail can note "a protected host ran under authorization".
    with _clean_env(VIPER_AUTHORIZED_TARGETS="x.com"):
        assert on_blocklist("x.com") is True          # still on the list...
        assert is_blocked("x.com")[0] is False        # ...but allowed by authorization
        assert on_blocklist("example.org") is False   # never on the list
