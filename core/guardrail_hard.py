#!/usr/bin/env python3
"""
VIPER 4.0 Hard Guardrail -- Deterministic Target Blocklist with an Authorized Override

Pure regex/string matching. NO LLM calls. NO network calls. NO external deps.
By default blocks government, military, education, international orgs, and major tech
domains — this protects against typos and un-scoped runs (a bare ``google.com`` with no
authorization stays refused).

It is NOT a prohibition on legitimate work: an authorized operator running against a
target they are enrolled to test (e.g. a HackerOne program) can OVERRIDE the blocklist
for that specific host by supplying proof of authorization — either
  * a loaded, in-scope program scope (pass the ScopeReasoner / scope object as
    ``authorized``; a target its ``decide()`` marks in-scope is allowed), or
  * the ``VIPER_AUTHORIZED_TARGETS`` env var (comma/semicolon list of hosts / ``*.wildcards``;
    ``*`` authorizes everything).
The override is target-specific and requires a deliberate, auditable operator signal, so
the safety net still catches an un-authorized major domain.
"""

import ipaddress
import os
import re
from typing import Optional, Tuple

# ---------------------------------------------------------------------------
# TLD suffix patterns (case-insensitive)
# ---------------------------------------------------------------------------
_TLD_PATTERNS = [
    # Government
    r'\.gov$',
    r'\.gov\.[a-z]{2,3}$',       # .gov.uk, .gov.au, .gov.br
    r'\.gob\.[a-z]{2,3}$',       # .gob.mx, .gob.es
    r'\.gouv\.[a-z]{2,3}$',      # .gouv.fr, .gouv.ci
    r'\.govt\.[a-z]{2,3}$',      # .govt.nz
    r'\.go\.[a-z]{2}$',          # .go.jp, .go.kr (2-letter ccTLDs only)
    r'\.gv\.[a-z]{2}$',          # .gv.at
    r'\.government\.[a-z]{2,3}$',
    # Military
    r'\.mil$',
    r'\.mil\.[a-z]{2,3}$',
    # Education
    r'\.edu$',
    r'\.edu\.[a-z]{2,3}$',
    r'\.ac\.[a-z]{2,3}$',        # .ac.uk, .ac.jp
    # International organizations
    r'\.int$',
]
_COMPILED_TLD_RE = re.compile(
    '|'.join(f'(?:{p})' for p in _TLD_PATTERNS), re.IGNORECASE
)

# ---------------------------------------------------------------------------
# Blocked major domains (at least 50 + intergovernmental orgs)
# ---------------------------------------------------------------------------
_BLOCKED_DOMAINS: frozenset = frozenset({
    # === Major Tech ===
    "google.com", "googleapis.com", "gstatic.com", "googlevideo.com",
    "youtube.com", "youtu.be", "android.com", "chromium.org",
    "amazon.com", "amazonaws.com", "aws.amazon.com",
    "microsoft.com", "azure.com", "live.com", "outlook.com", "office.com",
    "office365.com", "microsoftonline.com", "windows.com", "windows.net",
    "bing.com", "msn.com", "skype.com", "linkedin.com",
    "apple.com", "icloud.com", "apple.co.uk",
    "meta.com", "facebook.com", "fb.com", "instagram.com",
    "whatsapp.com", "whatsapp.net", "messenger.com",
    "twitter.com", "x.com", "t.co",
    "netflix.com", "adobe.com", "oracle.com", "salesforce.com",
    "ibm.com", "intel.com", "nvidia.com", "cisco.com", "vmware.com",
    "broadcom.com", "qualcomm.com", "samsung.com", "huawei.com",
    "dell.com", "hp.com", "hpe.com", "lenovo.com",
    "tiktok.com", "bytedance.com",
    "snap.com", "snapchat.com", "pinterest.com",
    "reddit.com", "twitch.tv", "discord.com", "discord.gg",
    "telegram.org", "telegram.me", "signal.org",
    "slack.com", "zoom.us", "zoom.com",
    "spotify.com", "soundcloud.com",
    "dropbox.com", "box.com",
    "github.com", "gitlab.com", "bitbucket.org",

    # === Cloud Providers ===
    "cloudflare.com", "akamai.com", "fastly.com", "digitalocean.com",
    "linode.com", "vultr.com", "heroku.com", "render.com",
    "vercel.com", "netlify.com", "fly.io",
    "rackspace.com", "ovhcloud.com",

    # === Financial / Banking ===
    "paypal.com", "stripe.com", "visa.com", "mastercard.com",
    "jpmorgan.com", "jpmorganchase.com", "bankofamerica.com",
    "chase.com", "wellsfargo.com", "goldmansachs.com",
    "morganstanley.com", "citigroup.com", "citibank.com",
    "americanexpress.com", "amex.com", "discover.com",
    "barclays.com", "hsbc.com", "ubs.com", "deutschebank.com",
    "creditsuisse.com", "bnpparibas.com", "socgen.com",
    "schwab.com", "fidelity.com", "vanguard.com",
    "coinbase.com", "binance.com", "kraken.com",

    # === E-commerce ===
    "ebay.com", "shopify.com", "alibaba.com", "aliexpress.com",
    "walmart.com", "target.com", "bestbuy.com", "costco.com",
    "etsy.com", "wayfair.com",

    # === Media / News ===
    "cnn.com", "bbc.com", "bbc.co.uk", "nytimes.com", "reuters.com",
    "washingtonpost.com", "theguardian.com", "bloomberg.com",
    "forbes.com", "wsj.com", "ft.com", "economist.com",
    "apnews.com", "aljazeera.com", "nbcnews.com", "foxnews.com",

    # === Open Source / Foundations ===
    "apache.org", "linux.org", "kernel.org", "mozilla.org",
    "wikipedia.org", "wikimedia.org", "gnu.org", "fsf.org",
    "python.org", "nodejs.org", "ruby-lang.org", "golang.org",

    # === DNS / Infrastructure ===
    "icann.org", "iana.org", "verisign.com", "pir.org",
    "cloudflare-dns.com", "opendns.com",

    # === Healthcare ===
    "who.int", "redcross.org",

    # === Intergovernmental / International ===
    "un.org", "undp.org", "unicef.org", "unhcr.org", "unep.org",
    "unesco.org", "wfp.org", "iaea.org",
    "unfpa.org", "unhabitat.org", "unodc.org",
    "nato.int", "europa.eu", "oecd.org",
    "worldbank.org", "imf.org", "wto.org",
    "icrc.org", "ifrc.org",
    "asean.org", "osce.org", "oas.org",
    "bis.org", "adb.org", "afdb.org", "aiib.org",
    "cern.ch", "iso.org",
    # UN Specialized Agencies
    "ilo.org", "fao.org", "icao.int", "imo.org", "itu.int",
    "wipo.int", "wmo.int", "ifad.org", "unido.org", "unwto.org",
    # International Courts
    "icj-cij.org", "icc-cpi.int",
    # Regional Organizations & Development Banks
    "african-union.org", "caricom.org", "eib.org", "iadb.org",
    # Science/Research & Arms Control
    "iter.org", "ctbto.org", "opcw.org",
})

# ---------------------------------------------------------------------------
# Safe target patterns
# ---------------------------------------------------------------------------
_SAFE_SUFFIXES = (".local", ".test", ".lab", ".internal", ".home", ".lan", ".example", ".localhost")

_SAFE_DOMAINS: frozenset = frozenset({
    # Vuln-web sandboxes (IBM, Acunetix, etc. — all explicitly authorized
    # for testing per their public T&Cs)
    "vulnweb.com", "testphp.vulnweb.com", "testasp.vulnweb.com",
    "testhtml5.vulnweb.com", "rest.vulnweb.com",
    "demo.testfire.net", "testfire.net",                # IBM AltoroMutual
    "demo.testfire.net.well-known", "altoromutual.com",
    "zero.webappsecurity.com", "crackme.cenzic.com",
    "ghost.deister.es", "hack.me",
    # CTF / lab platforms
    "hackthebox.com", "hackthebox.eu", "app.hackthebox.com",
    "tryhackme.com", "tryhackme.io",
    "dvwa.co.uk", "pentesterlab.com", "portswigger.net",
    "overthewire.org", "root-me.org", "ctftime.org",
    "vulnhub.com", "exploit.education", "hack.me",
    "picoctf.org", "picoctf.com",
})

_SAFE_HOSTNAME_KEYWORDS = (
    "juice-shop", "juiceshop", "dvwa", "webgoat", "bwapp",
    "metasploitable", "vulnhub", "hackthebox", "ctf",
)


def _normalize(raw: str) -> str:
    """Lowercase; reduce a URL/host to its authority host (the thing an HTTP client connects
    to), so blocklist matching can't be dodged by scheme/userinfo/backslash/IPv6/port tricks."""
    d = raw.strip().lower()
    d = d.replace("\\", "/")                       # some clients treat '\' as '/'; fold first
    d = re.sub(r"^[a-z][a-z0-9+.\-]*://", "", d)   # strip ANY scheme (http, https, ftp, ...)
    d = d.split("/")[0]                             # authority only (drop path/query/fragment)
    if "@" in d:                                    # drop userinfo — user@google.com -> google.com
        d = d.rsplit("@", 1)[1]
    if d.startswith("[") and "]" in d:             # bracketed IPv6 literal: [::1]:8080 -> ::1
        d = d[1:d.index("]")]
    else:
        d = d.split(":")[0]                        # drop port
    d = d.rstrip(".")
    return d


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def _env_authorized_hosts() -> list:
    """Hosts/wildcards the operator authorized via ``VIPER_AUTHORIZED_TARGETS`` (comma or
    semicolon separated). Always consulted, so an operator can authorize without threading
    a scope object through every call site."""
    raw = os.environ.get("VIPER_AUTHORIZED_TARGETS", "") or ""
    return [h.strip().lower() for h in raw.replace(";", ",").split(",") if h.strip()]


def _host_covered(host: str, entry: str) -> bool:
    """True if ``host`` is covered by an authorization entry: ``*``/``all``/``any`` (blanket),
    an exact host, a bare domain (covers its subdomains), or a ``*.domain`` wildcard."""
    e = (entry or "").strip().lower()
    if not e:
        return False
    if e in ("*", "all", "any"):
        return True
    e = e.lstrip("*").lstrip(".")          # "*.x.com" / ".x.com" -> "x.com"
    if not e:
        return False
    return host == e or host.endswith("." + e)


def _is_authorized(host: str, authorized) -> bool:
    """Does the operator have proof of authorization for ``host``? Sources:
      * the ``VIPER_AUTHORIZED_TARGETS`` env allowlist (always consulted);
      * ``authorized=True`` (explicit blanket operator assertion);
      * ``authorized`` a list/tuple/set of host/wildcard strings (an explicit allowlist);
      * a ScopeReasoner/scope object — but ONLY if it is explicitly flagged
        ``viper_authoritative = True`` (an operator-loaded ``--scope`` program file). An
        auto-derived scope built from the target itself is NEVER authoritative, so a target
        can't authorize itself and defeat the blocklist.
    Fail-closed: anything else, or a scope backend that errors, does not authorize."""
    for entry in _env_authorized_hosts():
        if _host_covered(host, entry):
            return True
    if authorized is True:
        return True
    if isinstance(authorized, (list, tuple, set, frozenset)):
        for entry in authorized:
            if isinstance(entry, str) and _host_covered(host, entry):
                return True
        return False
    # Scope object: honored only when the operator explicitly marked it authoritative.
    if getattr(authorized, "viper_authoritative", False) is True:
        decide = getattr(authorized, "decide", None)
        if callable(decide):
            try:
                if getattr(decide(host), "allowed", None) is True:
                    return True
            except Exception:  # noqa: BLE001 — never let a scope error weaken the block
                pass
        isc = getattr(authorized, "is_in_scope", None)
        if callable(isc):
            try:
                res = isc(host)
                if isinstance(res, tuple):        # ScopeManager.is_in_scope -> (bool, reason)
                    res = res[0] if res else False
                if res is True:
                    return True
            except Exception:  # noqa: BLE001
                pass
    return False


def _blocklist_reason(host: str) -> Optional[str]:
    """The raw blocklist verdict for a normalized host, IGNORING safe/authorized overrides.
    Returns a short reason string if the host is on the protected blocklist, else None."""
    if _COMPILED_TLD_RE.search(host):
        return (f"'{host}' belongs to a government, military, educational, or international "
                "organization TLD.")
    if host in _BLOCKED_DOMAINS:
        return f"'{host}' is a protected major domain."
    for blocked in _BLOCKED_DOMAINS:
        if host.endswith("." + blocked):
            return f"'{host}' is a subdomain of protected domain '{blocked}'."
    return None


def on_blocklist(target: str) -> bool:
    """True if ``target`` is on the raw protected blocklist, ignoring any authorization,
    env allowlist, or safe-target override. Useful for auditing an authorized override
    ("a protected host was allowed because it is authorized")."""
    d = _normalize(target)
    return bool(d) and _blocklist_reason(d) is not None


def is_blocked(target: str, authorized=None) -> Tuple[bool, str]:
    """Deterministic check: is this target a blocked domain?

    Args:
        target: the host/URL to check.
        authorized: optional proof of authorization that OVERRIDES the blocklist for this
            specific host — a ScopeReasoner/scope object (in-scope ``decide()`` allows), an
            iterable of authorized host/wildcard strings, or ``True`` for a blanket operator
            assertion. ``VIPER_AUTHORIZED_TARGETS`` is always consulted in addition.

    Returns:
        (blocked: bool, reason: str). If not blocked, reason is empty.
    """
    if not target:
        return False, ""

    d = _normalize(target)
    if not d:
        return False, ""

    # The protected blocklist is evaluated FIRST — before any safe-target heuristic — so a
    # protected host can never be rescued by a coincidental safe keyword (e.g. 'ctf.army.gov'
    # or 'dvwa.google.com'). A host that is NOT on the blocklist is allowed (labs, RFC1918,
    # loopback, arbitrary in-scope program hosts all land here).
    reason = _blocklist_reason(d)
    if reason is None:
        return False, ""

    # Authorized-engagement override: an operator-loaded --scope, the VIPER_AUTHORIZED_TARGETS
    # allowlist, or an explicit authorized= signal permits an otherwise-protected host, for
    # legitimate authorized testing (e.g. a HackerOne program you are enrolled in).
    if _is_authorized(d, authorized):
        return False, ""

    return True, (
        reason + " Scanning is blocked unless the target is authorized — load its program "
        "scope with --scope (in-scope targets are allowed) or add it to VIPER_AUTHORIZED_TARGETS."
    )


def is_safe_target(target: str) -> bool:
    """Returns True if target is a known-safe/intentionally-vulnerable app or internal address.

    Safe targets: .local, .test, 127.0.0.1, 10.x, 172.16-31.x, 192.168.x, known vuln apps.
    """
    if not target:
        return False

    d = _normalize(target)
    if not d:
        return False

    # Safe domain suffixes
    if any(d.endswith(s) for s in _SAFE_SUFFIXES):
        return True

    # Exact safe domain or subdomain of safe domain
    if d in _SAFE_DOMAINS:
        return True
    for safe in _SAFE_DOMAINS:
        if d.endswith("." + safe):
            return True

    # Safe hostname keywords — whole DNS-label match, NOT substring: 'ctf' authorizes a host
    # with a literal 'ctf' label, but must NOT rescue 'ctf.paypal.com' (a protected subdomain).
    if set(d.split(".")) & set(_SAFE_HOSTNAME_KEYWORDS):
        return True

    # Private/loopback IP check
    try:
        addr_str = d.split("/")[0]
        addr = ipaddress.ip_address(addr_str)
        if addr.is_private or addr.is_loopback or addr.is_link_local:
            return True
    except ValueError:
        pass

    # RFC1918 CIDR patterns (for string-form IPs)
    _private_patterns = [
        r'^127\.',                           # loopback
        r'^10\.',                            # 10.0.0.0/8
        r'^172\.(1[6-9]|2[0-9]|3[01])\.',   # 172.16.0.0/12
        r'^192\.168\.',                      # 192.168.0.0/16
        r'^169\.254\.',                      # link-local
        r'^0\.',                             # 0.0.0.0/8
        r'^::1$',                            # IPv6 loopback
        r'^fc[0-9a-f]{2}:',                 # IPv6 ULA
        r'^fe80:',                           # IPv6 link-local
    ]
    for pattern in _private_patterns:
        if re.match(pattern, d):
            return True

    # localhost
    if d in ("localhost", "127.0.0.1", "::1", "0.0.0.0"):
        return True

    return False


# ---------------------------------------------------------------------------
# Compatibility exports for Phase 3 API consumers
# ---------------------------------------------------------------------------

BLOCKED_TLDS = {'.gov', '.mil', '.edu', '.int', '.govt'}
BLOCKED_DOMAINS = set(_BLOCKED_DOMAINS)


def validate_target(target: str, authorized=None) -> Tuple[bool, str]:
    """Convenience wrapper: returns (valid, reason).

    ``valid=True`` means the target is NOT blocked (i.e. scanning is allowed).
    ``authorized`` is forwarded to :func:`is_blocked` (see its docstring).
    """
    blocked, reason = is_blocked(target, authorized=authorized)
    if blocked:
        return False, reason
    return True, ""
