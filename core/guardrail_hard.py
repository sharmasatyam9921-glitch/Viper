#!/usr/bin/env python3
"""
VIPER 4.0 Hard Guardrail -- Deterministic, Non-Disableable Target Blocklist

Pure regex/string matching. NO LLM calls. NO network calls. NO external deps.
Blocks government, military, education, international orgs, and major tech domains
regardless of any project settings.
"""

import ipaddress
import re
from typing import Tuple

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
    "nato.int", "europa.eu", "oecd.org",
    "worldbank.org", "imf.org", "wto.org",
    "icrc.org", "ifrc.org",
    "asean.org", "osce.org", "oas.org",
    "bis.org", "adb.org", "afdb.org", "aiib.org",
    "cern.ch", "iso.org",
})

# ---------------------------------------------------------------------------
# Safe target patterns
# ---------------------------------------------------------------------------
_SAFE_SUFFIXES = (".local", ".test", ".lab", ".internal", ".home", ".lan", ".example", ".localhost")

_SAFE_DOMAINS: frozenset = frozenset({
    "vulnweb.com", "testphp.vulnweb.com", "testasp.vulnweb.com",
    "testhtml5.vulnweb.com", "rest.vulnweb.com",
    "hackthebox.com", "hackthebox.eu", "app.hackthebox.com",
    "tryhackme.com", "tryhackme.io",
    "dvwa.co.uk", "pentesterlab.com", "portswigger.net",
    "overthewire.org", "root-me.org", "ctftime.org",
    "vulnhub.com", "exploit.education",
})

_SAFE_HOSTNAME_KEYWORDS = (
    "juice-shop", "juiceshop", "dvwa", "webgoat", "bwapp",
    "metasploitable", "vulnhub", "hackthebox", "ctf",
)


def _normalize(raw: str) -> str:
    """Lowercase, strip protocol/path/port/whitespace."""
    d = raw.strip().lower()
    for prefix in ("https://", "http://"):
        if d.startswith(prefix):
            d = d[len(prefix):]
    d = d.split("/")[0]
    d = d.split(":")[0]
    d = d.rstrip(".")
    return d


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def is_blocked(target: str) -> Tuple[bool, str]:
    """Deterministic check: is this target a blocked domain?

    Returns:
        (blocked: bool, reason: str). If not blocked, reason is empty.
    """
    if not target:
        return False, ""

    d = _normalize(target)
    if not d:
        return False, ""

    # Safe targets override everything
    if is_safe_target(d):
        return False, ""

    # TLD suffix match (gov/mil/edu/int)
    if _COMPILED_TLD_RE.search(d):
        return True, (
            f"'{d}' belongs to a government, military, educational, or international "
            "organization TLD. Scanning is permanently blocked."
        )

    # Exact domain match
    if d in _BLOCKED_DOMAINS:
        return True, f"'{d}' is a protected major domain. Scanning is permanently blocked."

    # Subdomain of blocked domain
    for blocked in _BLOCKED_DOMAINS:
        if d.endswith("." + blocked):
            return True, (
                f"'{d}' is a subdomain of protected domain '{blocked}'. "
                "Scanning is permanently blocked."
            )

    return False, ""


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

    # Safe hostname keywords
    if any(kw in d for kw in _SAFE_HOSTNAME_KEYWORDS):
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


def validate_target(target: str) -> Tuple[bool, str]:
    """Convenience wrapper: returns (valid, reason).

    ``valid=True`` means the target is NOT blocked (i.e. scanning is allowed).
    """
    blocked, reason = is_blocked(target)
    if blocked:
        return False, reason
    return True, ""
