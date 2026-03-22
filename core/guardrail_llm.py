#!/usr/bin/env python3
"""
VIPER 4.0 LLM-Based Target Guardrail

LLM-powered target validation that checks whether a domain/IP is safe to scan.
Falls back to deterministic checks when no LLM is available.

Blocks: .gov/.mil/.edu/.int, major tech, cloud providers, social media, banks,
        healthcare, critical infrastructure.
Allows: Private IPs (RFC1918), .local/.test/.lab, intentionally vulnerable apps.
"""

import asyncio
import ipaddress
import json
import logging
import re
import socket
from typing import Any, Optional, Tuple

logger = logging.getLogger("viper.guardrail_llm")

# ---------------------------------------------------------------------------
# LLM System Prompt
# ---------------------------------------------------------------------------

GUARDRAIL_SYSTEM_PROMPT = """You are a security guardrail for an authorized penetration testing platform.
Your job is to evaluate whether a target domain is safe to allow for scanning.

You must BLOCK targets that are:
- Government or military websites (.gov, .mil, country variants like .gov.uk, .gouv.fr, etc.)
- Major tech companies (google.com, amazon.com, microsoft.com, apple.com, meta.com, facebook.com, twitter.com, x.com, netflix.com, adobe.com, oracle.com, salesforce.com, ibm.com, intel.com, nvidia.com, etc. and ALL their subdomains/variants)
- Major cloud providers (aws.amazon.com, cloud.google.com, azure.microsoft.com, cloudflare.com, akamai.com, fastly.com, etc.)
- Social media platforms (instagram.com, tiktok.com, linkedin.com, reddit.com, pinterest.com, snapchat.com, youtube.com, twitch.tv, discord.com, telegram.org, whatsapp.com, etc.)
- Major financial institutions and banks (paypal.com, stripe.com, visa.com, mastercard.com, jpmorgan.com, bankofamerica.com, chase.com, wellsfargo.com, etc.)
- Major e-commerce platforms (ebay.com, shopify.com, alibaba.com, walmart.com, target.com, bestbuy.com, etc.)
- Healthcare organizations (who.int, cdc.gov, nih.gov, etc.)
- Educational institutions (.edu domains)
- Critical infrastructure (DNS root servers, major ISPs, ICANN, etc.)
- Major news/media organizations (cnn.com, bbc.com, nytimes.com, reuters.com, etc.)
- Domains of major open-source projects/foundations (apache.org, linux.org, mozilla.org, wikipedia.org, etc.)

You must ALLOW targets that are:
- Custom or obscure domains belonging to small companies or individuals
- Internal/lab domains (.local, .internal, .test, .lab, .home, .lan)
- Intentionally vulnerable apps (vulnhub.com, hackthebox.com, tryhackme.com, vulnweb.com, testphp.vulnweb.com, juice-shop, DVWA, WebGoat, etc.)
- Any domain that is NOT explicitly in the block categories
- Any domain you are not 100% sure belongs to a major company/government/critical service

IMPORTANT: Be lenient. When in doubt, ALLOW. Only block domains you are absolutely certain
belong to the categories above. This is a pentest platform -- users scan targets they own or
have permission to test.

Output ONLY valid JSON: {"allowed": true/false, "reason": "brief explanation"}"""

GUARDRAIL_DOMAIN_PROMPT = """Evaluate this target domain for a penetration testing scan:

Target domain: {target}

Should this target be allowed or blocked? Block well-known/public/government/major-company domains. Allow obscure/custom/small-org domains."""

GUARDRAIL_IP_PROMPT = """Evaluate these target IPs and their resolved hostnames for a penetration testing scan:

Target IPs: {ips}
Resolved hostnames: {hostnames}

Should these targets be allowed or blocked? Judge based on the resolved hostnames."""


# ---------------------------------------------------------------------------
# Deterministic helpers (no LLM needed)
# ---------------------------------------------------------------------------

# Known safe targets -- always allowed
_SAFE_DOMAINS = {
    "vulnweb.com", "testphp.vulnweb.com", "testasp.vulnweb.com",
    "testhtml5.vulnweb.com", "rest.vulnweb.com",
    "hackthebox.com", "hackthebox.eu", "app.hackthebox.com",
    "tryhackme.com", "tryhackme.io",
    "dvwa.co.uk", "pentesterlab.com", "portswigger.net",
    "overthewire.org", "root-me.org", "ctftime.org",
    "vulnhub.com", "exploit.education",
}

_SAFE_SUFFIXES = (".local", ".test", ".lab", ".internal", ".home", ".lan", ".example", ".localhost")

_SAFE_HOSTNAME_KEYWORDS = (
    "juice-shop", "juiceshop", "dvwa", "webgoat", "bwapp",
    "metasploitable", "vulnhub", "hackthebox", "ctf",
)

# Blocked TLD patterns
_BLOCKED_TLD_PATTERNS = [
    r'\.gov$', r'\.gov\.[a-z]{2,3}$',
    r'\.gob\.[a-z]{2,3}$', r'\.gouv\.[a-z]{2,3}$',
    r'\.govt\.[a-z]{2,3}$',
    r'\.go\.[a-z]{2}$', r'\.gv\.[a-z]{2}$',
    r'\.mil$', r'\.mil\.[a-z]{2,3}$',
    r'\.edu$', r'\.edu\.[a-z]{2,3}$',
    r'\.ac\.[a-z]{2,3}$',
    r'\.int$',
]
_BLOCKED_TLD_RE = re.compile('|'.join(f'(?:{p})' for p in _BLOCKED_TLD_PATTERNS), re.IGNORECASE)

# Major domains -- deterministic blocklist
_BLOCKED_DOMAINS = frozenset({
    # Tech giants
    "google.com", "google.co.uk", "google.de", "google.fr", "google.co.jp",
    "google.co.in", "google.com.br", "google.ca", "google.com.au",
    "googleapis.com", "gstatic.com", "googlevideo.com",
    "amazon.com", "amazon.co.uk", "amazon.de", "amazon.co.jp",
    "amazonaws.com", "aws.amazon.com",
    "microsoft.com", "azure.com", "live.com", "outlook.com", "office.com",
    "office365.com", "microsoftonline.com", "windows.com", "windows.net",
    "apple.com", "icloud.com", "apple.co.uk",
    "meta.com", "facebook.com", "fb.com", "instagram.com", "whatsapp.com",
    "whatsapp.net", "messenger.com",
    "twitter.com", "x.com", "t.co",
    "netflix.com", "adobe.com", "oracle.com", "salesforce.com",
    "ibm.com", "intel.com", "nvidia.com", "cisco.com", "vmware.com",
    "broadcom.com", "qualcomm.com", "samsung.com", "huawei.com",
    "dell.com", "hp.com", "hpe.com", "lenovo.com",
    # Cloud providers
    "cloudflare.com", "akamai.com", "fastly.com", "digitalocean.com",
    "linode.com", "vultr.com", "heroku.com", "render.com",
    "vercel.com", "netlify.com", "fly.io",
    # Social media
    "linkedin.com", "reddit.com", "pinterest.com", "snapchat.com",
    "tiktok.com", "youtube.com", "youtu.be", "twitch.tv",
    "discord.com", "discord.gg", "telegram.org", "telegram.me",
    "slack.com", "zoom.us", "zoom.com",
    # Financial
    "paypal.com", "stripe.com", "visa.com", "mastercard.com",
    "jpmorgan.com", "jpmorganchase.com", "bankofamerica.com",
    "chase.com", "wellsfargo.com", "goldmansachs.com",
    "morganstanley.com", "citigroup.com", "citibank.com",
    "americanexpress.com", "amex.com", "discover.com",
    "barclays.com", "hsbc.com", "ubs.com", "deutschebank.com",
    # E-commerce
    "ebay.com", "shopify.com", "alibaba.com", "aliexpress.com",
    "walmart.com", "target.com", "bestbuy.com", "costco.com",
    "etsy.com", "wayfair.com",
    # Media/News
    "cnn.com", "bbc.com", "bbc.co.uk", "nytimes.com", "reuters.com",
    "washingtonpost.com", "theguardian.com", "bloomberg.com",
    "forbes.com", "wsj.com",
    # Open source / foundations
    "apache.org", "linux.org", "kernel.org", "mozilla.org",
    "wikipedia.org", "wikimedia.org", "gnu.org", "fsf.org",
    "github.com", "gitlab.com", "bitbucket.org",
    # DNS / Infrastructure
    "icann.org", "iana.org", "verisign.com", "pir.org",
    # Healthcare
    "who.int", "redcross.org",
    # Intergovernmental
    "un.org", "nato.int", "europa.eu", "oecd.org", "worldbank.org",
    "imf.org", "wto.org",
})


def _normalize_domain(raw: str) -> str:
    """Lowercase, strip protocol/path/port/whitespace."""
    d = raw.strip().lower()
    for prefix in ("https://", "http://"):
        if d.startswith(prefix):
            d = d[len(prefix):]
    d = d.split("/")[0]
    d = d.split(":")[0]
    d = d.rstrip(".")
    return d


def is_private_ip(ip_str: str) -> bool:
    """Check if an IP address is private/RFC1918/loopback."""
    try:
        addr_str = ip_str.split("/")[0]
        addr = ipaddress.ip_address(addr_str)
        return addr.is_private or addr.is_loopback or addr.is_link_local
    except ValueError:
        return False


def _is_safe_domain(domain: str) -> bool:
    """Check if a domain is a known-safe target."""
    d = _normalize_domain(domain)
    if not d:
        return False
    # Safe suffixes
    if any(d.endswith(s) for s in _SAFE_SUFFIXES):
        return True
    # Exact safe domain match or subdomain
    if d in _SAFE_DOMAINS:
        return True
    for safe in _SAFE_DOMAINS:
        if d.endswith("." + safe):
            return True
    # Hostname keywords
    if any(kw in d for kw in _SAFE_HOSTNAME_KEYWORDS):
        return True
    return False


def _is_blocked_deterministic(domain: str) -> Tuple[bool, str]:
    """Deterministic block check -- no LLM needed."""
    d = _normalize_domain(domain)
    if not d:
        return False, ""

    # TLD check
    if _BLOCKED_TLD_RE.search(d):
        return True, (
            f"'{d}' belongs to a government, military, educational, or international "
            "organization TLD. Scanning is blocked."
        )

    # Exact domain or subdomain of blocked domain
    if d in _BLOCKED_DOMAINS:
        return True, f"'{d}' is a major protected domain. Scanning is blocked."
    for blocked in _BLOCKED_DOMAINS:
        if d.endswith("." + blocked):
            return True, f"'{d}' is a subdomain of protected domain '{blocked}'. Scanning is blocked."

    return False, ""


def resolve_ips(target_ips: list) -> list:
    """Reverse-DNS resolve public IPs to hostnames. Skips private IPs."""
    hostnames = []
    for ip_str in target_ips:
        addr_str = ip_str.split("/")[0]
        if is_private_ip(addr_str):
            continue
        try:
            hostname, _, _ = socket.gethostbyaddr(addr_str)
            if hostname and hostname != addr_str:
                hostnames.append(hostname)
                logger.info("Guardrail: %s -> %s", addr_str, hostname)
        except (socket.herror, socket.gaierror, OSError):
            logger.debug("Guardrail: no PTR record for %s", addr_str)
    return hostnames


def _extract_json(text: str) -> Optional[dict]:
    """Extract first JSON object from text."""
    # Try raw parse first
    try:
        return json.loads(text.strip())
    except (json.JSONDecodeError, ValueError):
        pass
    # Find JSON-like substring
    match = re.search(r'\{[^{}]*"allowed"[^{}]*\}', text, re.DOTALL)
    if match:
        try:
            return json.loads(match.group(0))
        except (json.JSONDecodeError, ValueError):
            pass
    return None


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

async def check_target_allowed(
    target: str,
    model_router: Any = None,
    target_ips: Optional[list] = None,
) -> Tuple[bool, str]:
    """Check if a target domain or IP list is allowed for scanning.

    Args:
        target: Domain string (or empty for IP-only mode).
        model_router: VIPER ModelRouter instance (optional).
        target_ips: List of IPs/CIDRs for IP mode.

    Returns:
        (allowed: bool, reason: str)
    """
    if target_ips is None:
        target_ips = []

    # --- Domain mode ---
    if target:
        # Always-safe targets bypass everything
        if _is_safe_domain(target):
            return True, f"'{target}' is a known safe/intentionally vulnerable target."

        # Deterministic block
        blocked, reason = _is_blocked_deterministic(target)
        if blocked:
            return False, reason

        # LLM check if available
        if model_router is not None:
            return await _llm_check_domain(model_router, target)

        # No LLM -- deterministic pass (lenient)
        return True, f"'{target}' passed deterministic checks (no LLM available for deep check)."

    # --- IP mode ---
    if not target_ips:
        return True, "No targets specified."

    # All private IPs -> auto-allow
    all_private = all(is_private_ip(ip.split("/")[0]) for ip in target_ips)
    if all_private:
        return True, "All targets are private/internal IPs."

    # Resolve public IPs
    try:
        hostnames = await asyncio.to_thread(resolve_ips, target_ips)
    except Exception:
        hostnames = resolve_ips(target_ips)

    if not hostnames:
        return True, "No recognizable hostnames resolved from target IPs."

    # Check resolved hostnames deterministically
    for hostname in hostnames:
        if _is_safe_domain(hostname):
            continue
        blocked, reason = _is_blocked_deterministic(hostname)
        if blocked:
            return False, reason

    # LLM check resolved hostnames
    if model_router is not None:
        return await _llm_check_ips(model_router, target_ips, hostnames)

    return True, "Target IPs passed deterministic checks."


async def _llm_check_domain(model_router: Any, domain: str) -> Tuple[bool, str]:
    """Ask LLM whether a domain is allowed."""
    prompt = GUARDRAIL_DOMAIN_PROMPT.format(target=domain)
    return await _invoke_guardrail_llm(model_router, prompt)


async def _llm_check_ips(
    model_router: Any, ips: list, hostnames: list
) -> Tuple[bool, str]:
    """Ask LLM whether IPs (with resolved hostnames) are allowed."""
    prompt = GUARDRAIL_IP_PROMPT.format(
        ips=", ".join(ips),
        hostnames=", ".join(hostnames),
    )
    return await _invoke_guardrail_llm(model_router, prompt)


async def _invoke_guardrail_llm(model_router: Any, user_prompt: str) -> Tuple[bool, str]:
    """Send guardrail prompt to LLM via model_router and parse JSON response."""
    for attempt in range(3):
        try:
            response = await model_router.generate(
                prompt=user_prompt,
                system_prompt=GUARDRAIL_SYSTEM_PROMPT,
                max_tokens=256,
                temperature=0.0,
            )

            text = response.text if hasattr(response, "text") else str(response)
            result = _extract_json(text)

            if result:
                allowed = result.get("allowed", True)
                reason = result.get("reason", "No reason provided")
                logger.info("Guardrail LLM result: allowed=%s, reason=%s", allowed, reason)
                return bool(allowed), str(reason)

            logger.warning("Guardrail attempt %d: no JSON in response", attempt + 1)

        except Exception as e:
            logger.warning("Guardrail attempt %d error: %s", attempt + 1, e)

    # All retries exhausted -- fail open (lenient)
    logger.error("Guardrail LLM check failed after 3 attempts, failing open")
    return True, "LLM guardrail check failed after 3 attempts (failing open)."


# ---------------------------------------------------------------------------
# Compatibility wrapper class for Phase 3 API consumers
# ---------------------------------------------------------------------------

class GuardrailLLM:
    """Wrapper providing a simple ``check(target)`` interface over the module functions."""

    def __init__(self, model_router=None):
        self.router = model_router

    async def check(self, target: str, context: Optional[Any] = None) -> Tuple[bool, str]:
        """Check whether *target* is allowed for scanning.

        Returns ``(allowed, reason)``.
        """
        if not self.router:
            # No LLM available -- fall through to deterministic check
            blocked, reason = _is_blocked_deterministic(target)
            if blocked:
                return False, reason
            return True, "No LLM available, deterministic check passed"
        try:
            return await check_target_allowed(target, model_router=self.router)
        except Exception as exc:
            logger.warning("GuardrailLLM.check failed: %s", exc)
            return True, "LLM check failed, allowing by default"
