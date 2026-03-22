#!/usr/bin/env python3
"""
VIPER LLM Guardrails — Target validation and safety checks.

Prevents VIPER from being used against unauthorized targets by enforcing
domain blocklists, allowlists, and optional LLM-based assessment.
"""

import ipaddress
import logging
import re
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse

logger = logging.getLogger("viper.guardrails")


class TargetGuardrail:
    """Validates targets before scanning to prevent unauthorized use.

    Validation flow:
      1. Check allowlist (known pentest platforms) -> auto-allow
      2. Check blocklist (gov/mil/edu/bank) -> auto-deny
      3. Check private/reserved IPs -> auto-allow
      4. If LLM router available, ask for assessment
      5. Default: allow with warning
    """

    BLOCKLIST_DOMAINS: List[str] = [
        "gov", "mil", "edu", "bank", "police",
        "nhs", "army", "navy", "parliament",
        "judiciary", "court", "irs", "fbi",
        "cia", "nsa", "dhs", "dod",
    ]

    ALLOWLIST_PATTERNS: List[str] = [
        "hackthebox", "tryhackme", "dvwa", "vulnhub",
        "juice-shop", "natas", "overthewire", "webgoat",
        "portswigger", "pentesterlab", "hacker101",
        "ctftime", "picoctf", "root-me",
        "metasploitable", "dvcp", "bwapp",
        "localhost", "127.0.0.1", "0.0.0.0",
        "testphp.vulnweb.com", "demo.testfire.net",
    ]

    PRIVATE_RANGES: List[str] = [
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "127.0.0.0/8",
        "::1/128",
        "fc00::/7",
        "fe80::/10",
    ]

    def __init__(self, extra_blocklist: Optional[List[str]] = None,
                 extra_allowlist: Optional[List[str]] = None):
        self.blocklist = list(self.BLOCKLIST_DOMAINS)
        self.allowlist = list(self.ALLOWLIST_PATTERNS)
        if extra_blocklist:
            self.blocklist.extend(extra_blocklist)
        if extra_allowlist:
            self.allowlist.extend(extra_allowlist)

        self._private_nets = [
            ipaddress.ip_network(r) for r in self.PRIVATE_RANGES
        ]
        self._validation_log: List[Dict] = []

    async def validate_target(self, target: str,
                              model_router=None) -> Tuple[bool, str]:
        """Validate whether a target is safe to scan.

        Args:
            target: Domain name, URL, or IP address
            model_router: Optional LLM router for ambiguous cases

        Returns:
            Tuple of (allowed: bool, reason: str)
        """
        domain = self._extract_domain(target)
        if not domain:
            reason = f"Could not parse target: {target}"
            self._log_validation(target, False, reason)
            return False, reason

        # Step 1: Check allowlist
        for pattern in self.allowlist:
            if pattern in domain.lower():
                reason = f"Target matches allowlist pattern: {pattern}"
                self._log_validation(target, True, reason)
                return True, reason

        # Step 2: Check blocklist
        domain_lower = domain.lower()
        tld = domain_lower.rsplit(".", 1)[-1] if "." in domain_lower else ""
        for blocked in self.blocklist:
            blocked_l = blocked.lower()
            if tld == blocked_l or f".{blocked_l}." in f".{domain_lower}.":
                reason = (f"Target domain '{domain}' matches blocklist "
                          f"entry: .{blocked} — scanning government, "
                          f"military, educational, and financial "
                          f"infrastructure is prohibited")
                self._log_validation(target, False, reason)
                return False, reason

        # Step 3: Check private/reserved IPs
        if self._is_private_ip(domain):
            reason = f"Target is a private/reserved IP address: {domain}"
            self._log_validation(target, True, reason)
            return True, reason

        # Step 4: LLM assessment for ambiguous targets
        if model_router is not None:
            try:
                llm_result = await self._llm_assess(domain, model_router)
                if llm_result is not None:
                    allowed, llm_reason = llm_result
                    self._log_validation(target, allowed, llm_reason)
                    return allowed, llm_reason
            except Exception as e:
                logger.warning("LLM assessment failed: %s", e)

        # Step 5: Default — allow with warning
        reason = (f"Target '{domain}' passed basic checks but is not on "
                  f"the allowlist. Ensure you have authorization to test "
                  f"this target.")
        logger.warning(reason)
        self._log_validation(target, True, reason)
        return True, reason

    def validate_target_sync(self, target: str) -> Tuple[bool, str]:
        """Synchronous version of validate_target (no LLM assessment)."""
        import asyncio
        loop = asyncio.new_event_loop()
        try:
            return loop.run_until_complete(
                self.validate_target(target, model_router=None)
            )
        finally:
            loop.close()

    def validate(self, target: str) -> Tuple[bool, str]:
        """Backward-compatible sync validate (alias for validate_target_sync)."""
        return self.validate_target_sync(target)

    def get_validation_log(self) -> List[Dict]:
        """Return the history of all validation checks."""
        return list(self._validation_log)

    # -----------------------------------------------------------------------
    # Internal helpers
    # -----------------------------------------------------------------------

    def _extract_domain(self, target: str) -> Optional[str]:
        """Extract the domain/host from a target string."""
        target = target.strip()
        if not target:
            return None

        # If it looks like a URL, parse it
        if "://" in target:
            parsed = urlparse(target)
            host = parsed.hostname
            return host if host else None

        # If it has a port, strip it
        if ":" in target and not target.startswith("["):
            target = target.rsplit(":", 1)[0]

        # Strip path components
        target = target.split("/")[0]
        return target if target else None

    def _is_private_ip(self, host: str) -> bool:
        """Check if a host string is a private/reserved IP address."""
        try:
            addr = ipaddress.ip_address(host)
            return any(addr in net for net in self._private_nets)
        except ValueError:
            return False

    async def _llm_assess(self, domain: str,
                          model_router) -> Optional[Tuple[bool, str]]:
        """Ask the LLM to assess whether a target is safe to scan."""
        prompt = (
            f"Is '{domain}' a legitimate penetration testing target? "
            f"Consider: Is it a known CTF/lab platform? A company's "
            f"bug bounty program? A personal test server? "
            f"Reply with ALLOW or DENY followed by a brief reason."
        )
        try:
            if hasattr(model_router, "generate"):
                response = await model_router.generate(prompt)
            elif hasattr(model_router, "ask"):
                response = await model_router.ask(prompt)
            else:
                return None

            text = str(response).strip().upper()
            if text.startswith("ALLOW"):
                return True, f"LLM assessment: {response}"
            elif text.startswith("DENY"):
                return False, f"LLM assessment: {response}"
        except Exception as e:
            logger.debug("LLM assess error: %s", e)
        return None

    def _log_validation(self, target: str, allowed: bool, reason: str):
        """Record a validation result."""
        import time
        self._validation_log.append({
            "target": target,
            "allowed": allowed,
            "reason": reason,
            "timestamp": time.time(),
        })
        level = logging.INFO if allowed else logging.WARNING
        logger.log(level, "Target validation: %s -> %s (%s)",
                   target, "ALLOWED" if allowed else "DENIED", reason)


class InputSanitizer:
    """Sanitizes and validates user inputs to prevent misuse."""

    MAX_URL_LENGTH = 2048
    MAX_WORDLIST_SIZE = 100_000

    # Patterns that should never appear in scan targets
    DANGEROUS_PATTERNS = [
        r";\s*(rm|del|format|mkfs|dd)\s",       # destructive commands
        r"\|\s*(nc|ncat|bash|sh|cmd)\s",         # shell piping
        r"&&\s*(curl|wget)\s.*\|.*sh",           # download-and-execute
    ]

    def __init__(self):
        self._compiled_patterns = [
            re.compile(p, re.IGNORECASE) for p in self.DANGEROUS_PATTERNS
        ]

    def sanitize_url(self, url: str) -> Tuple[bool, str]:
        """Validate and sanitize a URL for scanning.

        Returns:
            Tuple of (valid: bool, cleaned_url_or_error: str)
        """
        url = url.strip()
        if not url:
            return False, "Empty URL"
        if len(url) > self.MAX_URL_LENGTH:
            return False, f"URL exceeds max length ({self.MAX_URL_LENGTH})"

        # Check for injection in URL
        for pattern in self._compiled_patterns:
            if pattern.search(url):
                return False, "URL contains dangerous pattern"

        # Ensure scheme
        if not url.startswith(("http://", "https://")):
            url = f"https://{url}"

        parsed = urlparse(url)
        if not parsed.hostname:
            return False, "Could not parse hostname from URL"

        return True, url

    def sanitize_header(self, name: str, value: str) -> Tuple[bool, str]:
        """Validate an HTTP header name and value."""
        # Prevent CRLF injection in headers
        if "\r" in name or "\n" in name or "\r" in value or "\n" in value:
            return False, "Header contains CRLF characters"
        if len(value) > 8192:
            return False, "Header value too long"
        return True, value
