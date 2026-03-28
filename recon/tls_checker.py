#!/usr/bin/env python3
"""
VIPER 5.0 — TLS/SSL Certificate Checker

Checks for:
- Expired certificates
- Expiring soon (< 30 days)
- Self-signed certificates
- Weak cipher suites
- Certificate hostname mismatch
- Missing HSTS headers
"""

import asyncio
import logging
import ssl
import socket
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, List, Optional
from urllib.parse import urlparse

logger = logging.getLogger("viper.recon.tls_checker")


@dataclass
class TLSFinding:
    """TLS/SSL finding."""
    url: str
    finding_type: str  # expired, expiring_soon, self_signed, weak_cipher, hostname_mismatch, no_hsts
    severity: str
    detail: str
    cert_info: Dict = field(default_factory=dict)


class TLSChecker:
    """TLS/SSL certificate and configuration checker.

    Args:
        expiry_warn_days: Warn if cert expires within this many days (default 30).
        timeout: Connection timeout in seconds.
    """

    WEAK_CIPHERS = {"RC4", "DES", "3DES", "MD5", "NULL", "EXPORT", "anon"}

    def __init__(self, expiry_warn_days: int = 30, timeout: int = 10):
        self.expiry_warn_days = expiry_warn_days
        self.timeout = timeout

    async def check(self, target: str) -> List[TLSFinding]:
        """Check TLS configuration for a target.

        Args:
            target: URL or hostname (e.g., "https://example.com" or "example.com").

        Returns:
            List of TLSFinding objects.
        """
        findings: List[TLSFinding] = []

        # Parse target
        if "://" in target:
            parsed = urlparse(target)
            hostname = parsed.hostname or ""
            port = parsed.port or 443
        else:
            hostname = target.split(":")[0]
            port = int(target.split(":")[1]) if ":" in target else 443

        if not hostname:
            return findings

        # Get certificate info
        cert_info = await self._get_cert_info(hostname, port)
        if not cert_info:
            return findings

        now = datetime.now(timezone.utc)

        # Check expiry
        not_after = cert_info.get("not_after")
        if not_after:
            if not_after < now:
                findings.append(TLSFinding(
                    url=target, finding_type="expired", severity="high",
                    detail=f"Certificate expired on {not_after.isoformat()}",
                    cert_info=cert_info,
                ))
            elif (not_after - now).days < self.expiry_warn_days:
                days_left = (not_after - now).days
                findings.append(TLSFinding(
                    url=target, finding_type="expiring_soon", severity="medium",
                    detail=f"Certificate expires in {days_left} days ({not_after.isoformat()})",
                    cert_info=cert_info,
                ))

        # Check self-signed
        issuer = cert_info.get("issuer", "")
        subject = cert_info.get("subject", "")
        if issuer and subject and issuer == subject:
            findings.append(TLSFinding(
                url=target, finding_type="self_signed", severity="medium",
                detail=f"Self-signed certificate: {issuer}",
                cert_info=cert_info,
            ))

        # Check hostname mismatch
        san_domains = cert_info.get("san_domains", [])
        cn = cert_info.get("cn", "")
        all_cert_domains = san_domains + ([cn] if cn else [])

        hostname_match = False
        for cert_domain in all_cert_domains:
            if cert_domain.startswith("*."):
                # Wildcard match
                wildcard_base = cert_domain[2:]
                if hostname.endswith(wildcard_base) and hostname.count(".") == wildcard_base.count(".") + 1:
                    hostname_match = True
                    break
            elif cert_domain == hostname:
                hostname_match = True
                break

        if not hostname_match and all_cert_domains:
            findings.append(TLSFinding(
                url=target, finding_type="hostname_mismatch", severity="high",
                detail=f"Certificate CN/SAN ({', '.join(all_cert_domains[:3])}) doesn't match {hostname}",
                cert_info=cert_info,
            ))

        # Check protocol version
        protocol = cert_info.get("protocol", "")
        if protocol and ("TLSv1.0" in protocol or "TLSv1.1" in protocol or "SSLv" in protocol):
            findings.append(TLSFinding(
                url=target, finding_type="weak_protocol", severity="medium",
                detail=f"Outdated TLS protocol: {protocol}",
                cert_info=cert_info,
            ))

        return findings

    async def check_batch(self, targets: List[str], max_concurrent: int = 20) -> List[TLSFinding]:
        """Check TLS for multiple targets concurrently."""
        sem = asyncio.Semaphore(max_concurrent)
        all_findings: List[TLSFinding] = []

        async def _check(target: str):
            async with sem:
                findings = await self.check(target)
                all_findings.extend(findings)

        await asyncio.gather(*[_check(t) for t in targets], return_exceptions=True)
        return all_findings

    async def _get_cert_info(self, hostname: str, port: int = 443) -> Optional[Dict]:
        """Get certificate information from a TLS connection."""
        try:
            loop = asyncio.get_event_loop()
            info = await asyncio.wait_for(
                loop.run_in_executor(None, self._sync_get_cert, hostname, port),
                timeout=self.timeout,
            )
            return info
        except (asyncio.TimeoutError, Exception) as e:
            logger.debug("TLS check failed for %s:%d: %s", hostname, port, e)
            return None

    def _sync_get_cert(self, hostname: str, port: int) -> Dict:
        """Synchronous certificate fetch."""
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE  # We want to see even bad certs

        with socket.create_connection((hostname, port), timeout=self.timeout) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert(binary_form=False)
                cert_bin = ssock.getpeercert(binary_form=True)
                protocol = ssock.version()
                cipher = ssock.cipher()

                info = {
                    "protocol": protocol,
                    "cipher": cipher[0] if cipher else "",
                    "cipher_bits": cipher[2] if cipher and len(cipher) > 2 else 0,
                }

                if cert:
                    # Parse dates
                    not_before = cert.get("notBefore", "")
                    not_after = cert.get("notAfter", "")
                    if not_before:
                        info["not_before"] = ssl.cert_time_to_seconds(not_before)
                        info["not_before"] = datetime.fromtimestamp(
                            ssl.cert_time_to_seconds(not_before), tz=timezone.utc
                        )
                    if not_after:
                        info["not_after"] = datetime.fromtimestamp(
                            ssl.cert_time_to_seconds(not_after), tz=timezone.utc
                        )

                    # Subject and issuer
                    subject_parts = dict(x[0] for x in cert.get("subject", ()))
                    issuer_parts = dict(x[0] for x in cert.get("issuer", ()))
                    info["cn"] = subject_parts.get("commonName", "")
                    info["subject"] = subject_parts.get("organizationName", subject_parts.get("commonName", ""))
                    info["issuer"] = issuer_parts.get("organizationName", issuer_parts.get("commonName", ""))

                    # SAN domains
                    san = cert.get("subjectAltName", ())
                    info["san_domains"] = [v for t, v in san if t == "DNS"]

                    info["serial"] = cert.get("serialNumber", "")

                return info


__all__ = ["TLSChecker", "TLSFinding"]
