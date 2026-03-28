#!/usr/bin/env python3
"""
VIPER 5.0 — IP/CIDR Range Targeting

Expands CIDR notation into individual IPs, validates ranges,
and integrates with the recon pipeline for network-level scanning.

Supports:
  - Single IPs: 192.168.1.1
  - CIDR ranges: 10.0.0.0/24
  - IP ranges: 192.168.1.1-192.168.1.50
  - Mixed target lists: example.com, 10.0.0.0/24, 192.168.1.1
"""

import ipaddress
import logging
import re
from dataclasses import dataclass, field
from typing import List, Optional, Set, Tuple, Union

logger = logging.getLogger("viper.core.cidr_targeting")


@dataclass
class TargetSpec:
    """Parsed target specification."""
    original: str
    target_type: str  # "domain", "ip", "cidr", "range"
    ips: List[str] = field(default_factory=list)
    domain: str = ""
    cidr: str = ""
    total_hosts: int = 0


class CIDRTargeting:
    """IP/CIDR range targeting and expansion.

    Expands CIDR ranges, validates IPs, separates domains from IPs,
    and enforces scope limits.

    Args:
        max_hosts: Maximum total hosts to expand (default 65536 = /16).
        exclude_private: Skip RFC1918 private ranges (default False for pentesting).
    """

    # Private ranges (for scope checking, not exclusion)
    PRIVATE_RANGES = [
        ipaddress.ip_network("10.0.0.0/8"),
        ipaddress.ip_network("172.16.0.0/12"),
        ipaddress.ip_network("192.168.0.0/16"),
        ipaddress.ip_network("127.0.0.0/8"),
        ipaddress.ip_network("169.254.0.0/16"),
    ]

    def __init__(self, max_hosts: int = 65536, exclude_private: bool = False):
        self.max_hosts = max_hosts
        self.exclude_private = exclude_private

    def parse_targets(self, targets: List[str]) -> Tuple[List[str], List[str]]:
        """Parse mixed target list into (domains, ips).

        Args:
            targets: Mixed list of domains, IPs, CIDRs, ranges.

        Returns:
            Tuple of (domain_list, ip_list).
        """
        domains: List[str] = []
        ips: Set[str] = set()

        for target in targets:
            target = target.strip()
            if not target or target.startswith("#"):
                continue

            spec = self.classify(target)

            if spec.target_type == "domain":
                domains.append(spec.domain)
            else:
                for ip in spec.ips:
                    if self.exclude_private and self._is_private(ip):
                        continue
                    ips.add(ip)

            if len(ips) > self.max_hosts:
                logger.warning("IP count exceeds max_hosts (%d), truncating", self.max_hosts)
                break

        return domains, sorted(ips)[:self.max_hosts]

    def classify(self, target: str) -> TargetSpec:
        """Classify a single target string.

        Args:
            target: IP, CIDR, range, or domain string.

        Returns:
            TargetSpec with expanded IPs or domain.
        """
        target = target.strip().rstrip("/")

        # Strip protocol if present
        if "://" in target:
            target = target.split("://", 1)[1]
        # Strip port if present
        if ":" in target and not target.startswith("["):
            # Could be IPv6 or host:port
            parts = target.rsplit(":", 1)
            if parts[1].isdigit():
                target = parts[0]

        # Check CIDR notation (e.g., 10.0.0.0/24)
        if "/" in target:
            return self._parse_cidr(target)

        # Check IP range (e.g., 192.168.1.1-192.168.1.50)
        if "-" in target and self._looks_like_ip(target.split("-")[0]):
            return self._parse_range(target)

        # Check single IP
        if self._looks_like_ip(target):
            return TargetSpec(
                original=target, target_type="ip",
                ips=[target], total_hosts=1,
            )

        # It's a domain
        return TargetSpec(
            original=target, target_type="domain",
            domain=target, total_hosts=1,
        )

    def expand_cidr(self, cidr: str) -> List[str]:
        """Expand CIDR notation to list of IPs.

        Args:
            cidr: CIDR string (e.g., "192.168.1.0/24").

        Returns:
            List of IP strings (excludes network and broadcast).
        """
        try:
            network = ipaddress.ip_network(cidr, strict=False)
            if network.num_addresses > self.max_hosts:
                logger.warning("CIDR %s has %d hosts (max %d), truncating",
                              cidr, network.num_addresses, self.max_hosts)
            return [str(ip) for ip in list(network.hosts())[:self.max_hosts]]
        except ValueError as e:
            logger.error("Invalid CIDR: %s — %s", cidr, e)
            return []

    def expand_range(self, start_ip: str, end_ip: str) -> List[str]:
        """Expand IP range to list of IPs.

        Args:
            start_ip: Start IP (e.g., "192.168.1.1").
            end_ip: End IP (e.g., "192.168.1.50").
        """
        try:
            start = int(ipaddress.ip_address(start_ip))
            end = int(ipaddress.ip_address(end_ip))
            if end < start:
                start, end = end, start
            count = min(end - start + 1, self.max_hosts)
            return [str(ipaddress.ip_address(start + i)) for i in range(count)]
        except ValueError as e:
            logger.error("Invalid IP range: %s-%s — %s", start_ip, end_ip, e)
            return []

    def _parse_cidr(self, target: str) -> TargetSpec:
        """Parse CIDR notation."""
        ips = self.expand_cidr(target)
        return TargetSpec(
            original=target, target_type="cidr",
            ips=ips, cidr=target, total_hosts=len(ips),
        )

    def _parse_range(self, target: str) -> TargetSpec:
        """Parse IP range (start-end)."""
        parts = target.split("-", 1)
        ips = self.expand_range(parts[0].strip(), parts[1].strip())
        return TargetSpec(
            original=target, target_type="range",
            ips=ips, total_hosts=len(ips),
        )

    def _looks_like_ip(self, s: str) -> bool:
        """Check if string looks like an IP address."""
        try:
            ipaddress.ip_address(s)
            return True
        except ValueError:
            return bool(re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", s))

    def _is_private(self, ip_str: str) -> bool:
        """Check if IP is in a private range."""
        try:
            ip = ipaddress.ip_address(ip_str)
            return any(ip in net for net in self.PRIVATE_RANGES)
        except ValueError:
            return False

    def summarize(self, targets: List[str]) -> str:
        """Get a human-readable summary of targets."""
        domains, ips = self.parse_targets(targets)
        parts = []
        if domains:
            parts.append(f"{len(domains)} domains")
        if ips:
            parts.append(f"{len(ips)} IPs")
        return ", ".join(parts) if parts else "no targets"


__all__ = ["CIDRTargeting", "TargetSpec"]
