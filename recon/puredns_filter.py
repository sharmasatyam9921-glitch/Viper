#!/usr/bin/env python3
"""
VIPER 5.0 — Puredns Wildcard Filtering

Puredns removes wildcard/poisoned DNS entries from subdomain lists.
Critical for accuracy — without this, wildcard domains generate thousands
of false subdomains that waste scan time and produce FPs.
"""

import asyncio
import logging
import shutil
import tempfile
from pathlib import Path
from typing import List, Optional

logger = logging.getLogger("viper.recon.puredns")


class PurednsFilter:
    """Puredns subprocess wrapper for wildcard DNS filtering.

    Args:
        binary: Path to puredns binary.
        resolvers: Path to DNS resolver list.
        threads: Number of concurrent DNS workers (default 50).
    """

    BUILTIN_RESOLVERS = [
        "8.8.8.8", "8.8.4.4",           # Google
        "1.1.1.1", "1.0.0.1",           # Cloudflare
        "9.9.9.9", "149.112.112.112",   # Quad9
        "208.67.222.222", "208.67.220.220",  # OpenDNS
    ]

    def __init__(
        self,
        binary: Optional[str] = None,
        resolvers: Optional[str] = None,
        threads: int = 50,
    ):
        self.binary = binary or shutil.which("puredns")
        self.available = self.binary is not None
        self.resolvers_file = resolvers
        self.threads = threads

    async def filter_wildcards(self, subdomains: List[str], domain: str) -> List[str]:
        """Remove wildcard entries from a subdomain list.

        Args:
            subdomains: Raw subdomain list (may contain wildcards).
            domain: Parent domain for context.

        Returns:
            Filtered list with wildcards removed.
        """
        if not self.available:
            logger.info("puredns not installed, using Python fallback wildcard filter")
            return await self._fallback_filter(subdomains, domain)

        if not subdomains:
            return []

        # Write subdomains to temp file
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as sf:
            sf.write("\n".join(subdomains))
            input_file = sf.name

        # Write resolvers if not provided
        resolvers_file = self.resolvers_file
        if not resolvers_file:
            with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as rf:
                rf.write("\n".join(self.BUILTIN_RESOLVERS))
                resolvers_file = rf.name

        with tempfile.NamedTemporaryFile(suffix=".txt", delete=False) as of:
            output_file = of.name

        try:
            cmd = [
                self.binary, "resolve",
                input_file,
                "-r", resolvers_file,
                "-w", output_file,
                "-t", str(self.threads),
                "--wildcard-batch", "500000",
                "-q",  # Quiet
            ]

            logger.info("puredns: filtering %d subdomains for wildcards", len(subdomains))

            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await asyncio.wait_for(proc.communicate(), timeout=300)

            # Read filtered output
            filtered = Path(output_file).read_text().strip().splitlines()
            filtered = [s.strip() for s in filtered if s.strip()]

            removed = len(subdomains) - len(filtered)
            logger.info("puredns: %d/%d subdomains survived wildcard filter (%d removed)",
                        len(filtered), len(subdomains), removed)

            return filtered

        except asyncio.TimeoutError:
            logger.warning("puredns timed out, returning unfiltered list")
            return subdomains
        except Exception as e:
            logger.error("puredns failed: %s, returning unfiltered", e)
            return subdomains
        finally:
            Path(input_file).unlink(missing_ok=True)
            if not self.resolvers_file:
                Path(resolvers_file).unlink(missing_ok=True)
            Path(output_file).unlink(missing_ok=True)

    async def _fallback_filter(self, subdomains: List[str], domain: str) -> List[str]:
        """Python fallback: detect wildcards by checking if random subdomains resolve.

        If random-string.domain.com resolves, the domain has a wildcard DNS record.
        In that case, compare resolved IPs and filter out those matching the wildcard IP.
        """
        import socket
        import random
        import string

        # Generate random subdomain to test for wildcard
        random_sub = ''.join(random.choices(string.ascii_lowercase, k=16)) + "." + domain
        wildcard_ips = set()

        try:
            loop = asyncio.get_event_loop()
            result = await loop.run_in_executor(None, socket.gethostbyname, random_sub)
            wildcard_ips.add(result)
            logger.info("Wildcard DNS detected for %s (resolves to %s)", domain, result)

            # Test a second random to confirm
            random_sub2 = ''.join(random.choices(string.ascii_lowercase, k=16)) + "." + domain
            result2 = await loop.run_in_executor(None, socket.gethostbyname, random_sub2)
            wildcard_ips.add(result2)
        except socket.gaierror:
            # No wildcard — all subdomains are likely real
            logger.debug("No wildcard DNS for %s", domain)
            return subdomains

        if not wildcard_ips:
            return subdomains

        # Filter out subdomains that resolve to wildcard IPs
        filtered = []
        for sub in subdomains:
            try:
                loop = asyncio.get_event_loop()
                ip = await asyncio.wait_for(
                    loop.run_in_executor(None, socket.gethostbyname, sub),
                    timeout=3,
                )
                if ip not in wildcard_ips:
                    filtered.append(sub)
            except (socket.gaierror, asyncio.TimeoutError):
                # Doesn't resolve — skip
                pass

        removed = len(subdomains) - len(filtered)
        logger.info("Fallback wildcard filter: %d/%d survived (%d removed as wildcard)",
                    len(filtered), len(subdomains), removed)
        return filtered


__all__ = ["PurednsFilter"]
