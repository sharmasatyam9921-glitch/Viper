"""
VIPER 5.0 - Masscan Port Scanner
=================================
High-speed asynchronous port scanner wrapper around the ``masscan`` binary.

Masscan is significantly faster than naabu/nmap for large IP ranges
(millions of pps possible) but trades stealth for speed. This module
includes safe-default rate limiting (1000 pps) to avoid SYN floods
that would trip WAF/IPS systems.

Falls back gracefully if the masscan binary isn't installed — callers
get an empty result instead of an exception.

Requires masscan to be in $PATH OR the MASSCAN_PATH env var to point at it.
On Windows, masscan must be run as administrator (uses raw sockets).
"""

import asyncio
import ipaddress
import json
import logging
import os
import shutil
import tempfile
from pathlib import Path
from typing import Dict, List, Optional, Set, Union

logger = logging.getLogger("viper.recon.masscan")

MASSCAN_PATH = os.environ.get("MASSCAN_PATH", shutil.which("masscan"))
DEFAULT_PORTS = "21,22,23,25,53,80,110,135,139,143,443,445,993,995,1433,1521,1723,3306,3389,5432,5900,6379,8000,8008,8080,8443,8888,9000,9090,9200,11211,27017,3000,5000"
DEFAULT_RATE = 1000  # packets per second — safe default
MAX_RATE = 10000     # hard cap to prevent accidental SYN floods


def masscan_available() -> bool:
    """Return True if a masscan binary is on disk."""
    return MASSCAN_PATH is not None and Path(MASSCAN_PATH).exists()


def _expand_targets(targets: List[str]) -> List[str]:
    """
    Validate and expand a mix of single IPs and CIDR ranges.

    Drops anything that doesn't parse as an IPv4/IPv6 address or
    network. Returns the original strings (not exploded), since masscan
    handles CIDR natively and exploding a /16 would be wasteful.
    """
    valid: List[str] = []
    for t in targets:
        try:
            # Try as network first (handles /CIDR), then as single addr
            try:
                ipaddress.ip_network(t, strict=False)
            except ValueError:
                ipaddress.ip_address(t)
            valid.append(t)
        except ValueError:
            logger.debug("Skipping invalid target: %s", t)
    return valid


async def scan(
    targets: Union[List[str], Set[str]],
    ports: str = DEFAULT_PORTS,
    rate: int = DEFAULT_RATE,
    timeout: int = 600,
    extra_args: Optional[List[str]] = None,
) -> Dict[str, List[int]]:
    """
    Run masscan against ``targets`` and return ``{ip: [open_ports]}``.

    Args:
        targets: List/set of IPv4 addresses or CIDR ranges (e.g.
            ``["1.2.3.4", "10.0.0.0/24"]``).
        ports: Port spec, comma-separated (e.g. ``"80,443,8000-9000"``).
        rate: Packets per second. Capped at ``MAX_RATE`` (10000).
        timeout: Subprocess timeout in seconds.
        extra_args: Additional masscan flags.

    Returns:
        ``{ip: [port, port, ...]}``. Empty dict if masscan unavailable
        or no open ports found.
    """
    if not masscan_available():
        logger.info("masscan not installed — returning empty result")
        return {}

    target_list = _expand_targets(list(targets))
    if not target_list:
        logger.warning("No valid masscan targets after validation")
        return {}

    safe_rate = min(max(rate, 100), MAX_RATE)

    # Write JSON output to a temp file (masscan can stream JSON)
    out_file = tempfile.NamedTemporaryFile(
        mode="w", suffix=".json", delete=False
    )
    out_file.close()

    cmd = [
        MASSCAN_PATH,
        *target_list,
        "-p", ports,
        "--rate", str(safe_rate),
        "-oJ", out_file.name,
        "--wait", "0",
    ]
    if extra_args:
        cmd.extend(extra_args)

    logger.info(
        "Running masscan: %d targets, ports=%s, rate=%d pps",
        len(target_list), ports, safe_rate,
    )

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            await asyncio.wait_for(proc.wait(), timeout=timeout)
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()
            logger.warning("masscan timed out after %ds", timeout)

        # Parse JSON results
        result: Dict[str, List[int]] = {}
        try:
            with open(out_file.name, "r", encoding="utf-8") as f:
                content = f.read().strip()
            if not content:
                return {}

            # masscan outputs a JSON array (sometimes with trailing comma)
            content = content.rstrip(",").rstrip()
            if not content.startswith("["):
                content = "[" + content + "]"

            try:
                records = json.loads(content)
            except json.JSONDecodeError:
                # Fall back to line-by-line parsing for malformed array
                records = []
                for line in content.splitlines():
                    line = line.strip().rstrip(",")
                    if not line or line in ("[", "]"):
                        continue
                    try:
                        records.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue

            for rec in records:
                ip = rec.get("ip", "")
                if not ip:
                    continue
                for p in rec.get("ports", []):
                    port = p.get("port")
                    status = p.get("status", "")
                    if port and status == "open":
                        result.setdefault(ip, []).append(int(port))

            for ip in result:
                result[ip] = sorted(set(result[ip]))

            logger.info(
                "masscan found %d open ports across %d hosts",
                sum(len(v) for v in result.values()),
                len(result),
            )
            return result
        except (OSError, json.JSONDecodeError) as exc:
            logger.warning("masscan output parse failed: %s", exc)
            return {}
    finally:
        try:
            Path(out_file.name).unlink(missing_ok=True)
        except OSError:
            pass


def is_cidr(target: str) -> bool:
    """Return True if target is a valid IPv4/IPv6 CIDR range."""
    try:
        net = ipaddress.ip_network(target, strict=False)
        return net.prefixlen < net.max_prefixlen
    except ValueError:
        return False


def expand_cidr(cidr: str, max_hosts: int = 1024) -> List[str]:
    """
    Expand a CIDR range into individual host strings, capped at
    ``max_hosts`` to prevent runaway memory usage on large nets.
    """
    try:
        net = ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        return []

    hosts: List[str] = []
    for i, host in enumerate(net.hosts()):
        if i >= max_hosts:
            logger.warning(
                "CIDR %s truncated at %d hosts (full size %d)",
                cidr, max_hosts, net.num_addresses,
            )
            break
        hosts.append(str(host))
    return hosts
