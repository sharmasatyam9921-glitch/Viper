#!/usr/bin/env python3
"""
VIPER 4.0 FFuf Directory Fuzzer Integration.

Runs ffuf (Fuzz Faster U Fool) for directory/file discovery with
auto-calibration, recursive fuzzing, and JSON output parsing.

Supports root fuzzing and recursive fuzzing under discovered base paths.
Graceful fallback if ffuf is not installed.
"""

import json
import logging
import os
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse

logger = logging.getLogger("viper.ffuf")

HACKAGENT_DIR = Path(__file__).parent.parent
WORDLISTS_DIR = HACKAGENT_DIR / "wordlists"

# Default wordlists to try (in priority order)
DEFAULT_WORDLISTS = [
    "common.txt",
    "raft-small-words.txt",
]

# Extensions to fuzz
DEFAULT_EXTENSIONS = [".php", ".asp", ".aspx", ".jsp", ".html", ".js", ".json", ".xml", ".txt", ".bak", ".old", ".conf"]

# Status codes to filter out by default
DEFAULT_FILTER_CODES = [404, 429]

# Status codes to match by default
DEFAULT_MATCH_CODES = [200, 201, 202, 204, 301, 302, 307, 308, 401, 403, 405, 500]


@dataclass
class FfufResult:
    """A single path discovered by ffuf."""
    url: str
    status: int
    length: int
    words: int
    lines: int
    content_type: str = ""
    redirect_location: str = ""
    source: str = "ffuf"


@dataclass
class FfufDiscovery:
    """Aggregated results from an ffuf scan."""
    results: List[FfufResult] = field(default_factory=list)
    target: str = ""
    tool_available: bool = False
    scan_completed: bool = False
    fuzz_targets_count: int = 0
    error: str = ""

    def to_dict(self) -> dict:
        return {
            "results": [
                {
                    "url": r.url,
                    "status": r.status,
                    "length": r.length,
                    "words": r.words,
                    "lines": r.lines,
                    "content_type": r.content_type,
                    "redirect_location": r.redirect_location,
                }
                for r in self.results
            ],
            "target": self.target,
            "tool_available": self.tool_available,
            "scan_completed": self.scan_completed,
            "fuzz_targets_count": self.fuzz_targets_count,
            "error": self.error,
        }


def ffuf_available() -> bool:
    """Check if ffuf binary is installed and accessible."""
    return shutil.which("ffuf") is not None


def _find_wordlist(preferred: Optional[str] = None) -> Optional[str]:
    """Find a wordlist file. Checks VIPER wordlists dir, then common system paths."""
    if preferred and os.path.isfile(preferred):
        return preferred

    # Check VIPER wordlists directory
    for wl in DEFAULT_WORDLISTS:
        path = WORDLISTS_DIR / wl
        if path.is_file():
            return str(path)

    # Check common system paths
    system_dirs = [
        "/usr/share/wordlists",
        "/usr/share/seclists/Discovery/Web-Content",
        "/usr/share/dirbuster/wordlists",
        "/opt/SecLists/Discovery/Web-Content",
        os.path.expanduser("~/wordlists"),
    ]
    system_files = ["common.txt", "directory-list-2.3-small.txt", "raft-small-words.txt"]
    for d in system_dirs:
        for f in system_files:
            path = os.path.join(d, f)
            if os.path.isfile(path):
                return path

    return None


def _build_fuzz_targets(
    target: str,
    discovered_base_paths: Optional[List[str]] = None,
) -> List[str]:
    """
    Build list of FUZZ URLs: root + discovered base paths.

    Example:
        target = "https://example.com"
        discovered_base_paths = ["/api/v1", "/admin"]
        -> ["https://example.com/FUZZ", "https://example.com/api/v1/FUZZ", "https://example.com/admin/FUZZ"]
    """
    base = target.rstrip("/")
    targets = [f"{base}/FUZZ"]

    if discovered_base_paths:
        for bp in discovered_base_paths:
            bp = bp.strip("/")
            if bp:
                targets.append(f"{base}/{bp}/FUZZ")

    return targets


def _parse_ffuf_json(json_path: str) -> List[FfufResult]:
    """Parse ffuf JSON output file into FfufResult list."""
    results = []
    try:
        with open(json_path, "r") as f:
            data = json.load(f)

        items = data.get("results", [])
        for item in items:
            results.append(FfufResult(
                url=item.get("url", ""),
                status=item.get("status", 0),
                length=item.get("length", 0),
                words=item.get("words", 0),
                lines=item.get("lines", 0),
                content_type=item.get("content-type", item.get("content_type", "")),
                redirect_location=item.get("redirectlocation", ""),
            ))
    except (json.JSONDecodeError, FileNotFoundError, KeyError) as e:
        logger.warning(f"[FFuf] Failed to parse JSON output: {e}")
    return results


def run_ffuf(
    target: str,
    wordlist: Optional[str] = None,
    threads: int = 40,
    rate_limit: int = 0,
    timeout: int = 10,
    max_time: int = 300,
    match_codes: Optional[List[int]] = None,
    filter_codes: Optional[List[int]] = None,
    filter_size: Optional[str] = None,
    extensions: Optional[List[str]] = None,
    auto_calibrate: bool = True,
    recursion: bool = False,
    recursion_depth: int = 2,
    follow_redirects: bool = False,
    custom_headers: Optional[Dict[str, str]] = None,
    proxy: Optional[str] = None,
    discovered_base_paths: Optional[List[str]] = None,
) -> FfufDiscovery:
    """
    Run ffuf directory fuzzer against a target.

    Args:
        target: Base URL (e.g. https://example.com)
        wordlist: Path to wordlist file. Auto-detected if None.
        threads: Concurrent threads.
        rate_limit: Max requests per second (0 = unlimited).
        timeout: Per-request timeout in seconds.
        max_time: Overall max execution time in seconds.
        match_codes: HTTP status codes to include.
        filter_codes: HTTP status codes to exclude.
        filter_size: Response size filter (e.g. "0" to exclude empty).
        extensions: File extensions to append.
        auto_calibrate: Enable -ac auto-calibration for false positive filtering.
        recursion: Enable recursive fuzzing.
        recursion_depth: Max recursion depth.
        follow_redirects: Follow HTTP redirects.
        custom_headers: Custom HTTP headers dict.
        proxy: Proxy URL (e.g. http://127.0.0.1:8080, socks5://127.0.0.1:9050).
        discovered_base_paths: Base paths to fuzz under (e.g. ["/api/v1", "/admin"]).

    Returns:
        FfufDiscovery with discovered paths.
    """
    discovery = FfufDiscovery(target=target)

    if not ffuf_available():
        logger.info("[FFuf] Binary 'ffuf' not found — skipping directory fuzzing")
        discovery.error = "ffuf binary not installed"
        return discovery

    discovery.tool_available = True

    # Resolve wordlist
    wl_path = _find_wordlist(wordlist)
    if not wl_path:
        discovery.error = "No wordlist found for ffuf"
        logger.warning(f"[FFuf] {discovery.error}")
        return discovery

    if match_codes is None:
        match_codes = DEFAULT_MATCH_CODES
    if filter_codes is None:
        filter_codes = DEFAULT_FILTER_CODES

    fuzz_targets = _build_fuzz_targets(target, discovered_base_paths)
    discovery.fuzz_targets_count = len(fuzz_targets)

    logger.info(f"[FFuf] Starting directory fuzzing on {target}")
    logger.info(f"[FFuf] Wordlist: {wl_path}")
    logger.info(f"[FFuf] Fuzz targets: {len(fuzz_targets)} (root + base paths)")
    logger.info(f"[FFuf] Threads: {threads}, Rate: {rate_limit or 'unlimited'} req/s")
    logger.info(f"[FFuf] Auto-calibrate: {auto_calibrate}")

    output_dir = tempfile.mkdtemp(prefix="viper_ffuf_")
    all_results: List[FfufResult] = []
    seen_urls: Set[str] = set()

    try:
        for idx, fuzz_url in enumerate(fuzz_targets):
            output_file = os.path.join(output_dir, f"ffuf_{idx}.json")

            cmd = ["ffuf"]
            cmd.extend(["-u", fuzz_url])
            cmd.extend(["-w", wl_path])
            cmd.extend(["-t", str(threads)])
            cmd.extend(["-timeout", str(timeout)])
            cmd.extend(["-maxtime", str(max_time)])

            if rate_limit > 0:
                cmd.extend(["-rate", str(rate_limit)])

            if match_codes:
                cmd.extend(["-mc", ",".join(str(c) for c in match_codes)])

            if filter_codes:
                cmd.extend(["-fc", ",".join(str(c) for c in filter_codes)])

            if filter_size:
                cmd.extend(["-fs", filter_size])

            if extensions:
                cmd.extend(["-e", ",".join(extensions)])

            if auto_calibrate:
                cmd.append("-ac")

            if recursion:
                cmd.extend(["-recursion", "-recursion-depth", str(recursion_depth)])

            if follow_redirects:
                cmd.append("-r")

            if custom_headers:
                for k, v in custom_headers.items():
                    cmd.extend(["-H", f"{k}: {v}"])

            if proxy:
                cmd.extend(["-x", proxy])

            # JSON output + silent mode
            cmd.extend(["-of", "json", "-o", output_file])
            cmd.append("-s")

            logger.info(f"[FFuf] Fuzzing [{idx+1}/{len(fuzz_targets)}]: {fuzz_url}")

            try:
                subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=max_time + 60,
                )

                if os.path.isfile(output_file):
                    batch = _parse_ffuf_json(output_file)
                    for r in batch:
                        if r.url not in seen_urls:
                            seen_urls.add(r.url)
                            all_results.append(r)

            except subprocess.TimeoutExpired:
                logger.warning(f"[FFuf] Timeout on target {idx+1}")
            except Exception as e:
                logger.warning(f"[FFuf] Error on target {idx+1}: {e}")

        discovery.results = all_results
        discovery.scan_completed = True
        logger.info(f"[FFuf] Discovered {len(all_results)} unique paths")

    except Exception as e:
        discovery.error = str(e)
        logger.error(f"[FFuf] Scan error: {e}")
    finally:
        try:
            import shutil as _shutil
            _shutil.rmtree(output_dir, ignore_errors=True)
        except Exception:
            pass

    return discovery


async def run_ffuf_async(target: str, **kwargs) -> FfufDiscovery:
    """Async wrapper — runs ffuf in a thread to avoid blocking the event loop."""
    import asyncio
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, lambda: run_ffuf(target, **kwargs))
