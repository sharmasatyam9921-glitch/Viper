"""
VIPER 5.0 - CTF Mode
=====================
Flag detection, CTF-specific attack orchestration, and scoring support
for running VIPER against CTF challenges (HackTheBox, picoCTF, CTFtime,
etc.).

Usage (CLI)::

    python -m core.ctf_mode http://challenge.url --flag-prefix HTB

Usage (programmatic)::

    from core.ctf_mode import CTFRunner
    runner = CTFRunner(flag_prefix="HTB", submit_url="https://...")
    result = await runner.run("http://challenge.url")
    # result.flags: [{flag, source_url, evidence, confidence}]
"""

import asyncio
import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set

logger = logging.getLogger("viper.core.ctf_mode")


# ── Flag patterns ──────────────────────────────────────────────────────────
# Standard CTF flag formats. Order matters — more specific first.

FLAG_PATTERNS: Dict[str, re.Pattern] = {
    "htb": re.compile(r"HTB\{[^}]{4,200}\}"),
    "htb_lower": re.compile(r"htb\{[^}]{4,200}\}"),
    "pico": re.compile(r"picoCTF\{[^}]{4,200}\}"),
    "flag": re.compile(r"(?i)flag\{[^}]{4,200}\}"),
    "ctf": re.compile(r"(?i)ctf\{[^}]{4,200}\}"),
    "generic": re.compile(r"[A-Za-z0-9_]{2,20}\{[A-Za-z0-9_!@#$%^&*()\-+=\[\]/\\.:;,<>?~`'\" ]{8,200}\}"),
}

# Common hiding spots for flags
FLAG_LOCATIONS = [
    "/flag",
    "/flag.txt",
    "/flag.html",
    "/robots.txt",
    "/.env",
    "/.git/config",
    "/server-status",
    "/.htaccess",
    "/admin/flag",
    "/api/flag",
    "/static/flag.txt",
    "/hidden/flag",
    "/debug",
    "/console",
]


@dataclass
class Flag:
    value: str
    source_url: str
    pattern: str
    evidence: str = ""
    confidence: float = 1.0

    def to_dict(self) -> dict:
        return {
            "flag": self.value,
            "source_url": self.source_url,
            "pattern": self.pattern,
            "evidence": self.evidence[:500],
            "confidence": self.confidence,
        }


@dataclass
class CTFResult:
    target: str
    flags: List[Flag] = field(default_factory=list)
    attempted_paths: List[str] = field(default_factory=list)
    findings: List[Dict] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "flag_count": len(self.flags),
            "flags": [f.to_dict() for f in self.flags],
            "attempted_paths": self.attempted_paths,
            "findings": self.findings,
            "errors": self.errors,
        }


def extract_flags(content: str, source_url: str = "",
                  patterns: Optional[List[str]] = None) -> List[Flag]:
    """
    Extract flags from a text blob using the configured patterns.

    Args:
        content: Text to scan.
        source_url: URL where content was retrieved (for attribution).
        patterns: Pattern names to use. Defaults to all.

    Returns:
        List of Flag objects, deduplicated.
    """
    if not content:
        return []
    if patterns is None:
        patterns = list(FLAG_PATTERNS.keys())

    seen: Set[str] = set()
    flags: List[Flag] = []

    for name in patterns:
        pat = FLAG_PATTERNS.get(name)
        if pat is None:
            continue
        for match in pat.finditer(content):
            flag_value = match.group(0)
            if flag_value in seen:
                continue
            seen.add(flag_value)

            # Extract surrounding context (60 chars each side)
            start, end = match.span()
            ctx_start = max(0, start - 60)
            ctx_end = min(len(content), end + 60)
            evidence = content[ctx_start:ctx_end].replace("\n", " ")

            flags.append(Flag(
                value=flag_value,
                source_url=source_url,
                pattern=name,
                evidence=evidence,
                confidence=0.95 if name != "generic" else 0.6,
            ))

    return flags


class CTFRunner:
    """
    Orchestrates VIPER to hunt for flags on CTF challenges.

    Steps:
      1. HTTP probe target to confirm reachable
      2. Crawl and fuzz common flag locations
      3. Run full VIPER pipeline (web attacks) on discovered endpoints
      4. Extract flags from all response bodies
      5. Return structured CTFResult
    """

    def __init__(
        self,
        flag_prefix: str = "HTB",
        submit_url: Optional[str] = None,
        custom_flag_pattern: Optional[str] = None,
        timeout_minutes: float = 10,
    ):
        self.flag_prefix = flag_prefix
        self.submit_url = submit_url
        self.timeout_minutes = timeout_minutes

        # Build list of active patterns
        self.active_patterns = []
        if flag_prefix.upper() == "HTB":
            self.active_patterns = ["htb", "htb_lower", "flag", "ctf", "generic"]
        elif flag_prefix.lower() == "pico" or flag_prefix.upper() == "PICOCTF":
            self.active_patterns = ["pico", "flag", "ctf", "generic"]
        else:
            self.active_patterns = ["flag", "ctf", "generic"]

        if custom_flag_pattern:
            try:
                FLAG_PATTERNS["custom"] = re.compile(custom_flag_pattern)
                self.active_patterns.insert(0, "custom")
            except re.error as exc:
                logger.warning("Invalid custom flag pattern: %s", exc)

    async def probe_flag_locations(self, base_url: str) -> List[Flag]:
        """Hit common flag hiding spots. Returns any flags found."""
        import aiohttp
        flags: List[Flag] = []
        base_url = base_url.rstrip("/")

        async def _check(sess, path: str) -> List[Flag]:
            url = base_url + path
            try:
                async with sess.get(url, timeout=aiohttp.ClientTimeout(total=10),
                                    allow_redirects=True) as resp:
                    if resp.status != 404:
                        body = await resp.text(errors="replace")
                        return extract_flags(body, url, self.active_patterns)
            except Exception:
                pass
            return []

        try:
            async with aiohttp.ClientSession(
                connector=aiohttp.TCPConnector(ssl=False),
                headers={"User-Agent": "VIPER-CTF/5.0"},
            ) as sess:
                tasks = [_check(sess, p) for p in FLAG_LOCATIONS]
                results = await asyncio.gather(*tasks, return_exceptions=True)
                for r in results:
                    if isinstance(r, list):
                        flags.extend(r)
        except Exception as exc:
            logger.warning("probe_flag_locations failed: %s", exc)

        return flags

    async def scan_responses_for_flags(
        self, responses: List[Dict]
    ) -> List[Flag]:
        """Extract flags from a list of HTTP response dicts (from VIPER pipeline)."""
        flags: List[Flag] = []
        for resp in responses:
            body = resp.get("body") or resp.get("content") or ""
            title = resp.get("title", "")
            url = resp.get("url", "")
            combined = f"{title}\n{body}"
            flags.extend(extract_flags(combined, url, self.active_patterns))
        return flags

    async def run(self, target: str) -> CTFResult:
        """
        Main entry point. Runs the full CTF hunt workflow against target.
        """
        result = CTFResult(target=target)
        seen_flags: Set[str] = set()

        # Step 1: Probe common flag locations (fast, ~5s)
        logger.info("CTF: probing common flag locations on %s", target)
        quick_flags = await self.probe_flag_locations(target)
        for f in quick_flags:
            if f.value not in seen_flags:
                seen_flags.add(f.value)
                result.flags.append(f)
                logger.info("CTF FLAG FOUND (probe): %s @ %s",
                            f.value, f.source_url)

        result.attempted_paths = [target + p for p in FLAG_LOCATIONS]

        # Step 2: Run VIPER recon pipeline (web attacks, fuzzing)
        try:
            from recon.pipeline import ReconPipeline
            pipeline = ReconPipeline(settings={
                "skip_active_on_empty": False,
                # CTF challenges often have no subdomains; skip OSINT
                "osint_sources": [],
            })
            logger.info("CTF: running VIPER pipeline on %s", target)
            pipe_result = await pipeline.run(
                target,
                phases=[
                    "http_probe",
                    "resource_enum",
                    "vuln_scan",
                ],
                timeout_minutes=self.timeout_minutes,
            )

            # Extract flags from HTTP responses
            pipe_flags = await self.scan_responses_for_flags(
                pipe_result.http_responses
            )
            for f in pipe_flags:
                if f.value not in seen_flags:
                    seen_flags.add(f.value)
                    result.flags.append(f)
                    logger.info("CTF FLAG FOUND (pipeline): %s @ %s",
                                f.value, f.source_url)

            # Convert findings to simple dicts
            for v in pipe_result.vulnerabilities[:20]:
                result.findings.append({
                    "type": v.get("type") or v.get("template-id", "unknown"),
                    "severity": v.get("severity", "unknown"),
                    "url": v.get("url") or v.get("host", ""),
                    "info": (v.get("info") or {}).get("name", ""),
                })

        except Exception as exc:
            logger.warning("CTF pipeline run failed: %s", exc)
            result.errors.append(str(exc)[:300])

        return result


# ── CLI ─────────────────────────────────────────────────────────────────────

async def _main() -> int:
    import argparse
    import json
    import sys

    parser = argparse.ArgumentParser(
        description="VIPER CTF Mode — hunt flags on CTF challenges.")
    parser.add_argument("target", help="Challenge URL (e.g. http://chal.ctf.io:1337)")
    parser.add_argument("--flag-prefix", default="HTB",
                        help="Flag prefix (HTB, picoCTF, flag, ctf). Default: HTB")
    parser.add_argument("--custom-pattern",
                        help="Custom regex pattern for flag extraction")
    parser.add_argument("--timeout", type=float, default=10,
                        help="Max runtime in minutes (default 10)")
    parser.add_argument("--json", action="store_true",
                        help="Emit JSON result on stdout")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
        datefmt="%H:%M:%S",
        stream=sys.stderr,
    )

    runner = CTFRunner(
        flag_prefix=args.flag_prefix,
        custom_flag_pattern=args.custom_pattern,
        timeout_minutes=args.timeout,
    )

    result = await runner.run(args.target)

    if args.json:
        print(json.dumps(result.to_dict(), indent=2, default=str))
    else:
        print(f"\n{'='*60}")
        print(f"Target: {result.target}")
        print(f"Flags found: {len(result.flags)}")
        for i, f in enumerate(result.flags, 1):
            print(f"\n[{i}] {f.value}")
            print(f"    source:  {f.source_url}")
            print(f"    pattern: {f.pattern} (confidence={f.confidence:.2f})")
            print(f"    evidence: {f.evidence[:120]}")
        if result.findings:
            print(f"\nWeb findings: {len(result.findings)}")
            for finding in result.findings[:5]:
                print(f"  - [{finding['severity']}] {finding['type']} @ {finding['url']}")
        if result.errors:
            print(f"\nErrors:")
            for e in result.errors:
                print(f"  - {e}")
        print(f"{'='*60}")

    return 0 if result.flags else 1


if __name__ == "__main__":
    import sys
    sys.exit(asyncio.run(_main()))
