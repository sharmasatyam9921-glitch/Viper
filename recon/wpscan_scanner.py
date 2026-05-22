"""
VIPER 5.0 - WPScan Integration
================================
WordPress vulnerability scanner wrapper around the ``wpscan`` Ruby CLI.

Falls back gracefully if wpscan isn't installed. Runs conditionally
when Wappalyzer detects WordPress in the tech stack.

Set ``WPSCAN_API_TOKEN`` env var for the vulnerability database
(free tier: 25 req/day). Without it, wpscan still enumerates
plugins/themes/users but won't return CVEs.

Requires: ``gem install wpscan`` or wpscan binary in PATH.
"""

import asyncio
import json
import logging
import os
import shutil
from pathlib import Path
from typing import Dict, List, Optional

logger = logging.getLogger("viper.recon.wpscan")

WPSCAN_PATH = os.environ.get("WPSCAN_PATH", shutil.which("wpscan"))
WPSCAN_TOKEN = os.environ.get("WPSCAN_API_TOKEN", "").strip()


def wpscan_available() -> bool:
    return WPSCAN_PATH is not None and Path(WPSCAN_PATH).exists()


async def scan(
    url: str,
    enumerate: str = "vp,vt,u,cb,dbe",
    timeout: int = 300,
) -> Dict:
    """
    Run wpscan against a WordPress target.

    Args:
        url: Target URL (must be a WordPress site).
        enumerate: Comma-separated enum flags:
            vp=vulnerable plugins, vt=vulnerable themes,
            u=users, cb=config backups, dbe=db exports.
        timeout: Subprocess timeout in seconds.

    Returns::

        {
            "url": "...",
            "wordpress_version": "6.4.2",
            "themes": [...],
            "plugins": [...],
            "users": [...],
            "vulnerabilities": [...],
            "interesting_findings": [...],
        }
    """
    if not wpscan_available():
        logger.info("wpscan not installed — returning empty")
        return {"url": url, "error": "wpscan not installed"}

    cmd = [
        WPSCAN_PATH,
        "--url", url,
        "--format", "json",
        "--enumerate", enumerate,
        "--random-user-agent",
        "--no-update",
    ]
    if WPSCAN_TOKEN:
        cmd.extend(["--api-token", WPSCAN_TOKEN])

    logger.info("Running wpscan on %s", url)

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(), timeout=timeout
            )
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()
            return {"url": url, "error": "wpscan timed out"}

        output = stdout.decode("utf-8", errors="replace")

        try:
            data = json.loads(output)
        except json.JSONDecodeError:
            return {"url": url, "error": "wpscan output not JSON", "raw": output[:500]}

        result = {"url": url}

        # WordPress version
        ver = data.get("version", {})
        result["wordpress_version"] = ver.get("number", "unknown")
        result["version_status"] = ver.get("status", "")

        # Themes
        result["themes"] = []
        for name, info in data.get("main_theme", {}).items() if isinstance(data.get("main_theme"), dict) else []:
            result["themes"].append({
                "name": name, "version": info.get("version", {}).get("number", ""),
            })

        # Plugins
        result["plugins"] = []
        for name, info in (data.get("plugins", {}) or {}).items():
            vulns = info.get("vulnerabilities", [])
            result["plugins"].append({
                "name": name,
                "version": (info.get("version", {}) or {}).get("number", ""),
                "vulnerabilities": len(vulns),
                "vuln_details": [
                    {"title": v.get("title", ""), "cve": v.get("references", {}).get("cve", []),
                     "wpvulndb": v.get("references", {}).get("wpvulndb", [])}
                    for v in vulns[:10]
                ],
            })

        # Users
        result["users"] = [
            u.get("username", "") for u in (data.get("users", []) or [])[:20]
        ]

        # Vulnerabilities (flat list)
        result["vulnerabilities"] = []
        for plugin in result["plugins"]:
            for v in plugin.get("vuln_details", []):
                result["vulnerabilities"].append({
                    "source": f"plugin:{plugin['name']}",
                    "title": v["title"],
                    "cves": v.get("cve", []),
                })

        # Interesting findings
        result["interesting_findings"] = [
            {
                "url": f.get("url", ""),
                "type": f.get("type", ""),
                "to_s": f.get("to_s", ""),
            }
            for f in data.get("interesting_findings", [])[:20]
        ]

        logger.info("wpscan: %d plugins, %d vulns, %d users",
                     len(result["plugins"]),
                     len(result["vulnerabilities"]),
                     len(result["users"]))
        return result

    except (OSError, FileNotFoundError) as exc:
        logger.warning("wpscan execution failed: %s", exc)
        return {"url": url, "error": str(exc)}


def is_wordpress(tech_map: Dict) -> bool:
    """Check if any URL in the tech map has WordPress detected."""
    for url, techs in tech_map.items():
        for t in techs:
            name = t.get("name", "") if isinstance(t, dict) else str(t)
            if name.lower() in ("wordpress", "wp", "wordpress.com"):
                return True
    return False
