#!/usr/bin/env python3
"""
VIPER Continuous Monitoring Daemon — 24/7 target surveillance.

Re-scans targets on schedule, detects changes in attack surface,
alerts on NEW findings only (diff-based), and integrates with
FindingStream for real-time Discord/Telegram/Email notifications.

Usage:
    python viper_daemon.py                          # Single scan cycle
    python viper_daemon.py --daemon                 # Continuous (default 6h interval)
    python viper_daemon.py --daemon 120             # Custom interval (120 min)
    python viper_daemon.py --targets targets.txt    # Load targets from file
    python viper_daemon.py --scope scope.json       # With scope file
    python viper_daemon.py --full                   # Full hunt mode per cycle
    python viper_daemon.py --stealth 2              # Stealth level
"""
import asyncio
import hashlib
import json
import logging
import os
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

HACKAGENT_DIR = Path(__file__).parent
STATE_FILE = HACKAGENT_DIR / "state" / "daemon_state.json"
FINDINGS_DIR = HACKAGENT_DIR / "findings"
FINDINGS_DIR.mkdir(exist_ok=True)
(HACKAGENT_DIR / "state").mkdir(exist_ok=True)

# Add to path
if str(HACKAGENT_DIR) not in sys.path:
    sys.path.insert(0, str(HACKAGENT_DIR))

# Load .env
env_file = HACKAGENT_DIR / ".env"
if env_file.exists():
    for line in env_file.read_text().splitlines():
        line = line.strip()
        if "=" in line and not line.startswith("#"):
            k, v = line.split("=", 1)
            os.environ.setdefault(k.strip(), v.strip())

logger = logging.getLogger("viper.daemon")


class ViperDaemon:
    """24/7 continuous monitoring daemon.

    Re-scans targets on schedule, detects changes in attack surface,
    alerts on new findings via FindingStream.

    Features:
    - Diff-based finding detection (only alerts on NEW discoveries)
    - Persistent state across restarts (JSON-backed)
    - FindingStream integration (Discord, Telegram, Email)
    - Configurable scan interval and mode (quick vs full)
    - Graceful shutdown handling
    - Per-target scan history and statistics

    Args:
        targets: List of target URLs or target config dicts.
        interval_hours: Hours between scan cycles (default 6).
        scope_file: Optional path to scope JSON file.
        full_mode: Whether to run full hunts (vs quick).
        stealth: Stealth level 0-3.
    """

    def __init__(self, targets: Optional[List[str]] = None,
                 interval_hours: float = 6.0,
                 scope_file: Optional[str] = None,
                 full_mode: bool = False,
                 stealth: int = 0):
        self.targets = targets or []
        self.interval_hours = interval_hours
        self.scope_file = scope_file
        self.full_mode = full_mode
        self.stealth = stealth
        self._state = self._load_state()
        self._finding_stream = None
        self._scope = None
        self._shutdown = False
        self._cycle_count = 0

    def _load_state(self) -> dict:
        """Load persistent daemon state."""
        if STATE_FILE.exists():
            try:
                return json.loads(STATE_FILE.read_text())
            except (json.JSONDecodeError, OSError):
                pass
        return {
            "total_cycles": 0,
            "total_findings": 0,
            "new_findings_total": 0,
            "last_scan": None,
            "started_at": datetime.now().isoformat(),
            "targets": {},  # target_url -> {last_scan, finding_hashes, findings_count}
        }

    def _save_state(self):
        """Persist daemon state to disk."""
        try:
            STATE_FILE.write_text(json.dumps(self._state, indent=2, default=str))
        except OSError as e:
            logger.error("Failed to save daemon state: %s", e)

    def _log(self, msg: str, level: str = "info"):
        """Log with timestamp."""
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        prefix = {"info": "[*]", "warn": "[!]", "error": "[!]", "success": "[+]"}.get(level, "[*]")
        print(f"[{ts}] {prefix} {msg}")
        getattr(logger, level if level != "success" else "info")(msg)

    def _init_finding_stream(self):
        """Initialize FindingStream for notifications."""
        if self._finding_stream is not None:
            return
        try:
            from core.finding_stream import FindingStream, NotificationConfig
            config = NotificationConfig.from_env()
            has_channel = bool(config.discord_webhook or config.telegram_bot_token
                               or config.email_from or config.clawdbot_gateway)
            if has_channel:
                self._finding_stream = FindingStream(config)
                self._log("FindingStream initialized (notifications enabled)")
            else:
                self._log("No notification channels configured (set DISCORD_WEBHOOK_URL, "
                          "TELEGRAM_BOT_TOKEN, etc.)", "warn")
        except ImportError:
            self._log("FindingStream module not available", "warn")

    def _init_scope(self):
        """Load scope file if configured."""
        if self._scope is not None or not self.scope_file:
            return
        try:
            from scope.scope_manager import BugBountyScope
            scope_data = json.loads(Path(self.scope_file).read_text())
            self._scope = BugBountyScope.from_dict(scope_data)
            self._log(f"Scope loaded: {self.scope_file}")
        except Exception as e:
            self._log(f"Failed to load scope: {e}", "warn")

    async def run(self):
        """Main daemon loop. Runs until shutdown signal."""
        self._log(f"VIPER Daemon starting — {len(self.targets)} targets, "
                  f"interval={self.interval_hours}h, mode={'full' if self.full_mode else 'quick'}")

        self._init_finding_stream()
        self._init_scope()
        self._state["started_at"] = datetime.now().isoformat()

        while not self._shutdown:
            try:
                cycle_start = time.monotonic()
                self._cycle_count += 1
                self._log(f"=== Scan cycle #{self._cycle_count} starting ===")

                all_new = []
                for target in self.targets:
                    target_url = target if isinstance(target, str) else target.get("url", "")
                    if not target_url:
                        continue

                    try:
                        findings = await self._scan_target(target_url)
                        new_findings = self._diff_findings(target_url, findings)

                        if new_findings:
                            all_new.extend(new_findings)
                            self._log(f"  {len(new_findings)} NEW findings on {target_url}", "success")
                            await self._alert(new_findings)
                        else:
                            self._log(f"  No new findings on {target_url}")

                        # Update target state
                        self._update_target_state(target_url, findings, new_findings)

                    except Exception as e:
                        self._log(f"  Error scanning {target_url}: {e}", "error")

                # Persist findings to disk
                if all_new:
                    self._save_findings(all_new)

                elapsed = time.monotonic() - cycle_start
                self._state["total_cycles"] += 1
                self._state["last_scan"] = datetime.now().isoformat()
                self._save_state()

                self._log(f"=== Cycle #{self._cycle_count} complete: "
                          f"{len(all_new)} new findings in {elapsed:.0f}s ===")

                # Sleep until next cycle
                sleep_secs = self.interval_hours * 3600
                self._log(f"Next scan in {self.interval_hours}h")
                await self._interruptible_sleep(sleep_secs)

            except asyncio.CancelledError:
                self._log("Daemon cancelled")
                break
            except Exception as e:
                self._log(f"Cycle error: {e}", "error")
                await self._interruptible_sleep(300)  # 5 min backoff on error

        self._log("Daemon shutdown complete")
        self._save_state()

    async def run_once(self) -> List[dict]:
        """Run a single scan cycle and return new findings."""
        self._init_finding_stream()
        self._init_scope()

        all_new = []
        for target in self.targets:
            target_url = target if isinstance(target, str) else target.get("url", "")
            if not target_url:
                continue

            try:
                findings = await self._scan_target(target_url)
                new_findings = self._diff_findings(target_url, findings)
                if new_findings:
                    all_new.extend(new_findings)
                    await self._alert(new_findings)
                self._update_target_state(target_url, findings, new_findings)
            except Exception as e:
                self._log(f"Error scanning {target_url}: {e}", "error")

        if all_new:
            self._save_findings(all_new)

        self._state["total_cycles"] += 1
        self._state["last_scan"] = datetime.now().isoformat()
        self._save_state()

        return all_new

    async def _scan_target(self, target_url: str) -> List[dict]:
        """Scan a single target using ViperCore."""
        self._log(f"  Scanning: {target_url}")

        try:
            from viper_core import ViperCore
            viper = ViperCore()

            if self.stealth > 0 and hasattr(viper, 'set_stealth_level'):
                viper.set_stealth_level(self.stealth)

            if self.full_mode:
                result = await viper.full_hunt(
                    target_url=target_url,
                    scope=self._scope,
                    max_minutes=30,
                )
            else:
                import aiohttp
                async with aiohttp.ClientSession() as viper.session:
                    result = await viper.hunt(target_url, max_minutes=5)

            if result:
                findings = result.get("findings", [])
                # Tag each finding with scan metadata
                for f in findings:
                    f["_daemon_scan_time"] = datetime.now().isoformat()
                    f["_daemon_cycle"] = self._cycle_count
                    if "target_url" not in f:
                        f["target_url"] = target_url
                return findings

        except Exception as e:
            self._log(f"  ViperCore scan failed: {e}", "error")

        return []

    def _diff_findings(self, target: str, findings: List[dict]) -> List[dict]:
        """Compare with previous scan to find NEW findings only.

        Uses a deterministic hash of (vuln_type, url, param, payload)
        to deduplicate across scan cycles.

        Args:
            target: Target URL.
            findings: Current scan findings.

        Returns:
            List of findings that are genuinely new.
        """
        target_state = self._state.get("targets", {}).get(target, {})
        known_hashes: Set[str] = set(target_state.get("finding_hashes", []))

        new_findings = []
        for finding in findings:
            fhash = self._finding_hash(finding)
            if fhash not in known_hashes:
                finding["_finding_hash"] = fhash
                finding["_is_new"] = True
                new_findings.append(finding)

        return new_findings

    def _finding_hash(self, finding: dict) -> str:
        """Generate deterministic hash for a finding."""
        key_parts = [
            finding.get("vuln_type", finding.get("attack", "")),
            finding.get("url", finding.get("target_url", "")),
            finding.get("param", finding.get("parameter", "")),
            str(finding.get("payload", ""))[:200],  # Truncate long payloads
        ]
        raw = "|".join(str(p) for p in key_parts)
        return hashlib.sha256(raw.encode()).hexdigest()[:16]

    def _update_target_state(self, target_url: str,
                             all_findings: List[dict],
                             new_findings: List[dict]):
        """Update persistent state for a target after scan."""
        if "targets" not in self._state:
            self._state["targets"] = {}

        target_state = self._state["targets"].get(target_url, {
            "first_scan": datetime.now().isoformat(),
            "finding_hashes": [],
            "total_findings": 0,
            "new_findings": 0,
            "scan_count": 0,
        })

        # Add new hashes
        existing = set(target_state.get("finding_hashes", []))
        for f in all_findings:
            existing.add(self._finding_hash(f))

        target_state["finding_hashes"] = list(existing)
        target_state["last_scan"] = datetime.now().isoformat()
        target_state["total_findings"] = len(existing)
        target_state["new_findings"] = target_state.get("new_findings", 0) + len(new_findings)
        target_state["scan_count"] = target_state.get("scan_count", 0) + 1

        self._state["targets"][target_url] = target_state
        self._state["total_findings"] = sum(
            t.get("total_findings", 0) for t in self._state["targets"].values()
        )
        self._state["new_findings_total"] = (
            self._state.get("new_findings_total", 0) + len(new_findings)
        )

    async def _alert(self, findings: List[dict]):
        """Send alerts via FindingStream (Discord/Telegram/Email)."""
        if not self._finding_stream:
            return

        for finding in findings:
            try:
                await self._finding_stream.notify(finding)
            except Exception as e:
                self._log(f"  Alert failed: {e}", "warn")

    def _save_findings(self, findings: List[dict]):
        """Save new findings to disk."""
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        path = FINDINGS_DIR / f"daemon_{ts}.json"
        try:
            # Strip internal fields before saving
            clean = []
            for f in findings:
                c = {k: v for k, v in f.items() if not k.startswith("_")}
                c["discovered_at"] = f.get("_daemon_scan_time", datetime.now().isoformat())
                clean.append(c)
            path.write_text(json.dumps(clean, indent=2, default=str))
            self._log(f"  Saved {len(clean)} findings to {path.name}")
        except OSError as e:
            self._log(f"  Failed to save findings: {e}", "error")

    async def _interruptible_sleep(self, seconds: float):
        """Sleep that can be interrupted by shutdown signal."""
        try:
            await asyncio.sleep(seconds)
        except asyncio.CancelledError:
            self._shutdown = True

    def shutdown(self):
        """Signal graceful shutdown."""
        self._shutdown = True
        self._log("Shutdown requested")

    def get_status(self) -> dict:
        """Get current daemon status."""
        return {
            "running": not self._shutdown,
            "cycle_count": self._cycle_count,
            "total_cycles": self._state.get("total_cycles", 0),
            "total_findings": self._state.get("total_findings", 0),
            "new_findings_total": self._state.get("new_findings_total", 0),
            "last_scan": self._state.get("last_scan"),
            "started_at": self._state.get("started_at"),
            "targets": len(self.targets),
            "interval_hours": self.interval_hours,
        }

    @staticmethod
    def load_targets_file(path: str) -> List[str]:
        """Load targets from a text file (one URL per line)."""
        targets = []
        for line in Path(path).read_text().splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                if not line.startswith(("http://", "https://")):
                    line = "https://" + line
                targets.append(line)
        return targets


async def main():
    import argparse

    parser = argparse.ArgumentParser(description="VIPER Continuous Monitoring Daemon")
    parser.add_argument("targets", nargs="*", help="Target URLs to monitor")
    parser.add_argument("--daemon", action="store_true", help="Run continuously")
    parser.add_argument("--interval", type=float, default=6.0,
                        help="Hours between scan cycles (default: 6)")
    parser.add_argument("--targets-file", help="Load targets from file (one URL per line)")
    parser.add_argument("--scope", help="Path to scope JSON file")
    parser.add_argument("--full", action="store_true", help="Full hunt mode per cycle")
    parser.add_argument("--stealth", type=int, default=0, help="Stealth level 0-3")
    args = parser.parse_args()

    # Collect targets
    targets = list(args.targets) if args.targets else []
    if args.targets_file:
        targets.extend(ViperDaemon.load_targets_file(args.targets_file))

    if not targets:
        print("No targets specified. Use positional args or --targets-file.")
        print("Example: python viper_daemon.py https://example.com --daemon")
        sys.exit(1)

    daemon = ViperDaemon(
        targets=targets,
        interval_hours=args.interval,
        scope_file=args.scope,
        full_mode=args.full,
        stealth=args.stealth,
    )

    if args.daemon:
        # Handle Ctrl+C gracefully
        loop = asyncio.get_event_loop()

        def signal_handler():
            daemon.shutdown()

        try:
            import signal
            for sig in (signal.SIGINT, signal.SIGTERM):
                loop.add_signal_handler(sig, signal_handler)
        except (NotImplementedError, OSError):
            # Windows doesn't support add_signal_handler
            pass

        await daemon.run()
    else:
        findings = await daemon.run_once()
        print(f"\n=== Summary ===")
        print(f"New findings: {len(findings)}")
        for f in findings:
            sev = f.get("severity", "?").upper()
            vtype = f.get("vuln_type", f.get("attack", "?"))
            url = f.get("url", f.get("target_url", ""))[:70]
            print(f"  [{sev}] {vtype} @ {url}")
        status = daemon.get_status()
        print(f"\nTotal tracked: {status['total_findings']} | "
              f"Cycles: {status['total_cycles']}")


if __name__ == "__main__":
    asyncio.run(main())
