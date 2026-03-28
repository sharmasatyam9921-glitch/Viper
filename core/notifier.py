"""Notification system — alerts via Telegram/Clawdbot gateway."""

import json
import logging
import urllib.request

logger = logging.getLogger("viper.notifier")


class Notifier:
    """Sends alerts to Clawdbot gateway for Telegram delivery."""

    def __init__(self, gateway_url: str = "http://localhost:1999", enabled: bool = True):
        self.gateway_url = gateway_url.rstrip("/")
        self.enabled = enabled

    def notify(self, message: str, priority: str = "normal"):
        """Send a text notification. Non-blocking — never crashes the scanner."""
        if not self.enabled:
            return
        try:
            data = json.dumps({"text": message, "priority": priority}).encode()
            req = urllib.request.Request(
                f"{self.gateway_url}/api/notify",
                data=data,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            urllib.request.urlopen(req, timeout=5)
        except Exception as e:
            logger.debug("Notification failed (non-fatal): %s", e)

    def alert_finding(self, finding: dict):
        """Send alert for critical/high findings."""
        severity = finding.get("severity", "medium").upper()
        if severity in ("CRITICAL", "HIGH"):
            vuln = finding.get("type", finding.get("vuln_type", "unknown"))
            url = finding.get("url", "N/A")
            conf = finding.get("confidence", "N/A")
            msg = (
                f"VIPER Finding [{severity}]\n"
                f"Type: {vuln}\n"
                f"URL: {url}\n"
                f"Confidence: {conf}"
            )
            self.notify(msg, priority="high")

    def alert_session_complete(self, stats: dict):
        """Send summary when a scan session completes."""
        findings = stats.get("total_findings", 0)
        if findings > 0:
            msg = (
                f"VIPER Scan Complete\n"
                f"Findings: {findings}\n"
                f"Validated: {stats.get('validated_findings', 0)}\n"
                f"FPs caught: {stats.get('false_positives_caught', 0)}"
            )
            self.notify(msg, priority="normal")
