#!/usr/bin/env python3
"""
VIPER Finding Stream — Real-time notification of discoveries.

Streams findings to Discord webhooks, Telegram bots, and email
with severity-based routing.
"""

import asyncio
import json
import logging
import os
import time
import urllib.parse
import urllib.request
import ssl
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

logger = logging.getLogger("viper.finding_stream")


@dataclass
class NotificationConfig:
    """Configuration for notification channels."""
    discord_webhook: str = ""
    telegram_bot_token: str = ""
    telegram_chat_id: str = ""
    email_smtp_host: str = ""
    email_smtp_port: int = 587
    email_from: str = ""
    email_to: str = ""
    email_password: str = ""
    clawdbot_gateway: str = ""  # Clawdbot gateway URL for Telegram relay

    @classmethod
    def from_env(cls) -> "NotificationConfig":
        """Load config from environment variables."""
        return cls(
            discord_webhook=os.environ.get("DISCORD_WEBHOOK_URL", ""),
            telegram_bot_token=os.environ.get("TELEGRAM_BOT_TOKEN", ""),
            telegram_chat_id=os.environ.get("TELEGRAM_CHAT_ID", ""),
            email_smtp_host=os.environ.get("SMTP_HOST", "smtp.gmail.com"),
            email_smtp_port=int(os.environ.get("SMTP_PORT", "587")),
            email_from=os.environ.get("SMTP_FROM", ""),
            email_to=os.environ.get("SMTP_TO", ""),
            email_password=os.environ.get("SMTP_PASSWORD", ""),
            clawdbot_gateway=os.environ.get("CLAWDBOT_GATEWAY", ""),
        )


class FindingStream:
    """Real-time finding notification stream.

    Severity routing:
    - CRITICAL/HIGH → immediate alert to all channels
    - MEDIUM → Discord only, batched every 15 minutes
    - LOW/INFO → daily digest email only

    Args:
        config: NotificationConfig with channel credentials.
    """

    def __init__(self, config: Optional[NotificationConfig] = None):
        self.config = config or NotificationConfig.from_env()
        self._medium_buffer: List[dict] = []
        self._low_buffer: List[dict] = []
        self._last_medium_flush = time.monotonic()
        self._last_low_flush = time.monotonic()
        self._flush_interval_medium = 900  # 15 minutes
        self._flush_interval_low = 86400  # 24 hours
        self._ssl_ctx = ssl.create_default_context()

    async def notify(self, finding: dict) -> None:
        """Route a finding to appropriate notification channels.

        Args:
            finding: Dict with keys: vuln_type, severity, target_url,
                     cvss, evidence, estimated_bounty, evidence_hash.
        """
        severity = finding.get("severity", "info").lower()

        if severity in ("critical", "high"):
            await self._notify_all_channels(finding)
        elif severity == "medium":
            self._medium_buffer.append(finding)
            await self._maybe_flush_medium()
        else:
            self._low_buffer.append(finding)
            await self._maybe_flush_low()

    async def _notify_all_channels(self, finding: dict) -> None:
        """Send immediate alerts to all configured channels."""
        tasks = []
        if self.config.discord_webhook:
            tasks.append(self._send_discord(finding))
        if self.config.telegram_bot_token and self.config.telegram_chat_id:
            tasks.append(self._send_telegram(finding))
        if self.config.email_from and self.config.email_to:
            tasks.append(self._send_email([finding], subject_prefix="URGENT"))
        if self.config.clawdbot_gateway:
            tasks.append(self._send_clawdbot(finding))

        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

    async def _maybe_flush_medium(self) -> None:
        """Flush medium-severity buffer if 15 minutes elapsed."""
        if time.monotonic() - self._last_medium_flush >= self._flush_interval_medium:
            if self._medium_buffer:
                await self._send_discord_batch(self._medium_buffer)
                self._medium_buffer.clear()
            self._last_medium_flush = time.monotonic()

    async def _maybe_flush_low(self) -> None:
        """Flush low-severity buffer for daily digest."""
        if time.monotonic() - self._last_low_flush >= self._flush_interval_low:
            if self._low_buffer and self.config.email_from:
                await self._send_email(self._low_buffer, subject_prefix="Daily Digest")
                self._low_buffer.clear()
            self._last_low_flush = time.monotonic()

    async def flush_all(self) -> None:
        """Force flush all buffers (e.g., at session end)."""
        if self._medium_buffer:
            if self.config.discord_webhook:
                await self._send_discord_batch(self._medium_buffer)
            self._medium_buffer.clear()
        if self._low_buffer:
            if self.config.email_from:
                await self._send_email(self._low_buffer, subject_prefix="Session Summary")
            self._low_buffer.clear()

    def _format_finding(self, finding: dict) -> str:
        """Format a finding for notification."""
        severity = finding.get("severity", "info").upper()
        vuln_type = finding.get("vuln_type", "Unknown")
        target = finding.get("target_url", "Unknown target")
        cvss = finding.get("cvss", 0.0)
        evidence_hash = finding.get("evidence_hash", "")[:12]
        bounty = finding.get("estimated_bounty", "")

        lines = [
            f"**[{severity}]** {vuln_type}",
            f"Target: {target}",
            f"CVSS: {cvss}",
        ]
        if bounty:
            lines.append(f"Est. Bounty: {bounty}")
        if evidence_hash:
            lines.append(f"Evidence: {evidence_hash}")

        return "\n".join(lines)

    # ── Discord ──

    async def _send_discord(self, finding: dict) -> None:
        """Send finding to Discord webhook."""
        severity = finding.get("severity", "info").lower()
        color_map = {"critical": 0xFF0000, "high": 0xFF6600, "medium": 0xFFCC00, "low": 0x00CC00, "info": 0x0066FF}

        payload = {
            "embeds": [{
                "title": f"VIPER Finding: {finding.get('vuln_type', 'Unknown')}",
                "description": self._format_finding(finding),
                "color": color_map.get(severity, 0x808080),
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "footer": {"text": "VIPER Bug Bounty Agent"},
            }],
        }

        await self._webhook_post(self.config.discord_webhook, payload)

    async def _send_discord_batch(self, findings: List[dict]) -> None:
        """Send batched findings to Discord."""
        summary = f"**VIPER Batch: {len(findings)} findings**\n\n"
        for f in findings[:10]:
            summary += f"• [{f.get('severity', '?').upper()}] {f.get('vuln_type', '?')} — {f.get('target_url', '?')}\n"
        if len(findings) > 10:
            summary += f"\n...and {len(findings) - 10} more"

        payload = {
            "embeds": [{
                "title": f"VIPER Batch: {len(findings)} Medium Findings",
                "description": summary,
                "color": 0xFFCC00,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }],
        }

        await self._webhook_post(self.config.discord_webhook, payload)

    async def _webhook_post(self, url: str, payload: dict) -> None:
        """POST JSON to a webhook URL."""
        if not url:
            return
        try:
            data = json.dumps(payload).encode()
            req = urllib.request.Request(
                url, data=data, method="POST",
                headers={"Content-Type": "application/json"},
            )
            await asyncio.get_running_loop().run_in_executor(
                None,
                lambda: urllib.request.urlopen(req, timeout=10, context=self._ssl_ctx),
            )
        except Exception as exc:
            logger.debug("Webhook POST failed: %s", exc)

    # ── Telegram ──

    async def _send_telegram(self, finding: dict) -> None:
        """Send finding to Telegram bot."""
        if not self.config.telegram_bot_token or not self.config.telegram_chat_id:
            return

        text = f"🔴 VIPER Alert\n\n{self._format_finding(finding)}"
        text = text.replace("**", "*")  # Telegram uses single * for bold

        url = (
            f"https://api.telegram.org/bot{self.config.telegram_bot_token}"
            f"/sendMessage"
        )
        payload = {
            "chat_id": self.config.telegram_chat_id,
            "text": text,
            "parse_mode": "Markdown",
        }

        await self._webhook_post(url, payload)

    # ── Clawdbot Gateway ──

    async def _send_clawdbot(self, finding: dict) -> None:
        """Send finding to Clawdbot gateway for Telegram relay."""
        if not self.config.clawdbot_gateway:
            return
        severity = finding.get("severity", "info").upper()
        vuln = finding.get("vuln_type", finding.get("type", "unknown"))
        url = finding.get("target_url", finding.get("url", "N/A"))
        msg = f"VIPER Finding [{severity}]\nType: {vuln}\nURL: {url}"
        payload = {"text": msg, "priority": "high" if severity in ("CRITICAL", "HIGH") else "normal"}
        gateway = self.config.clawdbot_gateway.rstrip("/")
        await self._webhook_post(f"{gateway}/api/notify", payload)

    # ── Email ──

    async def _send_email(self, findings: List[dict], subject_prefix: str = "") -> None:
        """Send findings via email."""
        if not self.config.email_from or not self.config.email_to:
            return

        try:
            import smtplib
            from email.mime.text import MIMEText

            subject = f"[VIPER {subject_prefix}] {len(findings)} findings"
            body = f"VIPER Finding Report — {datetime.now(timezone.utc).isoformat()}\n\n"

            for f in findings:
                body += f"[{f.get('severity', '?').upper()}] {f.get('vuln_type', '?')}\n"
                body += f"  Target: {f.get('target_url', '?')}\n"
                body += f"  CVSS: {f.get('cvss', 0.0)}\n\n"

            msg = MIMEText(body)
            msg["Subject"] = subject
            msg["From"] = self.config.email_from
            msg["To"] = self.config.email_to

            def _send():
                with smtplib.SMTP(self.config.email_smtp_host, self.config.email_smtp_port) as server:
                    server.starttls()
                    server.login(self.config.email_from, self.config.email_password)
                    server.send_message(msg)

            await asyncio.get_running_loop().run_in_executor(None, _send)
            logger.info("Email sent: %s", subject)
        except Exception as exc:
            logger.debug("Email send failed: %s", exc)

    def get_stats(self) -> dict:
        """Return stream statistics."""
        return {
            "medium_buffer": len(self._medium_buffer),
            "low_buffer": len(self._low_buffer),
            "channels_configured": sum([
                bool(self.config.discord_webhook),
                bool(self.config.telegram_bot_token),
                bool(self.config.email_from),
            ]),
        }


__all__ = ["FindingStream", "NotificationConfig"]
