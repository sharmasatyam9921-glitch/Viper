#!/usr/bin/env python3
"""
VIPER 5.0 — False Positive Filter

Applies learned patterns to eliminate false positives BEFORE findings are reported.
This is the key differentiator that makes VIPER report quality production-grade.

Patterns are loaded from memory/failure_analysis.json (learned during hunts)
plus hardcoded universal patterns (CDN catch-alls, WAF blocks, etc.).
"""

import json
import logging
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

logger = logging.getLogger("viper.fp_filter")

MEMORY_DIR = Path(__file__).parent.parent / "memory"


@dataclass
class FPVerdict:
    """Result of false positive analysis."""
    is_fp: bool
    reason: str
    confidence: float  # 0.0 = uncertain, 1.0 = definitely FP
    pattern_id: str = ""


# ── Universal FP Patterns (hardcoded, always active) ────────────────────

UNIVERSAL_PATTERNS = [
    {
        "id": "cas_sso_catchall",
        "description": "CAS/SSO login page returned for all paths (HTTP 200)",
        "body_signatures": ["cas.mioffice.cn", "cas login", "cas/login", "service=http"],
        "applies_to": ["actuator", "swagger", "graphql", "oauth", "redirect", "debug", "config"],
    },
    {
        "id": "json_404_wrapper",
        "description": "API gateway returns HTTP 200 with JSON {code:404}",
        "body_signatures": ['"code":404', '"code": 404', '"status":404', '"statusCode":404'],
        "applies_to": ["actuator", "swagger", "graphql", "debug", "config", "info_disclosure"],
    },
    {
        "id": "cdn_default_page",
        "description": "CDN default/parking page (no real content)",
        "body_signatures": ["domain for sale", "parked domain", "coming soon", "under construction",
                            "default web page", "welcome to nginx", "apache2 default page",
                            "it works!", "test page for"],
        "applies_to": ["*"],
    },
    {
        "id": "waf_block_page",
        "description": "WAF/firewall block page mistaken for real response",
        "body_signatures": ["access denied", "request blocked", "security policy",
                            "cloudflare", "ray id", "incapsula", "imperva",
                            "akamai", "sucuri", "stackpath"],
        "applies_to": ["*"],
    },
    {
        "id": "soft_404",
        "description": "Custom 404 page returning HTTP 200",
        "body_signatures": ["page not found", "404 not found", "page doesn't exist",
                            "resource not found", "nothing here", "this page could not be found"],
        "applies_to": ["actuator", "swagger", "graphql", "debug", "config", "info_disclosure"],
    },
    {
        "id": "cors_wildcard_with_creds",
        "description": "ACAO=* with ACAC=true is blocked by browsers (not exploitable for cred theft)",
        "header_check": lambda h: h.get("acao") == "*" and h.get("acac", "").lower() == "true",
        "severity_override": "medium",
        "applies_to": ["cors"],
    },
    {
        "id": "redirect_to_login",
        "description": "Redirect goes to login/SSO page, not attacker domain",
        "redirect_check": lambda loc: any(k in loc.lower() for k in
                                           ["login", "signin", "auth", "cas/", "sso/",
                                            "oauth/authorize", "saml/"]),
        "applies_to": ["open_redirect", "oauth"],
    },
    {
        "id": "health_endpoint",
        "description": "Health check endpoints are expected behavior, not vulns",
        "url_patterns": [r"/health$", r"/healthz$", r"/ready$", r"/readyz$", r"/live$", r"/livez$",
                         r"/ping$", r"/status$", r"/__health$"],
        "applies_to": ["actuator", "debug", "info_disclosure"],
    },
    {
        "id": "robots_txt_not_vuln",
        "description": "robots.txt existence is not a vulnerability",
        "url_patterns": [r"/robots\.txt$"],
        "applies_to": ["info_disclosure"],
    },
    {
        "id": "empty_response_body",
        "description": "Empty or near-empty response body (no actual data exposure)",
        "body_check": lambda body: len(body.strip()) < 10,
        "applies_to": ["actuator", "debug", "info_disclosure", "config"],
    },
]


class FPFilter:
    """False positive filter using learned + hardcoded patterns.

    Usage:
        fpf = FPFilter()
        verdict = fpf.check(finding)
        if verdict.is_fp:
            logger.info("FP: %s (reason: %s)", finding['url'], verdict.reason)
    """

    def __init__(self, memory_path: Optional[Path] = None):
        self.memory_path = memory_path or (MEMORY_DIR / "failure_analysis.json")
        self.learned_patterns: List[Dict] = []
        self._load_learned_patterns()
        self.stats = {"checked": 0, "fp_caught": 0, "by_pattern": {}}

    def _load_learned_patterns(self) -> None:
        """Load learned FP patterns from memory."""
        if self.memory_path.exists():
            try:
                data = json.loads(self.memory_path.read_text())
                if isinstance(data, dict):
                    self.learned_patterns = data.get("lessons", [])
                elif isinstance(data, list):
                    self.learned_patterns = data
                logger.info("Loaded %d learned FP patterns", len(self.learned_patterns))
            except Exception as e:
                logger.warning("Failed to load FP patterns: %s", e)

    def check(self, finding: Dict[str, Any]) -> FPVerdict:
        """Check if a finding is a false positive.

        Args:
            finding: Dict with keys like url, type, severity, body, headers, status, etc.

        Returns:
            FPVerdict with is_fp=True if the finding is likely false positive.
        """
        self.stats["checked"] += 1

        url = finding.get("url", "")
        body = finding.get("body", finding.get("body_preview", finding.get("body_sample", "")))
        headers = finding.get("headers", {})
        status = finding.get("status", finding.get("status_code", 0))
        finding_type = finding.get("type", finding.get("vuln_type", finding.get("subtype", "")))
        redirect_location = finding.get("location", headers.get("Location", ""))

        body_lower = body.lower() if body else ""

        # Check universal patterns first
        for pattern in UNIVERSAL_PATTERNS:
            if not self._applies_to(pattern, finding_type):
                continue

            # Body signature check
            if "body_signatures" in pattern:
                for sig in pattern["body_signatures"]:
                    if sig.lower() in body_lower:
                        self._record_fp(pattern["id"])
                        sev_override = pattern.get("severity_override")
                        if sev_override:
                            return FPVerdict(
                                is_fp=False,
                                reason=f"Severity downgrade: {pattern['description']}",
                                confidence=0.9,
                                pattern_id=pattern["id"],
                            )
                        return FPVerdict(
                            is_fp=True,
                            reason=pattern["description"],
                            confidence=0.95,
                            pattern_id=pattern["id"],
                        )

            # Header check (lambda)
            if "header_check" in pattern:
                h = {"acao": finding.get("acao", headers.get("Access-Control-Allow-Origin", "")),
                     "acac": finding.get("acac", headers.get("Access-Control-Allow-Credentials", ""))}
                if pattern["header_check"](h):
                    sev_override = pattern.get("severity_override")
                    if sev_override:
                        # Not FP, but severity should be lowered
                        return FPVerdict(
                            is_fp=False,
                            reason=f"Severity cap: {pattern['description']}",
                            confidence=0.95,
                            pattern_id=pattern["id"],
                        )

            # Redirect check
            if "redirect_check" in pattern and redirect_location:
                if pattern["redirect_check"](redirect_location):
                    # Check if the DESTINATION is login, not attacker
                    parsed_loc = urlparse(redirect_location)
                    if "evil" not in parsed_loc.netloc.lower():
                        self._record_fp(pattern["id"])
                        return FPVerdict(
                            is_fp=True,
                            reason=pattern["description"],
                            confidence=0.9,
                            pattern_id=pattern["id"],
                        )

            # URL pattern check
            if "url_patterns" in pattern:
                for url_pat in pattern["url_patterns"]:
                    if re.search(url_pat, url, re.IGNORECASE):
                        self._record_fp(pattern["id"])
                        return FPVerdict(
                            is_fp=True,
                            reason=pattern["description"],
                            confidence=0.85,
                            pattern_id=pattern["id"],
                        )

            # Body check (lambda)
            if "body_check" in pattern and body:
                if pattern["body_check"](body):
                    self._record_fp(pattern["id"])
                    return FPVerdict(
                        is_fp=True,
                        reason=pattern["description"],
                        confidence=0.8,
                        pattern_id=pattern["id"],
                    )

        # Check learned patterns
        for lesson in self.learned_patterns:
            lesson_id = lesson.get("lesson_id", "")
            detection = lesson.get("detection", "")
            pattern_type = lesson.get("pattern", "")

            # CAS SSO pattern
            if "cas" in pattern_type.lower() and "cas" in body_lower:
                self._record_fp(lesson_id)
                return FPVerdict(
                    is_fp=True,
                    reason=f"Learned: {lesson.get('description', pattern_type)[:100]}",
                    confidence=lesson.get("confidence", 0.8),
                    pattern_id=lesson_id,
                )

            # JSON 404 wrapper
            if "json" in pattern_type.lower() and "404" in pattern_type:
                if '"code":404' in body_lower or '"code": 404' in body_lower:
                    self._record_fp(lesson_id)
                    return FPVerdict(
                        is_fp=True,
                        reason=f"Learned: {lesson.get('description', pattern_type)[:100]}",
                        confidence=lesson.get("confidence", 0.8),
                        pattern_id=lesson_id,
                    )

        return FPVerdict(is_fp=False, reason="No FP pattern matched", confidence=0.0)

    def check_batch(self, findings: List[Dict]) -> Tuple[List[Dict], List[Dict]]:
        """Filter a batch of findings, returning (real, false_positives)."""
        real = []
        fps = []
        for f in findings:
            verdict = self.check(f)
            f["_fp_verdict"] = {"is_fp": verdict.is_fp, "reason": verdict.reason,
                                "confidence": verdict.confidence, "pattern": verdict.pattern_id}
            if verdict.is_fp:
                fps.append(f)
            else:
                real.append(f)
        return real, fps

    def _applies_to(self, pattern: Dict, finding_type: str) -> bool:
        """Check if a pattern applies to this finding type."""
        applies = pattern.get("applies_to", ["*"])
        if "*" in applies:
            return True
        finding_type_lower = finding_type.lower()
        return any(a.lower() in finding_type_lower for a in applies)

    def _record_fp(self, pattern_id: str) -> None:
        """Record FP catch for stats."""
        self.stats["fp_caught"] += 1
        self.stats["by_pattern"][pattern_id] = self.stats["by_pattern"].get(pattern_id, 0) + 1

    def get_stats(self) -> Dict:
        """Return FP filter statistics."""
        return {
            **self.stats,
            "fp_rate": self.stats["fp_caught"] / max(self.stats["checked"], 1),
            "learned_patterns": len(self.learned_patterns),
            "universal_patterns": len(UNIVERSAL_PATTERNS),
        }


# Singleton for easy import
_default_filter = None


def get_fp_filter() -> FPFilter:
    """Get or create the default FP filter instance."""
    global _default_filter
    if _default_filter is None:
        _default_filter = FPFilter()
    return _default_filter


__all__ = ["FPFilter", "FPVerdict", "get_fp_filter"]
