#!/usr/bin/env python3
"""
VIPER Failure Analyzer — Learn from failed attack attempts.

Triggered after every failed attack. Analyzes the failure, extracts
lessons, and feeds bypass suggestions back into the fuzzer.
"""

import json
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger("viper.failure_analyzer")

FAILURE_ANALYSIS_PATH = Path(__file__).parent.parent / "memory" / "failure_analysis.json"


@dataclass
class LessonLearned:
    """A lesson extracted from a failed attack attempt."""
    attack_type: str
    target: str
    failure_reason: str
    waf_signature_detected: Optional[str] = None
    suggested_bypass: str = ""
    payload_mutation: str = ""
    confidence: float = 0.0
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    original_payload: str = ""
    response_status: int = 0

    def to_dict(self) -> dict:
        return {
            "attack_type": self.attack_type,
            "target": self.target,
            "failure_reason": self.failure_reason,
            "waf_signature_detected": self.waf_signature_detected,
            "suggested_bypass": self.suggested_bypass,
            "payload_mutation": self.payload_mutation,
            "confidence": self.confidence,
            "timestamp": self.timestamp,
            "original_payload": self.original_payload,
            "response_status": self.response_status,
        }


class FailureAnalyzer:
    """Analyze failed attack attempts and extract actionable lessons.

    When an LLM client is provided, uses AI analysis for deeper insights.
    Otherwise falls back to heuristic pattern matching.

    Args:
        llm_client: Optional LLM client for AI-powered analysis.
        storage_path: Path to store failure analysis results.
    """

    # Known WAF signatures in response bodies/headers
    WAF_PATTERNS = {
        "cloudflare": ["cf-ray", "cloudflare", "attention required", "ray id"],
        "aws_waf": ["awswaf", "x-amzn-waf", "request blocked"],
        "modsecurity": ["mod_security", "modsec", "not acceptable", "406"],
        "imperva": ["incapsula", "visid_incap", "incap_ses"],
        "akamai": ["akamai", "reference #", "access denied"],
        "sucuri": ["sucuri", "cloudproxy", "access denied"],
        "wordfence": ["wordfence", "blocked by", "security plugin"],
        "f5_bigip": ["bigip", "the requested url was rejected"],
    }

    # Common failure reasons by pattern
    FAILURE_HEURISTICS = {
        "403": "Access forbidden — likely WAF block or IP-based restriction",
        "406": "Not acceptable — WAF content inspection triggered",
        "429": "Rate limited — too many requests too fast",
        "500": "Server error — payload may have triggered unhandled exception",
        "502": "Bad gateway — upstream service rejected the request",
        "503": "Service unavailable — possible WAF/DDoS protection",
    }

    # Bypass suggestions per WAF
    BYPASS_SUGGESTIONS = {
        "cloudflare": [
            "Use Unicode encoding (fullwidth characters)",
            "Try chunk transfer encoding",
            "Add X-Forwarded-For: 127.0.0.1",
            "URL-encode key characters twice (double encoding)",
        ],
        "aws_waf": [
            "Use mixed case for SQL keywords",
            "Insert comments between keywords (SE/**/LECT)",
            "Use alternative functions (IF vs CASE)",
        ],
        "modsecurity": [
            "Use hex encoding for payloads",
            "Break payload across multiple parameters",
            "Use HTTP parameter pollution",
        ],
        "imperva": [
            "Encode payload in UTF-7",
            "Use newline characters in headers",
            "Try HTTP/2 specific bypass techniques",
        ],
    }

    def __init__(
        self,
        llm_client: Any = None,
        storage_path: Path = FAILURE_ANALYSIS_PATH,
    ):
        self.llm_client = llm_client
        self.storage_path = storage_path
        self.lessons: List[LessonLearned] = []
        self._load_history()

    def _load_history(self) -> None:
        """Load previous failure analysis from disk."""
        if self.storage_path.exists():
            try:
                data = json.loads(self.storage_path.read_text())
                for item in data.get("lessons", []):
                    self.lessons.append(LessonLearned(**item))
                logger.info("Loaded %d historical failure lessons", len(self.lessons))
            except Exception as exc:
                logger.debug("Failed to load failure history: %s", exc)

    def _save_history(self) -> None:
        """Persist failure analysis to disk."""
        self.storage_path.parent.mkdir(parents=True, exist_ok=True)
        data = {"lessons": [l.to_dict() for l in self.lessons[-500:]]}  # keep last 500
        self.storage_path.write_text(json.dumps(data, indent=2))

    async def analyze(self, failed_attempt: dict) -> LessonLearned:
        """Analyze a failed attack attempt and return a lesson.

        Args:
            failed_attempt: Dict with keys:
                - attack_type: str
                - target: str
                - payload: str
                - response_status: int
                - response_body: str (first 500 chars)
                - response_headers: dict
                - waf_detected: bool

        Returns:
            LessonLearned with analysis results.
        """
        attack_type = failed_attempt.get("attack_type", "unknown")
        target = failed_attempt.get("target", "")
        payload = failed_attempt.get("payload", "")
        status = failed_attempt.get("response_status", 0)
        body = failed_attempt.get("response_body", "")[:500]
        headers = failed_attempt.get("response_headers", {})

        # Try LLM analysis first
        if self.llm_client:
            lesson = await self._llm_analyze(failed_attempt)
            if lesson:
                self.lessons.append(lesson)
                self._save_history()
                return lesson

        # Fallback to heuristic analysis
        lesson = self._heuristic_analyze(
            attack_type=attack_type,
            target=target,
            payload=payload,
            status=status,
            body=body,
            headers=headers,
        )

        self.lessons.append(lesson)
        self._save_history()
        return lesson

    async def _llm_analyze(self, failed_attempt: dict) -> Optional[LessonLearned]:
        """Use LLM for deep failure analysis."""
        prompt = (
            f"Attack: {failed_attempt.get('attack_type')} on {failed_attempt.get('target')}\n"
            f"Payload: {failed_attempt.get('payload', '')[:200]}\n"
            f"Response: {failed_attempt.get('response_status')} {failed_attempt.get('response_body', '')[:500]}\n"
            f"WAF triggered: {failed_attempt.get('waf_detected', False)}\n\n"
            "Analyze why this failed. Return JSON:\n"
            "{\n"
            '  "failure_reason": str,\n'
            '  "waf_signature_detected": str | null,\n'
            '  "suggested_bypass": str,\n'
            '  "payload_mutation": str,\n'
            '  "confidence": float\n'
            "}"
        )

        try:
            # Use the LLM client (model_router or direct)
            if hasattr(self.llm_client, "complete"):
                response = await self.llm_client.complete(prompt)
            elif hasattr(self.llm_client, "generate"):
                response = await self.llm_client.generate(prompt)
            else:
                return None

            # Parse JSON from response
            text = str(response)
            # Extract JSON block
            start = text.find("{")
            end = text.rfind("}") + 1
            if start >= 0 and end > start:
                result = json.loads(text[start:end])
                return LessonLearned(
                    attack_type=failed_attempt.get("attack_type", "unknown"),
                    target=failed_attempt.get("target", ""),
                    failure_reason=result.get("failure_reason", ""),
                    waf_signature_detected=result.get("waf_signature_detected"),
                    suggested_bypass=result.get("suggested_bypass", ""),
                    payload_mutation=result.get("payload_mutation", ""),
                    confidence=float(result.get("confidence", 0.5)),
                    original_payload=failed_attempt.get("payload", "")[:200],
                    response_status=failed_attempt.get("response_status", 0),
                )
        except Exception as exc:
            logger.debug("LLM analysis failed: %s", exc)

        return None

    def _heuristic_analyze(
        self,
        attack_type: str,
        target: str,
        payload: str,
        status: int,
        body: str,
        headers: dict,
    ) -> LessonLearned:
        """Heuristic failure analysis based on response patterns."""
        body_lower = body.lower()
        headers_lower = {k.lower(): v.lower() for k, v in headers.items()}
        all_text = body_lower + " " + " ".join(headers_lower.values())

        # Detect WAF
        waf_detected = None
        suggested_bypass = ""
        for waf_name, signatures in self.WAF_PATTERNS.items():
            if any(sig in all_text for sig in signatures):
                waf_detected = waf_name
                bypasses = self.BYPASS_SUGGESTIONS.get(waf_name, [])
                suggested_bypass = bypasses[0] if bypasses else "Try encoding payload differently"
                break

        # Determine failure reason
        failure_reason = self.FAILURE_HEURISTICS.get(
            str(status),
            f"HTTP {status} — analyze response for specific rejection reason",
        )

        if waf_detected:
            failure_reason = f"WAF ({waf_detected}) blocked the request: {failure_reason}"

        # Suggest payload mutation
        payload_mutation = ""
        if "sql" in attack_type.lower():
            payload_mutation = "Try: mixed case, comment injection, alternative syntax"
        elif "xss" in attack_type.lower():
            payload_mutation = "Try: event handlers, SVG tags, template literals"
        elif "ssti" in attack_type.lower():
            payload_mutation = "Try: alternative template syntax, nested expressions"
        elif "ssrf" in attack_type.lower():
            payload_mutation = "Try: DNS rebinding, alternative protocols, IPv6"

        return LessonLearned(
            attack_type=attack_type,
            target=target,
            failure_reason=failure_reason,
            waf_signature_detected=waf_detected,
            suggested_bypass=suggested_bypass,
            payload_mutation=payload_mutation,
            confidence=0.6 if waf_detected else 0.4,
            original_payload=payload[:200],
            response_status=status,
        )

    def get_lessons_for_type(self, attack_type: str, limit: int = 10) -> List[LessonLearned]:
        """Get recent lessons for a specific attack type."""
        matching = [l for l in self.lessons if l.attack_type == attack_type]
        return matching[-limit:]

    def get_bypass_suggestions(self, waf_name: str) -> List[str]:
        """Get bypass suggestions for a specific WAF."""
        return self.BYPASS_SUGGESTIONS.get(waf_name, [])

    def get_stats(self) -> dict:
        """Return failure analysis statistics."""
        waf_counts: Dict[str, int] = {}
        for lesson in self.lessons:
            if lesson.waf_signature_detected:
                waf_counts[lesson.waf_signature_detected] = waf_counts.get(
                    lesson.waf_signature_detected, 0
                ) + 1

        return {
            "total_lessons": len(self.lessons),
            "waf_detections": waf_counts,
            "attack_types": list(set(l.attack_type for l in self.lessons)),
        }


__all__ = ["FailureAnalyzer", "LessonLearned"]
