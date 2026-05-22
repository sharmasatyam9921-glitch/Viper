"""
VIPER 6.1 - Report Quality Gate

CRITICAL: Triggered after HackerOne signal warning (negative signal).
This module enforces strict pre-submission quality control to RECOVER signal.

The 5 H1 Quality Principles (encoded as gate functions):
1. Quality Over Quantity   → strict validated+confidence gate, daily submission cap
2. Read The Guide          → enforced report template structure
3. Be Comprehensive, Yet Concise → length bounds + required sections
4. Read Existing Reports   → hacktivity comparison before novel submissions
5. Ask For Help            → explicit "human review needed" tier for ambiguous

Status: ENFORCED ON ALL FUTURE SUBMISSIONS until signal recovers above 0.
"""

import asyncio
import hashlib
import json
import re
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import aiohttp


SIGNAL_RECOVERY_MODE = True  # Set to False once signal recovers above 0


@dataclass
class QualityCheck:
    name: str
    passed: bool
    score: float  # 0..1
    notes: str = ""


@dataclass
class QualityVerdict:
    finding_id: str
    overall_score: float  # 0..1
    submit_now: bool  # green-light?
    needs_human_review: bool  # ask-for-help tier?
    checks: List[QualityCheck] = field(default_factory=list)
    rejection_reasons: List[str] = field(default_factory=list)


class ReportQualityGate:
    """STRICT pre-submission gate. Default-deny."""

    # Quality thresholds (signal recovery mode = ULTRA-strict)
    MIN_OVERALL_SCORE = 0.85 if SIGNAL_RECOVERY_MODE else 0.70
    MIN_VALIDATION_CONFIDENCE = 0.95 if SIGNAL_RECOVERY_MODE else 0.85
    MIN_CVSS = 6.0 if SIGNAL_RECOVERY_MODE else 4.0
    MIN_EVIDENCE_ARTIFACTS = 2 if SIGNAL_RECOVERY_MODE else 1
    MIN_REPRO_STEPS = 4 if SIGNAL_RECOVERY_MODE else 2
    MIN_DESCRIPTION_LENGTH = 500 if SIGNAL_RECOVERY_MODE else 200

    # Daily submission caps (Tip #1: quality over quantity)
    DAILY_SUBMISSION_CAP = 1 if SIGNAL_RECOVERY_MODE else 5

    # Required report sections (Tip #2: read the guide)
    REQUIRED_SECTIONS = [
        "Summary",
        "Steps to Reproduce",
        "Impact",
        "Recommended Remediation"
    ]

    # Excluded vuln types that historically yield low signal
    SIGNAL_KILLER_VULN_TYPES = {
        "info_missing_security_headers",
        "missing_hsts",
        "missing_csp",
        "self_xss",
        "logout_csrf",
        "click_jacking_no_impact",
        "verbose_error_message",
        "version_disclosure",
        "informational_only",
        "info_disclosure_low",
        "rate_limiting",  # Whatnot-style: explicitly out of scope
        "spf_dmarc_missing",
    }

    def __init__(self, history_path: Optional[Path] = None):
        self.history_path = history_path or Path(__file__).parent.parent / "memory" / "h1_submissions.jsonl"
        self.history_path.parent.mkdir(parents=True, exist_ok=True)

    def check(self, finding: Dict[str, Any], validation: Dict[str, Any],
              submission_draft: Dict[str, Any]) -> QualityVerdict:
        """Run ALL gate checks. Returns submit_now=True only if ALL pass."""
        finding_id = finding.get("id", hashlib.sha256(json.dumps(finding, sort_keys=True, default=str).encode()).hexdigest()[:16])
        verdict = QualityVerdict(finding_id=finding_id, overall_score=0.0, submit_now=False, needs_human_review=False)

        # CHECK 1: Validated by deterministic validator
        validated = validation.get("validated", False)
        confidence = validation.get("confidence", 0.0)
        verdict.checks.append(QualityCheck(
            name="validation_confirmed",
            passed=(validated and confidence >= self.MIN_VALIDATION_CONFIDENCE),
            score=confidence if validated else 0.0,
            notes=f"validated={validated} conf={confidence:.2f} (need ≥{self.MIN_VALIDATION_CONFIDENCE})"
        ))
        if not validated or confidence < self.MIN_VALIDATION_CONFIDENCE:
            verdict.rejection_reasons.append(
                f"Validation: validated={validated}, confidence={confidence:.2f} (require ≥{self.MIN_VALIDATION_CONFIDENCE})"
            )

        # CHECK 2: Vuln type not on signal-killer list (Tip #1)
        vuln_type = (finding.get("vuln_type") or "").lower().replace("-", "_")
        on_killer_list = vuln_type in self.SIGNAL_KILLER_VULN_TYPES
        verdict.checks.append(QualityCheck(
            name="vuln_type_not_signal_killer",
            passed=not on_killer_list,
            score=0.0 if on_killer_list else 1.0,
            notes=f"vuln_type='{vuln_type}'" + (" (BLOCKED — historical signal-killer)" if on_killer_list else "")
        ))
        if on_killer_list:
            verdict.rejection_reasons.append(
                f"Vuln type '{vuln_type}' historically yields negative signal. Excluded."
            )

        # CHECK 3: Severity threshold (Tip #1: quality over quantity)
        cvss = submission_draft.get("cvss_score", 0.0)
        verdict.checks.append(QualityCheck(
            name="severity_threshold",
            passed=cvss >= self.MIN_CVSS,
            score=min(cvss / 10.0, 1.0),
            notes=f"CVSS={cvss} (need ≥{self.MIN_CVSS})"
        ))
        if cvss < self.MIN_CVSS:
            verdict.rejection_reasons.append(
                f"CVSS {cvss} below quality threshold {self.MIN_CVSS} (Tip #1: quality over quantity)"
            )

        # CHECK 4: Evidence artifacts (Tip #3: comprehensive)
        evidence = validation.get("evidence", []) or submission_draft.get("evidence_artifacts", [])
        evidence_count = len(evidence) if isinstance(evidence, list) else 0
        verdict.checks.append(QualityCheck(
            name="evidence_artifacts",
            passed=evidence_count >= self.MIN_EVIDENCE_ARTIFACTS,
            score=min(evidence_count / float(self.MIN_EVIDENCE_ARTIFACTS), 1.0),
            notes=f"{evidence_count} artifacts (need ≥{self.MIN_EVIDENCE_ARTIFACTS})"
        ))
        if evidence_count < self.MIN_EVIDENCE_ARTIFACTS:
            verdict.rejection_reasons.append(
                f"Only {evidence_count} evidence artifacts (require ≥{self.MIN_EVIDENCE_ARTIFACTS}). "
                f"Capture full request+response for at least {self.MIN_EVIDENCE_ARTIFACTS} variations."
            )

        # CHECK 5: Reproducibility hash present
        repro_hash = validation.get("reproducibility_hash", "")
        verdict.checks.append(QualityCheck(
            name="reproducibility_hash",
            passed=bool(repro_hash) and len(repro_hash) >= 16,
            score=1.0 if repro_hash else 0.0,
            notes=f"hash={'present' if repro_hash else 'MISSING'}"
        ))
        if not repro_hash:
            verdict.rejection_reasons.append("Missing reproducibility hash from validator")

        # CHECK 6: Report structure (Tip #2: read the guide)
        description = submission_draft.get("description", "")
        missing_sections = [s for s in self.REQUIRED_SECTIONS if s not in description]
        verdict.checks.append(QualityCheck(
            name="required_sections",
            passed=len(missing_sections) == 0,
            score=1.0 - (len(missing_sections) / len(self.REQUIRED_SECTIONS)),
            notes=f"missing: {missing_sections}" if missing_sections else "all present"
        ))
        if missing_sections:
            verdict.rejection_reasons.append(
                f"Report missing required sections: {missing_sections} (Tip #2)"
            )

        # CHECK 7: Description length (Tip #3: comprehensive yet concise)
        desc_len = len(description)
        within_bounds = self.MIN_DESCRIPTION_LENGTH <= desc_len <= 5000
        verdict.checks.append(QualityCheck(
            name="description_length",
            passed=within_bounds,
            score=1.0 if within_bounds else 0.5,
            notes=f"{desc_len} chars (need {self.MIN_DESCRIPTION_LENGTH}-5000)"
        ))
        if not within_bounds:
            if desc_len < self.MIN_DESCRIPTION_LENGTH:
                verdict.rejection_reasons.append(
                    f"Description too short ({desc_len} chars). Min {self.MIN_DESCRIPTION_LENGTH}."
                )
            else:
                verdict.rejection_reasons.append(
                    f"Description too long ({desc_len} chars). Max 5000 — be concise (Tip #3)."
                )

        # CHECK 8: Reproduction steps detailed enough (Tip #3)
        repro_steps = submission_draft.get("reproduction_steps", [])
        verdict.checks.append(QualityCheck(
            name="repro_steps_detailed",
            passed=len(repro_steps) >= self.MIN_REPRO_STEPS,
            score=min(len(repro_steps) / float(self.MIN_REPRO_STEPS), 1.0),
            notes=f"{len(repro_steps)} steps (need ≥{self.MIN_REPRO_STEPS})"
        ))
        if len(repro_steps) < self.MIN_REPRO_STEPS:
            verdict.rejection_reasons.append(
                f"Only {len(repro_steps)} repro steps (need ≥{self.MIN_REPRO_STEPS}). "
                f"Include each request/response with explanation."
            )

        # CHECK 9: PoC code present (Tip #3)
        poc = submission_draft.get("poc_code", "") or ""
        verdict.checks.append(QualityCheck(
            name="poc_code_present",
            passed=len(poc) > 50,
            score=1.0 if len(poc) > 50 else 0.0,
            notes=f"PoC: {len(poc)} chars" + (" (MISSING)" if len(poc) <= 50 else "")
        ))
        if len(poc) <= 50:
            verdict.rejection_reasons.append(
                "PoC code missing or trivial. Include working exploit script."
            )

        # CHECK 10: Daily submission cap (Tip #1)
        today_count = self._count_submissions_today()
        verdict.checks.append(QualityCheck(
            name="daily_submission_cap",
            passed=today_count < self.DAILY_SUBMISSION_CAP,
            score=1.0 if today_count < self.DAILY_SUBMISSION_CAP else 0.0,
            notes=f"submitted today: {today_count}/{self.DAILY_SUBMISSION_CAP}"
        ))
        if today_count >= self.DAILY_SUBMISSION_CAP:
            verdict.rejection_reasons.append(
                f"Daily cap reached ({today_count}/{self.DAILY_SUBMISSION_CAP}). "
                f"Quality over quantity (Tip #1). Wait until tomorrow."
            )

        # CHECK 11: Not a duplicate of recent VIPER submission
        is_dup = self._is_duplicate(repro_hash)
        verdict.checks.append(QualityCheck(
            name="not_duplicate",
            passed=not is_dup,
            score=0.0 if is_dup else 1.0,
            notes=f"duplicate of prior submission: {is_dup}"
        ))
        if is_dup:
            verdict.rejection_reasons.append(
                f"Reproducibility hash matches a prior submission. Skipping duplicate."
            )

        # CHECK 12: Impact section explains business risk (Tip #2)
        impact = submission_draft.get("impact", "")
        impact_quality = self._assess_impact_quality(impact)
        verdict.checks.append(QualityCheck(
            name="impact_explains_business_risk",
            passed=impact_quality >= 0.7,
            score=impact_quality,
            notes=f"impact quality={impact_quality:.2f}"
        ))
        if impact_quality < 0.7:
            verdict.rejection_reasons.append(
                "Impact section too generic. Explain CONCRETE business risk "
                "(data exposed, accounts taken over, $ at risk)."
            )

        # COMPUTE OVERALL
        passed_count = sum(1 for c in verdict.checks if c.passed)
        verdict.overall_score = sum(c.score for c in verdict.checks) / len(verdict.checks)
        verdict.submit_now = (
            passed_count == len(verdict.checks)
            and verdict.overall_score >= self.MIN_OVERALL_SCORE
        )

        # AMBIGUOUS tier - needs human review (Tip #5: ask for help)
        if not verdict.submit_now:
            # If MOST checks pass and only structure issues remain → human review
            if passed_count >= len(verdict.checks) - 2 and verdict.overall_score >= 0.6:
                verdict.needs_human_review = True

        return verdict

    def _count_submissions_today(self) -> int:
        if not self.history_path.exists():
            return 0
        today = datetime.utcnow().date()
        count = 0
        with open(self.history_path) as f:
            for line in f:
                try:
                    e = json.loads(line)
                    ts = datetime.fromisoformat(e.get("submitted_at", "").replace("Z", ""))
                    if ts.date() == today:
                        count += 1
                except:
                    pass
        return count

    def _is_duplicate(self, repro_hash: str) -> bool:
        if not repro_hash or not self.history_path.exists():
            return False
        with open(self.history_path) as f:
            for line in f:
                try:
                    e = json.loads(line)
                    if e.get("reproducibility_hash") == repro_hash:
                        return True
                except:
                    pass
        return False

    def _assess_impact_quality(self, impact: str) -> float:
        """Heuristic: impact text should reference CONCRETE consequences."""
        if not impact or len(impact) < 50:
            return 0.0

        score = 0.0
        # Concrete impact keywords
        good_words = ["account takeover", "PII", "credentials", "session", "database",
                       "data exfiltration", "RCE", "privilege escalation", "financial",
                       "$", "users affected", "compliance", "GDPR", "PCI", "HIPAA",
                       "lateral movement", "access controls", "authorization"]
        for w in good_words:
            if w.lower() in impact.lower():
                score += 0.15

        # Bad signals
        bad_words = ["informational", "low impact", "self-xss", "may", "could potentially"]
        for w in bad_words:
            if w.lower() in impact.lower():
                score -= 0.2

        return max(0.0, min(1.0, score))

    def log_submission(self, submission: Dict[str, Any], verdict: QualityVerdict, h1_response: Dict):
        entry = {
            "submitted_at": datetime.utcnow().isoformat(),
            "title": submission.get("title", ""),
            "vuln_type": submission.get("vuln_type", ""),
            "severity": submission.get("severity", ""),
            "cvss": submission.get("cvss_score", 0),
            "reproducibility_hash": submission.get("reproducibility_hash", ""),
            "quality_score": verdict.overall_score,
            "h1_response": h1_response
        }
        with open(self.history_path, 'a') as f:
            f.write(json.dumps(entry, default=str) + "\n")

    def explain(self, verdict: QualityVerdict) -> str:
        """Human-readable explanation of gate decision."""
        lines = []
        lines.append(f"=== Report Quality Verdict ===")
        lines.append(f"Finding: {verdict.finding_id}")
        lines.append(f"Overall score: {verdict.overall_score:.2f} (need ≥{self.MIN_OVERALL_SCORE})")
        lines.append(f"Decision: {'SUBMIT' if verdict.submit_now else 'BLOCK' + (' (HUMAN REVIEW)' if verdict.needs_human_review else '')}")
        lines.append("")
        lines.append("Checks:")
        for c in verdict.checks:
            mark = "[PASS]" if c.passed else "[FAIL]"
            lines.append(f"  {mark} {c.name}: {c.notes}")
        if verdict.rejection_reasons:
            lines.append("")
            lines.append("Rejection reasons:")
            for r in verdict.rejection_reasons:
                lines.append(f"  - {r}")
        return "\n".join(lines)


# ============================================================
# DEMO
# ============================================================
if __name__ == "__main__":
    gate = ReportQualityGate()

    # Test a low-quality finding (would have hurt signal)
    bad_finding = {
        "id": "f1", "vuln_type": "info_missing_security_headers",
        "target": "https://example.com"
    }
    bad_validation = {
        "validated": True, "confidence": 0.7,
        "evidence": [{"a": 1}],
        "reproducibility_hash": "abc"
    }
    bad_draft = {
        "cvss_score": 2.5,
        "description": "Missing CSP header.",
        "reproduction_steps": ["GET /"],
        "poc_code": "",
        "impact": "Could allow XSS."
    }
    v = gate.check(bad_finding, bad_validation, bad_draft)
    print(gate.explain(v))
    print()

    # Test a high-quality finding
    good_finding = {
        "id": "f2", "vuln_type": "sql_injection",
        "target": "https://example.com/api/users", "parameter": "id"
    }
    good_validation = {
        "validated": True, "confidence": 0.99,
        "evidence": [{"req": 1}, {"req": 2}],
        "reproducibility_hash": "a" * 64,
        "method": "time_based"
    }
    good_draft = {
        "cvss_score": 8.8,
        "description": "## Summary\nSQL Injection in /api/users via id parameter.\n\n## Steps to Reproduce\n1. Send request\n2. Observe time delay\n\n## Impact\nFull database exfiltration possible. PII, credentials, payment data exposed. GDPR violation. ~10M users affected. Lateral movement to AWS via stored credentials.\n\n## Recommended Remediation\nUse parameterized queries. Apply least privilege to DB user." * 2,
        "reproduction_steps": ["Step 1", "Step 2", "Step 3", "Step 4"],
        "poc_code": "import requests\n# PoC for SQLi\n" + "x" * 100,
        "impact": "Account takeover via SQL injection. PII of millions of users exposed. Compliance violation: GDPR and PCI."
    }
    v2 = gate.check(good_finding, good_validation, good_draft)
    print(gate.explain(v2))
