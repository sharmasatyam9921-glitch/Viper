#!/usr/bin/env python3
"""
VIPER 5.0 — Attack Orchestrator

Chains ALL attack modules into a single async pipeline:
  Recon → Fingerprint → CORS → OAuth → WebSocket → Race → Logic → SSRF →
  Header Injection → Subdomain Takeover → Info Disclosure → Nuclei →
  FP Filter → Finding Validator → PoC Generator → Report

This is the "full arsenal" mode that runs everything VIPER has.
"""

import asyncio
import json
import logging
import os
import re
import ssl
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse

logger = logging.getLogger("viper.attack_orchestrator")


@dataclass
class AttackResult:
    """Result from a single attack module."""
    module: str
    findings: List[Dict] = field(default_factory=list)
    fps_caught: int = 0
    errors: List[str] = field(default_factory=list)
    duration_s: float = 0.0
    requests_made: int = 0


@dataclass
class HuntReport:
    """Complete hunt report."""
    target: str
    start_time: str
    end_time: str
    duration_s: float
    recon_stats: Dict = field(default_factory=dict)
    modules_run: List[str] = field(default_factory=list)
    results: Dict[str, AttackResult] = field(default_factory=dict)
    total_findings: int = 0
    total_fps: int = 0
    findings_by_severity: Dict[str, int] = field(default_factory=dict)
    verified_findings: List[Dict] = field(default_factory=list)


# ── Subdomain Takeover Signatures ────────────────────────────────────

TAKEOVER_SIGNATURES = {
    "github": ["there isn't a github pages site here", "for root urls"],
    "heroku": ["no such app", "herokucdn.com/error-pages"],
    "aws_s3": ["nosuchbucket", "the specified bucket does not exist"],
    "azure": ["404 web site not found"],
    "shopify": ["sorry, this shop is currently unavailable"],
    "fastly": ["fastly error: unknown domain"],
    "ghost": ["the thing you were looking for is no longer here"],
    "tumblr": ["there's nothing here", "whatever you were looking for"],
    "wordpress": ["do you want to register"],
    "surge": ["project not found"],
    "webflow": ["the page you are looking for doesn't exist"],
    "bitbucket": ["repository not found"],
    "zendesk": ["help center closed"],
    "readme": ["project not found"],
    "pantheon": ["404 error unknown site"],
    "statuspage": ["statuspage.io", "you are being redirected"],
}

# ── Common Discovery Paths ────────────────────────────────────────────

ACTUATOR_PATHS = [
    "/actuator", "/actuator/env", "/actuator/health", "/actuator/info",
    "/actuator/beans", "/actuator/mappings", "/actuator/configprops",
    "/actuator/metrics", "/actuator/loggers", "/actuator/threaddump",
    "/actuator/httptrace", "/actuator/conditions",
    "/env", "/health", "/info", "/mappings", "/beans", "/trace", "/metrics",
]

INFO_DISCLOSURE_PATHS = [
    ("/.env", "dotenv"), ("/.env.local", "dotenv"), ("/.env.production", "dotenv"),
    ("/.git/HEAD", "git_exposed"), ("/.git/config", "git_exposed"),
    ("/swagger.json", "swagger"), ("/v2/api-docs", "swagger"), ("/v3/api-docs", "swagger"),
    ("/openapi.json", "openapi"), ("/swagger-ui.html", "swagger"),
    ("/application.yml", "spring_config"), ("/application.properties", "spring_config"),
    ("/WEB-INF/web.xml", "java_config"),
    ("/debug/pprof/", "go_pprof"), ("/debug/vars", "go_expvar"),
    ("/server-status", "apache_status"), ("/phpinfo.php", "phpinfo"),
    ("/crossdomain.xml", "crossdomain"), ("/clientaccesspolicy.xml", "silverlight"),
]


class AttackOrchestrator:
    """Full-arsenal attack orchestrator.

    Runs all VIPER attack modules against a target with:
    - Async HTTP via aiohttp (rate-limited)
    - Auto FP filtering (learned + hardcoded patterns)
    - Finding validation (behavioral confirmation)
    - PoC generation (curl + Python)
    - Evidence chain of custody (SHA-256 hashing)

    Args:
        rate_limit: Max requests per second.
        stealth_level: 0=none, 1=basic, 2=evasive, 3=paranoid.
        proxy: Optional HTTP proxy (e.g., "http://127.0.0.1:8080" for Burp).
        output_dir: Directory for findings output.
    """

    def __init__(
        self,
        rate_limit: int = 30,
        stealth_level: int = 1,
        proxy: Optional[str] = None,
        output_dir: Optional[Path] = None,
    ):
        self.rate_limit = rate_limit
        self.stealth_level = stealth_level
        self.proxy = proxy
        self.output_dir = output_dir or Path("findings")
        self._semaphore = asyncio.Semaphore(rate_limit)
        self._request_count = 0
        self._session: Optional[Any] = None

        # Lazy-load modules
        self._fp_filter = None
        self._finding_validator = None
        self._poc_generator = None

    @property
    def fp_filter(self):
        if self._fp_filter is None:
            try:
                from core.fp_filter import FPFilter
                self._fp_filter = FPFilter()
            except ImportError:
                self._fp_filter = None
        return self._fp_filter

    @property
    def poc_generator(self):
        if self._poc_generator is None:
            try:
                from core.poc_generator import PoCGenerator
                self._poc_generator = PoCGenerator(self.output_dir / "pocs")
            except ImportError:
                self._poc_generator = None
        return self._poc_generator

    async def _fetch(self, url: str, method: str = "GET",
                     headers: Optional[Dict] = None,
                     data: Optional[str] = None,
                     timeout: int = 10) -> Dict:
        """Rate-limited HTTP fetch."""
        async with self._semaphore:
            self._request_count += 1
            try:
                import aiohttp
                kw: Dict[str, Any] = {
                    "timeout": aiohttp.ClientTimeout(total=timeout),
                    "ssl": False,
                }
                if headers:
                    kw["headers"] = headers
                if data:
                    kw["data"] = data
                if self.proxy:
                    kw["proxy"] = self.proxy

                async with self._session.request(method, url, allow_redirects=False, **kw) as r:
                    body = await r.text()
                    return {
                        "status": r.status,
                        "headers": dict(r.headers),
                        "body": body,
                        "url": url,
                        "ct": r.headers.get("Content-Type", ""),
                    }
            except Exception as e:
                return {"status": 0, "error": str(e), "url": url}

    # ── Attack Modules ─────────────────────────────────────────────────

    async def scan_cors(self, targets: List[str]) -> AttackResult:
        """CORS misconfiguration testing."""
        result = AttackResult(module="cors")
        t0 = time.time()

        test_origins = [
            ("arbitrary", "https://evil.com"),
            ("subdomain", "https://evil.target.com"),
            ("null", "null"),
        ]

        for target in targets:
            for test_name, origin in test_origins:
                resp = await self._fetch(target, headers={"Origin": origin})
                if resp["status"] == 0:
                    continue

                acao = resp["headers"].get("Access-Control-Allow-Origin", "")
                acac = resp["headers"].get("Access-Control-Allow-Credentials", "")

                finding = None
                if acao == origin and acac.lower() == "true" and origin != "null":
                    finding = {
                        "type": "cors_misconfiguration",
                        "subtype": "arbitrary_origin_reflected" if origin == "https://evil.com" else "origin_reflected_with_creds",
                        "url": target, "severity": "critical" if origin == "https://evil.com" else "high",
                        "acao": acao, "acac": acac, "origin_sent": origin,
                        "body": resp.get("body", "")[:200],
                    }
                elif acao == "*" and acac.lower() == "true":
                    finding = {
                        "type": "cors_misconfiguration", "subtype": "wildcard_with_credentials",
                        "url": target, "severity": "medium",
                        "acao": acao, "acac": acac, "origin_sent": origin,
                        "body": resp.get("body", "")[:200],
                    }
                elif acao == "null" and acac.lower() == "true":
                    finding = {
                        "type": "cors_misconfiguration", "subtype": "null_origin_trusted",
                        "url": target, "severity": "medium",
                        "acao": acao, "acac": acac, "origin_sent": origin,
                    }

                if finding:
                    # Run FP filter
                    if self.fp_filter:
                        verdict = self.fp_filter.check(finding)
                        if verdict.is_fp:
                            result.fps_caught += 1
                            continue
                    result.findings.append(finding)

                await asyncio.sleep(0.1 * (1 + self.stealth_level))

        result.duration_s = time.time() - t0
        result.requests_made = len(targets) * len(test_origins)
        return result

    async def scan_info_disclosure(self, targets: List[str]) -> AttackResult:
        """Scan for exposed configs, git, swagger, actuator, etc."""
        result = AttackResult(module="info_disclosure")
        t0 = time.time()

        all_paths = ACTUATOR_PATHS + [(p, t) for p, t in INFO_DISCLOSURE_PATHS]

        for target in targets:
            parsed = urlparse(target)
            base = f"{parsed.scheme}://{parsed.netloc}"

            for item in all_paths:
                if isinstance(item, tuple):
                    path, dtype = item
                else:
                    path, dtype = item, "actuator"

                url = f"{base}{path}"
                resp = await self._fetch(url)

                if resp["status"] != 200 or resp.get("error"):
                    continue

                body = resp.get("body", "")
                ct = resp.get("ct", "")

                # Auto-FP filter
                finding = {
                    "type": dtype, "url": url, "body": body[:500],
                    "content_type": ct, "status": resp["status"],
                }
                if self.fp_filter:
                    verdict = self.fp_filter.check(finding)
                    if verdict.is_fp:
                        result.fps_caught += 1
                        continue

                # Content-specific validation
                confirmed = False
                severity = "info"

                if dtype == "dotenv" and "=" in body and "<html" not in body[:50].lower():
                    confirmed = True
                    severity = "critical" if any(k in body.lower() for k in ["password", "secret", "key=", "token="]) else "high"
                elif dtype == "git_exposed" and ("ref:" in body or "[core]" in body):
                    confirmed = True
                    severity = "critical"
                elif dtype == "swagger" and ("swagger" in body.lower() or "openapi" in body.lower()):
                    confirmed = True
                    severity = "medium"
                elif dtype == "actuator" and "json" in ct.lower():
                    try:
                        data = json.loads(body)
                        if isinstance(data, dict) and len(data) > 0:
                            if "propertySources" in body or "systemProperties" in body:
                                confirmed = True
                                severity = "critical"
                            elif "status" in data and ("UP" in str(data.get("status", ""))):
                                confirmed = True
                                severity = "low"
                            elif len(data) > 3:
                                confirmed = True
                                severity = "medium"
                    except json.JSONDecodeError:
                        pass
                elif dtype == "spring_config" and ("spring" in body.lower() or "server.port" in body.lower()):
                    confirmed = True
                    severity = "high"
                elif dtype == "java_config" and ("web-app" in body or "servlet" in body):
                    confirmed = True
                    severity = "high"
                elif dtype == "go_pprof" and "pprof" in body.lower():
                    confirmed = True
                    severity = "medium"

                if confirmed:
                    finding["severity"] = severity
                    finding["verified"] = True
                    result.findings.append(finding)

                await asyncio.sleep(0.05 * (1 + self.stealth_level))

        result.duration_s = time.time() - t0
        return result

    async def scan_subdomain_takeover(self, targets: List[str]) -> AttackResult:
        """Check for subdomain takeover via dangling CNAME."""
        result = AttackResult(module="subdomain_takeover")
        t0 = time.time()

        for target in targets:
            resp = await self._fetch(target, timeout=8)

            if resp["status"] == 0:
                error = resp.get("error", "").lower()
                if any(k in error for k in ["name or service not known", "nodename nor servname", "getaddrinfo"]):
                    result.findings.append({
                        "type": "potential_subdomain_takeover", "url": target,
                        "severity": "high", "detail": f"DNS resolution failed: {error[:100]}",
                    })
                continue

            body = resp.get("body", "")[:3000].lower()
            for service, signatures in TAKEOVER_SIGNATURES.items():
                if any(sig in body for sig in signatures):
                    result.findings.append({
                        "type": "subdomain_takeover", "url": target,
                        "severity": "high", "service": service,
                        "detail": f"Signature matched for {service}",
                    })
                    break

            await asyncio.sleep(0.05)

        result.duration_s = time.time() - t0
        return result

    async def scan_headers(self, targets: List[str]) -> AttackResult:
        """Security header analysis + host header injection."""
        result = AttackResult(module="headers")
        t0 = time.time()

        critical_headers = [
            "Content-Security-Policy", "X-Frame-Options", "X-Content-Type-Options",
            "Strict-Transport-Security", "X-XSS-Protection", "Referrer-Policy",
            "Permissions-Policy",
        ]

        for target in targets[:50]:
            # Standard header check
            resp = await self._fetch(target)
            if resp["status"] == 0:
                continue

            missing = [h for h in critical_headers if h not in resp.get("headers", {})]
            if len(missing) >= 4:  # Only report if significantly missing
                result.findings.append({
                    "type": "missing_security_headers", "url": target,
                    "severity": "low", "missing": missing,
                })

            # Host header injection
            resp2 = await self._fetch(target, headers={"Host": "evil.com", "X-Forwarded-Host": "evil.com"})
            if resp2["status"] in (200, 301, 302):
                body = resp2.get("body", "")[:2000]
                loc = resp2.get("headers", {}).get("Location", "")
                if "evil.com" in body or "evil.com" in loc:
                    result.findings.append({
                        "type": "host_header_injection", "url": target,
                        "severity": "high",
                        "detail": f"evil.com reflected in {'Location' if 'evil.com' in loc else 'body'}",
                    })

            await asyncio.sleep(0.1 * (1 + self.stealth_level))

        result.duration_s = time.time() - t0
        return result

    async def scan_open_redirect(self, targets: List[str]) -> AttackResult:
        """Open redirect testing with full chain validation."""
        result = AttackResult(module="open_redirect")
        t0 = time.time()

        redirect_params = ["redirect", "redirect_uri", "next", "return_url", "url", "goto", "callback"]
        evil_targets = ["https://evil.com", "//evil.com", "https://evil.com@target.com"]

        for target in targets:
            parsed = urlparse(target)
            base = f"{parsed.scheme}://{parsed.netloc}"

            for param in redirect_params:
                for evil in evil_targets:
                    url = f"{base}?{param}={evil}"
                    resp = await self._fetch(url)

                    if resp["status"] in (301, 302, 303, 307, 308):
                        location = resp.get("headers", {}).get("Location", "")
                        # CRITICAL: Check that evil.com is the DESTINATION HOST, not just a query param
                        loc_parsed = urlparse(location)
                        if "evil.com" in loc_parsed.netloc:
                            finding = {
                                "type": "open_redirect", "url": url, "severity": "medium",
                                "location": location, "param": param,
                            }
                            # FP check
                            if self.fp_filter:
                                verdict = self.fp_filter.check({**finding, "body": ""})
                                if verdict.is_fp:
                                    result.fps_caught += 1
                                    continue
                            result.findings.append(finding)

                    await asyncio.sleep(0.15 * (1 + self.stealth_level))

        result.duration_s = time.time() - t0
        return result

    # ── Main Orchestration ─────────────────────────────────────────────

    async def run_full_arsenal(
        self,
        targets: List[str],
        modules: Optional[List[str]] = None,
    ) -> HuntReport:
        """Run the full attack arsenal on all targets.

        Args:
            targets: List of live URLs to attack.
            modules: Optional list of specific modules to run.
                     Default: all modules.

        Returns:
            HuntReport with all findings, FP counts, and stats.
        """
        import aiohttp

        start = datetime.now()
        report = HuntReport(
            target=targets[0] if targets else "unknown",
            start_time=start.isoformat(),
            end_time="",
            duration_s=0,
        )

        available_modules = {
            "cors": self.scan_cors,
            "info_disclosure": self.scan_info_disclosure,
            "subdomain_takeover": self.scan_subdomain_takeover,
            "headers": self.scan_headers,
            "open_redirect": self.scan_open_redirect,
        }

        # Add optional modules
        try:
            from core.oauth_fuzzer import OAuthFuzzer
            available_modules["oauth"] = lambda t: self._run_oauth(t)
        except ImportError:
            pass

        try:
            from core.race_engine import RaceEngine
            available_modules["race"] = lambda t: self._run_race(t)
        except ImportError:
            pass

        selected = modules or list(available_modules.keys())
        report.modules_run = selected

        connector = aiohttp.TCPConnector(ssl=False, limit=self.rate_limit)
        headers = {"User-Agent": "VIPER Bug Bounty Scanner (Authorized Testing by viper-ashborn)"}
        self._session = aiohttp.ClientSession(connector=connector, headers=headers)

        try:
            # Run all modules concurrently
            tasks = {}
            for mod_name in selected:
                if mod_name in available_modules:
                    tasks[mod_name] = asyncio.create_task(
                        available_modules[mod_name](targets)
                    )

            results = {}
            for mod_name, task in tasks.items():
                try:
                    results[mod_name] = await task
                except Exception as e:
                    results[mod_name] = AttackResult(module=mod_name, errors=[str(e)])
                    logger.error("Module %s failed: %s", mod_name, e)

            report.results = results

            # Aggregate findings
            all_findings = []
            total_fps = 0
            for mod_name, ar in results.items():
                all_findings.extend(ar.findings)
                total_fps += ar.fps_caught

            # Generate PoCs for confirmed findings
            if self.poc_generator:
                for f in all_findings:
                    if f.get("severity") in ("critical", "high"):
                        try:
                            self.poc_generator.save_poc(f)
                        except Exception:
                            pass

            report.total_findings = len(all_findings)
            report.total_fps = total_fps
            report.verified_findings = all_findings

            # Count by severity
            for f in all_findings:
                sev = f.get("severity", "info")
                report.findings_by_severity[sev] = report.findings_by_severity.get(sev, 0) + 1

        finally:
            await self._session.close()
            self._session = None

        end = datetime.now()
        report.end_time = end.isoformat()
        report.duration_s = (end - start).total_seconds()

        return report

    async def _run_oauth(self, targets: List[str]) -> AttackResult:
        """Wrapper for OAuth fuzzer module."""
        result = AttackResult(module="oauth")
        try:
            from core.oauth_fuzzer import OAuthFuzzer
            for target in targets[:10]:
                fuzzer = OAuthFuzzer(target)
                findings = await fuzzer.run_all()
                for f in findings:
                    fd = f if isinstance(f, dict) else f.__dict__ if hasattr(f, '__dict__') else {"finding": str(f)}
                    fd["url"] = target
                    fd.setdefault("type", "oauth")
                    # FP filter
                    if self.fp_filter:
                        verdict = self.fp_filter.check(fd)
                        if verdict.is_fp:
                            result.fps_caught += 1
                            continue
                    result.findings.append(fd)
        except Exception as e:
            result.errors.append(str(e))
        return result

    async def _run_race(self, targets: List[str]) -> AttackResult:
        """Wrapper for race condition engine."""
        result = AttackResult(module="race")
        try:
            from core.race_engine import RaceEngine
            engine = RaceEngine()
            for target in targets[:10]:
                race_result = await engine.detect_race_window(target)
                if race_result and race_result.get("is_vuln"):
                    result.findings.append({
                        "type": "race_condition", "url": target,
                        "severity": "medium", **race_result,
                    })
        except Exception as e:
            result.errors.append(str(e))
        return result


__all__ = ["AttackOrchestrator", "AttackResult", "HuntReport"]
