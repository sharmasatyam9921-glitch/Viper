#!/usr/bin/env python3
"""
VIPER 4.0 Phase 5 — Triage Engine.

Collects vulnerability data from the graph, correlates via LLM, and produces
prioritized remediation drafts with severity tiers.

Inspired by open-source pentesting frameworks.
"""

import hashlib
import json
import logging
import re
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional

from .triage_queries import TRIAGE_QUERIES, run_triage_queries

logger = logging.getLogger("viper.triage_engine")


# ── Severity weights ──────────────

SIGNAL_WEIGHTS = {
    "CHAIN_EXPLOIT_SUCCESS": 1200,
    "CONFIRMED_EXPLOIT": 1000,
    "CHAIN_ACCESS_GAINED": 900,
    "CISA_KEV": 800,
    "CHAIN_CREDENTIAL": 700,
    "SECRET_EXPOSED": 500,
    "CHAIN_REACHABILITY": 200,
    "DAST_CONFIRMED": 150,
    "INJECTABLE_PARAM": 100,
    "CVSS_SCORE": 100,       # multiplied by cvss/10
    "CERT_EXPIRED": 80,
    "CERT_WEAK": 40,
    "GVM_QOD": 30,
    "SEVERITY_WEIGHT": 50,   # critical=50, high=40, medium=20, low=10
}

SEVERITY_SCORES = {"critical": 50, "high": 40, "medium": 20, "low": 10, "info": 0}

# Max score for priority inversion (0 = highest priority)
MAX_PRIORITY_SCORE = 5000


@dataclass
class RemediationDraft:
    """A single remediation item produced by triage."""
    id: str = ""
    title: str = ""
    severity: str = "medium"            # emergency, critical, high, medium, low
    finding_type: str = ""              # sqli, xss, rce, exposure, secret, cert, etc.
    affected_assets: List[str] = field(default_factory=list)  # URLs, IPs, endpoints
    cwe_ids: List[str] = field(default_factory=list)
    cve_ids: List[str] = field(default_factory=list)
    description: str = ""
    recommendation: str = ""
    priority_score: float = 5.0         # 0-10 (10 = most urgent)
    evidence: str = ""
    # Extended fields
    category: str = ""
    remediation_type: str = ""          # code_fix, dependency_update, config_change, secret_rotation
    exploit_available: bool = False
    cisa_kev: bool = False
    capec_ids: List[str] = field(default_factory=list)
    solution: str = ""
    fix_complexity: str = "medium"      # low, medium, high, critical

    def to_dict(self) -> Dict:
        return asdict(self)


# ── Triage Engine ───────────────────────────────────────────────────────────

class TriageEngine:
    """
    Vulnerability triage engine.

    Phase 1 (sync): Run 9 triage queries, collect raw findings, sort by severity.
    Phase 2 (async): LLM-correlate, deduplicate, and produce detailed remediation drafts.
    """

    def __init__(self, graph_engine=None, model_router=None):
        """
        Args:
            graph_engine: Optional GraphEngine instance (from core.graph_engine)
            model_router: Optional ModelRouter for LLM-powered correlation
        """
        self.graph = graph_engine
        self._model_router = model_router

    async def triage_finding(self, finding):
        """Convenience method: priority-score a single finding dict."""
        severity_scores = {'critical': 10, 'high': 8, 'medium': 5, 'low': 2, 'info': 1}
        score = severity_scores.get(finding.get('severity', 'info'), 1)
        score *= finding.get('confidence', 0.5)
        return {'finding': finding, 'priority_score': score, 'action': 'investigate' if score > 5 else 'monitor'}

    async def triage(self) -> List[RemediationDraft]:
        """
        Full triage pipeline (async, uses LLM if available):

        1. Run 9 triage queries against graph
        2. Collect raw findings
        3. LLM-correlate and deduplicate
        4. Prioritize into severity tiers (Emergency, Critical, High, Medium, Low)
        5. Return RemediationDraft list
        """
        # Phase 1: Static collection
        logger.info("Phase 1: Running triage queries...")
        raw_data = run_triage_queries(self.graph)
        total_records = sum(r["count"] for r in raw_data)
        logger.info(f"Collected {total_records} records from {len(raw_data)} queries")

        if total_records == 0:
            logger.warning("No security data found in graph.")
            return []

        # Phase 2: LLM correlation (if model_router available)
        if self._model_router:
            try:
                logger.info("Phase 2: LLM correlation and deduplication...")
                return await self._llm_triage(raw_data)
            except Exception as e:
                logger.warning(f"LLM triage failed ({e}), falling back to sync triage")

        # Fallback: sync triage
        return self.triage_sync()

    def triage_sync(self) -> List[RemediationDraft]:
        """
        Synchronous triage (no LLM). Runs queries, scores, and sorts.

        Good for offline/fast mode — no deduplication or correlation,
        but still produces prioritized RemediationDraft list.
        """
        raw_data = run_triage_queries(self.graph)
        drafts = []

        # Process vulnerabilities
        for qr in raw_data:
            name = qr["name"]
            records = qr["records"]
            if not records:
                continue

            if name == "vulnerabilities":
                drafts.extend(self._process_vulns(records))
            elif name == "cve_chains":
                drafts.extend(self._process_cve_chains(records))
            elif name == "secrets":
                drafts.extend(self._process_secrets(records))
            elif name == "exploits":
                drafts.extend(self._process_exploits(records))
            elif name == "chain_findings":
                drafts.extend(self._process_chain_findings(records))
            elif name == "attack_chains":
                drafts.extend(self._process_attack_chains(records))
            elif name == "certificates":
                drafts.extend(self._process_certificates(records))
            elif name == "security_checks":
                drafts.extend(self._process_security_checks(records))
            # 'assets' query is context — no direct remediation items

        # Sort by priority_score descending (highest score = most urgent)
        drafts.sort(key=lambda d: d.priority_score, reverse=True)

        # Assign severity tiers based on score
        for d in drafts:
            d.severity = self._score_to_severity(d.priority_score)

        logger.info(f"Triage complete: {len(drafts)} remediation drafts")
        return drafts

    # ── Record processors ───────────────────────────────────────────────────

    def _process_vulns(self, records: List[Dict]) -> List[RemediationDraft]:
        drafts = []
        for r in records:
            signals = []
            sev = (r.get("severity") or "medium").lower()
            signals.append(("SEVERITY_WEIGHT", SEVERITY_SCORES.get(sev, 10)))

            cvss = r.get("cvss_score")
            if cvss:
                signals.append(("CVSS_SCORE", float(cvss) * 10))

            if r.get("cisa_kev"):
                signals.append(("CISA_KEV", SIGNAL_WEIGHTS["CISA_KEV"]))

            if r.get("source") in ("nuclei", "dast"):
                signals.append(("DAST_CONFIRMED", SIGNAL_WEIGHTS["DAST_CONFIRMED"]))

            params = r.get("parameters", [])
            if any(p.get("is_injectable") for p in params):
                signals.append(("INJECTABLE_PARAM", SIGNAL_WEIGHTS["INJECTABLE_PARAM"]))

            qod = r.get("qod")
            if qod and int(qod) >= 70:
                signals.append(("GVM_QOD", SIGNAL_WEIGHTS["GVM_QOD"]))

            score = self._compute_score(signals)
            endpoints = r.get("endpoints", [])
            assets = []
            for ep in endpoints:
                url = ep.get("url", "")
                path = ep.get("path", "")
                if url and path:
                    assets.append(f"{url}{path}")
                elif url:
                    assets.append(url)
            if r.get("target_ip"):
                assets.append(f"{r['target_ip']}:{r.get('target_port', '')}")

            cve_ids = r.get("cve_ids", [])
            if isinstance(cve_ids, str):
                cve_ids = [c.strip() for c in cve_ids.split(",") if c.strip()]

            drafts.append(RemediationDraft(
                id=self._make_id("vuln", r.get("vuln_id", r.get("name", ""))),
                title=r.get("name", "Unknown Vulnerability"),
                finding_type=r.get("category", "vulnerability"),
                affected_assets=assets[:10],
                cve_ids=cve_ids,
                description=r.get("description", "")[:500],
                recommendation=r.get("solution", ""),
                priority_score=score,
                evidence=r.get("matched_at", ""),
                category=r.get("category", ""),
                remediation_type=self._infer_remediation_type(r),
                exploit_available=False,
                cisa_kev=bool(r.get("cisa_kev")),
                solution=r.get("solution", ""),
            ))
        return drafts

    def _process_cve_chains(self, records: List[Dict]) -> List[RemediationDraft]:
        drafts = []
        for r in records:
            cves = r.get("cves", [])
            if not cves:
                continue
            signals = []
            max_cvss = 0
            cve_ids = []
            for c in cves:
                cve_ids.append(c.get("cve", ""))
                cvss = c.get("cvss")
                if cvss:
                    max_cvss = max(max_cvss, float(cvss))
            if max_cvss > 0:
                signals.append(("CVSS_SCORE", max_cvss * 10))
            exploit_count = r.get("exploit_count", 0)
            if exploit_count > 0:
                signals.append(("CONFIRMED_EXPLOIT", SIGNAL_WEIGHTS["CONFIRMED_EXPLOIT"]))

            sev = "critical" if max_cvss >= 9.0 else "high" if max_cvss >= 7.0 else "medium"
            signals.append(("SEVERITY_WEIGHT", SEVERITY_SCORES.get(sev, 20)))
            score = self._compute_score(signals)

            tech = r.get("technology", "unknown")
            version = r.get("version", "")
            drafts.append(RemediationDraft(
                id=self._make_id("cve_chain", f"{tech}:{version}"),
                title=f"Vulnerable {tech} {version} ({len(cve_ids)} CVEs)",
                finding_type="dependency",
                affected_assets=[f"{tech} {version}"],
                cwe_ids=r.get("cwes", []),
                cve_ids=cve_ids,
                capec_ids=r.get("capecs", []),
                description=f"{tech} {version} has {len(cve_ids)} known CVEs (max CVSS: {max_cvss})",
                recommendation=f"Update {tech} to the latest patched version",
                priority_score=score,
                category="dependency",
                remediation_type="dependency_update",
                exploit_available=exploit_count > 0,
            ))
        return drafts

    def _process_secrets(self, records: List[Dict]) -> List[RemediationDraft]:
        drafts = []
        for r in records:
            secrets = r.get("secrets", [])
            sensitive_files = r.get("sensitive_files", [])
            if not secrets and not sensitive_files:
                continue
            signals = [("SECRET_EXPOSED", SIGNAL_WEIGHTS["SECRET_EXPOSED"])]
            signals.append(("SEVERITY_WEIGHT", SEVERITY_SCORES["high"]))
            score = self._compute_score(signals)
            repo = r.get("full_name", r.get("repo", ""))
            items = [s.get("secret_type", "secret") for s in secrets]
            items.extend(sf.get("secret_type", "file") for sf in sensitive_files)
            drafts.append(RemediationDraft(
                id=self._make_id("secret", repo),
                title=f"Exposed secrets in {repo} ({len(secrets)} secrets, {len(sensitive_files)} sensitive files)",
                finding_type="secret",
                affected_assets=[repo],
                description=f"Found {len(secrets)} secrets and {len(sensitive_files)} sensitive files",
                recommendation="Rotate all exposed credentials immediately. Remove sensitive files from repository.",
                priority_score=score,
                evidence=", ".join(items[:5]),
                category="secret",
                remediation_type="secret_rotation",
            ))
        return drafts

    def _process_exploits(self, records: List[Dict]) -> List[RemediationDraft]:
        drafts = []
        for r in records:
            cve = r.get("cve", "")
            cvss = r.get("cvss")
            signals = [("CONFIRMED_EXPLOIT", SIGNAL_WEIGHTS["CONFIRMED_EXPLOIT"])]
            if cvss:
                signals.append(("CVSS_SCORE", float(cvss) * 10))
            sev = "critical" if (cvss and float(cvss) >= 9.0) else "high"
            signals.append(("SEVERITY_WEIGHT", SEVERITY_SCORES.get(sev, 40)))
            score = self._compute_score(signals)
            techs = r.get("affected_technologies", [])
            drafts.append(RemediationDraft(
                id=self._make_id("exploit", cve),
                title=f"Exploitable CVE: {cve}",
                finding_type="exploit",
                affected_assets=techs[:5],
                cve_ids=[cve] if cve else [],
                description=r.get("description", "")[:300],
                recommendation=f"Patch or mitigate {cve} immediately — exploit code available",
                priority_score=score,
                category="exploit",
                remediation_type="dependency_update",
                exploit_available=True,
            ))
        return drafts

    def _process_chain_findings(self, records: List[Dict]) -> List[RemediationDraft]:
        drafts = []
        for r in records:
            ftype = r.get("finding_type", "")
            signals = []
            if ftype == "exploit_success":
                signals.append(("CHAIN_EXPLOIT_SUCCESS", SIGNAL_WEIGHTS["CHAIN_EXPLOIT_SUCCESS"]))
            elif ftype in ("access_gained", "privilege_escalation"):
                signals.append(("CHAIN_ACCESS_GAINED", SIGNAL_WEIGHTS["CHAIN_ACCESS_GAINED"]))
            elif ftype == "credential_found":
                signals.append(("CHAIN_CREDENTIAL", SIGNAL_WEIGHTS["CHAIN_CREDENTIAL"]))
            else:
                signals.append(("CHAIN_REACHABILITY", SIGNAL_WEIGHTS["CHAIN_REACHABILITY"]))

            sev = (r.get("severity") or "high").lower()
            signals.append(("SEVERITY_WEIGHT", SEVERITY_SCORES.get(sev, 20)))
            score = self._compute_score(signals)

            assets = []
            if r.get("target_ip"):
                assets.append(f"{r['target_ip']}:{r.get('target_port', '')}")
            if r.get("target_value"):
                assets.append(r["target_value"])

            cve_ids = r.get("cve_ids", [])
            if isinstance(cve_ids, str):
                cve_ids = [c.strip() for c in cve_ids.split(",") if c.strip()]
            related = r.get("related_cves", [])
            all_cves = list(set(cve_ids + related))

            drafts.append(RemediationDraft(
                id=self._make_id("chain", r.get("finding_id", "")),
                title=r.get("title", f"Attack chain: {ftype}"),
                finding_type=ftype,
                affected_assets=assets,
                cve_ids=all_cves,
                description=r.get("description", "")[:300],
                recommendation=f"Address {ftype} finding — confirmed via automated attack chain",
                priority_score=score,
                evidence=r.get("evidence", "")[:200],
                category="attack_chain",
                remediation_type="code_fix",
            ))
        return drafts

    def _process_attack_chains(self, records: List[Dict]) -> List[RemediationDraft]:
        """Attack chain summaries — only generate drafts for successful chains."""
        drafts = []
        for r in records:
            if r.get("findings_count", 0) == 0:
                continue
            signals = [("CHAIN_REACHABILITY", SIGNAL_WEIGHTS["CHAIN_REACHABILITY"])]
            signals.append(("SEVERITY_WEIGHT", SEVERITY_SCORES["high"]))
            score = self._compute_score(signals)
            targets = [t.get("value", "") for t in r.get("targets", [])]
            drafts.append(RemediationDraft(
                id=self._make_id("attack_chain", r.get("chain_id", "")),
                title=r.get("title", f"Attack chain: {r.get('objective', 'N/A')}"),
                finding_type="attack_chain",
                affected_assets=targets[:5],
                description=f"Chain '{r.get('attack_path_type', '')}': {r.get('successful_steps', 0)} successful steps, {r.get('findings_count', 0)} findings",
                recommendation="Review attack chain findings and remediate root cause",
                priority_score=score,
                evidence=r.get("final_outcome", ""),
                category="attack_chain",
                remediation_type="code_fix",
            ))
        return drafts

    def _process_certificates(self, records: List[Dict]) -> List[RemediationDraft]:
        drafts = []
        for r in records:
            cert_status = r.get("cert_status", "valid")
            if cert_status == "valid" and not r.get("self_signed"):
                continue  # Skip healthy certs
            signals = []
            if cert_status == "expired":
                signals.append(("CERT_EXPIRED", SIGNAL_WEIGHTS["CERT_EXPIRED"]))
                signals.append(("SEVERITY_WEIGHT", SEVERITY_SCORES["high"]))
            elif cert_status == "expiring_soon":
                signals.append(("CERT_EXPIRED", SIGNAL_WEIGHTS["CERT_EXPIRED"] // 2))
                signals.append(("SEVERITY_WEIGHT", SEVERITY_SCORES["medium"]))
            if r.get("self_signed"):
                signals.append(("CERT_WEAK", SIGNAL_WEIGHTS["CERT_WEAK"]))
            key_bits = r.get("key_bits")
            if key_bits and int(key_bits) < 2048:
                signals.append(("CERT_WEAK", SIGNAL_WEIGHTS["CERT_WEAK"]))
            if not signals:
                continue
            score = self._compute_score(signals)
            assets = r.get("baseurl_urls", []) + r.get("ip_addresses", [])
            issues = []
            if cert_status == "expired":
                issues.append("expired")
            elif cert_status == "expiring_soon":
                issues.append("expiring soon")
            if r.get("self_signed"):
                issues.append("self-signed")
            if key_bits and int(key_bits) < 2048:
                issues.append(f"weak key ({key_bits}-bit)")
            drafts.append(RemediationDraft(
                id=self._make_id("cert", r.get("subject_cn", "")),
                title=f"Certificate issue: {r.get('subject_cn', 'unknown')} ({', '.join(issues)})",
                finding_type="certificate",
                affected_assets=assets[:5],
                description=f"TLS certificate for {r.get('subject_cn', '')} is {', '.join(issues)}",
                recommendation="Renew or replace the TLS certificate with a valid CA-signed cert",
                priority_score=score,
                evidence=f"Expires: {r.get('expires', 'N/A')}, Issuer: {r.get('issuer', 'N/A')}",
                category="certificate",
                remediation_type="infrastructure",
            ))
        return drafts

    def _process_security_checks(self, records: List[Dict]) -> List[RemediationDraft]:
        drafts = []
        for r in records:
            sev = (r.get("severity") or "medium").lower()
            signals = [("SEVERITY_WEIGHT", SEVERITY_SCORES.get(sev, 10))]
            score = self._compute_score(signals)
            assets = [r.get("affected_url", "")] if r.get("affected_url") else []
            drafts.append(RemediationDraft(
                id=self._make_id("seccheck", r.get("vuln_id", r.get("name", ""))),
                title=r.get("name", "Security Check Issue"),
                finding_type="misconfiguration",
                affected_assets=assets,
                description=r.get("description", "")[:300],
                recommendation=f"Fix {r.get('category', 'security')} misconfiguration",
                priority_score=score,
                category=r.get("category", "misconfiguration"),
                remediation_type="config_change",
            ))
        return drafts

    # ── LLM-powered triage ──────────────────────────────────────────────────

    async def _llm_triage(self, raw_data: List[Dict]) -> List[RemediationDraft]:
        """Use LLM to correlate, deduplicate, and prioritize findings."""
        # Format raw data for LLM
        data_text = self._format_raw_data(raw_data)

        prompt = f"""You are a vulnerability triage analyst. Analyze this security recon data and produce prioritized remediation entries.

## Raw Data
{data_text}

## Instructions
1. Correlate findings across data sources
2. Deduplicate (same CVE or same underlying issue = one entry)
3. Prioritize using: exploit availability > CISA KEV > attack chain evidence > CVSS > severity
4. Output as JSON array with fields: title, severity (critical/high/medium/low), finding_type, affected_assets (list), cwe_ids, cve_ids, description, recommendation, priority_score (0-10), evidence, category, remediation_type
5. Maximum 20 entries. Be specific and actionable.

Output ONLY a JSON array wrapped in ```json``` code fence."""

        try:
            response = await self._model_router.query(prompt, system="You are a security triage analyst.")
            return self._parse_llm_response(response)
        except Exception as e:
            logger.error(f"LLM triage failed: {e}")
            raise

    def _format_raw_data(self, raw_data: List[Dict]) -> str:
        """Format query results as compact text for LLM."""
        parts = []
        for qr in raw_data:
            if qr["count"] == 0:
                continue
            # Truncate records for LLM context
            records = qr["records"][:50]
            records_json = json.dumps(records, default=str, indent=1)
            if len(records_json) > 8000:
                records_json = records_json[:8000] + "\n... [truncated]"
            parts.append(f"### {qr['description']} ({qr['count']} records)\n```json\n{records_json}\n```")
        return "\n\n".join(parts)

    def _parse_llm_response(self, response: str) -> List[RemediationDraft]:
        """Parse LLM JSON output into RemediationDraft list."""
        # Extract JSON from code fence
        match = re.search(r"```json\s*\n(.*?)\n```", response, re.DOTALL)
        if not match:
            # Try raw JSON array
            match = re.search(r"\[\s*\{.*\}\s*\]", response, re.DOTALL)
            if not match:
                logger.error("Could not parse LLM response as JSON")
                return []
            json_str = match.group(0)
        else:
            json_str = match.group(1)

        try:
            items = json.loads(json_str)
        except json.JSONDecodeError as e:
            logger.error(f"JSON parse error: {e}")
            return []

        drafts = []
        for item in items:
            if not isinstance(item, dict):
                continue
            drafts.append(RemediationDraft(
                id=self._make_id("llm", item.get("title", "")),
                title=item.get("title", ""),
                severity=item.get("severity", "medium"),
                finding_type=item.get("finding_type", ""),
                affected_assets=item.get("affected_assets", []),
                cwe_ids=item.get("cwe_ids", []),
                cve_ids=item.get("cve_ids", []),
                description=item.get("description", ""),
                recommendation=item.get("recommendation", item.get("solution", "")),
                priority_score=float(item.get("priority_score", 5.0)),
                evidence=item.get("evidence", ""),
                category=item.get("category", ""),
                remediation_type=item.get("remediation_type", ""),
                exploit_available=item.get("exploit_available", False),
                cisa_kev=item.get("cisa_kev", False),
                capec_ids=item.get("capec_ids", []),
                solution=item.get("solution", item.get("recommendation", "")),
                fix_complexity=item.get("fix_complexity", "medium"),
            ))
        return drafts

    # ── Helpers ──────────────────────────────────────────────────────────────

    def _compute_score(self, signals: List[tuple]) -> float:
        """Compute priority score (0-10 scale, higher = more urgent)."""
        raw_score = sum(weight for _, weight in signals)
        # Normalize to 0-10 scale (max theoretical ~2500)
        normalized = min(raw_score / MAX_PRIORITY_SCORE * 10, 10.0)
        return round(normalized, 2)

    @staticmethod
    def _score_to_severity(score: float) -> str:
        """Convert numeric score to severity tier."""
        if score >= 8.0:
            return "emergency"
        elif score >= 6.0:
            return "critical"
        elif score >= 4.0:
            return "high"
        elif score >= 2.0:
            return "medium"
        else:
            return "low"

    @staticmethod
    def _make_id(prefix: str, key: str) -> str:
        """Generate deterministic ID for deduplication."""
        h = hashlib.md5(f"{prefix}:{key}".encode()).hexdigest()[:12]
        return f"{prefix}-{h}"

    @staticmethod
    def _infer_remediation_type(vuln: Dict) -> str:
        """Infer remediation type from vulnerability properties."""
        category = (vuln.get("category") or "").lower()
        source = (vuln.get("source") or "").lower()
        if category in ("dependency", "outdated"):
            return "dependency_update"
        if category in ("misconfiguration", "header"):
            return "config_change"
        if "secret" in category or "credential" in category:
            return "secret_rotation"
        if source == "security_check":
            return "config_change"
        return "code_fix"
