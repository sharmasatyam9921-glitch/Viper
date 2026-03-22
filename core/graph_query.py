#!/usr/bin/env python3
"""
VIPER 4.0 Natural Language → Graph Query Engine.

Converts natural language questions to graph queries:
- Cypher for Neo4j backend
- networkx traversals for SQLite/networkx backend

Uses VIPER's model_router for LLM calls ($0 via Claude CLI OAuth).
Inspired by open-source pentesting frameworks.
"""

import json
import logging
import re
from typing import Any, Dict, List, Optional

logger = logging.getLogger("viper.graph_query")

# Schema description for LLM prompt
GRAPH_SCHEMA = """
NODE TYPES AND PROPERTIES:
- Target(name) — Primary target domain
- Subdomain(name, status, source, actual_ip) — Discovered subdomain
- IP(address, version, is_cdn, cdn_name, organization, country, os)
- Port(number, protocol, ip_address, state)
- Service(name, port_number, ip_address, version, banner)
- Technology(name, version, categories, confidence, detected_by, cpe)
- BaseURL(url, scheme, host, status_code, content_type, title, server)
- Endpoint(path, method, baseurl, full_url, category, has_parameters)
- Parameter(name, position, endpoint_path, baseurl, is_injectable, type)
- Vulnerability(id, name, severity, source, template_id, matched_at, tags, cwe_ids, cves, cvss_score)
- CVE(id, cve_id, cvss, severity, description)
- MitreData(id, cve_id, cwe_id, cwe_name, cwe_description)
- Capec(capec_id, name, description, likelihood, severity)
- Secret(id, secret_type, severity, source_url)
- Certificate(subject_cn, issuer, not_before, not_after, tls_version)
- Finding(vuln_type, severity, confidence, url, payload, evidence, domain)
- AttackChain(chain_id, status)
- ChainStep(step_id, chain_id)
- ChainFinding(finding_id, finding_type, severity)

RELATIONSHIPS:
- (Subdomain)-[:BELONGS_TO]->(Target)
- (Subdomain)-[:RESOLVES_TO]->(IP)
- (IP)-[:HAS_PORT]->(Port)
- (Port)-[:RUNS_SERVICE]->(Service)
- (Service)-[:SERVES_URL]->(BaseURL)
- (BaseURL)-[:HAS_ENDPOINT]->(Endpoint)
- (Endpoint)-[:HAS_PARAMETER]->(Parameter)
- (*)-[:USES_TECHNOLOGY]->(Technology)
- (*)-[:HAS_VULNERABILITY]->(Vulnerability)
- (Vulnerability)-[:INCLUDES_CVE]->(CVE)
- (Technology)-[:HAS_KNOWN_CVE]->(CVE)
- (CVE)-[:HAS_CWE]->(MitreData)
- (MitreData)-[:HAS_CAPEC]->(Capec)
- (Vulnerability)-[:FOUND_AT]->(Endpoint)
- (Vulnerability)-[:AFFECTS_PARAMETER]->(Parameter)
- (AttackChain)-[:HAS_STEP]->(ChainStep)
"""

CYPHER_SYSTEM_PROMPT = f"""You are a Cypher query generator for a penetration testing knowledge graph.
Given a natural language question, generate a valid Neo4j Cypher query.

{GRAPH_SCHEMA}

RULES:
1. Always include LIMIT clause (default 50, max 500)
2. Use OPTIONAL MATCH for relationships that might not exist
3. Return useful properties, not entire nodes
4. For counts, use count() aggregation
5. Output ONLY the Cypher query, no explanation
6. All nodes have project_id and user_id properties for tenant isolation
"""


class GraphQueryEngine:
    """Convert natural language to graph queries."""

    def __init__(self, graph_engine, model_router=None):
        """
        Args:
            graph_engine: GraphEngine instance
            model_router: Optional ModelRouter for LLM-powered queries
        """
        self.graph = graph_engine
        self._model_router = model_router

    async def query(self, question: str, use_llm: bool = True) -> List[Dict]:
        """
        Query the graph with natural language.

        1. If Neo4j backend + LLM available → generate Cypher
        2. Otherwise → use keyword-based networkx query
        """
        # Try LLM-powered Cypher generation for Neo4j
        if use_llm and self._model_router and self._is_neo4j():
            try:
                return await self._cypher_query(question)
            except Exception as e:
                logger.warning(f"Cypher query failed: {e}, falling back to keyword search")

        # Fallback: keyword-based query
        return self._keyword_query(question)

    def query_sync(self, question: str) -> List[Dict]:
        """Synchronous query (keyword-based only)."""
        return self._keyword_query(question)

    def _is_neo4j(self) -> bool:
        from core.graph_engine import Neo4jBackend
        return isinstance(self.graph.backend, Neo4jBackend)

    async def _cypher_query(self, question: str, retries: int = 2) -> List[Dict]:
        """Generate and execute Cypher query via LLM."""
        cypher = await self._generate_cypher(question)
        if not cypher:
            return []

        # Inject tenant filter
        cypher = self._inject_tenant_filter(cypher)

        for attempt in range(retries + 1):
            try:
                results = self.graph.backend.query_raw(
                    cypher,
                    {"tenant_user_id": self.graph.user_id, "tenant_project_id": self.graph.project_id},
                )
                return self._format_results(results)
            except Exception as e:
                if attempt < retries:
                    logger.debug(f"Cypher retry {attempt+1}: {e}")
                    cypher = await self._generate_cypher(
                        question, previous_error=str(e), previous_cypher=cypher
                    )
                    cypher = self._inject_tenant_filter(cypher)
                else:
                    raise

    async def _generate_cypher(self, question: str, previous_error: str = None, previous_cypher: str = None) -> str:
        """Use LLM to generate Cypher from natural language."""
        prompt = f"Question: {question}"
        if previous_error:
            prompt += f"\n\nPrevious attempt failed with error: {previous_error}"
            prompt += f"\nPrevious Cypher: {previous_cypher}"
            prompt += "\nPlease fix the query."

        response = await self._model_router.ask(
            system=CYPHER_SYSTEM_PROMPT,
            prompt=prompt,
            max_tokens=500,
            temperature=0.0,
        )

        # Extract Cypher from response
        cypher = response.strip()
        # Remove markdown code blocks if present
        if "```" in cypher:
            match = re.search(r"```(?:cypher)?\s*\n?(.*?)```", cypher, re.DOTALL)
            if match:
                cypher = match.group(1).strip()

        return cypher

    def _inject_tenant_filter(self, cypher: str) -> str:
        """Add tenant isolation to Cypher queries.

        Inserts user_id/project_id predicates after the first MATCH clause.
        Handles existing WHERE (appends with AND) and missing WHERE (adds new).
        """
        if "user_id" not in cypher.lower() and "project_id" not in cypher.lower():
            match = re.search(r"((?:OPTIONAL\s+)?MATCH\s*\([^)]+\))", cypher, re.IGNORECASE)
            if match:
                var_match = re.search(r"\((\w+)", match.group(1))
                if var_match:
                    var_name = var_match.group(1)
                    tenant_cond = (
                        f"{var_name}.user_id = $tenant_user_id "
                        f"AND {var_name}.project_id = $tenant_project_id"
                    )
                    insert_pos = match.end()
                    rest = cypher[insert_pos:]
                    # Check for existing WHERE (with flexible whitespace)
                    where_match = re.match(r"\s+WHERE\s+", rest, re.IGNORECASE)
                    if where_match:
                        # Existing WHERE — prepend tenant condition with AND
                        after_where = rest[where_match.end():]
                        cypher = (
                            cypher[:insert_pos]
                            + f" WHERE {tenant_cond} AND "
                            + after_where
                        )
                    else:
                        # No WHERE — inject one
                        cypher = cypher[:insert_pos] + f" WHERE {tenant_cond}" + rest

        return cypher

    def _keyword_query(self, question: str) -> List[Dict]:
        """Keyword-based query for networkx backend."""
        return self.graph.backend.query_raw(question)

    @staticmethod
    def _format_results(results: List[Dict]) -> List[Dict]:
        """Format Neo4j results for display."""
        formatted = []
        for record in results:
            row = {}
            for key, value in record.items():
                if hasattr(value, "items"):  # Node-like
                    row[key] = dict(value)
                elif hasattr(value, "__iter__") and not isinstance(value, str):
                    row[key] = list(value)
                else:
                    row[key] = value
            formatted.append(row)
        return formatted

    # ── Pre-built queries (for triage, dashboards, etc.) ──

    def get_all_vulnerabilities(self, severity: str = None) -> List[Dict]:
        """Get all vulnerabilities, optionally filtered by severity."""
        filters = {"severity": severity} if severity else None
        return self.graph.find("Vulnerability", **filters) if filters else self.graph.find("Vulnerability")

    def get_attack_surface_summary(self) -> Dict:
        """Get attack surface overview."""
        stats = self.graph.stats()
        return {
            "total_nodes": stats.get("total_nodes", 0),
            "total_edges": stats.get("total_edges", 0),
            "node_types": stats.get("node_types", {}),
            "targets": len(self.graph.find("Target")),
            "subdomains": len(self.graph.find("Subdomain")),
            "vulnerabilities": len(self.graph.find("Vulnerability")),
            "findings": len(self.graph.find("Finding")),
            "technologies": len(self.graph.find("Technology")),
            "endpoints": len(self.graph.find("Endpoint")),
            "secrets": len(self.graph.find("Secret")),
        }

    def get_vuln_by_severity(self) -> Dict[str, int]:
        """Count vulnerabilities by severity."""
        counts = {}
        for vuln in self.graph.find("Vulnerability"):
            sev = vuln.get("severity", "info")
            counts[sev] = counts.get(sev, 0) + 1
        for finding in self.graph.find("Finding"):
            sev = finding.get("severity", "info")
            counts[sev] = counts.get(sev, 0) + 1
        return counts

    def get_tech_vulnerability_map(self) -> Dict[str, List[str]]:
        """Map technologies to their known CVEs."""
        result = {}
        for tech in self.graph.find("Technology"):
            tech_id = tech.get("id")
            if not tech_id:
                continue
            cves = self.graph.neighbors(tech_id, rel_type="HAS_KNOWN_CVE")
            if cves:
                result[tech.get("name", "")] = [c.get("cve_id", "") for c in cves]
        return result

    def get_target_summary(self, target: str) -> Dict:
        """Get a summary of findings and attack surface for a target."""
        summary = self.get_attack_surface_summary()
        vulns = self.get_all_vulnerabilities()
        target_vulns = [v for v in vulns if v.get("domain") == target or v.get("matched_at", "").find(target) >= 0]
        summary["target"] = target
        summary["target_vulnerabilities"] = len(target_vulns)
        summary["severity_breakdown"] = self.get_vuln_by_severity()
        return summary


# Consumer-facing alias
GraphQuery = GraphQueryEngine
