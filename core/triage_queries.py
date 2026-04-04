#!/usr/bin/env python3
"""
VIPER 4.0 Phase 5 — Triage Queries.

9 hardcoded queries for the static collection phase of vulnerability triage.
Dual-mode: Cypher for Neo4j backend, Python graph traversals for networkx.

Inspired by open-source pentesting frameworks.
"""

import logging
from typing import Any, Callable, Dict, List, Optional

logger = logging.getLogger("viper.triage_queries")


# ── networkx traversal helpers ──────────────────────────────────────────────

def _nx_nodes_by_label(graph, label: str, **filters) -> List[Dict]:
    """Get all nodes with a given label, optionally filtered by properties."""
    results = []
    G = graph.backend._graph if hasattr(graph.backend, '_graph') else None
    if G is None:
        return results
    for nid, data in G.nodes(data=True):
        if data.get("_label") != label:
            continue
        if data.get("project_id") != graph.project_id:
            continue
        if data.get("user_id") != graph.user_id:
            continue
        if all(data.get(k) == v for k, v in filters.items()):
            results.append({"_id": nid, **data})
    return results


def _nx_neighbors(graph, node_id: str, rel_type: str = None, direction: str = "out") -> List[Dict]:
    """Get neighbors of a node, optionally filtered by relationship type and direction."""
    G = graph.backend._graph if hasattr(graph.backend, '_graph') else None
    if G is None:
        return []
    results = []
    if direction in ("out", "both"):
        for _, target, edata in G.out_edges(node_id, data=True):
            if rel_type and edata.get("_type") != rel_type:
                continue
            ndata = G.nodes.get(target, {})
            results.append({"_id": target, **ndata})
    if direction in ("in", "both"):
        for source, _, edata in G.in_edges(node_id, data=True):
            if rel_type and edata.get("_type") != rel_type:
                continue
            ndata = G.nodes.get(source, {})
            results.append({"_id": source, **ndata})
    return results


# ── networkx query functions ────────────────────────────────────────────────

def _nx_vulnerabilities(graph) -> List[Dict]:
    """All vulnerabilities with endpoints, parameters, and GVM fields."""
    vulns = _nx_nodes_by_label(graph, "Vulnerability")
    results = []
    for v in vulns:
        vid = v["_id"]
        endpoints = _nx_neighbors(graph, vid, "FOUND_AT", "out")
        params = _nx_neighbors(graph, vid, "AFFECTS_PARAMETER", "out")
        # Resolve base URLs for endpoints
        ep_list = []
        for ep in endpoints:
            base_urls = _nx_neighbors(graph, ep["_id"], "BELONGS_TO", "out")
            base_url = base_urls[0].get("url", "") if base_urls else ""
            ep_list.append({"path": ep.get("path", ""), "method": ep.get("method", ""), "url": base_url})
        param_list = [
            {"name": p.get("name", ""), "type": p.get("type", ""), "is_injectable": p.get("is_injectable", False)}
            for p in params
        ]
        results.append({
            "vuln_id": v.get("id", vid),
            "name": v.get("name", ""),
            "severity": v.get("severity", ""),
            "source": v.get("source", ""),
            "category": v.get("category", ""),
            "cvss_score": v.get("cvss_score"),
            "description": v.get("description", ""),
            "matched_at": v.get("matched_at", ""),
            "template_id": v.get("template_id", ""),
            "solution": v.get("solution", ""),
            "solution_type": v.get("solution_type", ""),
            "qod": v.get("qod"),
            "qod_type": v.get("qod_type", ""),
            "cisa_kev": v.get("cisa_kev", False),
            "cve_ids": v.get("cve_ids", v.get("cves", [])),
            "remediated": v.get("remediated", False),
            "target_ip": v.get("target_ip", ""),
            "target_port": v.get("target_port", ""),
            "target_hostname": v.get("target_hostname", ""),
            "endpoints": ep_list,
            "parameters": param_list,
        })
    return results


def _nx_cve_chains(graph) -> List[Dict]:
    """Technology → CVE → CWE → CAPEC chains."""
    techs = _nx_nodes_by_label(graph, "Technology")
    results = []
    for t in techs:
        tid = t["_id"]
        cves_nodes = _nx_neighbors(graph, tid, "HAS_KNOWN_CVE", "out")
        if not cves_nodes:
            continue
        cves = []
        cwes = set()
        capecs = set()
        exploit_count = 0
        for c in cves_nodes:
            cves.append({"cve": c.get("id", c.get("cve_id", "")), "cvss": c.get("cvss_score", c.get("cvss")), "description": c.get("description", "")})
            mitre_nodes = _nx_neighbors(graph, c["_id"], "HAS_CWE", "out")
            for m in mitre_nodes:
                cwes.add(m.get("cwe_id", ""))
                capec_nodes = _nx_neighbors(graph, m["_id"], "HAS_CAPEC", "out")
                for cap in capec_nodes:
                    capecs.add(cap.get("capec_id", ""))
            exploits = _nx_neighbors(graph, c["_id"], "EXPLOITED_CVE", "in")
            exploit_count += len(exploits)
        results.append({
            "technology": t.get("name", ""),
            "version": t.get("version", ""),
            "cves": cves,
            "cwes": list(cwes),
            "capecs": list(capecs),
            "exploit_count": exploit_count,
        })
    return results


def _nx_secrets(graph) -> List[Dict]:
    """GitHub secrets and sensitive files."""
    domains = _nx_nodes_by_label(graph, "Target")
    results = []
    for d in domains:
        hunts = _nx_neighbors(graph, d["_id"], "HAS_GITHUB_HUNT", "out")
        for hunt in hunts:
            repos = _nx_neighbors(graph, hunt["_id"], "HAS_REPOSITORY", "out")
            for repo in repos:
                paths = _nx_neighbors(graph, repo["_id"], "HAS_PATH", "out")
                secrets_list = []
                sensitive_files = []
                for path in paths:
                    secs = _nx_neighbors(graph, path["_id"], "CONTAINS_SECRET", "out")
                    for s in secs:
                        secrets_list.append({"path": path.get("path", ""), "secret_type": s.get("secret_type", ""), "sample": s.get("sample", "")})
                    sfs = _nx_neighbors(graph, path["_id"], "CONTAINS_SENSITIVE_FILE", "out")
                    for sf in sfs:
                        sensitive_files.append({"path": sf.get("path", ""), "secret_type": sf.get("secret_type", "")})
                results.append({
                    "repo": repo.get("name", ""),
                    "full_name": repo.get("full_name", ""),
                    "secrets": secrets_list,
                    "sensitive_files": sensitive_files,
                })
    return results


def _nx_exploits(graph) -> List[Dict]:
    """Exploitable CVEs with confirmed exploits."""
    # Find all ExploitGvm nodes
    exploits = _nx_nodes_by_label(graph, "ExploitGvm")
    cve_map: Dict[str, Dict] = {}
    for ex in exploits:
        cve_nodes = _nx_neighbors(graph, ex["_id"], "EXPLOITED_CVE", "out")
        for c in cve_nodes:
            cve_id = c.get("id", c.get("cve_id", c["_id"]))
            if cve_id not in cve_map:
                cve_map[cve_id] = {
                    "cve": cve_id,
                    "cvss": c.get("cvss_score", c.get("cvss")),
                    "description": c.get("description", ""),
                    "affected_technologies": set(),
                    "exploits": [],
                }
            cve_map[cve_id]["exploits"].append({"exploit_id": ex.get("id", ex["_id"]), "source": ex.get("source", "")})
            # Find affected technologies
            tech_nodes = _nx_neighbors(graph, c["_id"], "HAS_KNOWN_CVE", "in")
            for t in tech_nodes:
                cve_map[cve_id]["affected_technologies"].add(t.get("name", ""))
    results = []
    for cve_id, data in cve_map.items():
        data["affected_technologies"] = list(data["affected_technologies"])
        results.append(data)
    return results


def _nx_assets(graph) -> List[Dict]:
    """Asset context: services, ports, IPs, base URLs."""
    subdomains = _nx_nodes_by_label(graph, "Subdomain")
    results = []
    for s in subdomains:
        ips = _nx_neighbors(graph, s["_id"], "RESOLVES_TO", "out")
        for ip in ips:
            ports = _nx_neighbors(graph, ip["_id"], "HAS_PORT", "out")
            services_list = []
            urls_list = []
            for port in ports:
                svcs = _nx_neighbors(graph, port["_id"], "RUNS_SERVICE", "out")
                for svc in svcs:
                    services_list.append({
                        "port": port.get("number"),
                        "protocol": port.get("protocol", "tcp"),
                        "service": svc.get("name", ""),
                        "product": svc.get("product", ""),
                        "version": svc.get("version", ""),
                    })
                    base_urls = _nx_neighbors(graph, svc["_id"], "SERVES_URL", "out")
                    for bu in base_urls:
                        urls_list.append(bu.get("url", ""))
            results.append({
                "subdomain": s.get("name", ""),
                "ip": ip.get("address", ""),
                "services": services_list,
                "urls": urls_list,
            })
    return results


def _nx_chain_findings(graph) -> List[Dict]:
    """Attack chain findings from pentesting sessions."""
    FINDING_TYPES = {"exploit_success", "credential_found", "access_gained",
                     "privilege_escalation", "vulnerability_confirmed"}
    findings = _nx_nodes_by_label(graph, "ChainFinding")
    results = []
    for cf in findings:
        if cf.get("finding_type") not in FINDING_TYPES:
            continue
        targets = _nx_neighbors(graph, cf["_id"], "FOUND_ON", "out")
        target_type = ""
        target_value = ""
        if targets:
            t = targets[0]
            target_type = t.get("_label", "")
            target_value = t.get("address", t.get("name", ""))
        cves = _nx_neighbors(graph, cf["_id"], "FINDING_RELATES_CVE", "out")
        related_cves = [c.get("id", c.get("cve_id", "")) for c in cves]
        cred_svcs = _nx_neighbors(graph, cf["_id"], "CREDENTIAL_FOR", "out")
        cred_service = cred_svcs[0].get("name", "") if cred_svcs else ""
        # Walk back: ChainStep -> AttackChain
        steps = _nx_neighbors(graph, cf["_id"], "PRODUCED", "in")
        chain_id = ""
        chain_status = ""
        attack_path = ""
        if steps:
            chains = _nx_neighbors(graph, steps[0]["_id"], "HAS_STEP", "in")
            if chains:
                chain_id = chains[0].get("chain_id", "")
                chain_status = chains[0].get("status", "")
                attack_path = chains[0].get("attack_path_type", "")
        results.append({
            "finding_id": cf.get("finding_id", cf["_id"]),
            "finding_type": cf.get("finding_type", ""),
            "severity": cf.get("severity", ""),
            "title": cf.get("title", ""),
            "description": cf.get("description", ""),
            "evidence": cf.get("evidence", ""),
            "confidence": cf.get("confidence"),
            "phase": cf.get("phase", ""),
            "target_ip": cf.get("target_ip", ""),
            "target_port": cf.get("target_port", ""),
            "cve_ids": cf.get("cve_ids", []),
            "attack_type": cf.get("attack_type", ""),
            "target_type": target_type,
            "target_value": target_value,
            "related_cves": related_cves,
            "credential_service": cred_service,
            "chain_id": chain_id,
            "chain_status": chain_status,
            "attack_path_type": attack_path,
        })
    return results


def _nx_attack_chains(graph) -> List[Dict]:
    """Attack chain session summaries."""
    chains = _nx_nodes_by_label(graph, "AttackChain")
    results = []
    for ac in chains:
        if ac.get("status") not in ("completed", "active"):
            continue
        targets = _nx_neighbors(graph, ac["_id"], "CHAIN_TARGETS", "out")
        target_list = []
        for t in targets:
            label = t.get("_label", "unknown")
            if label == "IP":
                val = t.get("address", "")
            elif label == "CVE":
                val = t.get("id", t.get("cve_id", ""))
            else:
                val = t.get("name", t.get("id", "unknown"))
            target_list.append({"type": label, "value": val})
        steps = _nx_neighbors(graph, ac["_id"], "HAS_STEP", "out")
        findings_count = 0
        failures_count = 0
        for step in steps:
            findings_count += len(_nx_neighbors(graph, step["_id"], "PRODUCED", "out"))
            failures_count += len(_nx_neighbors(graph, step["_id"], "FAILED_WITH", "out"))
        results.append({
            "chain_id": ac.get("chain_id", ac["_id"]),
            "title": ac.get("title", ""),
            "objective": ac.get("objective", ""),
            "status": ac.get("status", ""),
            "attack_path_type": ac.get("attack_path_type", ""),
            "total_steps": ac.get("total_steps", 0),
            "successful_steps": ac.get("successful_steps", 0),
            "failed_steps": ac.get("failed_steps", 0),
            "phases_reached": ac.get("phases_reached", ""),
            "final_outcome": ac.get("final_outcome", ""),
            "targets": target_list,
            "findings_count": findings_count,
            "failures_count": failures_count,
        })
    return results


def _nx_certificates(graph) -> List[Dict]:
    """TLS certificate findings."""
    from datetime import datetime, timedelta
    certs = _nx_nodes_by_label(graph, "Certificate")
    results = []
    now = datetime.utcnow()
    soon = now + timedelta(days=30)
    for cert in certs:
        base_urls = _nx_neighbors(graph, cert["_id"], "HAS_CERTIFICATE", "in")
        bu_urls = [bu.get("url", "") for bu in base_urls if bu.get("_label") == "BaseURL"]
        ip_addrs = [ip.get("address", "") for ip in base_urls if ip.get("_label") == "IP"]
        # Determine cert status
        not_after = cert.get("not_after")
        cert_status = "valid"
        if not_after:
            try:
                exp = datetime.fromisoformat(str(not_after).replace("Z", "+00:00")).replace(tzinfo=None)
                if exp < now:
                    cert_status = "expired"
                elif exp < soon:
                    cert_status = "expiring_soon"
            except (ValueError, TypeError):
                pass
        results.append({
            "subject_cn": cert.get("subject_cn", ""),
            "issuer": cert.get("issuer", ""),
            "valid_from": cert.get("not_before", ""),
            "expires": cert.get("not_after", ""),
            "san": cert.get("san", ""),
            "key_type": cert.get("key_type", ""),
            "key_bits": cert.get("key_bits"),
            "signature_algorithm": cert.get("signature_algorithm", ""),
            "self_signed": cert.get("self_signed", False),
            "source": cert.get("source", ""),
            "baseurl_urls": bu_urls,
            "ip_addresses": ip_addrs,
            "cert_status": cert_status,
        })
    return results


def _nx_security_checks(graph) -> List[Dict]:
    """Security check vulnerabilities (missing headers, misconfigs)."""
    vulns = _nx_nodes_by_label(graph, "Vulnerability")
    results = []
    for v in vulns:
        if v.get("source") != "security_check":
            continue
        base_urls = _nx_neighbors(graph, v["_id"], "HAS_VULNERABILITY", "in")
        affected_url = base_urls[0].get("url", "") if base_urls else ""
        results.append({
            "vuln_id": v.get("id", v["_id"]),
            "name": v.get("name", ""),
            "severity": v.get("severity", ""),
            "description": v.get("description", ""),
            "category": v.get("category", ""),
            "affected_url": affected_url,
        })
    return results


# ── Query definitions ───────────────────────────────────────────────────────

TRIAGE_QUERIES = [
    {
        "name": "vulnerabilities",
        "phase": "collecting_vulnerabilities",
        "description": "All vulnerabilities with endpoints, parameters, and GVM fields",
        "cypher": """
MATCH (v:Vulnerability {user_id: $userId, project_id: $projectId})
OPTIONAL MATCH (v)-[:FOUND_AT]->(e:Endpoint)
OPTIONAL MATCH (v)-[:AFFECTS_PARAMETER]->(p:Parameter)
OPTIONAL MATCH (e)-[:BELONGS_TO]->(b:BaseURL)
RETURN v.id AS vuln_id, v.name AS name, v.severity AS severity,
       v.source AS source, v.category AS category,
       v.cvss_score AS cvss_score, v.description AS description,
       v.matched_at AS matched_at, v.template_id AS template_id,
       v.solution AS solution, v.solution_type AS solution_type,
       v.qod AS qod, v.qod_type AS qod_type,
       v.cisa_kev AS cisa_kev, v.cve_ids AS cve_ids,
       v.remediated AS remediated,
       v.target_ip AS target_ip, v.target_port AS target_port,
       v.target_hostname AS target_hostname,
       collect(DISTINCT {path: e.path, method: e.method, url: b.url}) AS endpoints,
       collect(DISTINCT {name: p.name, type: p.type, is_injectable: p.is_injectable}) AS parameters
""",
        "networkx_fn": _nx_vulnerabilities,
    },
    {
        "name": "cve_chains",
        "phase": "collecting_cve_chains",
        "description": "Technology to CVE to CWE to CAPEC chains",
        "cypher": """
MATCH (t:Technology {user_id: $userId, project_id: $projectId})
      -[:HAS_KNOWN_CVE]->(c:CVE)
OPTIONAL MATCH (c)-[:HAS_CWE]->(m:MitreData)
OPTIONAL MATCH (m)-[:HAS_CAPEC]->(cap:Capec)
OPTIONAL MATCH (ex:ExploitGvm)-[:EXPLOITED_CVE]->(c)
RETURN t.name AS technology, t.version AS version,
       collect(DISTINCT {cve: c.id, cvss: c.cvss_score, description: c.description}) AS cves,
       collect(DISTINCT m.cwe_id) AS cwes,
       collect(DISTINCT cap.capec_id) AS capecs,
       count(DISTINCT ex) AS exploit_count
""",
        "networkx_fn": _nx_cve_chains,
    },
    {
        "name": "secrets",
        "phase": "collecting_secrets",
        "description": "GitHub secrets and sensitive files",
        "cypher": """
MATCH (d:Domain {user_id: $userId, project_id: $projectId})
      -[:HAS_GITHUB_HUNT]->(hunt:GithubHunt)
      -[:HAS_REPOSITORY]->(repo:GithubRepository)
OPTIONAL MATCH (repo)-[:HAS_PATH]->(path:GithubPath)
      -[:CONTAINS_SECRET]->(secret:GithubSecret)
OPTIONAL MATCH (path)-[:CONTAINS_SENSITIVE_FILE]->(sf:GithubSensitiveFile)
RETURN repo.name AS repo, repo.full_name AS full_name,
       collect(DISTINCT {path: path.path, secret_type: secret.secret_type, sample: secret.sample}) AS secrets,
       collect(DISTINCT {path: sf.path, secret_type: sf.secret_type}) AS sensitive_files
""",
        "networkx_fn": _nx_secrets,
    },
    {
        "name": "exploits",
        "phase": "collecting_exploits",
        "description": "Exploitable CVEs with confirmed exploits",
        "cypher": """
MATCH (ex:ExploitGvm {user_id: $userId, project_id: $projectId})
      -[:EXPLOITED_CVE]->(c:CVE)
OPTIONAL MATCH (t:Technology)-[:HAS_KNOWN_CVE]->(c)
RETURN c.id AS cve, c.cvss_score AS cvss, c.description AS description,
       collect(DISTINCT t.name) AS affected_technologies,
       collect(DISTINCT {exploit_id: ex.id, source: ex.source}) AS exploits
""",
        "networkx_fn": _nx_exploits,
    },
    {
        "name": "assets",
        "phase": "collecting_assets",
        "description": "Asset context: services, ports, IPs, base URLs",
        "cypher": """
MATCH (d:Domain {user_id: $userId, project_id: $projectId})
      -[:HAS_SUBDOMAIN]->(s:Subdomain)
      -[:RESOLVES_TO]->(ip:IP)
      -[:HAS_PORT]->(port:Port)
OPTIONAL MATCH (port)-[:RUNS_SERVICE]->(svc:Service)
OPTIONAL MATCH (svc)-[:SERVES_URL]->(b:BaseURL)
RETURN s.name AS subdomain, ip.address AS ip,
       collect(DISTINCT {port: port.number, protocol: port.protocol,
                         service: svc.name, product: svc.product, version: svc.version}) AS services,
       collect(DISTINCT b.url) AS urls
""",
        "networkx_fn": _nx_assets,
    },
    {
        "name": "chain_findings",
        "phase": "collecting_chain_findings",
        "description": "Attack chain findings from pentesting sessions",
        "cypher": """
MATCH (cf:ChainFinding {user_id: $userId, project_id: $projectId})
WHERE cf.finding_type IN ['exploit_success', 'credential_found', 'access_gained',
                          'privilege_escalation', 'vulnerability_confirmed']
OPTIONAL MATCH (cf)-[:FOUND_ON]->(target)
  WHERE target:IP OR target:Subdomain
OPTIONAL MATCH (cf)-[:FINDING_RELATES_CVE]->(cve:CVE)
OPTIONAL MATCH (cf)-[:CREDENTIAL_FOR]->(svc:Service)
OPTIONAL MATCH (step:ChainStep)-[:PRODUCED]->(cf)
OPTIONAL MATCH (ac:AttackChain)-[:HAS_STEP]->(step)
RETURN cf.finding_id AS finding_id, cf.finding_type AS finding_type,
       cf.severity AS severity, cf.title AS title,
       cf.description AS description, cf.evidence AS evidence,
       cf.confidence AS confidence, cf.phase AS phase,
       cf.target_ip AS target_ip, cf.target_port AS target_port,
       cf.cve_ids AS cve_ids, cf.attack_type AS attack_type,
       labels(target)[0] AS target_type,
       CASE WHEN target:IP THEN target.address ELSE target.name END AS target_value,
       collect(DISTINCT cve.id) AS related_cves,
       svc.name AS credential_service,
       ac.chain_id AS chain_id, ac.status AS chain_status,
       ac.attack_path_type AS attack_path_type
""",
        "networkx_fn": _nx_chain_findings,
    },
    {
        "name": "attack_chains",
        "phase": "collecting_attack_chains",
        "description": "Attack chain session summaries",
        "cypher": """
MATCH (ac:AttackChain {user_id: $userId, project_id: $projectId})
WHERE ac.status IN ['completed', 'active']
OPTIONAL MATCH (ac)-[:CHAIN_TARGETS]->(target)
OPTIONAL MATCH (ac)-[:HAS_STEP]->(step:ChainStep)-[:PRODUCED]->(cf:ChainFinding)
OPTIONAL MATCH (ac)-[:HAS_STEP]->(fstep:ChainStep)-[:FAILED_WITH]->(fail:ChainFailure)
RETURN ac.chain_id AS chain_id, ac.title AS title,
       ac.objective AS objective, ac.status AS status,
       ac.attack_path_type AS attack_path_type,
       ac.total_steps AS total_steps,
       ac.successful_steps AS successful_steps,
       ac.failed_steps AS failed_steps,
       ac.phases_reached AS phases_reached,
       ac.final_outcome AS final_outcome,
       collect(DISTINCT {type: labels(target)[0],
                         value: CASE WHEN target:IP THEN target.address
                                     WHEN target:Subdomain THEN target.name
                                     WHEN target:CVE THEN target.id
                                     ELSE coalesce(target.name, target.id, 'unknown') END}) AS targets,
       count(DISTINCT cf) AS findings_count,
       count(DISTINCT fail) AS failures_count
""",
        "networkx_fn": _nx_attack_chains,
    },
    {
        "name": "certificates",
        "phase": "collecting_certificates",
        "description": "TLS certificate findings",
        "cypher": """
MATCH (cert:Certificate {user_id: $userId, project_id: $projectId})
OPTIONAL MATCH (bu:BaseURL)-[:HAS_CERTIFICATE]->(cert)
OPTIONAL MATCH (ip:IP)-[:HAS_CERTIFICATE]->(cert)
RETURN cert.subject_cn AS subject_cn,
       cert.issuer AS issuer,
       cert.not_before AS valid_from,
       cert.not_after AS expires,
       cert.san AS san,
       cert.key_type AS key_type,
       cert.key_bits AS key_bits,
       cert.signature_algorithm AS signature_algorithm,
       cert.self_signed AS self_signed,
       cert.source AS source,
       collect(DISTINCT bu.url) AS baseurl_urls,
       collect(DISTINCT ip.address) AS ip_addresses,
       CASE WHEN cert.not_after < datetime() THEN 'expired'
            WHEN cert.not_after < datetime() + duration('P30D') THEN 'expiring_soon'
            ELSE 'valid' END AS cert_status
""",
        "networkx_fn": _nx_certificates,
    },
    {
        "name": "security_checks",
        "phase": "collecting_security_checks",
        "description": "Security check vulnerabilities (missing headers, misconfigs)",
        "cypher": """
MATCH (v:Vulnerability {user_id: $userId, project_id: $projectId, source: 'security_check'})
OPTIONAL MATCH (bu:BaseURL)-[:HAS_VULNERABILITY]->(v)
RETURN v.id AS vuln_id, v.name AS name, v.severity AS severity,
       v.description AS description, v.category AS category,
       bu.url AS affected_url
""",
        "networkx_fn": _nx_security_checks,
    },
]


# ── Public API ──────────────────────────────────────────────────────────────

def run_triage_queries(graph_engine) -> List[Dict]:
    """
    Run all 9 triage queries against the graph and return results.

    Auto-detects backend: Neo4j uses Cypher, networkx uses Python traversals.

    Args:
        graph_engine: GraphEngine instance (from core.graph_engine)

    Returns:
        List of dicts: [{name, description, records: [...], count: int}, ...]
    """
    is_neo4j = _is_neo4j_backend(graph_engine)
    results = []

    for query_def in TRIAGE_QUERIES:
        name = query_def["name"]
        try:
            if is_neo4j:
                records = _run_cypher(graph_engine, query_def["cypher"])
            else:
                records = query_def["networkx_fn"](graph_engine)

            results.append({
                "name": name,
                "description": query_def["description"],
                "records": records,
                "count": len(records),
            })
            logger.info(f"Triage query '{name}': {len(records)} records")
        except Exception as e:
            logger.error(f"Triage query '{name}' failed: {e}")
            results.append({
                "name": name,
                "description": query_def["description"],
                "records": [],
                "count": 0,
                "error": str(e),
            })

    return results


def run_triage_query(graph_engine, query_name: str) -> Dict:
    """
    Run a specific triage query by name.

    Args:
        graph_engine: GraphEngine instance
        query_name: One of the 9 query names (e.g., 'vulnerabilities', 'cve_chains')

    Returns:
        Dict: {name, description, records: [...], count: int}

    Raises:
        ValueError: If query_name is not found.
    """
    query_def = None
    for q in TRIAGE_QUERIES:
        if q["name"] == query_name:
            query_def = q
            break
    if not query_def:
        valid = [q["name"] for q in TRIAGE_QUERIES]
        raise ValueError(f"Unknown triage query '{query_name}'. Valid: {valid}")

    is_neo4j = _is_neo4j_backend(graph_engine)
    try:
        if is_neo4j:
            records = _run_cypher(graph_engine, query_def["cypher"])
        else:
            records = query_def["networkx_fn"](graph_engine)
        return {
            "name": query_name,
            "description": query_def["description"],
            "records": records,
            "count": len(records),
        }
    except Exception as e:
        logger.error(f"Triage query '{query_name}' failed: {e}")
        return {
            "name": query_name,
            "description": query_def["description"],
            "records": [],
            "count": 0,
            "error": str(e),
        }


# ── Internal helpers ────────────────────────────────────────────────────────

def _is_neo4j_backend(graph_engine) -> bool:
    """Check if graph engine is using Neo4j backend."""
    backend = graph_engine.backend
    return type(backend).__name__ == "Neo4jBackend"


class TriageQueries:
    """Compatibility wrapper for programmatic access to triage queries."""

    def __init__(self, graph_engine=None):
        self.graph = graph_engine

    def get_high_priority(self):
        return []

    def get_by_severity(self, severity):
        return []


def compute_risk_score(triage_results: Dict[str, Any]) -> tuple:
    """
    Compute a weighted risk score from triage query results using 14 signals.

    Args:
        triage_results: Dict keyed by query name from run_all_triage / run_triage_queries,
                        e.g. {"vulnerabilities": {records: [...]}, "exploits": {...}, ...}

    Returns:
        (score: int, breakdown: dict) where breakdown maps signal names to their
        contribution points.
    """
    score = 0
    breakdown: Dict[str, int] = {}

    # Helper to get records list from triage results
    def _records(name: str) -> List[Dict]:
        entry = triage_results.get(name, {})
        if isinstance(entry, dict):
            return entry.get("records", [])
        if isinstance(entry, list):
            return entry
        return []

    # 1. CHAIN_EXPLOIT_SUCCESS (1200) — findings with exploit_success type
    chain_findings = _records("chain_findings")
    exploit_successes = [f for f in chain_findings if f.get("finding_type") == "exploit_success"]
    if exploit_successes:
        pts = 1200
        score += pts
        breakdown["CHAIN_EXPLOIT_SUCCESS"] = pts

    # 2. CONFIRMED_EXPLOIT (1000) — public exploit available for CVE
    exploits = _records("exploits")
    if exploits:
        pts = 1000
        score += pts
        breakdown["CONFIRMED_EXPLOIT"] = pts

    # 3. CHAIN_ACCESS_GAINED (900) — access_gained or privilege_escalation
    access_findings = [
        f for f in chain_findings
        if f.get("finding_type") in ("access_gained", "privilege_escalation")
    ]
    if access_findings:
        pts = 900
        score += pts
        breakdown["CHAIN_ACCESS_GAINED"] = pts

    # 4. CISA_KEV (800) — in CISA Known Exploited Vulnerabilities
    vulns = _records("vulnerabilities")
    kev_vulns = [v for v in vulns if v.get("cisa_kev")]
    if kev_vulns:
        pts = 800
        score += pts
        breakdown["CISA_KEV"] = pts

    # 5. CHAIN_CREDENTIAL (700) — credential_found in findings
    cred_findings = [f for f in chain_findings if f.get("finding_type") == "credential_found"]
    if cred_findings:
        pts = 700
        score += pts
        breakdown["CHAIN_CREDENTIAL"] = pts

    # 6. SECRET_EXPOSED (500) — GitHub secrets or sensitive files
    secrets = _records("secrets")
    has_secrets = any(
        r.get("secrets") or r.get("sensitive_files")
        for r in secrets
    )
    if has_secrets:
        pts = 500
        score += pts
        breakdown["SECRET_EXPOSED"] = pts

    # 7. CHAIN_REACHABILITY (200) — internet-facing (< 3 hops to vuln)
    assets = _records("assets")
    if assets:
        # Assets with services/urls imply internet-facing reachability
        reachable = any(a.get("services") or a.get("urls") for a in assets)
        if reachable:
            pts = 200
            score += pts
            breakdown["CHAIN_REACHABILITY"] = pts

    # 8. DAST_CONFIRMED (150) — Nuclei DAST finding
    nuclei_vulns = [v for v in vulns if v.get("source") == "nuclei"]
    if nuclei_vulns:
        pts = 150
        score += pts
        breakdown["DAST_CONFIRMED"] = pts

    # 9. INJECTABLE_PARAM (100) — parameter with is_injectable=true
    injectable = any(
        p.get("is_injectable")
        for v in vulns
        for p in v.get("parameters", [])
    )
    if injectable:
        pts = 100
        score += pts
        breakdown["INJECTABLE_PARAM"] = pts

    # 10. CVSS_SCORE (variable) — max CVSS * 10 (0-100 points)
    max_cvss = 0.0
    for v in vulns:
        try:
            cvss = float(v.get("cvss_score") or 0)
            if cvss > max_cvss:
                max_cvss = cvss
        except (ValueError, TypeError):
            pass
    # Also check CVE chains for CVSS
    cve_chains = _records("cve_chains")
    for chain in cve_chains:
        for cve in chain.get("cves", []):
            try:
                cvss = float(cve.get("cvss") or 0)
                if cvss > max_cvss:
                    max_cvss = cvss
            except (ValueError, TypeError):
                pass
    if max_cvss > 0:
        pts = int(max_cvss * 10)
        score += pts
        breakdown["CVSS_SCORE"] = pts

    # 11. CERT_EXPIRED (80) — expired TLS certificate
    certs = _records("certificates")
    expired_certs = [c for c in certs if c.get("cert_status") == "expired"]
    if expired_certs:
        pts = 80
        score += pts
        breakdown["CERT_EXPIRED"] = pts

    # 12. CERT_WEAK (40) — self-signed or weak key
    weak_certs = [
        c for c in certs
        if c.get("self_signed") or (c.get("key_bits") and int(c.get("key_bits", 4096)) < 2048)
    ]
    if weak_certs:
        pts = 40
        score += pts
        breakdown["CERT_WEAK"] = pts

    # 13. GVM_QOD (30) — Quality of Detection >= 70
    high_qod = any(
        (v.get("qod") or 0) >= 70
        for v in vulns
        if v.get("qod") is not None
    )
    if high_qod:
        pts = 30
        score += pts
        breakdown["GVM_QOD"] = pts

    # 14. SEVERITY_WEIGHT (variable) — critical=50, high=40, medium=20, low=10
    severity_map = {"critical": 50, "high": 40, "medium": 20, "low": 10}
    max_sev_pts = 0
    for v in vulns:
        sev = (v.get("severity") or "").lower()
        pts_sev = severity_map.get(sev, 0)
        if pts_sev > max_sev_pts:
            max_sev_pts = pts_sev
    # Also check chain findings severity
    for f in chain_findings:
        sev = (f.get("severity") or "").lower()
        pts_sev = severity_map.get(sev, 0)
        if pts_sev > max_sev_pts:
            max_sev_pts = pts_sev
    if max_sev_pts > 0:
        score += max_sev_pts
        breakdown["SEVERITY_WEIGHT"] = max_sev_pts

    return (score, breakdown)


def _run_cypher(graph_engine, query: str) -> List[Dict]:
    """Execute a Cypher query against Neo4j backend."""
    backend = graph_engine.backend
    params = {"userId": graph_engine.user_id, "projectId": graph_engine.project_id}
    # Use backend's raw query method
    if hasattr(backend, "run_query"):
        return backend.run_query(query, params)
    elif hasattr(backend, "_driver"):
        with backend._driver.session() as session:
            result = session.run(query, params)
            return [dict(record) for record in result]
    else:
        raise RuntimeError("Neo4j backend has no query method")
