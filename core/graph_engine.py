#!/usr/bin/env python3
"""
VIPER 4.0 Knowledge Graph Engine — Dual-backend (Neo4j + networkx/SQLite).

30 node types, 35+ relationship types. Inspired by open-source pentesting frameworks.
Falls back to networkx+SQLite when Neo4j is unavailable.
"""

import json
import os
import queue
import sqlite3
import logging
import threading
from abc import ABC, abstractmethod
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

try:
    import networkx as nx
except ImportError:
    nx = None

try:
    from neo4j import GraphDatabase
except ImportError:
    GraphDatabase = None

logger = logging.getLogger("viper.graph")

# ══════════════════════════════════════════════════════════════════════
# NODE TYPE CONSTANTS
# ══════════════════════════════════════════════════════════════════════

# Core Recon
TARGET = "Target"
SUBDOMAIN = "Subdomain"
IP = "IP"
PORT = "Port"
SERVICE = "Service"
DNS_RECORD = "DNSRecord"
BASE_URL = "BaseURL"
TECHNOLOGY = "Technology"
CERTIFICATE = "Certificate"
HEADER = "Header"

# Vulnerability & Security
ENDPOINT = "Endpoint"
PARAMETER = "Parameter"
VULNERABILITY = "Vulnerability"
CVE = "CVE"
MITRE_DATA = "MitreData"
CAPEC = "Capec"
EXPLOIT_GVM = "ExploitGvm"
SECRET = "Secret"

# GitHub
GITHUB_HUNT = "GithubHunt"
GITHUB_REPOSITORY = "GithubRepository"
GITHUB_PATH = "GithubPath"
GITHUB_SECRET = "GithubSecret"
GITHUB_SENSITIVE_FILE = "GithubSensitiveFile"

# Attack Chains
ATTACK_CHAIN = "AttackChain"
CHAIN_STEP = "ChainStep"
CHAIN_FINDING = "ChainFinding"
CHAIN_DECISION = "ChainDecision"
CHAIN_FAILURE = "ChainFailure"

# Other
TRACEROUTE = "Traceroute"
EXTERNAL_DOMAIN = "ExternalDomain"

# Legacy compat (lowercase aliases for existing VIPER code)
ATTACK = "Attack"
FINDING = "Finding"

ALL_NODE_TYPES = [
    TARGET, SUBDOMAIN, IP, PORT, SERVICE, DNS_RECORD, BASE_URL, TECHNOLOGY,
    CERTIFICATE, HEADER, ENDPOINT, PARAMETER, VULNERABILITY, CVE, MITRE_DATA,
    CAPEC, EXPLOIT_GVM, SECRET, GITHUB_HUNT, GITHUB_REPOSITORY, GITHUB_PATH,
    GITHUB_SECRET, GITHUB_SENSITIVE_FILE, ATTACK_CHAIN, CHAIN_STEP,
    CHAIN_FINDING, CHAIN_DECISION, CHAIN_FAILURE, TRACEROUTE, EXTERNAL_DOMAIN,
    ATTACK, FINDING,
]

# ══════════════════════════════════════════════════════════════════════
# RELATIONSHIP CONSTANTS
# ══════════════════════════════════════════════════════════════════════

BELONGS_TO = "BELONGS_TO"
RESOLVES_TO = "RESOLVES_TO"
HAS_DNS_RECORD = "HAS_DNS_RECORD"
HAS_PORT = "HAS_PORT"
HAS_VULNERABILITY = "HAS_VULNERABILITY"
RUNS_SERVICE = "RUNS_SERVICE"
SERVES_URL = "SERVES_URL"
HAS_ENDPOINT = "HAS_ENDPOINT"
HAS_PARAMETER = "HAS_PARAMETER"
USES_TECHNOLOGY = "USES_TECHNOLOGY"
HAS_HEADER = "HAS_HEADER"
HAS_CERTIFICATE = "HAS_CERTIFICATE"
HAS_SECRET = "HAS_SECRET"
HAS_KNOWN_CVE = "HAS_KNOWN_CVE"
INCLUDES_CVE = "INCLUDES_CVE"
HAS_CWE = "HAS_CWE"
HAS_CAPEC = "HAS_CAPEC"
FOUND_AT = "FOUND_AT"
AFFECTS_PARAMETER = "AFFECTS_PARAMETER"
EXPLOITED_CVE = "EXPLOITED_CVE"
WAF_BYPASS_VIA = "WAF_BYPASS_VIA"
HAS_TRACEROUTE = "HAS_TRACEROUTE"
DISCOVERED_BY = "DISCOVERED_BY"
HAS_GITHUB_HUNT = "HAS_GITHUB_HUNT"
HAS_REPOSITORY = "HAS_REPOSITORY"
HAS_PATH = "HAS_PATH"
CONTAINS_SECRET = "CONTAINS_SECRET"
CONTAINS_SENSITIVE_FILE = "CONTAINS_SENSITIVE_FILE"
# Legacy compat
HAS_VULN = "HAS_VULNERABILITY"
USES_TECH = "USES_TECHNOLOGY"
ATTACKED_WITH = "ATTACKED_WITH"
FOUND_BY = "FOUND_BY"

# Chain relationships
CHAIN_HAS_STEP = "HAS_STEP"
CHAIN_NEXT_STEP = "NEXT_STEP"
CHAIN_HAS_FINDING = "HAS_FINDING"
CHAIN_HAS_DECISION = "HAS_DECISION"
CHAIN_HAS_FAILURE = "HAS_FAILURE"

# ══════════════════════════════════════════════════════════════════════
# VIS.JS STYLING
# ══════════════════════════════════════════════════════════════════════

NODE_COLORS = {
    TARGET: {"background": "#4da6ff", "border": "#3b82f6"},
    SUBDOMAIN: {"background": "#818cf8", "border": "#6366f1"},
    IP: {"background": "#a78bfa", "border": "#7c3aed"},
    PORT: {"background": "#c084fc", "border": "#9333ea"},
    SERVICE: {"background": "#e879f9", "border": "#c026d3"},
    TECHNOLOGY: {"background": "#00c853", "border": "#16a34a"},
    VULNERABILITY: {"background": "#ff4444", "border": "#dc2626"},
    CVE: {"background": "#ff6b6b", "border": "#ef4444"},
    FINDING: {"background": "#ff4444", "border": "#dc2626"},
    ENDPOINT: {"background": "#38bdf8", "border": "#0ea5e9"},
    PARAMETER: {"background": "#67e8f9", "border": "#22d3ee"},
    CERTIFICATE: {"background": "#a3e635", "border": "#84cc16"},
    SECRET: {"background": "#fbbf24", "border": "#f59e0b"},
    ATTACK: {"background": "#ff8c00", "border": "#ea580c"},
    ATTACK_CHAIN: {"background": "#f472b6", "border": "#ec4899"},
    BASE_URL: {"background": "#60a5fa", "border": "#3b82f6"},
}

NODE_SHAPES = {
    TARGET: "dot",
    SUBDOMAIN: "dot",
    IP: "hexagon",
    PORT: "triangle",
    SERVICE: "square",
    TECHNOLOGY: "square",
    VULNERABILITY: "star",
    CVE: "star",
    FINDING: "star",
    ENDPOINT: "dot",
    PARAMETER: "dot",
    CERTIFICATE: "diamond",
    SECRET: "diamond",
    ATTACK: "diamond",
    ATTACK_CHAIN: "triangleDown",
    BASE_URL: "dot",
}


# ══════════════════════════════════════════════════════════════════════
# GRAPH BACKEND ABC
# ══════════════════════════════════════════════════════════════════════

class GraphBackend(ABC):
    """Abstract backend for graph storage."""

    @abstractmethod
    def add_node(self, node_type: str, unique_key: str, properties: Dict) -> str:
        """Add or update a node. Returns node_id."""

    @abstractmethod
    def add_relationship(self, src_id: str, dst_id: str, rel_type: str, properties: Dict = None) -> None:
        """Add a relationship between two nodes."""

    @abstractmethod
    def get_node(self, node_id: str) -> Optional[Dict]:
        """Get node by ID."""

    @abstractmethod
    def find_nodes(self, node_type: str, filters: Dict = None, limit: int = 100) -> List[Dict]:
        """Find nodes by type and optional filters."""

    @abstractmethod
    def get_neighbors(self, node_id: str, rel_type: str = None, direction: str = "out") -> List[Dict]:
        """Get neighboring nodes."""

    @abstractmethod
    def query_raw(self, query: str, params: Dict = None) -> List[Dict]:
        """Execute raw query (Cypher for Neo4j, custom for networkx)."""

    @abstractmethod
    def get_full_graph(self, project_id: str = None) -> Dict:
        """Get entire graph as nodes+edges dict."""

    @abstractmethod
    def clear_project(self, project_id: str) -> int:
        """Clear all data for a project. Returns count deleted."""

    @abstractmethod
    def stats(self) -> Dict:
        """Get graph statistics."""

    @abstractmethod
    def close(self):
        """Close connections."""


# ══════════════════════════════════════════════════════════════════════
# NETWORKX + SQLITE BACKEND (always available)
# ══════════════════════════════════════════════════════════════════════

class NetworkxBackend(GraphBackend):
    """In-memory networkx graph with SQLite persistence."""

    def __init__(self, db_path: str = None):
        if nx is None:
            raise ImportError("networkx required: pip install networkx")

        self.graph = nx.DiGraph()
        self._node_index: Dict[str, str] = {}  # unique_key -> node_id
        self._counter = 0
        self._db_path = db_path or str(
            Path.home() / ".viper" / "data" / "graph.db"
        )
        Path(self._db_path).parent.mkdir(parents=True, exist_ok=True)
        self._load_from_sqlite()

    def _make_id(self) -> str:
        self._counter += 1
        return f"n{self._counter}"

    def add_node(self, node_type: str, unique_key: str, properties: Dict) -> str:
        key = f"{node_type}:{unique_key}"
        if key in self._node_index:
            nid = self._node_index[key]
            self.graph.nodes[nid].update(properties)
            self.graph.nodes[nid]["updated_at"] = datetime.now().isoformat()
            return nid

        nid = self._make_id()
        self._node_index[key] = nid
        self.graph.add_node(
            nid,
            node_type=node_type,
            unique_key=unique_key,
            label=properties.get("name", properties.get("label", unique_key)),
            created_at=datetime.now().isoformat(),
            updated_at=datetime.now().isoformat(),
            **properties,
        )
        return nid

    def add_relationship(self, src_id: str, dst_id: str, rel_type: str, properties: Dict = None) -> None:
        if self.graph.has_node(src_id) and self.graph.has_node(dst_id):
            self.graph.add_edge(src_id, dst_id, rel=rel_type, **(properties or {}))

    def get_node(self, node_id: str) -> Optional[Dict]:
        if not self.graph.has_node(node_id):
            return None
        data = dict(self.graph.nodes[node_id])
        data["id"] = node_id
        return data

    def find_nodes(self, node_type: str, filters: Dict = None, limit: int = 100) -> List[Dict]:
        results = []
        for nid, data in self.graph.nodes(data=True):
            if data.get("node_type") != node_type:
                continue
            if filters:
                match = all(data.get(k) == v for k, v in filters.items())
                if not match:
                    continue
            d = dict(data)
            d["id"] = nid
            results.append(d)
            if len(results) >= limit:
                break
        return results

    def get_neighbors(self, node_id: str, rel_type: str = None, direction: str = "out") -> List[Dict]:
        if not self.graph.has_node(node_id):
            return []
        results = []
        if direction in ("out", "both"):
            for _, neighbor, edata in self.graph.out_edges(node_id, data=True):
                if rel_type and edata.get("rel") != rel_type:
                    continue
                d = dict(self.graph.nodes[neighbor])
                d["id"] = neighbor
                d["_rel"] = edata.get("rel", "")
                results.append(d)
        if direction in ("in", "both"):
            for neighbor, _, edata in self.graph.in_edges(node_id, data=True):
                if rel_type and edata.get("rel") != rel_type:
                    continue
                d = dict(self.graph.nodes[neighbor])
                d["id"] = neighbor
                d["_rel"] = edata.get("rel", "")
                results.append(d)
        return results

    def query_raw(self, query: str, params: Dict = None) -> List[Dict]:
        """Simple keyword-based query for networkx (not Cypher)."""
        query_lower = query.lower()
        results = []

        # Parse simple queries
        if "all" in query_lower and any(nt.lower() in query_lower for nt in ALL_NODE_TYPES):
            for nt in ALL_NODE_TYPES:
                if nt.lower() in query_lower:
                    results = self.find_nodes(nt, limit=500)
                    break
        elif "stats" in query_lower or "count" in query_lower:
            results = [self.stats()]
        elif "neighbors" in query_lower or "connected" in query_lower:
            # Find node by name in query
            for nid, data in self.graph.nodes(data=True):
                label = data.get("label", "").lower()
                if label and label in query_lower:
                    results = self.get_neighbors(nid, direction="both")
                    break
        else:
            # Fuzzy search: match any node whose label contains query terms
            terms = [t for t in query_lower.split() if len(t) > 2]
            for nid, data in self.graph.nodes(data=True):
                label = str(data.get("label", "")).lower()
                if any(t in label for t in terms):
                    d = dict(data)
                    d["id"] = nid
                    results.append(d)
                    if len(results) >= 50:
                        break

        return results

    def get_full_graph(self, project_id: str = None) -> Dict:
        nodes = []
        for nid, data in self.graph.nodes(data=True):
            if project_id and data.get("project_id") != project_id:
                continue
            d = dict(data)
            d["id"] = nid
            nodes.append(d)
        edges = []
        node_ids = {n["id"] for n in nodes}
        for u, v, edata in self.graph.edges(data=True):
            if u in node_ids and v in node_ids:
                edges.append({"from": u, "to": v, **edata})
        return {"nodes": nodes, "edges": edges}

    def clear_project(self, project_id: str) -> int:
        to_remove = [
            nid for nid, data in self.graph.nodes(data=True)
            if data.get("project_id") == project_id
        ]
        for nid in to_remove:
            self.graph.remove_node(nid)
        # Clean up node index
        self._node_index = {
            k: v for k, v in self._node_index.items()
            if self.graph.has_node(v)
        }
        return len(to_remove)

    def stats(self) -> Dict:
        type_counts = {}
        for _, data in self.graph.nodes(data=True):
            nt = data.get("node_type", "unknown")
            type_counts[nt] = type_counts.get(nt, 0) + 1
        return {
            "total_nodes": self.graph.number_of_nodes(),
            "total_edges": self.graph.number_of_edges(),
            "node_types": type_counts,
            "backend": "networkx+sqlite",
        }

    def close(self):
        self._save_to_sqlite()

    def _save_to_sqlite(self):
        """Persist graph to SQLite."""
        conn = sqlite3.connect(self._db_path)
        try:
            conn.execute("CREATE TABLE IF NOT EXISTS graph_nodes (id TEXT PRIMARY KEY, node_type TEXT, label TEXT, data TEXT)")
            conn.execute("CREATE TABLE IF NOT EXISTS graph_edges (src TEXT, dst TEXT, rel TEXT, data TEXT, PRIMARY KEY (src, dst, rel))")
            conn.execute("CREATE TABLE IF NOT EXISTS graph_meta (key TEXT PRIMARY KEY, value TEXT)")
            conn.execute("DELETE FROM graph_nodes")
            conn.execute("DELETE FROM graph_edges")

            for nid, ndata in self.graph.nodes(data=True):
                conn.execute(
                    "INSERT INTO graph_nodes VALUES (?,?,?,?)",
                    (nid, ndata.get("node_type", ""), ndata.get("label", ""),
                     json.dumps({k: v for k, v in ndata.items()}, default=str)),
                )
            for u, v, edata in self.graph.edges(data=True):
                conn.execute(
                    "INSERT OR REPLACE INTO graph_edges VALUES (?,?,?,?)",
                    (u, v, edata.get("rel", ""),
                     json.dumps({k: v for k, v in edata.items()}, default=str)),
                )
            conn.execute(
                "INSERT OR REPLACE INTO graph_meta VALUES (?,?)",
                ("node_index", json.dumps(self._node_index)),
            )
            conn.execute(
                "INSERT OR REPLACE INTO graph_meta VALUES (?,?)",
                ("node_counter", str(self._counter)),
            )
            conn.commit()
        finally:
            conn.close()

    def _load_from_sqlite(self):
        """Load graph from SQLite if exists."""
        if not Path(self._db_path).exists():
            return
        conn = sqlite3.connect(self._db_path)
        conn.row_factory = sqlite3.Row
        try:
            try:
                row = conn.execute("SELECT value FROM graph_meta WHERE key='node_index'").fetchone()
                if row:
                    self._node_index = json.loads(row[0])
            except Exception:
                pass
            try:
                row = conn.execute("SELECT value FROM graph_meta WHERE key='node_counter'").fetchone()
                if row:
                    self._counter = int(row[0])
            except Exception:
                pass
            try:
                for row in conn.execute("SELECT * FROM graph_nodes"):
                    nid = row["id"]
                    data = json.loads(row["data"]) if row["data"] else {}
                    self.graph.add_node(nid, **data)
            except Exception:
                pass
            try:
                for row in conn.execute("SELECT * FROM graph_edges"):
                    data = json.loads(row["data"]) if row["data"] else {}
                    self.graph.add_edge(row["src"], row["dst"], **data)
            except Exception:
                pass
        finally:
            conn.close()

    # ── Vis.js export ──

    def to_vis_json(self) -> Dict:
        """Export graph as vis.js compatible JSON."""
        vis_nodes = []
        for nid, data in self.graph.nodes(data=True):
            ntype = data.get("node_type", TARGET)
            colors = NODE_COLORS.get(ntype, NODE_COLORS.get(TARGET, {}))
            shape = NODE_SHAPES.get(ntype, "dot")
            degree = self.graph.degree(nid)
            size = 10 + min(degree * 3, 30)

            if ntype in (VULNERABILITY, FINDING, CVE):
                sev = data.get("severity", "info")
                sev_sizes = {"critical": 20, "high": 16, "medium": 12, "low": 8, "info": 6}
                size = sev_sizes.get(sev, 10)

            vis_nodes.append({
                "id": nid,
                "label": data.get("label", nid)[:40],
                "group": ntype,
                "shape": shape,
                "size": size,
                "color": colors,
                "title": json.dumps(
                    {k: v for k, v in data.items() if k not in ("label",)},
                    default=str, indent=2,
                ),
            })

        vis_edges = []
        for u, v, edata in self.graph.edges(data=True):
            vis_edges.append({
                "from": u, "to": v,
                "arrows": "to",
                "title": edata.get("rel", ""),
                "width": 2 if edata.get("rel") in (HAS_VULNERABILITY, FOUND_BY) else 1,
            })

        return {"nodes": vis_nodes, "edges": vis_edges}


# ══════════════════════════════════════════════════════════════════════
# NEO4J BACKEND (optional, when Neo4j available)
# ══════════════════════════════════════════════════════════════════════

class Neo4jBackend(GraphBackend):
    """Neo4j graph database backend."""

    def __init__(self, uri: str, user: str = "neo4j", password: str = os.environ.get("NEO4J_PASSWORD", "changeme")):
        if GraphDatabase is None:
            raise ImportError("neo4j driver required: pip install neo4j")
        self._driver = GraphDatabase.driver(uri, auth=(user, password))
        self._init_constraints()

    def _init_constraints(self):
        """Create uniqueness constraints for all node types."""
        constraints = [
            (TARGET, "name"), (SUBDOMAIN, "name"), (IP, "address"),
            (TECHNOLOGY, "name"), (VULNERABILITY, "id"), (CVE, "id"),
            (MITRE_DATA, "id"), (CAPEC, "capec_id"), (SECRET, "id"),
            (ENDPOINT, "full_url"), (BASE_URL, "url"),
            (ATTACK_CHAIN, "chain_id"), (CHAIN_STEP, "step_id"),
            (CHAIN_FINDING, "finding_id"), (CHAIN_DECISION, "decision_id"),
            (CHAIN_FAILURE, "failure_id"),
        ]
        with self._driver.session() as session:
            for node_type, prop in constraints:
                try:
                    session.run(
                        f"CREATE CONSTRAINT IF NOT EXISTS FOR (n:{node_type}) "
                        f"REQUIRE n.{prop} IS UNIQUE"
                    )
                except Exception as e:
                    logger.debug(f"Constraint {node_type}.{prop}: {e}")

    def add_node(self, node_type: str, unique_key: str, properties: Dict) -> str:
        props = {**properties, "updated_at": datetime.now().isoformat()}
        # Determine the unique property name from the node type
        unique_prop = self._unique_prop(node_type)
        props[unique_prop] = unique_key

        with self._driver.session() as session:
            result = session.run(
                f"MERGE (n:{node_type} {{{unique_prop}: $key}}) "
                f"ON CREATE SET n += $props, n.created_at = datetime() "
                f"ON MATCH SET n += $props "
                f"RETURN elementId(n) AS id",
                key=unique_key, props=self._sanitize_props(props),
            )
            record = result.single()
            return str(record["id"]) if record else unique_key

    def add_relationship(self, src_id: str, dst_id: str, rel_type: str, properties: Dict = None) -> None:
        props = self._sanitize_props(properties or {})
        with self._driver.session() as session:
            session.run(
                f"MATCH (a) WHERE elementId(a) = $src "
                f"MATCH (b) WHERE elementId(b) = $dst "
                f"MERGE (a)-[r:{rel_type}]->(b) SET r += $props",
                src=src_id, dst=dst_id, props=props,
            )

    def get_node(self, node_id: str) -> Optional[Dict]:
        with self._driver.session() as session:
            result = session.run(
                "MATCH (n) WHERE elementId(n) = $id RETURN n, labels(n) AS labels",
                id=node_id,
            )
            record = result.single()
            if not record:
                return None
            node = dict(record["n"])
            node["id"] = node_id
            node["node_type"] = record["labels"][0] if record["labels"] else ""
            return node

    def find_nodes(self, node_type: str, filters: Dict = None, limit: int = 100) -> List[Dict]:
        where_clauses = []
        params = {"limit": limit}
        if filters:
            for i, (k, v) in enumerate(filters.items()):
                pname = f"p{i}"
                where_clauses.append(f"n.{k} = ${pname}")
                params[pname] = v
        where = " AND ".join(where_clauses)
        where_str = f"WHERE {where}" if where else ""

        with self._driver.session() as session:
            result = session.run(
                f"MATCH (n:{node_type}) {where_str} RETURN n, elementId(n) AS id LIMIT $limit",
                **params,
            )
            return [
                {**dict(r["n"]), "id": str(r["id"]), "node_type": node_type}
                for r in result
            ]

    def get_neighbors(self, node_id: str, rel_type: str = None, direction: str = "out") -> List[Dict]:
        rel_filter = f":{rel_type}" if rel_type else ""
        if direction == "out":
            pattern = f"(a)-[r{rel_filter}]->(b)"
        elif direction == "in":
            pattern = f"(a)<-[r{rel_filter}]-(b)"
        else:
            pattern = f"(a)-[r{rel_filter}]-(b)"

        with self._driver.session() as session:
            result = session.run(
                f"MATCH {pattern} WHERE elementId(a) = $id "
                f"RETURN b, elementId(b) AS id, type(r) AS rel, labels(b) AS labels",
                id=node_id,
            )
            return [
                {**dict(r["b"]), "id": str(r["id"]),
                 "node_type": r["labels"][0] if r["labels"] else "",
                 "_rel": r["rel"]}
                for r in result
            ]

    def query_raw(self, query: str, params: Dict = None) -> List[Dict]:
        with self._driver.session() as session:
            result = session.run(query, **(params or {}))
            return [dict(r) for r in result]

    def get_full_graph(self, project_id: str = None) -> Dict:
        where = "WHERE n.project_id = $pid" if project_id else ""
        params = {"pid": project_id} if project_id else {}

        with self._driver.session() as session:
            # Get nodes
            result = session.run(
                f"MATCH (n) {where} RETURN n, elementId(n) AS id, labels(n) AS labels LIMIT 5000",
                **params,
            )
            nodes = []
            node_ids = set()
            for r in result:
                nid = str(r["id"])
                node_ids.add(nid)
                nodes.append({
                    **dict(r["n"]), "id": nid,
                    "node_type": r["labels"][0] if r["labels"] else "",
                })

            # Get edges
            result = session.run(
                "MATCH (a)-[r]->(b) "
                "WHERE elementId(a) IN $ids AND elementId(b) IN $ids "
                "RETURN elementId(a) AS src, elementId(b) AS dst, type(r) AS rel",
                ids=list(node_ids),
            )
            edges = [{"from": str(r["src"]), "to": str(r["dst"]), "rel": r["rel"]} for r in result]

        return {"nodes": nodes, "edges": edges}

    def clear_project(self, project_id: str) -> int:
        with self._driver.session() as session:
            result = session.run(
                "MATCH (n {project_id: $pid}) DETACH DELETE n RETURN count(n) AS cnt",
                pid=project_id,
            )
            record = result.single()
            return record["cnt"] if record else 0

    def stats(self) -> Dict:
        with self._driver.session() as session:
            result = session.run(
                "MATCH (n) RETURN labels(n)[0] AS label, count(n) AS cnt"
            )
            type_counts = {r["label"]: r["cnt"] for r in result}
            result2 = session.run("MATCH ()-[r]->() RETURN count(r) AS cnt")
            edge_count = result2.single()["cnt"]

        return {
            "total_nodes": sum(type_counts.values()),
            "total_edges": edge_count,
            "node_types": type_counts,
            "backend": "neo4j",
        }

    def close(self):
        self._driver.close()

    @staticmethod
    def _unique_prop(node_type: str) -> str:
        prop_map = {
            TARGET: "name", SUBDOMAIN: "name", IP: "address",
            PORT: "port_key", SERVICE: "service_key", DNS_RECORD: "record_key",
            BASE_URL: "url", TECHNOLOGY: "name", CERTIFICATE: "subject_cn",
            HEADER: "header_key", ENDPOINT: "full_url", PARAMETER: "param_key",
            VULNERABILITY: "id", CVE: "id", MITRE_DATA: "id", CAPEC: "capec_id",
            EXPLOIT_GVM: "id", SECRET: "id",
            GITHUB_HUNT: "id", GITHUB_REPOSITORY: "id", GITHUB_PATH: "id",
            GITHUB_SECRET: "id", GITHUB_SENSITIVE_FILE: "id",
            ATTACK_CHAIN: "chain_id", CHAIN_STEP: "step_id",
            CHAIN_FINDING: "finding_id", CHAIN_DECISION: "decision_id",
            CHAIN_FAILURE: "failure_id",
            TRACEROUTE: "target_ip", EXTERNAL_DOMAIN: "domain",
            ATTACK: "attack_key", FINDING: "finding_key",
        }
        return prop_map.get(node_type, "name")

    @staticmethod
    def _sanitize_props(props: Dict) -> Dict:
        """Ensure all property values are Neo4j-compatible."""
        sanitized = {}
        for k, v in props.items():
            if v is None:
                continue
            if isinstance(v, (str, int, float, bool)):
                sanitized[k] = v
            elif isinstance(v, (list, tuple)):
                # Neo4j supports homogeneous lists
                sanitized[k] = [str(x) for x in v]
            elif isinstance(v, dict):
                sanitized[k] = json.dumps(v, default=str)
            else:
                sanitized[k] = str(v)
        return sanitized


# ══════════════════════════════════════════════════════════════════════
# GRAPH ENGINE (main interface)
# ══════════════════════════════════════════════════════════════════════

class GraphEngine:
    """
    VIPER 4.0 Knowledge Graph Engine.

    Dual-backend: uses Neo4j if available (NEO4J_URI env), falls back to networkx+SQLite.
    Provides high-level methods for populating graph from recon/scan/exploit data.
    """

    _SENTINEL = object()  # Poison pill for clean shutdown

    def __init__(self, db_path: str = None, project_id: str = "default", user_id: str = "viper"):
        self.project_id = project_id
        self.user_id = user_id
        self._backend = self._select_backend(db_path)
        self._executor = ThreadPoolExecutor(max_workers=2, thread_name_prefix="graph")

        # Background write queue
        self._async_writes_enabled = True
        self._write_queue: queue.Queue = queue.Queue()
        self._writer_thread = threading.Thread(
            target=self._writer_loop, name="graph-writer", daemon=True,
        )
        self._writer_thread.start()
        self._write_errors: List[Exception] = []
        self._write_lock = threading.Lock()

        logger.info(f"GraphEngine initialized: {self._backend.stats().get('backend', 'unknown')}")

    def _select_backend(self, db_path: str = None) -> GraphBackend:
        """Auto-select best available backend."""
        neo4j_uri = os.environ.get("NEO4J_URI")
        if neo4j_uri and GraphDatabase is not None:
            try:
                neo_user = os.environ.get("NEO4J_USER", "neo4j")
                neo_pass = os.environ.get("NEO4J_PASSWORD", "changeme")
                backend = Neo4jBackend(neo4j_uri, neo_user, neo_pass)
                logger.info(f"Using Neo4j backend: {neo4j_uri}")
                return backend
            except Exception as e:
                logger.warning(f"Neo4j unavailable ({e}), falling back to networkx")

        return NetworkxBackend(db_path)

    @property
    def backend(self) -> GraphBackend:
        return self._backend

    # ── Tenant-scoped properties ──

    def _props(self, **kwargs) -> Dict:
        """Add project/user scoping to properties."""
        return {**kwargs, "project_id": self.project_id, "user_id": self.user_id}

    # ── High-level node creation ──

    def add_target(self, domain: str, **attrs) -> str:
        return self._backend.add_node(TARGET, domain, self._props(name=domain, **attrs))

    def add_subdomain(self, subdomain: str, parent_domain: str, **attrs) -> str:
        parent_id = self.add_target(parent_domain)
        sub_id = self._backend.add_node(SUBDOMAIN, subdomain, self._props(name=subdomain, **attrs))
        self._backend.add_relationship(sub_id, parent_id, BELONGS_TO)
        return sub_id

    def add_ip(self, address: str, **attrs) -> str:
        version = "ipv6" if ":" in address else "ipv4"
        return self._backend.add_node(IP, address, self._props(address=address, version=version, **attrs))

    def add_port(self, ip_address: str, port_num: int, protocol: str = "tcp", **attrs) -> str:
        ip_id = self.add_ip(ip_address)
        port_key = f"{ip_address}:{port_num}/{protocol}"
        port_id = self._backend.add_node(
            PORT, port_key, self._props(number=port_num, protocol=protocol, ip_address=ip_address, **attrs)
        )
        self._backend.add_relationship(ip_id, port_id, HAS_PORT)
        return port_id

    def add_service(self, ip_address: str, port_num: int, service_name: str, **attrs) -> str:
        port_id = self.add_port(ip_address, port_num)
        svc_key = f"{service_name}@{ip_address}:{port_num}"
        svc_id = self._backend.add_node(
            SERVICE, svc_key, self._props(name=service_name, port_number=port_num, ip_address=ip_address, **attrs)
        )
        self._backend.add_relationship(port_id, svc_id, RUNS_SERVICE)
        return svc_id

    def add_technology(self, host: str, tech_name: str, version: str = "", **attrs) -> str:
        tech_key = f"{tech_name}:{version}" if version else tech_name
        tech_id = self._backend.add_node(
            TECHNOLOGY, tech_key, self._props(name=tech_name, version=version, **attrs)
        )
        # Link to host (could be domain, subdomain, IP, or base_url)
        host_nodes = self._backend.find_nodes(TARGET, {"name": host}, limit=1)
        if not host_nodes:
            host_nodes = self._backend.find_nodes(SUBDOMAIN, {"name": host}, limit=1)
        if not host_nodes:
            host_nodes = self._backend.find_nodes(IP, {"address": host}, limit=1)
        if not host_nodes:
            host_nodes = self._backend.find_nodes(BASE_URL, {"url": host}, limit=1)
        if host_nodes:
            self._backend.add_relationship(host_nodes[0]["id"], tech_id, USES_TECHNOLOGY)
        return tech_id

    def add_base_url(self, url: str, **attrs) -> str:
        return self._backend.add_node(BASE_URL, url, self._props(url=url, **attrs))

    def add_endpoint(self, path: str, base_url: str, method: str = "GET", **attrs) -> str:
        full_url = f"{method}:{base_url}{path}"
        ep_id = self._backend.add_node(
            ENDPOINT, full_url, self._props(path=path, baseurl=base_url, method=method, full_url=full_url, **attrs)
        )
        url_nodes = self._backend.find_nodes(BASE_URL, {"url": base_url}, limit=1)
        if url_nodes:
            self._backend.add_relationship(url_nodes[0]["id"], ep_id, HAS_ENDPOINT)
        return ep_id

    def add_parameter(self, name: str, endpoint_path: str, base_url: str, position: str = "query", **attrs) -> str:
        param_key = f"{name}@{position}:{endpoint_path}:{base_url}"
        param_id = self._backend.add_node(
            PARAMETER, param_key,
            self._props(name=name, position=position, endpoint_path=endpoint_path, baseurl=base_url, **attrs),
        )
        full_url = f"GET:{base_url}{endpoint_path}"
        ep_nodes = self._backend.find_nodes(ENDPOINT, {"full_url": full_url}, limit=1)
        if ep_nodes:
            self._backend.add_relationship(ep_nodes[0]["id"], param_id, HAS_PARAMETER)
        return param_id

    def add_vulnerability(self, vuln_id: str, name: str, severity: str, **attrs) -> str:
        return self._backend.add_node(
            VULNERABILITY, vuln_id,
            self._props(id=vuln_id, name=name, severity=severity, discovered_at=datetime.now().isoformat(), **attrs),
        )

    def add_cve(self, cve_id: str, **attrs) -> str:
        return self._backend.add_node(CVE, cve_id, self._props(id=cve_id, cve_id=cve_id, **attrs))

    def add_mitre_data(self, cve_id: str, cwe_id: str, **attrs) -> str:
        mitre_id = f"{cve_id}-{cwe_id}"
        mitre_node = self._backend.add_node(
            MITRE_DATA, mitre_id, self._props(id=mitre_id, cve_id=cve_id, cwe_id=cwe_id, **attrs)
        )
        # Link CVE → CWE
        cve_nodes = self._backend.find_nodes(CVE, {"cve_id": cve_id}, limit=1)
        if cve_nodes:
            self._backend.add_relationship(cve_nodes[0]["id"], mitre_node, HAS_CWE)
        return mitre_node

    def add_capec(self, capec_id: str, cwe_id: str = None, **attrs) -> str:
        capec_node = self._backend.add_node(
            CAPEC, capec_id, self._props(capec_id=capec_id, **attrs)
        )
        if cwe_id:
            mitre_nodes = self._backend.find_nodes(MITRE_DATA, {"cwe_id": cwe_id}, limit=1)
            if mitre_nodes:
                self._backend.add_relationship(mitre_nodes[0]["id"], capec_node, HAS_CAPEC)
        return capec_node

    def add_certificate(self, subject_cn: str, **attrs) -> str:
        return self._backend.add_node(CERTIFICATE, subject_cn, self._props(subject_cn=subject_cn, **attrs))

    def add_secret(self, secret_id: str, secret_type: str, **attrs) -> str:
        return self._backend.add_node(
            SECRET, secret_id, self._props(id=secret_id, secret_type=secret_type, **attrs)
        )

    def add_dns_record(self, subdomain: str, record_type: str, value: str, **attrs) -> str:
        key = f"{record_type}:{value}@{subdomain}"
        rec_id = self._backend.add_node(
            DNS_RECORD, key, self._props(type=record_type, value=value, subdomain=subdomain, **attrs)
        )
        sub_nodes = self._backend.find_nodes(SUBDOMAIN, {"name": subdomain}, limit=1)
        if sub_nodes:
            self._backend.add_relationship(sub_nodes[0]["id"], rec_id, HAS_DNS_RECORD)
        return rec_id

    # ── Attack Chain nodes ──

    def add_attack_chain(self, chain_id: str, **attrs) -> str:
        return self._backend.add_node(ATTACK_CHAIN, chain_id, self._props(chain_id=chain_id, **attrs))

    def add_chain_step(self, step_id: str, chain_id: str, **attrs) -> str:
        step_node = self._backend.add_node(CHAIN_STEP, step_id, self._props(step_id=step_id, chain_id=chain_id, **attrs))
        chain_nodes = self._backend.find_nodes(ATTACK_CHAIN, {"chain_id": chain_id}, limit=1)
        if chain_nodes:
            self._backend.add_relationship(chain_nodes[0]["id"], step_node, CHAIN_HAS_STEP)
        return step_node

    def add_chain_finding(self, finding_id: str, chain_id: str, **attrs) -> str:
        finding_node = self._backend.add_node(CHAIN_FINDING, finding_id, self._props(finding_id=finding_id, **attrs))
        chain_nodes = self._backend.find_nodes(ATTACK_CHAIN, {"chain_id": chain_id}, limit=1)
        if chain_nodes:
            self._backend.add_relationship(chain_nodes[0]["id"], finding_node, CHAIN_HAS_FINDING)
        return finding_node

    # ── GitHub nodes ──

    def add_github_hunt(self, hunt_id: str, target: str, **attrs) -> str:
        return self._backend.add_node(GITHUB_HUNT, hunt_id, self._props(id=hunt_id, target=target, **attrs))

    def add_github_secret(self, secret_id: str, **attrs) -> str:
        return self._backend.add_node(GITHUB_SECRET, secret_id, self._props(id=secret_id, **attrs))

    # ── Legacy compat (for existing VIPER code) ──

    def add_attack(self, domain: str, attack_type: str, success: bool = False, url: str = "", **attrs) -> str:
        atk_key = f"{attack_type}@{domain}"
        return self._backend.add_node(
            ATTACK, atk_key,
            self._props(attack_type=attack_type, success=success, url=url, domain=domain, **attrs),
        )

    def add_finding(self, domain: str, vuln_type: str, severity: str = "info", confidence: float = 0.0, url: str = "", **attrs) -> str:
        finding_key = f"finding:{vuln_type}@{url or domain}"
        finding_id = self._backend.add_node(
            FINDING, finding_key,
            self._props(vuln_type=vuln_type, severity=severity, confidence=confidence, url=url, domain=domain, **attrs),
        )
        target_nodes = self._backend.find_nodes(TARGET, {"name": domain}, limit=1)
        if target_nodes:
            self._backend.add_relationship(target_nodes[0]["id"], finding_id, HAS_VULNERABILITY)
        return finding_id

    # ── Linking helpers ──

    def link(self, src_id: str, dst_id: str, rel_type: str, **props) -> None:
        self._backend.add_relationship(src_id, dst_id, rel_type, props if props else None)

    def link_vuln_to_endpoint(self, vuln_id: str, endpoint_id: str) -> None:
        self._backend.add_relationship(vuln_id, endpoint_id, FOUND_AT)

    def link_vuln_to_param(self, vuln_id: str, param_id: str) -> None:
        self._backend.add_relationship(vuln_id, param_id, AFFECTS_PARAMETER)

    def link_vuln_to_cve(self, vuln_id: str, cve_id: str) -> None:
        vuln_nodes = self._backend.find_nodes(VULNERABILITY, {"id": vuln_id}, limit=1)
        cve_nodes = self._backend.find_nodes(CVE, {"cve_id": cve_id}, limit=1)
        if vuln_nodes and cve_nodes:
            self._backend.add_relationship(vuln_nodes[0]["id"], cve_nodes[0]["id"], INCLUDES_CVE)

    def link_tech_to_cve(self, tech_name: str, cve_id: str) -> None:
        tech_nodes = self._backend.find_nodes(TECHNOLOGY, {"name": tech_name}, limit=1)
        cve_nodes = self._backend.find_nodes(CVE, {"cve_id": cve_id}, limit=1)
        if tech_nodes and cve_nodes:
            self._backend.add_relationship(tech_nodes[0]["id"], cve_nodes[0]["id"], HAS_KNOWN_CVE)

    # ── Bulk import from recon data ──

    def populate_from_recon(self, target: str, recon_data: Dict) -> Dict:
        """Populate graph from VIPER recon results."""
        stats = {"nodes_created": 0, "relationships_created": 0}

        self.add_target(target)
        stats["nodes_created"] += 1

        # Subdomains
        for sub in recon_data.get("subdomains", []):
            name = sub if isinstance(sub, str) else sub.get("host", sub.get("domain", ""))
            if name:
                self.add_subdomain(name, target)
                stats["nodes_created"] += 1

        # Ports
        for p in recon_data.get("ports", []):
            if isinstance(p, dict):
                port_num = p.get("port", 0)
                ip = p.get("ip", target)
                svc = p.get("service", "")
                self.add_port(ip, port_num)
                if svc:
                    self.add_service(ip, port_num, svc)
                stats["nodes_created"] += 1
            elif isinstance(p, int):
                self.add_port(target, p)
                stats["nodes_created"] += 1

        # Technologies
        for tech in recon_data.get("technologies", []):
            name = tech if isinstance(tech, str) else tech.get("name", "")
            version = "" if isinstance(tech, str) else tech.get("version", "")
            if name:
                self.add_technology(target, name, version)
                stats["nodes_created"] += 1

        # URLs
        for url in recon_data.get("urls", recon_data.get("endpoints", [])):
            if isinstance(url, str):
                self.add_base_url(url)
            elif isinstance(url, dict):
                self.add_base_url(url.get("url", ""))

        # DNS records
        for rec in recon_data.get("dns_records", []):
            if isinstance(rec, dict):
                self.add_dns_record(
                    rec.get("subdomain", target),
                    rec.get("type", "A"),
                    rec.get("value", ""),
                )

        return stats

    def populate_from_findings(self, target: str, findings: List[Dict]) -> Dict:
        """Populate graph from VIPER findings."""
        stats = {"findings_added": 0}
        for f in findings:
            self.add_finding(
                domain=f.get("domain", target),
                vuln_type=f.get("vuln_type", f.get("type", "unknown")),
                severity=f.get("severity", "info"),
                confidence=f.get("confidence", 0),
                url=f.get("url", ""),
                payload=f.get("payload", ""),
                evidence=f.get("evidence", ""),
            )
            stats["findings_added"] += 1
        return stats

    def populate_from_nuclei(self, target: str, nuclei_results: List[Dict]) -> Dict:
        """Populate graph from Nuclei scan results with CVE/MITRE linking."""
        stats = {"vulns_added": 0, "cves_linked": 0}
        for r in nuclei_results:
            vuln_id = r.get("template-id", r.get("id", f"nuclei-{datetime.now().timestamp()}"))
            vuln_node = self.add_vulnerability(
                vuln_id=vuln_id,
                name=r.get("info", {}).get("name", r.get("name", vuln_id)),
                severity=r.get("info", {}).get("severity", r.get("severity", "info")),
                source="nuclei",
                template_id=r.get("template-id", ""),
                matched_at=r.get("matched-at", r.get("url", "")),
                tags=r.get("info", {}).get("tags", []),
                description=r.get("info", {}).get("description", ""),
            )
            stats["vulns_added"] += 1

            # Link CVEs
            cve_ids = r.get("info", {}).get("classification", {}).get("cve-id", [])
            if isinstance(cve_ids, str):
                cve_ids = [cve_ids]
            for cve_id in (cve_ids or []):
                if cve_id:
                    self.add_cve(cve_id, name=r.get("info", {}).get("name", ""))
                    self.link_vuln_to_cve(vuln_id, cve_id)
                    stats["cves_linked"] += 1

        return stats

    # ── Query interface ──

    def query(self, question: str) -> List[Dict]:
        """Query graph with natural language (simple mode) or raw query."""
        return self._backend.query_raw(question)

    def find(self, node_type: str, **filters) -> List[Dict]:
        return self._backend.find_nodes(node_type, filters if filters else None)

    def neighbors(self, node_id: str, rel_type: str = None) -> List[Dict]:
        return self._backend.get_neighbors(node_id, rel_type, direction="both")

    def full_graph(self) -> Dict:
        return self._backend.get_full_graph(self.project_id)

    def stats(self) -> Dict:
        return self._backend.stats()

    def to_vis_json(self) -> Dict:
        """Export for vis.js visualization."""
        if isinstance(self._backend, NetworkxBackend):
            return self._backend.to_vis_json()
        # For Neo4j, convert full_graph to vis format
        graph_data = self.full_graph()
        vis_nodes = []
        for n in graph_data["nodes"]:
            ntype = n.get("node_type", TARGET)
            vis_nodes.append({
                "id": n["id"],
                "label": n.get("label", n.get("name", n["id"]))[:40],
                "group": ntype,
                "shape": NODE_SHAPES.get(ntype, "dot"),
                "color": NODE_COLORS.get(ntype, {}),
            })
        vis_edges = [{"from": e["from"], "to": e["to"], "title": e.get("rel", ""), "arrows": "to"} for e in graph_data["edges"]]
        return {"nodes": vis_nodes, "edges": vis_edges}

    # ── Background write queue ──

    @property
    def async_writes_enabled(self) -> bool:
        """Whether write_async queues writes or falls through to synchronous."""
        return self._async_writes_enabled

    @async_writes_enabled.setter
    def async_writes_enabled(self, value: bool):
        self._async_writes_enabled = value

    def write_async(self, method_name: str, *args, **kwargs):
        """
        Queue a graph write for background execution.

        When async_writes_enabled is True, the call is pushed onto the write
        queue and executed by the background writer thread.  When False, the
        method is invoked synchronously on the calling thread.

        Args:
            method_name: Name of a method on this GraphEngine instance
                         (e.g. "add_node", "add_finding", "link").
            *args, **kwargs: Forwarded to the resolved method.
        """
        method = getattr(self, method_name, None)
        if method is None:
            raise AttributeError(f"GraphEngine has no method '{method_name}'")

        if not self._async_writes_enabled:
            return method(*args, **kwargs)

        self._write_queue.put((method_name, args, kwargs))

    def _writer_loop(self):
        """Background thread that drains the write queue sequentially."""
        while True:
            item = self._write_queue.get()
            if item is self._SENTINEL:
                self._write_queue.task_done()
                break
            method_name, args, kwargs = item
            try:
                method = getattr(self, method_name)
                method(*args, **kwargs)
            except Exception as exc:
                logger.error(f"Background graph write failed ({method_name}): {exc}")
                with self._write_lock:
                    self._write_errors.append(exc)
            finally:
                self._write_queue.task_done()

    def flush(self, timeout: float = None):
        """
        Block until the write queue is fully drained.

        Call this at hunt end to ensure all queued graph writes have been
        persisted before generating reports or shutting down.

        Args:
            timeout: Max seconds to wait. None means wait forever.

        Raises:
            TimeoutError: If the queue is not drained within *timeout*.
        """
        if timeout is None:
            self._write_queue.join()
        else:
            done = threading.Event()

            def _watch():
                self._write_queue.join()
                done.set()

            watcher = threading.Thread(target=_watch, daemon=True)
            watcher.start()
            if not done.wait(timeout=timeout):
                raise TimeoutError(
                    f"Graph write queue not drained within {timeout}s "
                    f"({self._write_queue.qsize()} items remaining)"
                )

    def drain_errors(self) -> List[Exception]:
        """Return and clear any errors from background writes."""
        with self._write_lock:
            errs = list(self._write_errors)
            self._write_errors.clear()
        return errs

    @property
    def pending_writes(self) -> int:
        """Approximate number of queued writes waiting to execute."""
        return self._write_queue.qsize()

    def shutdown(self):
        """
        Flush pending writes, stop the writer thread, and release resources.

        Blocks until the queue is empty, then sends a poison pill to the
        writer thread and waits for it to exit.
        """
        # Drain all pending work first
        self._write_queue.join()
        # Send poison pill
        self._write_queue.put(self._SENTINEL)
        self._writer_thread.join(timeout=5)
        # Persist and close
        self.save()
        self._executor.shutdown(wait=False)
        self._backend.close()
        logger.info("GraphEngine shutdown complete")

    # ── Persistence ──

    def save(self):
        """Persist graph to disk."""
        if isinstance(self._backend, NetworkxBackend):
            self._backend._save_to_sqlite()

    def close(self):
        """Shutdown graph engine (delegates to shutdown for clean teardown)."""
        self.shutdown()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()

    def __repr__(self):
        s = self.stats()
        return f"GraphEngine({s.get('backend', '?')}, nodes={s.get('total_nodes', 0)}, edges={s.get('total_edges', 0)})"

    # ── Consumer-facing aliases ──

    def add_node(self, node_type, node_id, properties=None):
        return self._backend.add_node(node_type, node_id, self._props(**(properties or {})))

    def add_edge(self, from_id, to_id, rel_type, properties=None):
        return self._backend.add_relationship(from_id, to_id, rel_type, properties)

    def get_nodes_by_type(self, node_type):
        return self.find(node_type)

    def get_edges_from(self, node_id):
        return self.neighbors(node_id)

    def get_neighbors(self, node_id):
        edges = self.neighbors(node_id)
        return [e.get('to_id') or e.get('target') or e.get('id') for e in edges]
