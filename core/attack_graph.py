#!/usr/bin/env python3
"""
VIPER Attack Graph — In-memory graph database using networkx.

Builds a directed graph of targets, subdomains, ports, technologies,
vulnerabilities, and attacks. Supports querying attack chains,
attack surface analysis, and exporting for vis.js visualization.
"""

import json
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

try:
    import networkx as nx
except ImportError:
    nx = None


# Relationship types
RESOLVES_TO = "RESOLVES_TO"
HAS_PORT = "HAS_PORT"
USES_TECH = "USES_TECH"
HAS_VULN = "HAS_VULN"
ATTACKED_WITH = "ATTACKED_WITH"
FOUND_BY = "FOUND_BY"

# Node types
TARGET = "target"
SUBDOMAIN = "subdomain"
PORT = "port"
TECHNOLOGY = "technology"
VULNERABILITY = "vulnerability"
ATTACK = "attack"
FINDING = "finding"

# Colors for vis.js export
NODE_COLORS = {
    TARGET: {"background": "#4da6ff", "border": "#3b82f6"},
    SUBDOMAIN: {"background": "#818cf8", "border": "#6366f1"},
    PORT: {"background": "#a78bfa", "border": "#7c3aed"},
    TECHNOLOGY: {"background": "#00c853", "border": "#16a34a"},
    VULNERABILITY: {"background": "#ff4444", "border": "#dc2626"},
    ATTACK: {"background": "#ff8c00", "border": "#ea580c"},
    FINDING: {"background": "#ff4444", "border": "#dc2626"},
}

NODE_SHAPES = {
    TARGET: "dot",
    SUBDOMAIN: "dot",
    PORT: "triangle",
    TECHNOLOGY: "square",
    VULNERABILITY: "star",
    ATTACK: "diamond",
    FINDING: "star",
}


class AttackGraph:
    """In-memory attack graph backed by networkx DiGraph."""

    def __init__(self):
        if nx is None:
            raise ImportError("networkx is required: pip install networkx")
        self.graph = nx.DiGraph()
        self._node_counter = 0
        self._node_index: Dict[str, str] = {}  # key -> node_id

    def _make_key(self, node_type: str, identifier: str) -> str:
        return f"{node_type}:{identifier}"

    def _get_or_create(self, node_type: str, identifier: str, **attrs) -> str:
        """Get existing node ID or create new node. Returns node_id."""
        key = self._make_key(node_type, identifier)
        if key in self._node_index:
            nid = self._node_index[key]
            # Update attributes
            if attrs:
                self.graph.nodes[nid].update(attrs)
            return nid

        self._node_counter += 1
        nid = f"n{self._node_counter}"
        self._node_index[key] = nid
        self.graph.add_node(
            nid,
            node_type=node_type,
            label=identifier,
            created_at=datetime.now().isoformat(),
            **attrs,
        )
        return nid

    # ── Node creation methods ──

    def add_target(self, domain: str, **attrs) -> str:
        return self._get_or_create(TARGET, domain, domain=domain, **attrs)

    def add_subdomain(self, subdomain: str, parent_domain: str, **attrs) -> str:
        parent_id = self.add_target(parent_domain)
        sub_id = self._get_or_create(SUBDOMAIN, subdomain, domain=subdomain, **attrs)
        self.graph.add_edge(sub_id, parent_id, rel=RESOLVES_TO)
        return sub_id

    def add_port(self, domain: str, port: int, service: str = "", **attrs) -> str:
        target_id = self.add_target(domain)
        port_label = f"{domain}:{port}"
        port_id = self._get_or_create(
            PORT, port_label, port=port, service=service, **attrs
        )
        self.graph.add_edge(target_id, port_id, rel=HAS_PORT)
        return port_id

    def add_technology(self, domain: str, tech_name: str, **attrs) -> str:
        target_id = self.add_target(domain)
        tech_id = self._get_or_create(TECHNOLOGY, tech_name, **attrs)
        self.graph.add_edge(target_id, tech_id, rel=USES_TECH)
        return tech_id

    def add_vulnerability(
        self,
        domain: str,
        vuln_type: str,
        severity: str = "info",
        url: str = "",
        **attrs,
    ) -> str:
        target_id = self.add_target(domain)
        vuln_label = f"{vuln_type}@{domain}"
        vuln_id = self._get_or_create(
            VULNERABILITY,
            vuln_label,
            vuln_type=vuln_type,
            severity=severity,
            url=url,
            **attrs,
        )
        self.graph.add_edge(target_id, vuln_id, rel=HAS_VULN)
        return vuln_id

    def add_attack(
        self,
        domain: str,
        attack_type: str,
        success: bool = False,
        url: str = "",
        **attrs,
    ) -> str:
        target_id = self.add_target(domain)
        atk_label = f"{attack_type}@{domain}"
        atk_id = self._get_or_create(
            ATTACK,
            atk_label,
            attack_type=attack_type,
            success=success,
            url=url,
            **attrs,
        )
        self.graph.add_edge(target_id, atk_id, rel=ATTACKED_WITH)
        return atk_id

    def add_finding(
        self,
        domain: str,
        vuln_type: str,
        attack_type: str = "",
        severity: str = "info",
        confidence: float = 0.0,
        url: str = "",
        **attrs,
    ) -> str:
        """Add a finding node linked to target, vulnerability, and attack."""
        target_id = self.add_target(domain)
        finding_label = f"finding:{vuln_type}@{url or domain}"
        finding_id = self._get_or_create(
            FINDING,
            finding_label,
            vuln_type=vuln_type,
            severity=severity,
            confidence=confidence,
            url=url,
            **attrs,
        )
        self.graph.add_edge(target_id, finding_id, rel=HAS_VULN)

        if attack_type:
            atk_key = self._make_key(ATTACK, f"{attack_type}@{domain}")
            if atk_key in self._node_index:
                self.graph.add_edge(
                    self._node_index[atk_key], finding_id, rel=FOUND_BY
                )

        return finding_id

    def link(self, src_id: str, dst_id: str, rel: str = "", **attrs) -> None:
        """Add a custom edge between two nodes."""
        if self.graph.has_node(src_id) and self.graph.has_node(dst_id):
            self.graph.add_edge(src_id, dst_id, rel=rel, **attrs)

    # ── Query methods ──

    def get_attack_surface(self, domain: str) -> Dict[str, Any]:
        """Get full attack surface for a domain."""
        key = self._make_key(TARGET, domain)
        if key not in self._node_index:
            return {"domain": domain, "nodes": [], "edges": []}

        target_id = self._node_index[key]
        # BFS from target
        connected = set()
        queue = [target_id]
        while queue:
            node = queue.pop(0)
            if node in connected:
                continue
            connected.add(node)
            for neighbor in self.graph.successors(node):
                if neighbor not in connected:
                    queue.append(neighbor)
            for neighbor in self.graph.predecessors(node):
                if neighbor not in connected:
                    queue.append(neighbor)

        nodes = []
        for nid in connected:
            data = dict(self.graph.nodes[nid])
            data["id"] = nid
            nodes.append(data)

        edges = []
        for u, v, edata in self.graph.edges(data=True):
            if u in connected and v in connected:
                edges.append({"from": u, "to": v, **edata})

        return {"domain": domain, "nodes": nodes, "edges": edges}

    def get_attack_chain(self, finding_id: str) -> List[Dict]:
        """Trace back the attack chain that led to a finding."""
        if not self.graph.has_node(finding_id):
            return []

        chain = []
        visited = set()
        queue = [finding_id]
        while queue:
            node = queue.pop(0)
            if node in visited:
                continue
            visited.add(node)
            data = dict(self.graph.nodes[node])
            data["id"] = node
            chain.append(data)
            for pred in self.graph.predecessors(node):
                if pred not in visited:
                    queue.append(pred)

        return list(reversed(chain))

    def shortest_path(self, src_label: str, dst_label: str) -> List[str]:
        """Find shortest path between two node labels."""
        src_id = None
        dst_id = None
        for key, nid in self._node_index.items():
            if src_label in key and src_id is None:
                src_id = nid
            if dst_label in key and dst_id is None:
                dst_id = nid

        if not src_id or not dst_id:
            return []

        try:
            path = nx.shortest_path(self.graph.to_undirected(), src_id, dst_id)
            return [
                {"id": nid, **dict(self.graph.nodes[nid])} for nid in path
            ]
        except nx.NetworkXNoPath:
            return []

    def most_connected(self, n: int = 10) -> List[Dict]:
        """Get the n most connected nodes."""
        degree_list = sorted(
            self.graph.degree(), key=lambda x: x[1], reverse=True
        )[:n]
        result = []
        for nid, degree in degree_list:
            data = dict(self.graph.nodes[nid])
            data["id"] = nid
            data["connections"] = degree
            result.append(data)
        return result

    def get_tech_vuln_map(self) -> Dict[str, List[str]]:
        """Map technologies to vulnerabilities found in targets using them."""
        tech_vulns: Dict[str, Set[str]] = {}

        for nid, data in self.graph.nodes(data=True):
            if data.get("node_type") != TECHNOLOGY:
                continue
            tech_name = data.get("label", "")
            # Find targets using this tech
            for pred in self.graph.predecessors(nid):
                pred_data = self.graph.nodes[pred]
                if pred_data.get("node_type") != TARGET:
                    continue
                # Find vulns on this target
                for succ in self.graph.successors(pred):
                    succ_data = self.graph.nodes[succ]
                    if succ_data.get("node_type") in (VULNERABILITY, FINDING):
                        if tech_name not in tech_vulns:
                            tech_vulns[tech_name] = set()
                        tech_vulns[tech_name].add(
                            succ_data.get("vuln_type", succ_data.get("label", ""))
                        )

        return {k: sorted(v) for k, v in tech_vulns.items()}

    # ── Export methods ──

    def to_vis_json(self) -> Dict[str, list]:
        """Export graph as vis.js compatible nodes and edges."""
        vis_nodes = []
        for nid, data in self.graph.nodes(data=True):
            ntype = data.get("node_type", TARGET)
            colors = NODE_COLORS.get(ntype, NODE_COLORS[TARGET])
            shape = NODE_SHAPES.get(ntype, "dot")

            degree = self.graph.degree(nid)
            size = 10 + min(degree * 3, 30)

            if ntype == VULNERABILITY or ntype == FINDING:
                sev = data.get("severity", "info")
                sev_sizes = {"critical": 20, "high": 16, "medium": 12, "low": 8, "info": 6}
                size = sev_sizes.get(sev, 10)
                sev_colors = {
                    "critical": {"background": "#ff4444", "border": "#dc2626"},
                    "high": {"background": "#ff8c00", "border": "#ea580c"},
                    "medium": {"background": "#ffd700", "border": "#eab308"},
                    "low": {"background": "#4da6ff", "border": "#3b82f6"},
                    "info": {"background": "#888888", "border": "#6b7280"},
                }
                colors = sev_colors.get(sev, colors)

            vis_nodes.append({
                "id": nid,
                "label": data.get("label", nid),
                "group": ntype,
                "shape": shape,
                "size": size,
                "color": colors,
                "title": json.dumps(
                    {k: v for k, v in data.items() if k != "label"},
                    default=str,
                ),
            })

        vis_edges = []
        for u, v, edata in self.graph.edges(data=True):
            rel = edata.get("rel", "")
            edge_colors = {
                RESOLVES_TO: "rgba(129, 140, 248, 0.4)",
                HAS_PORT: "rgba(167, 139, 250, 0.4)",
                USES_TECH: "rgba(0, 200, 83, 0.3)",
                HAS_VULN: "rgba(255, 68, 68, 0.5)",
                ATTACKED_WITH: "rgba(255, 140, 0, 0.4)",
                FOUND_BY: "rgba(255, 68, 68, 0.6)",
            }
            vis_edges.append({
                "from": u,
                "to": v,
                "color": {"color": edge_colors.get(rel, "rgba(255,255,255,0.15)")},
                "arrows": "to",
                "title": rel,
                "width": 1.5 if rel in (HAS_VULN, FOUND_BY) else 1,
            })

        return {"nodes": vis_nodes, "edges": vis_edges}

    def to_dict(self) -> Dict[str, Any]:
        """Export full graph as serializable dict."""
        nodes = []
        for nid, data in self.graph.nodes(data=True):
            nodes.append({"id": nid, **{k: v for k, v in data.items()}})

        edges = []
        for u, v, edata in self.graph.edges(data=True):
            edges.append({"from": u, "to": v, **{k: v for k, v in edata.items()}})

        return {
            "node_count": self.graph.number_of_nodes(),
            "edge_count": self.graph.number_of_edges(),
            "nodes": nodes,
            "edges": edges,
        }

    # ── Persistence ──

    def save_to_db(self, db_path: str) -> None:
        """Persist graph to SQLite database."""
        path = Path(db_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(str(path))
        try:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS graph_nodes (
                    id TEXT PRIMARY KEY,
                    node_type TEXT,
                    label TEXT,
                    data TEXT
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS graph_edges (
                    src TEXT,
                    dst TEXT,
                    rel TEXT,
                    data TEXT,
                    PRIMARY KEY (src, dst, rel)
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS graph_meta (
                    key TEXT PRIMARY KEY,
                    value TEXT
                )
            """)

            conn.execute("DELETE FROM graph_nodes")
            conn.execute("DELETE FROM graph_edges")

            for nid, ndata in self.graph.nodes(data=True):
                conn.execute(
                    "INSERT INTO graph_nodes (id, node_type, label, data) VALUES (?, ?, ?, ?)",
                    (nid, ndata.get("node_type", ""), ndata.get("label", ""),
                     json.dumps({k: v for k, v in ndata.items()}, default=str)),
                )

            for u, v, edata in self.graph.edges(data=True):
                conn.execute(
                    "INSERT OR REPLACE INTO graph_edges (src, dst, rel, data) VALUES (?, ?, ?, ?)",
                    (u, v, edata.get("rel", ""),
                     json.dumps({k: v for k, v in edata.items()}, default=str)),
                )

            conn.execute(
                "INSERT OR REPLACE INTO graph_meta (key, value) VALUES (?, ?)",
                ("node_index", json.dumps(self._node_index)),
            )
            conn.execute(
                "INSERT OR REPLACE INTO graph_meta (key, value) VALUES (?, ?)",
                ("node_counter", str(self._node_counter)),
            )
            conn.execute(
                "INSERT OR REPLACE INTO graph_meta (key, value) VALUES (?, ?)",
                ("saved_at", datetime.now().isoformat()),
            )

            conn.commit()
        finally:
            conn.close()

    @classmethod
    def load_from_db(cls, db_path: str) -> "AttackGraph":
        """Load graph from SQLite database."""
        path = Path(db_path)
        if not path.exists():
            return cls()

        graph = cls()
        conn = sqlite3.connect(str(path))
        conn.row_factory = sqlite3.Row
        try:
            # Load meta
            try:
                row = conn.execute(
                    "SELECT value FROM graph_meta WHERE key='node_index'"
                ).fetchone()
                if row:
                    graph._node_index = json.loads(row[0])
            except Exception:
                pass

            try:
                row = conn.execute(
                    "SELECT value FROM graph_meta WHERE key='node_counter'"
                ).fetchone()
                if row:
                    graph._node_counter = int(row[0])
            except Exception:
                pass

            # Load nodes
            for row in conn.execute("SELECT * FROM graph_nodes"):
                nid = row["id"]
                try:
                    data = json.loads(row["data"])
                except Exception:
                    data = {}
                graph.graph.add_node(nid, **data)

            # Load edges
            for row in conn.execute("SELECT * FROM graph_edges"):
                try:
                    data = json.loads(row["data"])
                except Exception:
                    data = {}
                graph.graph.add_edge(row["src"], row["dst"], **data)

        finally:
            conn.close()

        return graph

    # ── Build from hunt data ──

    @classmethod
    def build_from_hunt(
        cls,
        target: str,
        recon_data: Optional[Dict] = None,
        findings: Optional[List[Dict]] = None,
        attack_history: Optional[List[Dict]] = None,
        technologies: Optional[List[str]] = None,
    ) -> "AttackGraph":
        """Build an attack graph from hunt results."""
        graph = cls()
        graph.add_target(target)

        # Add recon data
        if recon_data:
            for sub in recon_data.get("subdomains", []):
                if isinstance(sub, str):
                    graph.add_subdomain(sub, target)
                elif isinstance(sub, dict):
                    graph.add_subdomain(sub.get("host", sub.get("domain", "")), target)

            for port_info in recon_data.get("ports", []):
                if isinstance(port_info, dict):
                    graph.add_port(
                        target, port_info.get("port", 0),
                        service=port_info.get("service", ""),
                    )
                elif isinstance(port_info, int):
                    graph.add_port(target, port_info)

        # Add technologies
        for tech in (technologies or []):
            if isinstance(tech, str) and tech:
                graph.add_technology(target, tech)
            elif isinstance(tech, dict):
                graph.add_technology(target, tech.get("name", ""))

        # Add attacks
        for atk in (attack_history or []):
            domain = atk.get("domain", target)
            graph.add_attack(
                domain,
                atk.get("attack_type", atk.get("type", "unknown")),
                success=bool(atk.get("success")),
                url=atk.get("url", ""),
            )

        # Add findings
        for f in (findings or []):
            domain = f.get("domain", target)
            graph.add_finding(
                domain,
                vuln_type=f.get("vuln_type", f.get("type", "unknown")),
                attack_type=f.get("attack_type", f.get("source", "")),
                severity=f.get("severity", "info"),
                confidence=f.get("confidence", 0),
                url=f.get("url", ""),
            )

        return graph

    def __len__(self) -> int:
        return self.graph.number_of_nodes()

    def __repr__(self) -> str:
        return (
            f"AttackGraph(nodes={self.graph.number_of_nodes()}, "
            f"edges={self.graph.number_of_edges()})"
        )
