"""BloodHound runner — collector + JSON ingestion + analysis.

Two operating modes:

1. **Collector mode** — drive `bloodhound-python` (Linux/cross-platform) or
   document the SharpHound deploy steps. Output: directory of .json files
   (users.json, computers.json, groups.json, domains.json, ous.json, etc.).

2. **Ingestion mode** — read those .json files, build an in-memory networkx
   DiGraph of the AD forest. No Neo4j required for the queries this module
   ships. (Optional Neo4j connector is also provided for users who want
   the full BloodHound CE web UI.)

Pre-canned queries live in pentest/bh_queries.py — they operate on the
in-memory graph this module produces.

No third-party deps for parser/queries beyond `networkx` (already used by
core/graph_engine.py per the project layout).
"""

from __future__ import annotations

import asyncio
import json
import logging
import shutil
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Optional

logger = logging.getLogger("viper.bloodhound")


# ---------------------------------------------------------------------------
# Data shapes
# ---------------------------------------------------------------------------


@dataclass
class BHNode:
    sid: str  # AD SID (S-1-5-21-...) or BH ObjectIdentifier
    name: str
    type: str  # "User" | "Computer" | "Group" | "Domain" | "OU" | "GPO"
    properties: dict = field(default_factory=dict)


@dataclass
class BHEdge:
    src: str
    dst: str
    kind: str  # "MemberOf" | "AdminTo" | "GenericAll" | "DCSync" | etc.


@dataclass
class BHGraph:
    nodes: dict[str, BHNode] = field(default_factory=dict)
    edges: list[BHEdge] = field(default_factory=list)

    def add_node(self, n: BHNode) -> None:
        self.nodes[n.sid] = n

    def add_edge(self, e: BHEdge) -> None:
        self.edges.append(e)

    def to_networkx(self):
        """Convert to networkx.DiGraph. Lazy-imports networkx."""
        import networkx as nx
        g = nx.DiGraph()
        for n in self.nodes.values():
            # Drop keys that conflict with our explicit attrs
            extra = {k: v for k, v in n.properties.items() if k not in ("name", "type")}
            g.add_node(n.sid, name=n.name, type=n.type, **extra)
        for e in self.edges:
            g.add_edge(e.src, e.dst, kind=e.kind)
        return g

    @property
    def stats(self) -> dict:
        type_counts: dict[str, int] = {}
        for n in self.nodes.values():
            type_counts[n.type] = type_counts.get(n.type, 0) + 1
        edge_kinds: dict[str, int] = {}
        for e in self.edges:
            edge_kinds[e.kind] = edge_kinds.get(e.kind, 0) + 1
        return {
            "nodes_total": len(self.nodes),
            "nodes_by_type": type_counts,
            "edges_total": len(self.edges),
            "edges_by_kind": edge_kinds,
        }


# ---------------------------------------------------------------------------
# Collector
# ---------------------------------------------------------------------------


@dataclass
class CollectorResult:
    success: bool
    output_dir: Path
    domain: str = ""
    json_files: list[Path] = field(default_factory=list)
    stdout: str = ""
    stderr: str = ""
    error: Optional[str] = None


async def run_collector_python(
    *,
    domain: str,
    user: str,
    password: str = "",
    nthash: str = "",
    dc_ip: str,
    output_dir: Path,
    collection: str = "Default",
    timeout: float = 600.0,
) -> CollectorResult:
    """Run bloodhound-python collector against a target domain.

    bloodhound-python is the cross-platform Python collector (pip install bloodhound).

    collection: "Default" | "All" | "Group,LocalAdmin,Session,Trusts" | etc.
    """
    binary = shutil.which("bloodhound-python")
    if binary is None:
        # Try python -m fallback
        try:
            import bloodhound  # type: ignore
            import sys
            cmd_prefix = [sys.executable, "-m", "bloodhound"]
        except ImportError:
            return CollectorResult(
                success=False, output_dir=output_dir,
                error="bloodhound-python not installed (pip install bloodhound)",
            )
    else:
        cmd_prefix = [binary]

    output_dir.mkdir(parents=True, exist_ok=True)
    args = [
        "-d", domain,
        "-u", user,
        "-ns", dc_ip,
        "-c", collection,
        "--zip",  # collected output as zip
    ]
    if nthash:
        args += ["--hashes", f":{nthash}"]
    elif password:
        args += ["-p", password]

    cmd = [*cmd_prefix, *args]
    logger.info("running: %s", " ".join(cmd))

    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        cwd=str(output_dir),
    )
    try:
        out_b, err_b = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        proc.kill()
        return CollectorResult(
            success=False, output_dir=output_dir,
            error=f"timeout after {timeout}s",
        )

    json_files = sorted(output_dir.glob("*.json")) + sorted(output_dir.glob("*.zip"))
    return CollectorResult(
        success=proc.returncode == 0,
        output_dir=output_dir,
        domain=domain,
        json_files=json_files,
        stdout=out_b.decode("utf-8", errors="replace"),
        stderr=err_b.decode("utf-8", errors="replace"),
        error=None if proc.returncode == 0 else f"collector exit {proc.returncode}",
    )


def sharphound_command(
    *,
    output_dir: str = ".",
    collection: str = "Default",
    domain: Optional[str] = None,
    randomize_filenames: bool = True,
) -> str:
    """Build a SharpHound.exe command line for the user to run on the
    Windows target. (We don't deploy/exec SharpHound from here — that's
    transport-specific; this just documents the command.)"""
    parts = [
        "SharpHound.exe",
        f"--CollectionMethods {collection}",
        f"--OutputDirectory \"{output_dir}\"",
    ]
    if domain:
        parts.append(f"--Domain {domain}")
    if randomize_filenames:
        parts.append("--RandomizeFilenames --PrettyPrint")
    return " ".join(parts)


# ---------------------------------------------------------------------------
# Parser — read collector .json files into BHGraph
# ---------------------------------------------------------------------------


_TYPE_FILE_MAP = {
    "users": "User",
    "computers": "Computer",
    "groups": "Group",
    "domains": "Domain",
    "ous": "OU",
    "gpos": "GPO",
    "containers": "Container",
}


def parse_dump(dump_dir: Path) -> BHGraph:
    """Read a directory of BloodHound .json files into a BHGraph.

    Supports both legacy BloodHound (Cobbr) and modern BHCE (SpecterOps) JSON
    schemas. Schema autodetected per file.
    """
    graph = BHGraph()
    if not dump_dir.exists():
        return graph

    json_files = list(dump_dir.glob("*.json"))
    for jf in json_files:
        # Pick type from filename: e.g. "20260507100000_users.json" -> "users"
        stem = jf.stem.lower()
        node_type = None
        for key, t in _TYPE_FILE_MAP.items():
            if key in stem:
                node_type = t
                break
        if node_type is None:
            continue
        try:
            data = json.loads(jf.read_text(encoding="utf-8", errors="replace"))
        except (json.JSONDecodeError, OSError):
            continue
        _ingest_file(graph, data, node_type)

    return graph


def _ingest_file(graph: BHGraph, data: dict, node_type: str) -> None:
    items = data.get("data", []) if isinstance(data, dict) else data
    if not isinstance(items, list):
        return
    for item in items:
        if not isinstance(item, dict):
            continue
        # Modern BH schema: ObjectIdentifier + Properties
        sid = item.get("ObjectIdentifier") or item.get("objectid") or ""
        props = item.get("Properties") or item.get("properties") or {}
        name = props.get("name") or props.get("Name") or props.get("samaccountname") or sid
        graph.add_node(BHNode(
            sid=sid,
            name=str(name).upper(),
            type=node_type,
            properties=props,
        ))
        # Edges from this node
        _extract_edges(graph, item, sid, node_type)


def _extract_edges(graph: BHGraph, item: dict, src_sid: str, node_type: str) -> None:
    """Pull edges from a node entry. Handles common BH edge fields."""
    # Common edge collections in BH JSON:
    edge_fields = [
        ("MemberOf", "MemberOf"),
        ("Members", "MemberOf"),  # reversed edge
        ("AdminTo", "AdminTo"),
        ("LocalAdmins", "AdminTo"),  # reversed
        ("DcomUsers", "ExecuteDCOM"),
        ("RemoteDesktopUsers", "CanRDP"),
        ("PSRemoteUsers", "CanPSRemote"),
        ("Sessions", "HasSession"),
        ("AllowedToDelegate", "AllowedToDelegate"),
        ("Aces", "ACE"),  # special — has .RightName field
    ]
    for field_name, edge_kind in edge_fields:
        edges = item.get(field_name) or []
        if not isinstance(edges, list):
            continue
        for edge in edges:
            if not isinstance(edge, dict):
                continue
            target = edge.get("ObjectIdentifier") or edge.get("MemberId") or edge.get("PrincipalSID") or edge.get("ComputerSID") or edge.get("UserSID")
            if not target:
                continue

            actual_kind = edge_kind
            if edge_kind == "ACE":
                # ACE has a RightName like "GenericAll" / "WriteOwner" / "DCSync"
                actual_kind = edge.get("RightName") or edge.get("rightname") or "ACE"

            # Reversed edges
            if field_name in ("Members", "LocalAdmins"):
                graph.add_edge(BHEdge(src=target, dst=src_sid, kind=actual_kind))
            else:
                graph.add_edge(BHEdge(src=src_sid, dst=target, kind=actual_kind))


# ---------------------------------------------------------------------------
# Optional Neo4j connector (no-op if neo4j package not installed)
# ---------------------------------------------------------------------------


@dataclass
class Neo4jConfig:
    uri: str = "bolt://localhost:7687"
    user: str = "neo4j"
    password: str = "BloodHound"


async def push_to_neo4j(graph: BHGraph, cfg: Neo4jConfig) -> dict:
    """Optional: push our parsed graph into a Neo4j DB so user can use the
    BloodHound web UI for visualization. Requires `pip install neo4j`.

    Best-effort: returns a status dict; never raises.
    """
    try:
        from neo4j import GraphDatabase  # type: ignore
    except ImportError:
        return {"ok": False, "error": "neo4j package not installed"}

    def _push():
        driver = GraphDatabase.driver(cfg.uri, auth=(cfg.user, cfg.password))
        n_nodes = 0
        n_edges = 0
        try:
            with driver.session() as session:
                for n in graph.nodes.values():
                    session.run(
                        f"MERGE (x:{n.type} {{sid: $sid}}) "
                        f"SET x.name = $name",
                        sid=n.sid, name=n.name,
                    )
                    n_nodes += 1
                for e in graph.edges:
                    # Sanitize edge kind for Cypher relationship name
                    kind = "".join(c for c in e.kind if c.isalnum()) or "RELATED"
                    session.run(
                        f"MATCH (a {{sid: $src}}), (b {{sid: $dst}}) "
                        f"MERGE (a)-[r:{kind}]->(b)",
                        src=e.src, dst=e.dst,
                    )
                    n_edges += 1
        finally:
            driver.close()
        return {"ok": True, "nodes_pushed": n_nodes, "edges_pushed": n_edges}

    return await asyncio.to_thread(_push)
