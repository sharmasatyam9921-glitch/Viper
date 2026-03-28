"""IANA port-to-service name mapping (15,000+ entries).

Singleton loader for the IANA Service Name and Transport Protocol Port Number Registry.
Data source: data/iana_services.csv (downloaded from IANA).

Usage:
    from core.iana_services import IANAServices
    svc = IANAServices.get_instance()
    print(svc.get_service(443))       # "https"
    print(svc.get_port("ssh"))        # 22
    print(svc.is_database_port(3306)) # True
"""

import csv
import logging
import os
from typing import Dict, List, Optional, Set, Tuple

logger = logging.getLogger("viper.iana_services")

# Well-known admin/management ports
_ADMIN_PORTS: Set[int] = {
    22, 23, 2222,           # SSH, Telnet
    3389,                    # RDP
    5900, 5901, 5902,       # VNC
    8080, 8443, 8888,       # HTTP admin/alt
    9090, 9200, 9443,       # Management consoles
    10000,                   # Webmin
    2082, 2083, 2086, 2087, # cPanel
    8006,                    # Proxmox
    8834,                    # Nessus
    4848,                    # GlassFish admin
    9000,                    # SonarQube / Portainer
    7071,                    # Zimbra admin
    6080, 6443,             # K8s
    2376, 2377,             # Docker
}

# Well-known database ports
_DATABASE_PORTS: Set[int] = {
    3306,   # MySQL / MariaDB
    5432,   # PostgreSQL
    1433,   # MSSQL
    1521,   # Oracle
    27017,  # MongoDB
    6379,   # Redis
    9042,   # Cassandra
    5984,   # CouchDB
    8529,   # ArangoDB
    7474,   # Neo4j
    8086,   # InfluxDB
    11211,  # Memcached
    9200,   # Elasticsearch
    26257,  # CockroachDB
    28015,  # RethinkDB
    7000, 7001,  # Cassandra inter-node
    6380,   # Redis (alt)
}


class IANAServices:
    """Singleton IANA port/service registry."""

    _instance = None

    @classmethod
    def get_instance(cls) -> "IANAServices":
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    def __init__(self):
        self._services: Dict[Tuple[int, str], str] = {}   # (port, proto) -> name
        self._names: Dict[str, int] = {}                    # name -> first port
        self._loaded = False
        self._load()

    def _load(self):
        """Load from data/iana_services.csv."""
        csv_path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "data", "iana_services.csv",
        )
        if not os.path.exists(csv_path):
            logger.warning("IANA services CSV not found: %s", csv_path)
            return

        count = 0
        try:
            with open(csv_path, newline="", encoding="utf-8") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    name = (row.get("Service Name") or "").strip().lower()
                    port_str = (row.get("Port Number") or "").strip()
                    proto = (row.get("Transport Protocol") or "").strip().lower()

                    if not name or not port_str or not proto:
                        continue

                    # Handle port ranges like "49152-65535"
                    if "-" in port_str:
                        continue  # Skip ranges, only store specific ports

                    try:
                        port = int(port_str)
                    except ValueError:
                        continue

                    self._services[(port, proto)] = name
                    # Reverse map: first occurrence wins
                    if name not in self._names:
                        self._names[name] = port
                    count += 1

            self._loaded = True
            logger.info("Loaded %d IANA service entries", count)
        except Exception as e:
            logger.error("Failed to load IANA services: %s", e)

    def get_service(self, port: int, protocol: str = "tcp") -> str:
        """Get friendly service name for a port.

        Args:
            port: Port number.
            protocol: Transport protocol ("tcp" or "udp"). Defaults to "tcp".

        Returns:
            Service name string, or "unknown" if not found.
        """
        name = self._services.get((port, protocol.lower()))
        if name:
            return name
        # Fallback: try the other protocol
        alt = "udp" if protocol.lower() == "tcp" else "tcp"
        return self._services.get((port, alt), "unknown")

    def get_port(self, service_name: str) -> Optional[int]:
        """Reverse lookup: service name to port.

        Args:
            service_name: Service name (e.g. "ssh", "http", "mysql").

        Returns:
            Port number, or None if not found.
        """
        return self._names.get(service_name.strip().lower())

    def is_admin_port(self, port: int) -> bool:
        """Check if port is typically an admin/management port."""
        if port in _ADMIN_PORTS:
            return True
        # Also check IANA name for admin-ish keywords
        name = self.get_service(port)
        if name == "unknown":
            return False
        admin_keywords = {"admin", "manage", "console", "control", "panel", "webmin"}
        return any(kw in name for kw in admin_keywords)

    def is_database_port(self, port: int) -> bool:
        """Check if port is typically a database port."""
        if port in _DATABASE_PORTS:
            return True
        name = self.get_service(port)
        if name == "unknown":
            return False
        db_keywords = {"mysql", "postgres", "mongo", "redis", "oracle", "mssql",
                       "cassandra", "couch", "elastic", "influx", "memcache",
                       "neo4j", "arango", "cockroach"}
        return any(kw in name for kw in db_keywords)

    def get_services_in_range(self, start: int, end: int,
                               protocol: str = "tcp") -> Dict[int, str]:
        """Get all known services in a port range.

        Args:
            start: Start port (inclusive).
            end: End port (inclusive).
            protocol: Transport protocol.

        Returns:
            Dict of {port: service_name}.
        """
        proto = protocol.lower()
        result = {}
        for (p, pr), name in self._services.items():
            if pr == proto and start <= p <= end:
                result[p] = name
        return dict(sorted(result.items()))

    def enrich_port_list(self, ports: List[int],
                          protocol: str = "tcp") -> List[Dict]:
        """Enrich a list of open ports with service info.

        Args:
            ports: List of port numbers.
            protocol: Transport protocol.

        Returns:
            List of {"port": int, "service": str, "is_admin": bool, "is_database": bool}.
        """
        return [
            {
                "port": p,
                "service": self.get_service(p, protocol),
                "is_admin": self.is_admin_port(p),
                "is_database": self.is_database_port(p),
            }
            for p in sorted(ports)
        ]

    @property
    def total_entries(self) -> int:
        return len(self._services)

    def __repr__(self) -> str:
        return f"IANAServices(entries={self.total_entries}, loaded={self._loaded})"
