"""
VIPER 4.0 - MITRE CWE/CAPEC Enrichment Engine
================================================
Offline CVE -> CWE -> CAPEC enrichment using local JSON databases
from CVE2CAPEC (https://github.com/Galeax/CVE2CAPEC).

Database structure (data/mitre_db/):
    database/CVE-YYYY.jsonl  - CVE -> {CWE[], CAPEC[], TECHNIQUES[]}
    resources/cwe_db.json    - CWE -> {ChildOf[], RelatedAttackPatterns[]}
    resources/capec_db.json  - CAPEC -> {name, techniques}
    resources/cwe_metadata.json   - CWE -> {name, description, consequences, mitigations, ...}
    resources/capec_metadata.json - CAPEC -> {name, description, ...}

No external dependencies. Stdlib only.
"""

import json
import os
from pathlib import Path
from typing import Dict, List, Optional


# Default DB path relative to this file's parent
_DEFAULT_DB_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "data", "mitre_db"
)


class MitreEnricher:
    """Offline MITRE CWE/CAPEC enrichment from local JSON databases."""

    def __init__(self, db_path: str = None):
        self.db_path = Path(db_path or _DEFAULT_DB_PATH)
        self._cve_index: Dict[str, dict] = {}  # Lazy-loaded per-year
        self._loaded_years: set = set()
        self._cwe_db: Optional[dict] = None
        self._capec_db: Optional[dict] = None
        self._cwe_metadata: Optional[dict] = None
        self._capec_metadata: Optional[dict] = None

    # =========================================================================
    # Database Loading (lazy)
    # =========================================================================

    def _load_cwe_db(self) -> dict:
        if self._cwe_db is None:
            path = self.db_path / "resources" / "cwe_db.json"
            if path.exists():
                with open(path, "r", encoding="utf-8") as f:
                    self._cwe_db = json.load(f)
            else:
                self._cwe_db = {}
        return self._cwe_db

    def _load_capec_db(self) -> dict:
        if self._capec_db is None:
            path = self.db_path / "resources" / "capec_db.json"
            if path.exists():
                with open(path, "r", encoding="utf-8") as f:
                    self._capec_db = json.load(f)
            else:
                self._capec_db = {}
        return self._capec_db

    def _load_cwe_metadata(self) -> dict:
        if self._cwe_metadata is None:
            path = self.db_path / "resources" / "cwe_metadata.json"
            if path.exists():
                with open(path, "r", encoding="utf-8") as f:
                    self._cwe_metadata = json.load(f)
            else:
                self._cwe_metadata = {}
        return self._cwe_metadata

    def _load_capec_metadata(self) -> dict:
        if self._capec_metadata is None:
            path = self.db_path / "resources" / "capec_metadata.json"
            if path.exists():
                with open(path, "r", encoding="utf-8") as f:
                    self._capec_metadata = json.load(f)
            else:
                self._capec_metadata = {}
        return self._capec_metadata

    def _load_cve_year(self, year: str):
        """Load a CVE-YYYY.jsonl file into the index."""
        if year in self._loaded_years:
            return
        path = self.db_path / "database" / f"CVE-{year}.jsonl"
        if path.exists():
            with open(path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        entry = json.loads(line)
                        # Each line is {cve_id: {CWE:[], CAPEC:[], TECHNIQUES:[]}}
                        for cve_id, data in entry.items():
                            self._cve_index[cve_id] = data
                    except json.JSONDecodeError:
                        continue
        self._loaded_years.add(year)

    def _ensure_cve_loaded(self, cve_id: str):
        """Ensure the year for a given CVE is loaded."""
        # CVE-YYYY-NNNNN -> extract YYYY
        parts = cve_id.split("-")
        if len(parts) >= 3:
            year = parts[1]
            self._load_cve_year(year)

    # =========================================================================
    # Public API
    # =========================================================================

    def enrich_cve(self, cve_id: str) -> dict:
        """
        Enrich a CVE with CWE weaknesses and CAPEC attack patterns.

        Returns:
            {
                "cve_id": "CVE-2024-12345",
                "cwes": [
                    {
                        "cwe_id": "CWE-79",
                        "name": "...",
                        "description": "...",
                        "abstraction": "...",
                        "likelihood_of_exploit": "...",
                        "consequences": [...],
                        "mitigations": [...],
                        "capecs": [
                            {"capec_id": "CAPEC-86", "name": "...", ...}
                        ]
                    }
                ],
                "direct_capecs": ["86", "53", ...],
                "technique_ids": ["T1027", ...]
            }
        """
        cve_id = cve_id.upper().strip()
        self._ensure_cve_loaded(cve_id)

        result = {
            "cve_id": cve_id,
            "cwes": [],
            "direct_capecs": [],
            "technique_ids": [],
        }

        cve_data = self._cve_index.get(cve_id)
        if not cve_data:
            return result

        # Extract CWE IDs and CAPEC IDs from CVE2CAPEC database
        cwe_ids = cve_data.get("CWE", [])
        direct_capec_ids = cve_data.get("CAPEC", [])
        technique_ids = cve_data.get("TECHNIQUES", [])

        result["direct_capecs"] = [str(c) for c in direct_capec_ids]
        result["technique_ids"] = [str(t) for t in technique_ids]

        # Enrich each CWE
        for cwe_id in cwe_ids:
            cwe_info = self.get_cwe(str(cwe_id))
            if cwe_info:
                # Attach related CAPECs
                capecs = self.get_capecs_for_cwe(str(cwe_id))
                cwe_info["capecs"] = capecs
                result["cwes"].append(cwe_info)

        return result

    def enrich_vulnerability(self, vuln: dict) -> dict:
        """
        Enrich a vulnerability dict with MITRE data from its CVE references.

        Looks for CVE IDs in vuln["cve"], vuln["cve_id"], vuln["references"],
        or vuln["id"] fields.

        Returns the vuln dict with added "mitre_enrichment" key.
        """
        cve_ids = set()

        # Extract CVE IDs from various fields
        for field in ("cve", "cve_id", "id"):
            val = vuln.get(field, "")
            if isinstance(val, str) and val.upper().startswith("CVE-"):
                cve_ids.add(val.upper())
            elif isinstance(val, list):
                for v in val:
                    if isinstance(v, str) and v.upper().startswith("CVE-"):
                        cve_ids.add(v.upper())

        # Check references list
        refs = vuln.get("references", [])
        if isinstance(refs, list):
            for ref in refs:
                r = ref if isinstance(ref, str) else ref.get("url", "")
                # Extract CVE-YYYY-NNNNN from URLs/strings
                import re
                for match in re.finditer(r"CVE-\d{4}-\d{4,}", r, re.IGNORECASE):
                    cve_ids.add(match.group(0).upper())

        enrichments = []
        for cve_id in sorted(cve_ids):
            enrichment = self.enrich_cve(cve_id)
            if enrichment["cwes"] or enrichment["direct_capecs"]:
                enrichments.append(enrichment)

        vuln["mitre_enrichment"] = enrichments
        return vuln

    def get_cwe(self, cwe_id: str) -> Optional[dict]:
        """
        Get CWE details combining cwe_db.json (hierarchy) and cwe_metadata.json (details).

        Args:
            cwe_id: CWE ID as string (e.g., "79" or "CWE-79")

        Returns:
            Dict with CWE details or None if not found.
        """
        # Normalize: strip "CWE-" prefix
        cwe_id = str(cwe_id).replace("CWE-", "").strip()

        cwe_db = self._load_cwe_db()
        cwe_meta = self._load_cwe_metadata()

        hierarchy = cwe_db.get(cwe_id, {})
        metadata = cwe_meta.get(cwe_id, {})

        if not hierarchy and not metadata:
            return None

        result = {
            "cwe_id": f"CWE-{cwe_id}",
            "name": metadata.get("name", "Unknown"),
            "abstraction": metadata.get("abstraction", ""),
            "mapping": metadata.get("mapping", ""),
            "description": metadata.get("description", ""),
        }

        # Optional detailed fields from metadata
        if metadata.get("extended_description"):
            result["extended_description"] = metadata["extended_description"]
        if metadata.get("likelihood_of_exploit"):
            result["likelihood_of_exploit"] = metadata["likelihood_of_exploit"]
        if metadata.get("consequences"):
            result["consequences"] = metadata["consequences"]
        if metadata.get("mitigations"):
            result["mitigations"] = metadata["mitigations"]
        if metadata.get("detection_methods"):
            result["detection_methods"] = metadata["detection_methods"]
        if metadata.get("observed_examples"):
            result["observed_examples"] = metadata["observed_examples"]

        # Hierarchy from cwe_db
        if hierarchy.get("ChildOf"):
            result["parent_cwes"] = [f"CWE-{p}" for p in hierarchy["ChildOf"]]
        if hierarchy.get("RelatedAttackPatterns"):
            result["related_capec_ids"] = [str(c) for c in hierarchy["RelatedAttackPatterns"]]

        return result

    def get_capec(self, capec_id: str) -> Optional[dict]:
        """
        Get CAPEC attack pattern details.

        Args:
            capec_id: CAPEC ID as string (e.g., "86" or "CAPEC-86")

        Returns:
            Dict with CAPEC details or None if not found.
        """
        capec_id = str(capec_id).replace("CAPEC-", "").strip()

        capec_db = self._load_capec_db()
        capec_meta = self._load_capec_metadata()

        basic = capec_db.get(capec_id, {})
        metadata = capec_meta.get(capec_id, {})

        if not basic and not metadata:
            return None

        result = {
            "capec_id": f"CAPEC-{capec_id}",
            "name": basic.get("name") or metadata.get("name", "Unknown"),
        }

        # Detailed metadata if available
        if metadata.get("description"):
            result["description"] = metadata["description"]
        if metadata.get("abstraction"):
            result["abstraction"] = metadata["abstraction"]
        if metadata.get("status"):
            result["status"] = metadata["status"]
        if metadata.get("prerequisites"):
            result["prerequisites"] = metadata["prerequisites"]
        if metadata.get("consequences"):
            result["consequences"] = metadata["consequences"]
        if metadata.get("mitigations"):
            result["mitigations"] = metadata["mitigations"]
        if metadata.get("severity"):
            result["severity"] = metadata["severity"]
        if metadata.get("likelihood"):
            result["likelihood"] = metadata["likelihood"]

        # Technique references from capec_db
        techniques_raw = basic.get("techniques", "")
        if techniques_raw:
            result["techniques_raw"] = techniques_raw

        return result

    def get_capecs_for_cwe(self, cwe_id: str) -> list:
        """
        Get all CAPEC entries related to a CWE.

        Uses the RelatedAttackPatterns field from cwe_db.json.
        """
        cwe_id = str(cwe_id).replace("CWE-", "").strip()
        cwe_db = self._load_cwe_db()
        entry = cwe_db.get(cwe_id, {})
        capec_ids = entry.get("RelatedAttackPatterns", [])

        results = []
        for capec_id in capec_ids:
            capec = self.get_capec(str(capec_id))
            if capec:
                results.append(capec)
        return results

    def get_attack_surface(self, cve_ids: list) -> dict:
        """
        Build an attack surface summary from multiple CVEs.

        Returns:
            {
                "total_cves": N,
                "enriched_cves": N,
                "unique_cwes": [...],
                "unique_capecs": [...],
                "attack_categories": {...},
                "severity_distribution": {...}
            }
        """
        all_cwes = {}
        all_capecs = {}

        enriched = 0
        for cve_id in cve_ids:
            result = self.enrich_cve(cve_id)
            if result["cwes"] or result["direct_capecs"]:
                enriched += 1
            for cwe in result["cwes"]:
                cid = cwe["cwe_id"]
                if cid not in all_cwes:
                    all_cwes[cid] = cwe
                for capec in cwe.get("capecs", []):
                    pid = capec["capec_id"]
                    if pid not in all_capecs:
                        all_capecs[pid] = capec

        return {
            "total_cves": len(cve_ids),
            "enriched_cves": enriched,
            "unique_cwes": list(all_cwes.values()),
            "unique_capecs": list(all_capecs.values()),
            "cwe_count": len(all_cwes),
            "capec_count": len(all_capecs),
        }


# =============================================================================
# Module-level convenience
# =============================================================================

_default_enricher: Optional[MitreEnricher] = None


def _get_enricher() -> MitreEnricher:
    global _default_enricher
    if _default_enricher is None:
        _default_enricher = MitreEnricher()
    return _default_enricher


def enrich(cve_id: str) -> dict:
    """Quick enrichment for a single CVE."""
    return _get_enricher().enrich_cve(cve_id)


def enrich_bulk(cve_ids: list) -> list:
    """Enrich multiple CVEs."""
    enricher = _get_enricher()
    return [enricher.enrich_cve(cve) for cve in cve_ids]


def attack_surface(cve_ids: list) -> dict:
    """Build attack surface summary from CVE list."""
    return _get_enricher().get_attack_surface(cve_ids)


if __name__ == "__main__":
    # Quick test
    e = MitreEnricher()
    print("[*] MITRE Enricher loaded")
    print(f"    DB path: {e.db_path}")
    print(f"    CWE DB entries: {len(e._load_cwe_db())}")
    print(f"    CAPEC DB entries: {len(e._load_capec_db())}")

    # Test enrichment
    test_cve = "CVE-2024-21732"
    result = e.enrich_cve(test_cve)
    print(f"\n[*] Enrichment for {test_cve}:")
    print(f"    CWEs: {[c['cwe_id'] for c in result['cwes']]}")
    print(f"    Direct CAPECs: {len(result['direct_capecs'])}")
    if result["cwes"]:
        cwe = result["cwes"][0]
        print(f"    First CWE: {cwe['cwe_id']} - {cwe['name']}")
        print(f"    CAPECs for this CWE: {len(cwe.get('capecs', []))}")
