#!/usr/bin/env python3
"""
VIPER 4.0 - Offline MITRE CVE/CWE/CAPEC Enrichment Engine
===========================================================
Provides offline CVE -> CWE -> CAPEC -> ATT&CK enrichment using local
JSON databases from CVE2CAPEC (https://github.com/Galeax/CVE2CAPEC).

Database layout (data/mitre_db/):
    database/CVE-YYYY.jsonl    - CVE -> {CWE[], CAPEC[], TECHNIQUES[]}
    resources/cwe_db.json      - CWE hierarchy + RelatedAttackPatterns
    resources/capec_db.json    - CAPEC patterns + technique refs
    resources/cwe_metadata.json   - Full CWE details (name, desc, mitigations)
    resources/capec_metadata.json - Full CAPEC details (name, desc, severity)

No external dependencies required for enrichment. Only stdlib.
Download function requires 'requests'.
"""

import json
import os
import re
from pathlib import Path
from typing import Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

_BASE_DIR = Path(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
_DEFAULT_DB_PATH = _BASE_DIR / "data" / "mitre_db"

# CVE2CAPEC GitHub raw URLs
_CVE2CAPEC_RAW = "https://raw.githubusercontent.com/Galeax/CVE2CAPEC/main"
_RESOURCE_FILES = ["resources/capec_db.json", "resources/cwe_db.json"]
_DATABASE_YEARS = list(range(1999, 2027))


# ---------------------------------------------------------------------------
# Singleton cache
# ---------------------------------------------------------------------------

class _Cache:
    """In-memory cache for loaded MITRE databases."""
    cwe_db: Optional[dict] = None
    capec_db: Optional[dict] = None
    cwe_metadata: Optional[dict] = None
    capec_metadata: Optional[dict] = None
    cve_index: Dict[str, dict] = {}
    loaded_years: set = set()
    db_path: Path = _DEFAULT_DB_PATH

_cache = _Cache()


def _reset_cache(db_path: Path = None):
    """Reset the cache (useful for testing or switching DB paths)."""
    _cache.cwe_db = None
    _cache.capec_db = None
    _cache.cwe_metadata = None
    _cache.capec_metadata = None
    _cache.cve_index = {}
    _cache.loaded_years = set()
    if db_path:
        _cache.db_path = db_path


def set_db_path(path: str):
    """Set a custom database path and reset the cache."""
    _reset_cache(Path(path))


# ---------------------------------------------------------------------------
# Lazy loaders
# ---------------------------------------------------------------------------

def _load_json(filename: str) -> dict:
    """Load a JSON file from the resources directory."""
    path = _cache.db_path / "resources" / filename
    if path.exists():
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    return {}


def _get_cwe_db() -> dict:
    if _cache.cwe_db is None:
        _cache.cwe_db = _load_json("cwe_db.json")
    return _cache.cwe_db


def _get_capec_db() -> dict:
    if _cache.capec_db is None:
        _cache.capec_db = _load_json("capec_db.json")
    return _cache.capec_db


def _get_cwe_metadata() -> dict:
    if _cache.cwe_metadata is None:
        _cache.cwe_metadata = _load_json("cwe_metadata.json")
    return _cache.cwe_metadata


def _get_capec_metadata() -> dict:
    if _cache.capec_metadata is None:
        _cache.capec_metadata = _load_json("capec_metadata.json")
    return _cache.capec_metadata


def _load_cve_year(year: str):
    """Load CVE-YYYY.jsonl into the in-memory index."""
    if year in _cache.loaded_years:
        return
    path = _cache.db_path / "database" / f"CVE-{year}.jsonl"
    if path.exists():
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                    for cve_id, data in entry.items():
                        _cache.cve_index[cve_id] = data
                except json.JSONDecodeError:
                    continue
    _cache.loaded_years.add(year)


def _ensure_cve_loaded(cve_id: str):
    """Load the year file for a given CVE ID."""
    parts = cve_id.split("-")
    if len(parts) >= 3:
        _load_cve_year(parts[1])


# ---------------------------------------------------------------------------
# Technology -> CVE mapping (built from loaded CVE data + CWE metadata)
# ---------------------------------------------------------------------------

# Common technology keywords to CWE families
_TECH_CWE_MAP: Dict[str, List[str]] = {
    "apache": ["CWE-79", "CWE-22", "CWE-200", "CWE-400"],
    "nginx": ["CWE-444", "CWE-22", "CWE-200"],
    "wordpress": ["CWE-79", "CWE-89", "CWE-352", "CWE-434"],
    "php": ["CWE-79", "CWE-89", "CWE-78", "CWE-22", "CWE-98"],
    "java": ["CWE-502", "CWE-611", "CWE-89", "CWE-79"],
    "spring": ["CWE-502", "CWE-917", "CWE-79", "CWE-89"],
    "node": ["CWE-1321", "CWE-78", "CWE-22", "CWE-400"],
    "express": ["CWE-79", "CWE-22", "CWE-352", "CWE-1321"],
    "django": ["CWE-79", "CWE-89", "CWE-352", "CWE-22"],
    "flask": ["CWE-79", "CWE-94", "CWE-22"],
    "react": ["CWE-79", "CWE-1321"],
    "angular": ["CWE-79"],
    "mysql": ["CWE-89", "CWE-200", "CWE-287"],
    "postgresql": ["CWE-89", "CWE-200", "CWE-287"],
    "mongodb": ["CWE-943", "CWE-200", "CWE-287"],
    "redis": ["CWE-287", "CWE-200"],
    "docker": ["CWE-250", "CWE-284", "CWE-200"],
    "kubernetes": ["CWE-284", "CWE-287", "CWE-200"],
    "iis": ["CWE-22", "CWE-200", "CWE-693"],
    "tomcat": ["CWE-22", "CWE-200", "CWE-502"],
    "jenkins": ["CWE-78", "CWE-502", "CWE-284"],
    "grafana": ["CWE-22", "CWE-287", "CWE-200"],
    "elasticsearch": ["CWE-200", "CWE-287", "CWE-94"],
    "openssl": ["CWE-327", "CWE-311", "CWE-125"],
}


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def enrich_cve(cve_id: str) -> dict:
    """
    Look up a CVE and return full CWE + CAPEC + ATT&CK enrichment.

    Args:
        cve_id: CVE identifier (e.g. "CVE-2024-12345")

    Returns:
        {
            "cve_id": "CVE-2024-12345",
            "cwes": [{"cwe_id": "CWE-79", "name": ..., "capecs": [...]}],
            "direct_capecs": ["86", ...],
            "technique_ids": ["T1059.007", ...],
            "attack_patterns": [{"capec_id": ..., "name": ..., ...}],
        }
    """
    cve_id = cve_id.upper().strip()
    _ensure_cve_loaded(cve_id)

    result = {
        "cve_id": cve_id,
        "cwes": [],
        "direct_capecs": [],
        "technique_ids": [],
        "attack_patterns": [],
    }

    cve_data = _cache.cve_index.get(cve_id)
    if not cve_data:
        return result

    cwe_ids = cve_data.get("CWE", [])
    direct_capec_ids = cve_data.get("CAPEC", [])
    technique_ids = cve_data.get("TECHNIQUES", [])

    result["direct_capecs"] = [str(c) for c in direct_capec_ids]
    result["technique_ids"] = [str(t) for t in technique_ids]

    # Enrich each CWE
    for cwe_id_num in cwe_ids:
        cwe_info = _get_cwe_details(str(cwe_id_num))
        if cwe_info:
            capecs = get_capec_for_cwe(f"CWE-{cwe_id_num}")
            cwe_info["capecs"] = capecs
            result["cwes"].append(cwe_info)

    # Enrich direct CAPECs
    for capec_id in direct_capec_ids:
        capec_info = _get_capec_details(str(capec_id))
        if capec_info:
            result["attack_patterns"].append(capec_info)

    return result


def enrich_technology(tech_name: str, version: str = None) -> dict:
    """
    Map a technology name/version to known CWEs and CAPEC attack patterns.

    Uses a technology-to-CWE-family mapping plus optional CVE database
    search for version-specific vulnerabilities.

    Args:
        tech_name: Technology name (e.g. "apache", "wordpress", "node")
        version: Optional version string (e.g. "2.4.49")

    Returns:
        {
            "technology": "apache",
            "version": "2.4.49",
            "common_cwes": [...],
            "attack_patterns": [...],
            "cve_matches": [...],  # Only if version provided and CVEs found
        }
    """
    tech_lower = tech_name.lower().strip()
    result = {
        "technology": tech_name,
        "version": version,
        "common_cwes": [],
        "attack_patterns": [],
        "cve_matches": [],
    }

    # Find matching tech family
    matched_cwes = set()
    for tech_key, cwes in _TECH_CWE_MAP.items():
        if tech_key in tech_lower or tech_lower in tech_key:
            matched_cwes.update(cwes)

    # Enrich each CWE
    for cwe_id in sorted(matched_cwes):
        cwe_info = _get_cwe_details(cwe_id.replace("CWE-", ""))
        if cwe_info:
            capecs = get_capec_for_cwe(cwe_id)
            cwe_info["capecs"] = capecs
            result["common_cwes"].append(cwe_info)
            for capec in capecs:
                result["attack_patterns"].append(capec)

    # Version-specific CVE search (scan loaded years)
    if version:
        search_pattern = f"{tech_lower}.*{re.escape(version)}"
        # We search through loaded CVE index descriptions if available
        # For now, rely on CWE mappings which cover the technology family
        pass

    return result


def get_capec_for_cwe(cwe_id: str) -> list:
    """
    Get CAPEC attack patterns associated with a CWE weakness.

    Args:
        cwe_id: CWE identifier (e.g. "CWE-79" or "79")

    Returns:
        List of CAPEC detail dicts with name, description, severity, etc.
    """
    cwe_num = str(cwe_id).replace("CWE-", "").strip()
    cwe_db = _get_cwe_db()
    entry = cwe_db.get(cwe_num, {})
    capec_ids = entry.get("RelatedAttackPatterns", [])

    results = []
    for capec_id in capec_ids:
        capec = _get_capec_details(str(capec_id))
        if capec:
            results.append(capec)
    return results


def get_attack_techniques(capec_id: str) -> list:
    """
    Get ATT&CK technique IDs associated with a CAPEC attack pattern.

    Args:
        capec_id: CAPEC identifier (e.g. "CAPEC-86" or "86")

    Returns:
        List of ATT&CK technique ID strings (e.g. ["T1059.007", "T1185"])
    """
    capec_num = str(capec_id).replace("CAPEC-", "").strip()
    capec_db = _get_capec_db()
    entry = capec_db.get(capec_num, {})

    techniques_raw = entry.get("techniques", "")
    if not techniques_raw:
        return []

    # techniques field can be a string like "T1059.007, T1185" or a list
    if isinstance(techniques_raw, list):
        return [str(t).strip() for t in techniques_raw if t]
    if isinstance(techniques_raw, str):
        return [t.strip() for t in techniques_raw.split(",") if t.strip()]
    return []


def database_available() -> bool:
    """Check if the offline MITRE database is available."""
    resources = _cache.db_path / "resources"
    return (
        (resources / "cwe_db.json").exists()
        and (resources / "capec_db.json").exists()
    )


def database_stats() -> dict:
    """Return statistics about the loaded database."""
    cwe_db = _get_cwe_db()
    capec_db = _get_capec_db()
    cwe_meta = _get_cwe_metadata()
    capec_meta = _get_capec_metadata()

    db_dir = _cache.db_path / "database"
    year_files = sorted(db_dir.glob("CVE-*.jsonl")) if db_dir.exists() else []

    return {
        "db_path": str(_cache.db_path),
        "cwe_entries": len(cwe_db),
        "capec_entries": len(capec_db),
        "cwe_metadata_entries": len(cwe_meta),
        "capec_metadata_entries": len(capec_meta),
        "cve_year_files": len(year_files),
        "cve_years": [f.stem.replace("CVE-", "") for f in year_files],
        "cves_loaded_in_memory": len(_cache.cve_index),
    }


def download_database(db_path: str = None, include_cves: bool = True):
    """
    Download MITRE CVE/CWE/CAPEC databases for offline enrichment.

    Downloads from CVE2CAPEC GitHub repository:
    - resources/cwe_db.json
    - resources/capec_db.json
    - database/CVE-YYYY.jsonl (optional, ~95MB total)

    Args:
        db_path: Custom database path (default: data/mitre_db/)
        include_cves: Whether to download CVE JSONL files (large, ~95MB)
    """
    try:
        import requests
    except ImportError:
        print("[!] 'requests' package required for download. Install with: pip install requests")
        return False

    target = Path(db_path) if db_path else _DEFAULT_DB_PATH
    (target / "resources").mkdir(parents=True, exist_ok=True)
    (target / "database").mkdir(parents=True, exist_ok=True)

    success = True

    # Download resource files
    for resource in _RESOURCE_FILES:
        url = f"{_CVE2CAPEC_RAW}/{resource}"
        dest = target / resource
        print(f"[*] Downloading {resource}...", end=" ", flush=True)
        try:
            resp = requests.get(url, timeout=60)
            resp.raise_for_status()
            dest.write_bytes(resp.content)
            print("OK")
        except Exception as e:
            print(f"FAILED ({e})")
            success = False

    # Download CVE JSONL files
    if include_cves:
        from datetime import datetime
        years = range(1999, datetime.now().year + 1)
        for year in years:
            filename = f"database/CVE-{year}.jsonl"
            url = f"{_CVE2CAPEC_RAW}/{filename}"
            dest = target / filename
            print(f"[*] Downloading CVE-{year}.jsonl...", end=" ", flush=True)
            try:
                resp = requests.get(url, timeout=120)
                if resp.status_code == 404:
                    print("skipped (not found)")
                    continue
                resp.raise_for_status()
                dest.write_bytes(resp.content)
                size_mb = len(resp.content) / (1024 * 1024)
                print(f"OK ({size_mb:.1f} MB)")
            except Exception as e:
                print(f"FAILED ({e})")
                success = False

    # Download CWE and CAPEC metadata (enriched)
    for meta_file in ["resources/cwe_metadata.json", "resources/capec_metadata.json"]:
        url = f"{_CVE2CAPEC_RAW}/{meta_file}"
        dest = target / meta_file
        if not dest.exists():
            print(f"[*] Downloading {meta_file}...", end=" ", flush=True)
            try:
                resp = requests.get(url, timeout=60)
                if resp.status_code == 200:
                    dest.write_bytes(resp.content)
                    print("OK")
                else:
                    print(f"skipped ({resp.status_code})")
            except Exception as e:
                print(f"FAILED ({e})")

    # Write update marker
    from datetime import datetime
    marker = target / ".last_update"
    marker.write_text(datetime.now().isoformat())

    if success:
        print(f"\n[+] Database downloaded to {target}")
    else:
        print(f"\n[!] Some downloads failed. Check output above.")

    # Reset cache to pick up new data
    _reset_cache(target)
    return success


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _get_cwe_details(cwe_num: str) -> Optional[dict]:
    """Get full CWE details from both cwe_db and cwe_metadata."""
    cwe_num = cwe_num.replace("CWE-", "").strip()
    cwe_db = _get_cwe_db()
    cwe_meta = _get_cwe_metadata()

    hierarchy = cwe_db.get(cwe_num, {})
    metadata = cwe_meta.get(cwe_num, {})

    if not hierarchy and not metadata:
        return None

    result = {
        "cwe_id": f"CWE-{cwe_num}",
        "name": metadata.get("name", "Unknown"),
        "description": metadata.get("description", ""),
        "abstraction": metadata.get("abstraction", ""),
    }

    if metadata.get("likelihood_of_exploit"):
        result["likelihood_of_exploit"] = metadata["likelihood_of_exploit"]
    if metadata.get("consequences"):
        result["consequences"] = metadata["consequences"]
    if metadata.get("mitigations"):
        result["mitigations"] = metadata["mitigations"]
    if hierarchy.get("ChildOf"):
        result["parent_cwes"] = [f"CWE-{p}" for p in hierarchy["ChildOf"]]
    if hierarchy.get("RelatedAttackPatterns"):
        result["related_capec_ids"] = [
            f"CAPEC-{c}" for c in hierarchy["RelatedAttackPatterns"]
        ]

    return result


def _get_capec_details(capec_num: str) -> Optional[dict]:
    """Get full CAPEC details from both capec_db and capec_metadata."""
    capec_num = capec_num.replace("CAPEC-", "").strip()
    capec_db = _get_capec_db()
    capec_meta = _get_capec_metadata()

    basic = capec_db.get(capec_num, {})
    metadata = capec_meta.get(capec_num, {})

    if not basic and not metadata:
        return None

    result = {
        "capec_id": f"CAPEC-{capec_num}",
        "name": basic.get("name") or metadata.get("name", "Unknown"),
    }

    if metadata.get("description"):
        result["description"] = metadata["description"]
    if metadata.get("severity"):
        result["severity"] = metadata["severity"]
    if metadata.get("likelihood"):
        result["likelihood"] = metadata["likelihood"]
    if metadata.get("prerequisites"):
        result["prerequisites"] = metadata["prerequisites"]
    if metadata.get("mitigations"):
        result["mitigations"] = metadata["mitigations"]

    # ATT&CK techniques
    techniques = get_attack_techniques(capec_num)
    if techniques:
        result["attack_techniques"] = techniques

    return result


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import sys

    if len(sys.argv) > 1 and sys.argv[1] == "--download":
        include_cves = "--no-cves" not in sys.argv
        download_database(include_cves=include_cves)
        sys.exit(0)

    if not database_available():
        print("[!] MITRE database not found. Run with --download first.")
        print(f"    Expected at: {_DEFAULT_DB_PATH}")
        sys.exit(1)

    stats = database_stats()
    print("[*] MITRE Offline Enrichment Engine")
    print(f"    DB path: {stats['db_path']}")
    print(f"    CWE entries: {stats['cwe_entries']}")
    print(f"    CAPEC entries: {stats['capec_entries']}")
    print(f"    CVE year files: {stats['cve_year_files']}")

    # Test with a CVE if provided
    if len(sys.argv) > 1 and sys.argv[1].upper().startswith("CVE-"):
        cve_id = sys.argv[1].upper()
        print(f"\n[*] Enriching {cve_id}:")
        result = enrich_cve(cve_id)
        print(f"    CWEs: {[c['cwe_id'] for c in result['cwes']]}")
        print(f"    Direct CAPECs: {result['direct_capecs']}")
        print(f"    Techniques: {result['technique_ids']}")
        if result["cwes"]:
            cwe = result["cwes"][0]
            print(f"    First CWE: {cwe['cwe_id']} - {cwe['name']}")
            capecs = cwe.get("capecs", [])
            print(f"    CAPECs for {cwe['cwe_id']}: {len(capecs)}")
            for c in capecs[:3]:
                print(f"      - {c['capec_id']}: {c['name']}")

    # Test technology enrichment
    if len(sys.argv) > 1 and not sys.argv[1].startswith(("CVE-", "--")):
        tech = sys.argv[1]
        ver = sys.argv[2] if len(sys.argv) > 2 else None
        print(f"\n[*] Technology enrichment for: {tech} {ver or ''}")
        result = enrich_technology(tech, ver)
        print(f"    Common CWEs: {[c['cwe_id'] for c in result['common_cwes']]}")
        print(f"    Attack patterns: {len(result['attack_patterns'])}")

    # Test CWE -> CAPEC
    print("\n[*] Sample CWE-79 -> CAPEC:")
    capecs = get_capec_for_cwe("CWE-79")
    for c in capecs:
        techs = c.get("attack_techniques", [])
        print(f"    {c['capec_id']}: {c['name']} -> ATT&CK: {techs}")
