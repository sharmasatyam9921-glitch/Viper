#!/usr/bin/env python3
"""
VIPER Chain of Custody — Evidence integrity tracking for findings.

On finding creation: SHA-256 hash the finding JSON.
Store: {finding_id, hash, timestamp, agent_id, target}
Verify integrity and generate evidence manifests signed with HMAC.
"""

import hashlib
import hmac
import json
import logging
import os
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger("viper.chain_of_custody")

CUSTODY_DIR = Path(__file__).parent.parent / "reports"


class ChainOfCustody:
    """Evidence integrity tracking for vulnerability findings.

    Creates SHA-256 hashes of findings on creation, tracks custody
    chain across agents, and generates HMAC-signed evidence manifests.

    Args:
        session_key: Secret key for HMAC signing. If not provided,
                     a random key is generated per session.
        custody_dir: Directory for storing manifests.
    """

    def __init__(
        self,
        session_key: Optional[str] = None,
        custody_dir: Path = CUSTODY_DIR,
    ):
        self._session_key = (session_key or os.urandom(32).hex()).encode()
        self._custody_dir = custody_dir
        self._entries: List[Dict[str, Any]] = []

    def record_finding(
        self,
        finding_id: str,
        finding_data: dict,
        agent_id: str = "unknown",
        target: str = "",
    ) -> Dict[str, str]:
        """Hash a finding and record custody entry.

        Args:
            finding_id: Unique identifier for the finding.
            finding_data: The complete finding as a dict (will be JSON-serialized).
            agent_id: The agent that created the finding.
            target: The target URL/domain.

        Returns:
            Dict with finding_id, hash, and timestamp.
        """
        # Canonical JSON serialization for reproducible hashing
        canonical = json.dumps(finding_data, sort_keys=True, separators=(",", ":"))
        finding_hash = hashlib.sha256(canonical.encode()).hexdigest()

        entry = {
            "finding_id": finding_id,
            "hash": finding_hash,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "agent_id": agent_id,
            "target": target,
            "data_size": len(canonical),
        }

        self._entries.append(entry)
        logger.info("Recorded custody for finding '%s': hash=%s", finding_id, finding_hash[:16])
        return entry

    def verify_integrity(self, finding_path: str) -> bool:
        """Verify that a finding file hasn't been tampered with.

        Reads the finding JSON, computes its SHA-256 hash, and compares
        against the recorded hash in the custody chain.

        Args:
            finding_path: Path to the finding JSON file.

        Returns:
            True if the hash matches, False otherwise.
        """
        path = Path(finding_path)
        if not path.exists():
            logger.warning("Finding file not found: %s", finding_path)
            return False

        try:
            data = json.loads(path.read_text())
        except (json.JSONDecodeError, OSError) as exc:
            logger.warning("Failed to read finding: %s", exc)
            return False

        finding_id = data.get("finding_id", path.stem)

        # Compute current hash
        canonical = json.dumps(data, sort_keys=True, separators=(",", ":"))
        current_hash = hashlib.sha256(canonical.encode()).hexdigest()

        # Find recorded hash
        recorded = None
        for entry in self._entries:
            if entry["finding_id"] == finding_id:
                recorded = entry
                break

        if not recorded:
            logger.warning("No custody record for finding '%s'", finding_id)
            return False

        if current_hash == recorded["hash"]:
            logger.info("Integrity verified for finding '%s'", finding_id)
            return True
        else:
            logger.warning(
                "INTEGRITY VIOLATION for finding '%s': expected %s, got %s",
                finding_id, recorded["hash"][:16], current_hash[:16],
            )
            return False

    def generate_evidence_manifest(self, session_id: str = "") -> Dict[str, Any]:
        """Generate a signed evidence manifest for all findings in this session.

        The manifest includes all custody entries and is signed with
        HMAC-SHA256 using the session key.

        Args:
            session_id: Identifier for the current session.

        Returns:
            Dict with entries, signature, and metadata.
        """
        manifest = {
            "session_id": session_id,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "total_findings": len(self._entries),
            "entries": self._entries,
        }

        # Sign manifest
        manifest_json = json.dumps(manifest, sort_keys=True, separators=(",", ":"))
        signature = hmac.new(
            self._session_key,
            manifest_json.encode(),
            hashlib.sha256,
        ).hexdigest()

        manifest["signature"] = signature

        # Save to disk
        self._custody_dir.mkdir(parents=True, exist_ok=True)
        sid = session_id or f"session_{int(time.time())}"
        manifest_path = self._custody_dir / f"{sid}_manifest.json"
        manifest_path.write_text(json.dumps(manifest, indent=2))

        logger.info(
            "Evidence manifest generated: %s (%d entries, sig=%s)",
            manifest_path, len(self._entries), signature[:16],
        )

        return manifest

    def verify_manifest(self, manifest_path: str) -> bool:
        """Verify the HMAC signature of a manifest file.

        Args:
            manifest_path: Path to the manifest JSON.

        Returns:
            True if signature is valid.
        """
        try:
            data = json.loads(Path(manifest_path).read_text())
        except Exception as exc:
            logger.warning("Failed to read manifest: %s", exc)
            return False

        stored_sig = data.pop("signature", "")

        # Recompute
        manifest_json = json.dumps(data, sort_keys=True, separators=(",", ":"))
        expected_sig = hmac.new(
            self._session_key,
            manifest_json.encode(),
            hashlib.sha256,
        ).hexdigest()

        if hmac.compare_digest(stored_sig, expected_sig):
            logger.info("Manifest signature verified")
            return True
        else:
            logger.warning("MANIFEST SIGNATURE INVALID")
            return False

    def get_entries(self) -> List[Dict[str, Any]]:
        """Return all custody entries."""
        return list(self._entries)

    def get_stats(self) -> dict:
        """Return custody statistics."""
        return {
            "total_entries": len(self._entries),
            "agents": list(set(e["agent_id"] for e in self._entries)),
            "targets": list(set(e["target"] for e in self._entries)),
        }


__all__ = ["ChainOfCustody"]
