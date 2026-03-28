#!/usr/bin/env python3
"""
VIPER SQLite Database - Persistent memory for findings, targets, and attack history.

Replaces the scattered JSON/pickle files with a single structured database.
"""

import json
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple

DB_PATH = Path(__file__).parent.parent / "data" / "viper.db"


class ViperDB:
    def __init__(self, db_path: Path = DB_PATH):
        db_path.parent.mkdir(parents=True, exist_ok=True)
        self.db_path = db_path
        self.conn = sqlite3.connect(str(db_path), timeout=10)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA busy_timeout=5000")
        self.conn.execute("PRAGMA foreign_keys=ON")
        self._init_tables()

    def _init_tables(self):
        self.conn.executescript("""
            CREATE TABLE IF NOT EXISTS targets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                url TEXT UNIQUE NOT NULL,
                domain TEXT NOT NULL,
                technologies TEXT DEFAULT '[]',
                waf TEXT,
                first_seen TEXT NOT NULL,
                last_scanned TEXT,
                notes TEXT DEFAULT ''
            );

            CREATE TABLE IF NOT EXISTS findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target_id INTEGER NOT NULL REFERENCES targets(id),
                vuln_type TEXT NOT NULL,
                severity TEXT NOT NULL,
                title TEXT NOT NULL,
                url TEXT NOT NULL,
                payload TEXT,
                evidence TEXT,
                confidence REAL DEFAULT 0.0,
                validated INTEGER DEFAULT 0,
                reported INTEGER DEFAULT 0,
                duplicate_of INTEGER,
                cvss REAL DEFAULT 0.0,
                cwe TEXT DEFAULT '',
                poc_path TEXT,
                found_at TEXT NOT NULL,
                UNIQUE(target_id, vuln_type, url, payload)
            );

            CREATE TABLE IF NOT EXISTS attack_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target_id INTEGER NOT NULL REFERENCES targets(id),
                attack_type TEXT NOT NULL,
                payload TEXT,
                success INTEGER NOT NULL DEFAULT 0,
                response_status INTEGER,
                response_length INTEGER,
                response_time_ms REAL,
                notes TEXT,
                timestamp TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS waf_fingerprints (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                domain TEXT UNIQUE NOT NULL,
                waf_type TEXT NOT NULL,
                bypass_techniques TEXT DEFAULT '[]',
                last_checked TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS tech_stacks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                domain TEXT UNIQUE NOT NULL,
                technologies TEXT DEFAULT '[]',
                headers TEXT DEFAULT '{}',
                last_updated TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_findings_target ON findings(target_id);
            CREATE INDEX IF NOT EXISTS idx_findings_type ON findings(vuln_type);
            CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
            CREATE INDEX IF NOT EXISTS idx_attack_history_target ON attack_history(target_id);
            CREATE INDEX IF NOT EXISTS idx_attack_history_type ON attack_history(attack_type);
        """)
        self.conn.commit()

    def close(self):
        self.conn.close()

    # ── Targets ──

    def add_target(self, url: str, domain: str, technologies: List[str] = None, waf: str = None) -> int:
        now = datetime.utcnow().isoformat()
        try:
            cur = self.conn.execute(
                "INSERT INTO targets (url, domain, technologies, waf, first_seen, last_scanned) VALUES (?, ?, ?, ?, ?, ?)",
                (url, domain, json.dumps(technologies or []), waf, now, now),
            )
            self.conn.commit()
            return cur.lastrowid
        except sqlite3.IntegrityError:
            # Already exists, update last_scanned
            self.conn.execute(
                "UPDATE targets SET last_scanned = ?, technologies = COALESCE(?, technologies), waf = COALESCE(?, waf) WHERE url = ?",
                (now, json.dumps(technologies) if technologies else None, waf, url),
            )
            self.conn.commit()
            return self.get_target_id(url)

    def get_target_id(self, url: str) -> Optional[int]:
        row = self.conn.execute("SELECT id FROM targets WHERE url = ?", (url,)).fetchone()
        return row["id"] if row else None

    def get_target(self, target_id: int) -> Optional[Dict]:
        row = self.conn.execute("SELECT * FROM targets WHERE id = ?", (target_id,)).fetchone()
        if row:
            d = dict(row)
            d["technologies"] = json.loads(d["technologies"])
            return d
        return None

    # ── Findings ──

    def add_finding(
        self, target_id: int, vuln_type: str, severity: str, title: str,
        url: str, payload: str = None, evidence: str = None,
        confidence: float = 0.0, cvss: float = 0.0, cwe: str = "",
        poc_path: str = None, validated: bool = False,
    ) -> Optional[int]:
        now = datetime.utcnow().isoformat()
        try:
            cur = self.conn.execute(
                """INSERT INTO findings
                   (target_id, vuln_type, severity, title, url, payload, evidence,
                    confidence, validated, cvss, cwe, poc_path, found_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (target_id, vuln_type, severity, title, url, payload, evidence,
                 confidence, int(validated), cvss, cwe, poc_path, now),
            )
            self.conn.commit()
            return cur.lastrowid
        except sqlite3.IntegrityError:
            return None  # Duplicate

    def is_duplicate(self, target_id: int, vuln_type: str, url: str, payload: str = None) -> Tuple[bool, Optional[int]]:
        if payload:
            row = self.conn.execute(
                "SELECT id FROM findings WHERE target_id = ? AND vuln_type = ? AND url = ? AND payload = ?",
                (target_id, vuln_type, url, payload),
            ).fetchone()
        else:
            row = self.conn.execute(
                "SELECT id FROM findings WHERE target_id = ? AND vuln_type = ? AND url = ?",
                (target_id, vuln_type, url),
            ).fetchone()
        if row:
            return True, row["id"]
        return False, None

    def get_findings_for_target(self, target_id: int, severity: str = None) -> List[Dict]:
        if severity:
            rows = self.conn.execute(
                "SELECT * FROM findings WHERE target_id = ? AND severity = ? ORDER BY found_at DESC",
                (target_id, severity),
            ).fetchall()
        else:
            rows = self.conn.execute(
                "SELECT * FROM findings WHERE target_id = ? ORDER BY found_at DESC",
                (target_id,),
            ).fetchall()
        return [dict(r) for r in rows]

    def get_all_findings(self, validated_only: bool = False) -> List[Dict]:
        if validated_only:
            rows = self.conn.execute(
                "SELECT f.*, t.domain FROM findings f JOIN targets t ON f.target_id = t.id WHERE f.validated = 1 ORDER BY f.found_at DESC"
            ).fetchall()
        else:
            rows = self.conn.execute(
                "SELECT f.*, t.domain FROM findings f JOIN targets t ON f.target_id = t.id ORDER BY f.found_at DESC"
            ).fetchall()
        return [dict(r) for r in rows]

    def mark_reported(self, finding_id: int):
        self.conn.execute("UPDATE findings SET reported = 1 WHERE id = ?", (finding_id,))
        self.conn.commit()

    # ── Attack History ──

    def log_attack(
        self, target_id: int, attack_type: str, payload: str = None,
        success: bool = False, response_status: int = None,
        response_length: int = None, response_time_ms: float = None,
        notes: str = None,
    ):
        now = datetime.utcnow().isoformat()
        self.conn.execute(
            """INSERT INTO attack_history
               (target_id, attack_type, payload, success, response_status,
                response_length, response_time_ms, notes, timestamp)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (target_id, attack_type, payload, int(success), response_status,
             response_length, response_time_ms, notes, now),
        )
        self.conn.commit()

    def get_attack_history(self, target_id: int, attack_type: str = None, limit: int = 100) -> List[Dict]:
        if attack_type:
            rows = self.conn.execute(
                "SELECT * FROM attack_history WHERE target_id = ? AND attack_type = ? ORDER BY timestamp DESC LIMIT ?",
                (target_id, attack_type, limit),
            ).fetchall()
        else:
            rows = self.conn.execute(
                "SELECT * FROM attack_history WHERE target_id = ? ORDER BY timestamp DESC LIMIT ?",
                (target_id, limit),
            ).fetchall()
        return [dict(r) for r in rows]

    def get_success_rate(self, attack_type: str) -> float:
        row = self.conn.execute(
            "SELECT COUNT(*) as total, SUM(success) as wins FROM attack_history WHERE attack_type = ?",
            (attack_type,),
        ).fetchone()
        if row and row["total"] > 0:
            return (row["wins"] or 0) / row["total"]
        return 0.0

    # ── WAF Fingerprints ──

    def set_waf(self, domain: str, waf_type: str, bypass_techniques: List[str] = None):
        now = datetime.utcnow().isoformat()
        try:
            self.conn.execute(
                "INSERT INTO waf_fingerprints (domain, waf_type, bypass_techniques, last_checked) VALUES (?, ?, ?, ?)",
                (domain, waf_type, json.dumps(bypass_techniques or []), now),
            )
        except sqlite3.IntegrityError:
            self.conn.execute(
                "UPDATE waf_fingerprints SET waf_type = ?, bypass_techniques = ?, last_checked = ? WHERE domain = ?",
                (waf_type, json.dumps(bypass_techniques or []), now, domain),
            )
        self.conn.commit()

    def get_waf(self, domain: str) -> Optional[Dict]:
        row = self.conn.execute("SELECT * FROM waf_fingerprints WHERE domain = ?", (domain,)).fetchone()
        if row:
            d = dict(row)
            d["bypass_techniques"] = json.loads(d["bypass_techniques"])
            return d
        return None

    # ── Tech Stacks ──

    def set_tech_stack(self, domain: str, technologies: List[str], headers: Dict = None):
        now = datetime.utcnow().isoformat()
        try:
            self.conn.execute(
                "INSERT INTO tech_stacks (domain, technologies, headers, last_updated) VALUES (?, ?, ?, ?)",
                (domain, json.dumps(technologies), json.dumps(headers or {}), now),
            )
        except sqlite3.IntegrityError:
            self.conn.execute(
                "UPDATE tech_stacks SET technologies = ?, headers = ?, last_updated = ? WHERE domain = ?",
                (json.dumps(technologies), json.dumps(headers or {}), now, domain),
            )
        self.conn.commit()

    def get_tech_stack(self, domain: str) -> Optional[Dict]:
        row = self.conn.execute("SELECT * FROM tech_stacks WHERE domain = ?", (domain,)).fetchone()
        if row:
            d = dict(row)
            d["technologies"] = json.loads(d["technologies"])
            d["headers"] = json.loads(d["headers"])
            return d
        return None

    # ── Migration ──

    def migrate_from_json(self, memory_dir: Path):
        """One-time migration from legacy JSON/pickle memory files."""
        # Migrate viper_memory.json
        memory_file = memory_dir / "viper_memory.json"
        if memory_file.exists():
            try:
                data = json.loads(memory_file.read_text())
                for attack in data.get("successful_attacks", []):
                    url = attack.get("target", "")
                    if not url:
                        continue
                    from urllib.parse import urlparse
                    domain = urlparse(url).netloc or url
                    tid = self.add_target(url, domain)
                    self.log_attack(
                        target_id=tid,
                        attack_type=attack.get("technique", "unknown"),
                        payload=attack.get("payload"),
                        success=True,
                        notes=attack.get("result"),
                    )
                for attack in data.get("failed_attacks", []):
                    url = attack.get("target", "")
                    if not url:
                        continue
                    from urllib.parse import urlparse
                    domain = urlparse(url).netloc or url
                    tid = self.add_target(url, domain)
                    self.log_attack(
                        target_id=tid,
                        attack_type=attack.get("technique", "unknown"),
                        payload=attack.get("payload"),
                        success=False,
                        notes=attack.get("error"),
                    )
            except (json.JSONDecodeError, KeyError) as e:
                print(f"Migration warning (viper_memory.json): {e}")

        # Migrate viper_kb.json
        kb_file = memory_dir / "viper_kb.json"
        if kb_file.exists():
            try:
                data = json.loads(kb_file.read_text())
                for program, info in data.get("programs", {}).items():
                    for finding in info.get("findings", []):
                        url = finding.get("url", f"https://{program}")
                        from urllib.parse import urlparse
                        domain = urlparse(url).netloc or program
                        tid = self.add_target(url, domain)
                        self.add_finding(
                            target_id=tid,
                            vuln_type=finding.get("technique", "unknown"),
                            severity=finding.get("severity", "info"),
                            title=finding.get("notes", "Migrated finding"),
                            url=url,
                        )
            except (json.JSONDecodeError, KeyError) as e:
                print(f"Migration warning (viper_kb.json): {e}")

    # ── Stats ──

    def stats(self) -> Dict:
        targets = self.conn.execute("SELECT COUNT(*) as c FROM targets").fetchone()["c"]
        findings = self.conn.execute("SELECT COUNT(*) as c FROM findings").fetchone()["c"]
        validated = self.conn.execute("SELECT COUNT(*) as c FROM findings WHERE validated = 1").fetchone()["c"]
        attacks = self.conn.execute("SELECT COUNT(*) as c FROM attack_history").fetchone()["c"]
        return {
            "targets": targets,
            "findings": findings,
            "validated_findings": validated,
            "attacks_logged": attacks,
        }


if __name__ == "__main__":
    db = ViperDB()
    print("VIPER DB initialized at:", DB_PATH)
    print("Stats:", db.stats())

    # Run migration if memory dir exists
    memory_dir = Path(__file__).parent.parent / "memory"
    if memory_dir.exists():
        print("Migrating from legacy JSON files...")
        db.migrate_from_json(memory_dir)
        print("After migration:", db.stats())
    db.close()
