#!/usr/bin/env python3
"""
EvoGraph — Cross-Session Evolutionary Attack Memory

Persistent SQLite-backed memory that accumulates knowledge across hunts.
Each session makes the next one smarter by storing:
- Q-table snapshots (load the best historical one at startup)
- Attack results per tech stack (PHP + Apache → SSTI works 40%)
- ReACT reasoning traces for post-session analysis
- Failed approaches (deprioritized automatically)
"""

import json
import logging
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("viper.evograph")

DEFAULT_DB_PATH = Path(__file__).parent.parent / "data" / "evograph.db"


class EvoGraph:
    """Cross-session evolutionary attack memory."""

    def __init__(self, db_path: Path = DEFAULT_DB_PATH):
        db_path.parent.mkdir(parents=True, exist_ok=True)
        self.db_path = db_path
        self.conn = sqlite3.connect(str(db_path))
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA foreign_keys=ON")
        self._init_tables()

    def _init_tables(self):
        self.conn.executescript("""
            CREATE TABLE IF NOT EXISTS sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target TEXT NOT NULL,
                tech_stack TEXT DEFAULT '',
                start_time TEXT NOT NULL,
                end_time TEXT,
                findings_count INTEGER DEFAULT 0,
                total_reward REAL DEFAULT 0.0
            );

            CREATE TABLE IF NOT EXISTS attack_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id INTEGER NOT NULL REFERENCES sessions(id),
                attack_type TEXT NOT NULL,
                target_tech TEXT DEFAULT '',
                success INTEGER NOT NULL DEFAULT 0,
                confidence REAL DEFAULT 0.0,
                reward REAL DEFAULT 0.0,
                reasoning TEXT DEFAULT '',
                timestamp TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS tech_attack_map (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                tech_signature TEXT NOT NULL,
                attack_type TEXT NOT NULL,
                attempts INTEGER DEFAULT 0,
                successes INTEGER DEFAULT 0,
                total_reward REAL DEFAULT 0.0,
                avg_reward REAL DEFAULT 0.0,
                UNIQUE(tech_signature, attack_type)
            );

            CREATE TABLE IF NOT EXISTS q_snapshots (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id INTEGER NOT NULL REFERENCES sessions(id),
                state_key TEXT NOT NULL,
                action TEXT NOT NULL,
                q_value REAL NOT NULL
            );

            CREATE TABLE IF NOT EXISTS reasoning_traces (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id INTEGER NOT NULL REFERENCES sessions(id),
                step_num INTEGER NOT NULL,
                thought TEXT DEFAULT '',
                action TEXT DEFAULT '',
                observation TEXT DEFAULT '',
                reward REAL DEFAULT 0.0,
                timestamp TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_attack_history_session
                ON attack_history(session_id);
            CREATE INDEX IF NOT EXISTS idx_tech_attack_map_tech
                ON tech_attack_map(tech_signature);
            CREATE INDEX IF NOT EXISTS idx_q_snapshots_session
                ON q_snapshots(session_id);
            CREATE INDEX IF NOT EXISTS idx_reasoning_traces_session
                ON reasoning_traces(session_id);
        """)
        self.conn.commit()

    # ── Session lifecycle ──

    def start_session(self, target_url: str, tech_stack: List[str]) -> int:
        """Register a new hunt session. Returns session_id."""
        tech_sig = self._normalize_tech(tech_stack)
        cur = self.conn.execute(
            "INSERT INTO sessions (target, tech_stack, start_time) VALUES (?, ?, ?)",
            (target_url, tech_sig, datetime.now().isoformat()),
        )
        self.conn.commit()
        session_id = cur.lastrowid
        logger.info("EvoGraph session %d started for %s [%s]", session_id, target_url, tech_sig)
        return session_id

    def end_session(self, session_id: int, findings_count: int, total_reward: float):
        """Close a session with final stats."""
        self.conn.execute(
            "UPDATE sessions SET end_time=?, findings_count=?, total_reward=? WHERE id=?",
            (datetime.now().isoformat(), findings_count, total_reward, session_id),
        )
        self.conn.commit()
        logger.info("EvoGraph session %d ended: %d findings, reward=%.1f",
                     session_id, findings_count, total_reward)

    def get_sessions(self) -> List[Dict]:
        """List all recorded sessions."""
        cursor = self.conn.execute(
            "SELECT * FROM sessions ORDER BY start_time DESC"
        )
        columns = [desc[0] for desc in cursor.description]
        return [dict(zip(columns, row)) for row in cursor.fetchall()]

    def is_duplicate_finding(self, target: str, vuln_type: str, url: str) -> bool:
        """Check if this finding was already recorded in a previous session."""
        cursor = self.conn.execute(
            "SELECT COUNT(*) FROM attacks WHERE target_tech LIKE ? AND attack_type=? AND success=1",
            (f"%{target}%", vuln_type)
        )
        return cursor.fetchone()[0] > 0

    # ── Recording ──

    def record_attack(
        self,
        session_id: int,
        attack_type: str,
        target_tech: List[str],
        success: bool,
        confidence: float = 0.0,
        reward: float = 0.0,
        reasoning: str = "",
    ):
        """Record an attack attempt and update tech-attack mapping."""
        tech_sig = self._normalize_tech(target_tech)
        self.conn.execute(
            "INSERT INTO attack_history "
            "(session_id, attack_type, target_tech, success, confidence, reward, reasoning, timestamp) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (session_id, attack_type, tech_sig, int(success), confidence, reward, reasoning,
             datetime.now().isoformat()),
        )
        # Upsert tech_attack_map
        self.conn.execute(
            "INSERT INTO tech_attack_map (tech_signature, attack_type, attempts, successes, total_reward, avg_reward) "
            "VALUES (?, ?, 1, ?, ?, ?) "
            "ON CONFLICT(tech_signature, attack_type) DO UPDATE SET "
            "attempts = attempts + 1, "
            "successes = successes + ?, "
            "total_reward = total_reward + ?, "
            "avg_reward = (total_reward + ?) / (attempts + 1)",
            (tech_sig, attack_type, int(success), reward, reward,
             int(success), reward, reward),
        )
        self.conn.commit()

    def record_reasoning_step(
        self,
        session_id: int,
        step_num: int,
        thought: str,
        action: str,
        observation: str,
        reward: float,
    ):
        """Record a ReACT reasoning step."""
        self.conn.execute(
            "INSERT INTO reasoning_traces "
            "(session_id, step_num, thought, action, observation, reward, timestamp) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (session_id, step_num, thought, action, observation[:2000], reward,
             datetime.now().isoformat()),
        )
        self.conn.commit()

    # ── Queries ──

    def get_best_attacks_for_tech(self, tech_stack: List[str], top_n: int = 10) -> List[Dict[str, Any]]:
        """
        Get historically best attacks for a tech stack, ranked by success rate.
        Matches any tech component (e.g., 'php' matches 'apache,mysql,php').
        """
        tech_parts = [t.strip().lower() for t in tech_stack if t.strip()]
        if not tech_parts:
            return []

        # Build WHERE clause matching any tech component
        where_clauses = " OR ".join(["tech_signature LIKE ?"] * len(tech_parts))
        params = [f"%{t}%" for t in tech_parts]

        rows = self.conn.execute(
            f"SELECT attack_type, SUM(attempts) as total_attempts, SUM(successes) as total_successes, "
            f"AVG(avg_reward) as mean_reward "
            f"FROM tech_attack_map WHERE {where_clauses} "
            f"GROUP BY attack_type HAVING total_attempts >= 2 "
            f"ORDER BY (CAST(total_successes AS REAL) / MAX(total_attempts, 1)) DESC, mean_reward DESC "
            f"LIMIT ?",
            params + [top_n],
        ).fetchall()

        return [
            {
                "attack_type": row["attack_type"],
                "attempts": row["total_attempts"],
                "successes": row["total_successes"],
                "success_rate": row["total_successes"] / max(row["total_attempts"], 1),
                "avg_reward": row["mean_reward"],
            }
            for row in rows
        ]

    def get_attack_success_rate(self, attack_type: str, tech_signature: str = "") -> Dict[str, Any]:
        """Get overall and per-tech success rate for an attack type."""
        # Overall
        overall = self.conn.execute(
            "SELECT SUM(attempts) as att, SUM(successes) as suc, AVG(avg_reward) as rew "
            "FROM tech_attack_map WHERE attack_type=?",
            (attack_type,),
        ).fetchone()

        result: Dict[str, Any] = {
            "attack_type": attack_type,
            "overall_attempts": overall["att"] or 0,
            "overall_successes": overall["suc"] or 0,
            "overall_success_rate": (overall["suc"] or 0) / max(overall["att"] or 1, 1),
            "overall_avg_reward": overall["rew"] or 0.0,
        }

        if tech_signature:
            per_tech = self.conn.execute(
                "SELECT attempts, successes, avg_reward FROM tech_attack_map "
                "WHERE attack_type=? AND tech_signature LIKE ?",
                (attack_type, f"%{tech_signature.lower()}%"),
            ).fetchone()
            if per_tech:
                result["tech_attempts"] = per_tech["attempts"]
                result["tech_successes"] = per_tech["successes"]
                result["tech_success_rate"] = per_tech["successes"] / max(per_tech["attempts"], 1)
                result["tech_avg_reward"] = per_tech["avg_reward"]

        return result

    def get_failed_approaches(self, target_tech: List[str], last_n: int = 50) -> List[str]:
        """Get attacks that consistently fail on this tech stack (success rate < 5%)."""
        tech_parts = [t.strip().lower() for t in target_tech if t.strip()]
        if not tech_parts:
            return []

        where_clauses = " OR ".join(["tech_signature LIKE ?"] * len(tech_parts))
        params = [f"%{t}%" for t in tech_parts]

        rows = self.conn.execute(
            f"SELECT attack_type, SUM(attempts) as att, SUM(successes) as suc "
            f"FROM tech_attack_map WHERE {where_clauses} "
            f"GROUP BY attack_type HAVING att >= 5 AND (CAST(suc AS REAL) / att) < 0.05 "
            f"ORDER BY att DESC LIMIT ?",
            params + [last_n],
        ).fetchall()

        return [row["attack_type"] for row in rows]

    # ── Q-table persistence ──

    def save_q_table(self, session_id: int, q_table: Dict):
        """Snapshot current Q-table for this session."""
        rows = []
        for state_key, actions in q_table.items():
            key_str = json.dumps(list(state_key)) if isinstance(state_key, tuple) else str(state_key)
            for action, q_val in actions.items():
                rows.append((session_id, key_str, action, q_val))

        if rows:
            self.conn.executemany(
                "INSERT INTO q_snapshots (session_id, state_key, action, q_value) VALUES (?, ?, ?, ?)",
                rows,
            )
            self.conn.commit()
            logger.info("Saved Q-table snapshot: %d entries for session %d", len(rows), session_id)

    def load_best_q_table(self) -> Dict[Tuple, Dict[str, float]]:
        """Load Q-table from the most successful session (highest total_reward)."""
        best = self.conn.execute(
            "SELECT id FROM sessions WHERE total_reward = "
            "(SELECT MAX(total_reward) FROM sessions WHERE total_reward > 0) "
            "ORDER BY id DESC LIMIT 1"
        ).fetchone()

        if not best:
            return {}

        session_id = best["id"]
        rows = self.conn.execute(
            "SELECT state_key, action, q_value FROM q_snapshots WHERE session_id=?",
            (session_id,),
        ).fetchall()

        q_table: Dict[Tuple, Dict[str, float]] = {}
        for row in rows:
            try:
                key = tuple(json.loads(row["state_key"]))
            except (json.JSONDecodeError, TypeError):
                key = tuple(row["state_key"].split(","))
            if key not in q_table:
                q_table[key] = {}
            q_table[key][row["action"]] = row["q_value"]

        logger.info("Loaded best Q-table from session %d: %d state-action pairs",
                     session_id, len(rows))
        return q_table

    # ── Stats ──

    def get_evolution_stats(self) -> Dict[str, Any]:
        """Return stats: total_sessions, total_attacks, overall_success_rate, improvement_trend."""
        sess = self.conn.execute("SELECT COUNT(*) as cnt FROM sessions").fetchone()
        atk = self.conn.execute(
            "SELECT COUNT(*) as cnt, SUM(success) as suc FROM attack_history"
        ).fetchone()

        # Improvement trend: compare avg reward of last 5 sessions vs first 5
        first5 = self.conn.execute(
            "SELECT AVG(total_reward) as avg FROM "
            "(SELECT total_reward FROM sessions ORDER BY id ASC LIMIT 5)"
        ).fetchone()
        last5 = self.conn.execute(
            "SELECT AVG(total_reward) as avg FROM "
            "(SELECT total_reward FROM sessions ORDER BY id DESC LIMIT 5)"
        ).fetchone()

        first_avg = first5["avg"] or 0.0
        last_avg = last5["avg"] or 0.0
        trend = last_avg - first_avg

        return {
            "total_sessions": sess["cnt"],
            "total_attacks": atk["cnt"],
            "total_successes": atk["suc"] or 0,
            "overall_success_rate": (atk["suc"] or 0) / max(atk["cnt"], 1),
            "improvement_trend": trend,
            "first_5_avg_reward": first_avg,
            "last_5_avg_reward": last_avg,
        }

    def export_knowledge(self) -> Dict[str, Any]:
        """Export all learned knowledge as JSON for analysis."""
        # Tech-attack map
        tech_map = self.conn.execute(
            "SELECT tech_signature, attack_type, attempts, successes, avg_reward "
            "FROM tech_attack_map ORDER BY attempts DESC"
        ).fetchall()

        # Session summaries
        sessions = self.conn.execute(
            "SELECT id, target, tech_stack, start_time, end_time, findings_count, total_reward "
            "FROM sessions ORDER BY id DESC LIMIT 100"
        ).fetchall()

        return {
            "tech_attack_map": [dict(r) for r in tech_map],
            "sessions": [dict(r) for r in sessions],
            "stats": self.get_evolution_stats(),
        }

    # ── Helpers ──

    @staticmethod
    def _normalize_tech(tech_stack: List[str]) -> str:
        """Normalize tech stack to a sorted, lowercase, comma-separated string."""
        return ",".join(sorted(set(t.strip().lower() for t in tech_stack if t.strip())))

    def close(self):
        """Close the database connection."""
        if self.conn:
            self.conn.close()
