"""
VIPER 5.0 - CTF Feedback / Training Ingestion
==============================================
Takes structured feedback from a human researcher (challenge name,
category, techniques that worked/failed, final flag location) and
burns it into VIPER's knowledge base + attack history so VIPER's
future runs benefit from the lesson.

Also exposes a programmatic ingestion API for importing writeups in
bulk (from GitHub writeup repos, ctftime, personal notes).

Schema for a feedback entry::

    {
        "challenge": "Giddy (HTB Machines)",
        "category": "web",
        "platform": "hackthebox",
        "difficulty": "medium",
        "url_hint": "http://10.10.10.104",
        "tech_stack": ["IIS", "ASP.NET", "SQL Server"],
        "techniques_tried": [
            {"name": "default_creds", "worked": false},
            {"name": "sqli_error", "worked": false},
            {"name": "sqli_union", "worked": true, "payload": "' UNION SELECT ..."},
        ],
        "winning_path": "SQLi in search box -> extract credentials -> SMB login -> RCE via payload serialization",
        "flag_location": "C:\\\\Users\\\\Administrator\\\\Desktop\\\\root.txt",
        "notes": "Arbitrary notes/insights.",
        "writeup_url": "https://ippsec.rocks/?...",
    }
"""

import json
import logging
import re
import sqlite3
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

logger = logging.getLogger("viper.core.ctf_feedback")

HACKAGENT_DIR = Path(__file__).parent.parent
FEEDBACK_DB = HACKAGENT_DIR / "data" / "ctf_feedback.db"


@dataclass
class FeedbackEntry:
    challenge: str
    category: str
    platform: str = "unknown"
    difficulty: str = ""
    url_hint: str = ""
    tech_stack: List[str] = field(default_factory=list)
    techniques_tried: List[Dict] = field(default_factory=list)
    winning_path: str = ""
    flag_location: str = ""
    notes: str = ""
    writeup_url: str = ""
    ts: float = field(default_factory=time.time)

    def to_dict(self) -> dict:
        return self.__dict__.copy()

    @classmethod
    def from_dict(cls, d: dict) -> "FeedbackEntry":
        return cls(
            challenge=d.get("challenge", ""),
            category=d.get("category", ""),
            platform=d.get("platform", "unknown"),
            difficulty=d.get("difficulty", ""),
            url_hint=d.get("url_hint", ""),
            tech_stack=list(d.get("tech_stack", [])),
            techniques_tried=list(d.get("techniques_tried", [])),
            winning_path=d.get("winning_path", ""),
            flag_location=d.get("flag_location", ""),
            notes=d.get("notes", ""),
            writeup_url=d.get("writeup_url", ""),
            ts=float(d.get("ts", time.time())),
        )


class CTFFeedbackStore:
    """
    SQLite-backed store for CTF feedback entries. Tracks:
      - Raw feedback entries (for audit + reingestion)
      - Per-technique success counts (skill performance)
      - Per-(category, tech_stack) winning techniques (retrieval)
    """

    def __init__(self, db_path: Optional[Path] = None):
        self.db_path = str(db_path or FEEDBACK_DB)
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        self._init_schema()

    def _init_schema(self) -> None:
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.executescript("""
            CREATE TABLE IF NOT EXISTS feedback (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                challenge TEXT, category TEXT, platform TEXT,
                difficulty TEXT, url_hint TEXT,
                tech_stack_json TEXT, techniques_json TEXT,
                winning_path TEXT, flag_location TEXT,
                notes TEXT, writeup_url TEXT, ts REAL
            );
            CREATE TABLE IF NOT EXISTS technique_stats (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                technique TEXT, category TEXT,
                tries INTEGER DEFAULT 0, wins INTEGER DEFAULT 0,
                last_payload TEXT, updated_at REAL,
                UNIQUE(technique, category)
            );
            CREATE TABLE IF NOT EXISTS tech_recipes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                tech_fingerprint TEXT,
                category TEXT,
                winning_techniques_json TEXT,
                sample_count INTEGER DEFAULT 0,
                updated_at REAL,
                UNIQUE(tech_fingerprint, category)
            );
            CREATE INDEX IF NOT EXISTS idx_fb_category ON feedback(category);
            CREATE INDEX IF NOT EXISTS idx_stats_tech ON technique_stats(technique);
        """)
        conn.commit()
        conn.close()

    # ── Ingestion ───────────────────────────────────────────────────────

    def add(self, entry: FeedbackEntry) -> int:
        """Store a feedback entry and update all derived stats."""
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        try:
            c.execute(
                """INSERT INTO feedback
                   (challenge, category, platform, difficulty, url_hint,
                    tech_stack_json, techniques_json, winning_path,
                    flag_location, notes, writeup_url, ts)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    entry.challenge, entry.category, entry.platform,
                    entry.difficulty, entry.url_hint,
                    json.dumps(entry.tech_stack),
                    json.dumps(entry.techniques_tried),
                    entry.winning_path, entry.flag_location,
                    entry.notes, entry.writeup_url, entry.ts,
                ),
            )
            fb_id = c.lastrowid

            # Update per-technique stats
            for t in entry.techniques_tried:
                if not isinstance(t, dict):
                    continue
                name = t.get("name", "").strip()
                if not name:
                    continue
                won = bool(t.get("worked", False))
                payload = str(t.get("payload", ""))[:1000]
                c.execute(
                    """INSERT INTO technique_stats(technique, category, tries, wins, last_payload, updated_at)
                       VALUES (?,?,1,?,?,?)
                       ON CONFLICT(technique, category) DO UPDATE SET
                         tries = tries + 1,
                         wins = wins + ?,
                         last_payload = COALESCE(?, last_payload),
                         updated_at = ?""",
                    (name, entry.category,
                     1 if won else 0,
                     payload if payload else None,
                     entry.ts,
                     1 if won else 0,
                     payload if payload else None,
                     entry.ts),
                )

            # Update tech_stack → winning techniques recipe
            if entry.tech_stack:
                fp = _fingerprint_stack(entry.tech_stack)
                winning = [
                    t.get("name") for t in entry.techniques_tried
                    if isinstance(t, dict) and t.get("worked")
                ]
                if winning:
                    existing = c.execute(
                        "SELECT winning_techniques_json, sample_count FROM tech_recipes "
                        "WHERE tech_fingerprint = ? AND category = ?",
                        (fp, entry.category),
                    ).fetchone()
                    if existing:
                        old = json.loads(existing[0]) or []
                        merged = list(dict.fromkeys(old + winning))
                        c.execute(
                            """UPDATE tech_recipes
                               SET winning_techniques_json = ?,
                                   sample_count = sample_count + 1,
                                   updated_at = ?
                               WHERE tech_fingerprint = ? AND category = ?""",
                            (json.dumps(merged), entry.ts, fp, entry.category),
                        )
                    else:
                        c.execute(
                            """INSERT INTO tech_recipes
                               (tech_fingerprint, category, winning_techniques_json,
                                sample_count, updated_at)
                               VALUES (?,?,?,1,?)""",
                            (fp, entry.category, json.dumps(winning), entry.ts),
                        )

            conn.commit()
        finally:
            conn.close()

        # Also burn a human-readable summary into the KB (FTS)
        try:
            self._write_kb_entry(entry)
        except Exception as exc:
            logger.debug("KB write failed: %s", exc)

        logger.info("Feedback ingested: %s [%s] (id=%d)",
                    entry.challenge, entry.category, fb_id)
        return fb_id

    def _write_kb_entry(self, entry: FeedbackEntry) -> None:
        from core.knowledge_base import KnowledgeBase
        kb = KnowledgeBase()
        techs = ", ".join(entry.tech_stack) or "unknown stack"
        winning = [
            t.get("name", "?") for t in entry.techniques_tried
            if isinstance(t, dict) and t.get("worked")
        ]
        tried = [
            t.get("name", "?") for t in entry.techniques_tried
            if isinstance(t, dict)
        ]
        title = f"CTF Writeup: {entry.challenge}"[:200]
        content = (
            f"Challenge: {entry.challenge} ({entry.platform}, "
            f"difficulty={entry.difficulty or 'unknown'}).\n"
            f"Category: {entry.category}. Stack: {techs}.\n"
            f"Winning techniques: {', '.join(winning) or 'none recorded'}.\n"
            f"All techniques tried: {', '.join(tried) or 'n/a'}.\n"
            f"Solution path: {entry.winning_path or 'n/a'}.\n"
            f"Flag location: {entry.flag_location or 'n/a'}.\n"
            f"Notes: {entry.notes or 'n/a'}"
        )
        kb.add(title=title, content=content[:2500],
               source=entry.platform or "ctf_feedback",
               category=f"ctf_{entry.category}")

    # ── Retrieval / ranking ─────────────────────────────────────────────

    def list(self, limit: int = 100) -> List[Dict]:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            "SELECT * FROM feedback ORDER BY ts DESC LIMIT ?", (limit,),
        ).fetchall()
        conn.close()
        return [_row_to_feedback_dict(r) for r in rows]

    def technique_ranking(
        self, category: Optional[str] = None, min_tries: int = 1
    ) -> List[Dict]:
        """Rank techniques by win rate within a category (or globally)."""
        conn = sqlite3.connect(self.db_path)
        if category:
            rows = conn.execute(
                """SELECT technique, category, tries, wins, last_payload
                   FROM technique_stats
                   WHERE category = ? AND tries >= ?
                   ORDER BY (CAST(wins AS REAL)/tries) DESC, wins DESC, tries DESC""",
                (category, min_tries),
            ).fetchall()
        else:
            rows = conn.execute(
                """SELECT technique, category, tries, wins, last_payload
                   FROM technique_stats
                   WHERE tries >= ?
                   ORDER BY (CAST(wins AS REAL)/tries) DESC, wins DESC, tries DESC""",
                (min_tries,),
            ).fetchall()
        conn.close()
        return [
            {
                "technique": r[0], "category": r[1],
                "tries": r[2], "wins": r[3],
                "win_rate": round(r[3] / r[2], 3) if r[2] else 0.0,
                "last_payload": r[4],
            }
            for r in rows
        ]

    def recommend_for_stack(
        self, tech_stack: List[str], category: str, top_k: int = 5
    ) -> List[str]:
        """Recommend winning techniques for a (stack, category) signal."""
        fp = _fingerprint_stack(tech_stack)
        conn = sqlite3.connect(self.db_path)
        # Exact fingerprint match first
        exact = conn.execute(
            """SELECT winning_techniques_json, sample_count FROM tech_recipes
               WHERE tech_fingerprint = ? AND category = ?""",
            (fp, category),
        ).fetchone()
        if exact:
            conn.close()
            return json.loads(exact[0] or "[]")[:top_k]

        # Fuzzy match: any recipe that shares a tech token
        all_recipes = conn.execute(
            """SELECT tech_fingerprint, winning_techniques_json, sample_count
               FROM tech_recipes WHERE category = ?""",
            (category,),
        ).fetchall()
        conn.close()

        tokens = set(_normalize_techs(tech_stack))
        scored: List[tuple] = []
        for fp2, techs_json, count in all_recipes:
            fp_tokens = set(fp2.split("|"))
            overlap = len(tokens & fp_tokens)
            if overlap:
                for t in json.loads(techs_json or "[]"):
                    scored.append((overlap * count, t))

        # Aggregate by technique, sort by score
        agg: Dict[str, int] = {}
        for score, t in scored:
            agg[t] = agg.get(t, 0) + score
        ordered = sorted(agg.items(), key=lambda x: x[1], reverse=True)
        return [t for t, _ in ordered[:top_k]]

    def stats(self) -> Dict:
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        total = c.execute("SELECT COUNT(*) FROM feedback").fetchone()[0]
        by_cat = dict(c.execute(
            "SELECT category, COUNT(*) FROM feedback GROUP BY category"
        ).fetchall())
        tried = c.execute("SELECT SUM(tries) FROM technique_stats").fetchone()[0] or 0
        wins = c.execute("SELECT SUM(wins) FROM technique_stats").fetchone()[0] or 0
        top_techs = c.execute(
            """SELECT technique, SUM(wins) as w FROM technique_stats
               GROUP BY technique ORDER BY w DESC LIMIT 10"""
        ).fetchall()
        recipes = c.execute("SELECT COUNT(*) FROM tech_recipes").fetchone()[0]
        conn.close()
        return {
            "total_entries": total,
            "by_category": by_cat,
            "techniques_tried_total": tried,
            "wins_total": wins,
            "top_winning_techniques": [
                {"technique": t, "wins": w} for t, w in top_techs if w
            ],
            "tech_recipes": recipes,
        }


# ── Helpers ─────────────────────────────────────────────────────────────────

_TECH_NORMALIZE = {
    "php": ["php", "laravel", "symfony", "codeigniter"],
    "node": ["node", "nodejs", "express", "nestjs", "next.js", "next"],
    "python": ["python", "flask", "django", "fastapi", "tornado"],
    "ruby": ["ruby", "rails"],
    "java": ["java", "spring", "struts"],
    "go": ["go", "golang", "gin", "echo"],
    "dotnet": [".net", "asp.net", "aspnet", "iis"],
    "wordpress": ["wordpress", "wp"],
    "drupal": ["drupal"],
    "joomla": ["joomla"],
    "mysql": ["mysql", "mariadb"],
    "postgres": ["postgres", "postgresql"],
    "mongo": ["mongo", "mongodb"],
    "redis": ["redis"],
    "nginx": ["nginx"],
    "apache": ["apache", "httpd"],
    "iis": ["iis"],
}


def _normalize_techs(stack: List[str]) -> List[str]:
    out: List[str] = []
    for raw in stack:
        t = str(raw).lower().strip()
        matched = False
        for norm, aliases in _TECH_NORMALIZE.items():
            if any(a in t for a in aliases):
                out.append(norm)
                matched = True
                break
        if not matched and t:
            out.append(t)
    # Stable, unique
    return sorted(set(out))


def _fingerprint_stack(stack: List[str]) -> str:
    return "|".join(_normalize_techs(stack)) or "unknown"


def _row_to_feedback_dict(row) -> Dict:
    return {
        "id": row["id"],
        "challenge": row["challenge"],
        "category": row["category"],
        "platform": row["platform"],
        "difficulty": row["difficulty"],
        "url_hint": row["url_hint"],
        "tech_stack": json.loads(row["tech_stack_json"] or "[]"),
        "techniques_tried": json.loads(row["techniques_json"] or "[]"),
        "winning_path": row["winning_path"],
        "flag_location": row["flag_location"],
        "notes": row["notes"],
        "writeup_url": row["writeup_url"],
        "ts": row["ts"],
    }


# ── Bulk ingest helpers ─────────────────────────────────────────────────────

def ingest_json_file(path: Path) -> int:
    """
    Load and ingest a JSON file containing either:
      - a single FeedbackEntry dict, OR
      - a list of FeedbackEntry dicts.

    Returns count ingested.
    """
    store = CTFFeedbackStore()
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    entries = data if isinstance(data, list) else [data]
    n = 0
    for item in entries:
        try:
            entry = FeedbackEntry.from_dict(item)
            if entry.challenge:
                store.add(entry)
                n += 1
        except Exception as exc:
            logger.warning("Skip bad entry: %s", exc)
    return n


# ── CLI ─────────────────────────────────────────────────────────────────────

def _cli() -> int:
    import argparse
    import sys

    p = argparse.ArgumentParser(
        description="VIPER CTF feedback ingestion CLI.",
    )
    sub = p.add_subparsers(dest="cmd", required=True)

    sub_add = sub.add_parser("add", help="Add a single feedback entry")
    sub_add.add_argument("--challenge", required=True)
    sub_add.add_argument("--category", required=True,
                         help="web, crypto, pwn, rev, forensics, misc, osint")
    sub_add.add_argument("--platform", default="hackthebox")
    sub_add.add_argument("--difficulty", default="")
    sub_add.add_argument("--tech-stack", default="",
                         help="Comma-separated, e.g. 'php,mysql,nginx'")
    sub_add.add_argument("--tried", action="append", default=[],
                         help="Repeat: 'name:worked[:payload]' "
                              "e.g. --tried sqli_union:1:\"' UNION SELECT ...\"")
    sub_add.add_argument("--winning-path", default="")
    sub_add.add_argument("--flag-location", default="")
    sub_add.add_argument("--notes", default="")
    sub_add.add_argument("--writeup-url", default="")

    sub_import = sub.add_parser("import", help="Import a JSON file of entries")
    sub_import.add_argument("file")

    sub.add_parser("stats", help="Show feedback DB stats")

    sub_rank = sub.add_parser("rank", help="Rank techniques by win rate")
    sub_rank.add_argument("--category", default=None)
    sub_rank.add_argument("--min-tries", type=int, default=1)

    sub_rec = sub.add_parser("recommend", help="Recommend techniques for a stack")
    sub_rec.add_argument("--category", required=True)
    sub_rec.add_argument("--stack", required=True,
                         help="Comma-separated stack")
    sub_rec.add_argument("--top", type=int, default=5)

    sub.add_parser("list", help="List recent feedback entries")

    args = p.parse_args()
    store = CTFFeedbackStore()

    if args.cmd == "add":
        techs = []
        for raw in args.tried:
            parts = raw.split(":", 2)
            if len(parts) < 2:
                continue
            techs.append({
                "name": parts[0],
                "worked": parts[1].lower() in ("1", "true", "yes", "y"),
                "payload": parts[2] if len(parts) > 2 else "",
            })
        entry = FeedbackEntry(
            challenge=args.challenge,
            category=args.category,
            platform=args.platform,
            difficulty=args.difficulty,
            tech_stack=[s.strip() for s in args.tech_stack.split(",") if s.strip()],
            techniques_tried=techs,
            winning_path=args.winning_path,
            flag_location=args.flag_location,
            notes=args.notes,
            writeup_url=args.writeup_url,
        )
        fb_id = store.add(entry)
        print(f"Added feedback id={fb_id} for {entry.challenge!r}")
        return 0

    if args.cmd == "import":
        n = ingest_json_file(Path(args.file))
        print(f"Imported {n} entries from {args.file}")
        return 0

    if args.cmd == "stats":
        print(json.dumps(store.stats(), indent=2))
        return 0

    if args.cmd == "rank":
        rows = store.technique_ranking(category=args.category,
                                       min_tries=args.min_tries)
        if not rows:
            print("(no techniques yet)")
            return 0
        print(f"{'technique':<30} {'cat':<12} {'wins':>5} {'tries':>6} {'rate':>6}")
        for r in rows[:20]:
            print(f"{r['technique'][:30]:<30} {r['category'][:12]:<12} "
                  f"{r['wins']:>5} {r['tries']:>6} {r['win_rate']:>6}")
        return 0

    if args.cmd == "recommend":
        stack = [s.strip() for s in args.stack.split(",") if s.strip()]
        recs = store.recommend_for_stack(stack, args.category, args.top)
        print(f"Top {len(recs)} techniques for {args.category} on {stack}:")
        for r in recs:
            print(f"  - {r}")
        return 0

    if args.cmd == "list":
        for fb in store.list(limit=20):
            print(f"[{fb['id']}] {fb['challenge']} ({fb['category']}/{fb['platform']})")
            if fb["winning_path"]:
                print(f"    path: {fb['winning_path'][:100]}")
        return 0

    return 1


if __name__ == "__main__":
    import sys
    sys.exit(_cli())
