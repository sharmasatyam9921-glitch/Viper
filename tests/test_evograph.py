"""Tests for EvoGraph — cross-session evolutionary attack memory."""
import pytest
from core.evograph import EvoGraph


class TestEvoGraphSchema:
    def test_schema_version_is_integer(self, evograph_db):
        version = evograph_db.get_schema_version()
        assert isinstance(version, int)
        assert version >= 1

    def test_all_expected_tables_exist(self, evograph_db):
        tables_query = evograph_db.conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        ).fetchall()
        table_names = {row[0] for row in tables_query}
        expected = {
            "sessions", "attack_history", "tech_attack_map",
            "q_snapshots", "reasoning_traces", "schema_meta"
        }
        for table in expected:
            assert table in table_names, f"Table '{table}' missing"

    def test_sessions_table_has_required_columns(self, evograph_db):
        cols = evograph_db.conn.execute("PRAGMA table_info(sessions)").fetchall()
        col_names = {c[1] for c in cols}
        assert "target" in col_names
        assert "tech_stack" in col_names
        assert "start_time" in col_names
        assert "findings_count" in col_names

    def test_attack_history_has_required_columns(self, evograph_db):
        cols = evograph_db.conn.execute("PRAGMA table_info(attack_history)").fetchall()
        col_names = {c[1] for c in cols}
        assert "session_id" in col_names
        assert "attack_type" in col_names
        assert "success" in col_names
        assert "reward" in col_names

    def test_tech_attack_map_has_unique_constraint(self, evograph_db):
        """Second upsert on same tech+attack should not raise."""
        sid = evograph_db.start_session("http://example.com", ["php"])
        evograph_db.record_attack(sid, "sqli", ["php"], True)
        evograph_db.record_attack(sid, "sqli", ["php"], False)  # no exception


class TestEvoGraphSessionLifecycle:
    def test_start_session_returns_integer_id(self, evograph_db):
        sid = evograph_db.start_session("http://example.com", ["php", "apache"])
        assert isinstance(sid, int)
        assert sid > 0

    def test_multiple_sessions_return_different_ids(self, evograph_db):
        sid1 = evograph_db.start_session("http://a.com", ["php"])
        sid2 = evograph_db.start_session("http://b.com", ["django"])
        assert sid1 != sid2

    def test_end_session_updates_record(self, evograph_db):
        sid = evograph_db.start_session("http://example.com", ["php"])
        evograph_db.end_session(sid, findings_count=3, total_reward=25.0)
        sessions = evograph_db.get_sessions()
        completed = next(s for s in sessions if s["id"] == sid)
        assert completed["findings_count"] == 3
        assert completed["total_reward"] == 25.0
        assert completed["end_time"] is not None

    def test_get_sessions_returns_list(self, evograph_db):
        evograph_db.start_session("http://example.com", ["php"])
        sessions = evograph_db.get_sessions()
        assert isinstance(sessions, list)
        assert len(sessions) >= 1

    def test_get_sessions_most_recent_first(self, evograph_db):
        s1 = evograph_db.start_session("http://a.com", [])
        s2 = evograph_db.start_session("http://b.com", [])
        sessions = evograph_db.get_sessions()
        ids = [s["id"] for s in sessions]
        assert ids.index(s2) < ids.index(s1)

    def test_session_has_expected_keys(self, evograph_db):
        sid = evograph_db.start_session("http://example.com", ["php"])
        sessions = evograph_db.get_sessions()
        s = next(s for s in sessions if s["id"] == sid)
        assert "target" in s
        assert "tech_stack" in s
        assert "start_time" in s


class TestEvoGraphRecordAttack:
    def test_record_attack_success(self, evograph_db):
        sid = evograph_db.start_session("http://example.com", ["php"])
        evograph_db.record_attack(sid, "sqli", ["php", "mysql"], True, confidence=0.9, reward=10.0)
        # Verify in attack_history
        rows = evograph_db.conn.execute(
            "SELECT * FROM attack_history WHERE session_id=?", (sid,)
        ).fetchall()
        assert len(rows) == 1

    def test_record_attack_failure(self, evograph_db):
        sid = evograph_db.start_session("http://example.com", ["django"])
        evograph_db.record_attack(sid, "sqli", ["django"], False)
        rows = evograph_db.conn.execute(
            "SELECT * FROM attack_history WHERE session_id=?", (sid,)
        ).fetchall()
        assert len(rows) == 1
        assert rows[0]["success"] == 0

    def test_record_attack_updates_tech_attack_map(self, evograph_db):
        sid = evograph_db.start_session("http://example.com", ["php"])
        evograph_db.record_attack(sid, "xss", ["php"], True, reward=5.0)
        rows = evograph_db.conn.execute(
            "SELECT * FROM tech_attack_map WHERE attack_type='xss'"
        ).fetchall()
        assert len(rows) >= 1
        assert rows[0]["attempts"] == 1
        assert rows[0]["successes"] == 1

    def test_record_multiple_attacks_increments_attempts(self, evograph_db):
        sid = evograph_db.start_session("http://example.com", ["php"])
        evograph_db.record_attack(sid, "lfi", ["php"], True)
        evograph_db.record_attack(sid, "lfi", ["php"], False)
        rows = evograph_db.conn.execute(
            "SELECT attempts FROM tech_attack_map WHERE attack_type='lfi'"
        ).fetchall()
        assert rows[0]["attempts"] == 2


class TestEvoGraphReasoningTraces:
    def test_record_reasoning_step_persists(self, evograph_db):
        sid = evograph_db.start_session("http://example.com", [])
        evograph_db.record_reasoning_step(
            sid, step_num=1,
            thought="Identified login form",
            action="inject_sqli",
            observation="error in response",
            reward=0.5,
        )
        rows = evograph_db.conn.execute(
            "SELECT * FROM reasoning_traces WHERE session_id=?", (sid,)
        ).fetchall()
        assert len(rows) == 1
        assert rows[0]["thought"] == "Identified login form"
        assert rows[0]["step_num"] == 1

    def test_multiple_reasoning_steps(self, evograph_db):
        sid = evograph_db.start_session("http://example.com", [])
        for i in range(5):
            evograph_db.record_reasoning_step(
                sid, step_num=i,
                thought=f"step {i}",
                action="think",
                observation="ok",
                reward=0.1 * i,
            )
        rows = evograph_db.conn.execute(
            "SELECT * FROM reasoning_traces WHERE session_id=?", (sid,)
        ).fetchall()
        assert len(rows) == 5


class TestEvoGraphBestAttacks:
    def test_get_best_attacks_empty_tech_returns_empty(self, evograph_db):
        result = evograph_db.get_best_attacks_for_tech([])
        assert result == []

    def test_get_best_attacks_no_history_returns_empty(self, evograph_db):
        result = evograph_db.get_best_attacks_for_tech(["php"])
        assert result == []

    def test_get_best_attacks_returns_successful_attacks(self, evograph_db):
        sid = evograph_db.start_session("http://example.com", ["php"])
        # Need at least 2 attempts to appear in results (HAVING total_attempts >= 2)
        evograph_db.record_attack(sid, "sqli", ["php"], True, reward=10.0)
        evograph_db.record_attack(sid, "sqli", ["php"], True, reward=10.0)
        evograph_db.record_attack(sid, "xss", ["php"], False, reward=0.0)
        evograph_db.record_attack(sid, "xss", ["php"], False, reward=0.0)
        result = evograph_db.get_best_attacks_for_tech(["php"])
        attack_types = [r["attack_type"] for r in result]
        assert "sqli" in attack_types

    def test_get_best_attacks_respects_top_n(self, evograph_db):
        sid = evograph_db.start_session("http://example.com", ["java"])
        for attack in ["sqli", "xss", "lfi", "ssrf"]:
            evograph_db.record_attack(sid, attack, ["java"], True, reward=5.0)
            evograph_db.record_attack(sid, attack, ["java"], True, reward=5.0)
        result = evograph_db.get_best_attacks_for_tech(["java"], top_n=2)
        assert len(result) <= 2


class TestEvoGraphNormalizeTech:
    def test_normalize_tech_sorts_and_joins(self, evograph_db):
        sig1 = evograph_db._normalize_tech(["php", "apache", "mysql"])
        sig2 = evograph_db._normalize_tech(["mysql", "php", "apache"])
        assert sig1 == sig2

    def test_normalize_tech_lowercases(self, evograph_db):
        sig = evograph_db._normalize_tech(["PHP", "Apache"])
        assert sig == sig.lower()

    def test_normalize_tech_empty_returns_empty_string(self, evograph_db):
        sig = evograph_db._normalize_tech([])
        assert sig == ""
