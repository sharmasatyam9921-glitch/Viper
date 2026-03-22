#!/usr/bin/env python3
"""
VIPER Dashboard — Zero-dependency real-time hunt monitoring backend.

Full-featured HTTP server with 20+ REST API endpoints + SSE streaming.
Reads from SQLite databases (viper.db + evograph.db).

Usage:
    python dashboard/server.py                        # Default port 8080
    python dashboard/server.py --dashboard-port 9000  # Custom port
    python dashboard/server.py --port 9000            # Also works
"""

import base64
import hashlib
import json
import math
import os
import queue
import sqlite3
import struct
import sys
import threading
import time
from datetime import datetime, timedelta
from http.server import HTTPServer, BaseHTTPRequestHandler
from socketserver import ThreadingMixIn

class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    daemon_threads = True
from pathlib import Path
from urllib.parse import urlparse, parse_qs


# ── WebSocket Message Types ──

class MessageType:
    """Typed message constants for WebSocket communication."""
    # Server -> Client
    CONNECTED = 'connected'
    THINKING = 'thinking'
    THINKING_CHUNK = 'thinking_chunk'
    TOOL_START = 'tool_start'
    TOOL_OUTPUT = 'tool_output'
    TOOL_COMPLETE = 'tool_complete'
    PHASE_UPDATE = 'phase_update'
    TODO_UPDATE = 'todo_update'
    APPROVAL_REQUEST = 'approval_request'
    QUESTION_REQUEST = 'question_request'
    FINDING_NEW = 'finding_new'
    DEEP_THINK = 'deep_think'
    ERROR = 'error'
    FILE_READY = 'file_ready'
    # Client -> Server
    APPROVAL_RESPONSE = 'approval_response'
    ANSWER = 'answer'
    GUIDANCE = 'guidance'
    STOP = 'stop'
    RESUME = 'resume'

# ── Path resolution ──

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = PROJECT_ROOT / "data"
VIPER_DB = DATA_DIR / "viper.db"
EVOGRAPH_DB = DATA_DIR / "evograph.db"
LOGS_DIR = PROJECT_ROOT / "logs"
REPORTS_DIR = PROJECT_ROOT / "reports"
METRICS_FILE = PROJECT_ROOT / "core" / "viper_metrics.json"
STATE_FILE = PROJECT_ROOT / "core" / "viper_state.json"
DASHBOARD_DIR = Path(__file__).resolve().parent
STATE_DIR = PROJECT_ROOT / "state"
EVENT_QUEUE_FILE = STATE_DIR / "event_queue.json"

# VIPER 4.0 imports
try:
    import sys as _sys
    _sys.path.insert(0, str(PROJECT_ROOT))
    from core.graph_engine import GraphEngine
    from core.settings_manager import SettingsManager
    V4_AVAILABLE = True
except ImportError:
    V4_AVAILABLE = False

# VIPER 4.0 global instances (lazy-init)
_graph_engine = None
_settings_manager = None

def _get_graph_engine():
    global _graph_engine
    if _graph_engine is None and V4_AVAILABLE:
        try:
            _graph_engine = GraphEngine()
        except Exception:
            pass
    return _graph_engine

def _get_settings():
    global _settings_manager
    if _settings_manager is None and V4_AVAILABLE:
        try:
            _settings_manager = SettingsManager()
        except Exception:
            pass
    return _settings_manager

# ── Thread-safe SQLite helpers ──

_db_lock = threading.Lock()


def _connect(db_path):
    """Connect to a SQLite DB. Returns None if missing."""
    if not db_path.exists():
        return None
    try:
        conn = sqlite3.connect(str(db_path), check_same_thread=False)
        conn.row_factory = sqlite3.Row
        return conn
    except Exception:
        return None


def _query(db_path, sql, params=(), one=False):
    """Thread-safe query helper. Returns list of dicts, or single dict if one=True."""
    with _db_lock:
        conn = _connect(db_path)
        if not conn:
            return {} if one else []
        try:
            rows = conn.execute(sql, params).fetchall()
            if one:
                return dict(rows[0]) if rows else {}
            return [dict(r) for r in rows]
        except Exception:
            return {} if one else []
        finally:
            conn.close()


def _scalar(db_path, sql, params=(), default=0):
    """Thread-safe scalar query helper."""
    with _db_lock:
        conn = _connect(db_path)
        if not conn:
            return default
        try:
            row = conn.execute(sql, params).fetchone()
            return row[0] if row else default
        except Exception:
            return default
        finally:
            conn.close()


def _table_exists(db_path, table_name):
    """Check if a table exists in the database."""
    return bool(_scalar(
        db_path,
        "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?",
        (table_name,),
    ))


def _tables(db_path):
    """List all table names in a database."""
    rows = _query(db_path, "SELECT name FROM sqlite_master WHERE type='table'")
    return [r["name"] for r in rows]


# ── SSE Event Bus ──

class EventBus:
    """Thread-safe Server-Sent Events bus. Clients subscribe via queue."""

    def __init__(self, max_history=100):
        self._lock = threading.Lock()
        self._subscribers = []
        self._history = []
        self._max_history = max_history

    def subscribe(self):
        """Return a queue that will receive (event_type, data_dict) tuples."""
        q = queue.Queue(maxsize=256)
        with self._lock:
            self._subscribers.append(q)
        return q

    def unsubscribe(self, q):
        with self._lock:
            try:
                self._subscribers.remove(q)
            except ValueError:
                pass

    def publish(self, event_type, data):
        """Broadcast an event to all subscribers."""
        msg = (event_type, data)
        with self._lock:
            self._history.append(msg)
            if len(self._history) > self._max_history:
                self._history = self._history[-self._max_history:]
            dead = []
            for q in self._subscribers:
                try:
                    q.put_nowait(msg)
                except queue.Full:
                    dead.append(q)
            for q in dead:
                try:
                    self._subscribers.remove(q)
                except ValueError:
                    pass

    @property
    def subscriber_count(self):
        with self._lock:
            return len(self._subscribers)


event_bus = EventBus()


# ── WebSocket handler (stdlib, no external deps) ──

WS_MAGIC = b"258EAFA5-E914-47DA-95CA-5AB5DC799073"
_ws_clients = []
_ws_lock = threading.Lock()


def _ws_accept_key(key: str) -> str:
    """Compute WebSocket Sec-WebSocket-Accept value."""
    h = hashlib.sha1(key.encode() + WS_MAGIC).digest()
    return base64.b64encode(h).decode()


def _ws_encode_frame(data: str) -> bytes:
    """Encode a text WebSocket frame."""
    payload = data.encode("utf-8")
    length = len(payload)
    frame = bytearray()
    frame.append(0x81)  # FIN + text opcode
    if length <= 125:
        frame.append(length)
    elif length <= 65535:
        frame.append(126)
        frame.extend(struct.pack(">H", length))
    else:
        frame.append(127)
        frame.extend(struct.pack(">Q", length))
    frame.extend(payload)
    return bytes(frame)


def _ws_decode_frame(data: bytes):
    """Decode a WebSocket frame. Returns (opcode, payload, bytes_consumed) or None."""
    if len(data) < 2:
        return None
    b1, b2 = data[0], data[1]
    opcode = b1 & 0x0F
    masked = b2 & 0x80
    length = b2 & 0x7F
    offset = 2

    if length == 126:
        if len(data) < 4:
            return None
        length = struct.unpack(">H", data[2:4])[0]
        offset = 4
    elif length == 127:
        if len(data) < 10:
            return None
        length = struct.unpack(">Q", data[2:10])[0]
        offset = 10

    if masked:
        if len(data) < offset + 4:
            return None
        mask = data[offset:offset + 4]
        offset += 4
    else:
        mask = None

    if len(data) < offset + length:
        return None

    payload = data[offset:offset + length]
    if mask:
        payload = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))

    return opcode, payload, offset + length


def _ws_broadcast(event_type: str, data: dict):
    """Send event to all WebSocket clients."""
    msg = json.dumps({"type": event_type, "payload": data}, default=str)
    frame = _ws_encode_frame(msg)
    with _ws_lock:
        dead = []
        for sock in _ws_clients:
            try:
                sock.sendall(frame)
            except Exception:
                dead.append(sock)
        for sock in dead:
            try:
                _ws_clients.remove(sock)
            except ValueError:
                pass


def _handle_ws_message(payload: bytes, sock):
    """Process an incoming typed WebSocket message from a client."""
    try:
        msg = json.loads(payload.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError):
        return

    msg_type = msg.get("type", "")
    data = msg.get("payload", {})

    STATE_DIR.mkdir(parents=True, exist_ok=True)

    if msg_type == MessageType.APPROVAL_RESPONSE:
        # Write approval response for agent to pick up
        resp_file = STATE_DIR / "approval_response.json"
        resp_file.write_text(json.dumps({
            "approved": data.get("approved", False),
            "reason": data.get("reason", ""),
            "timestamp": time.time(),
        }), encoding="utf-8")
        _ws_broadcast(MessageType.PHASE_UPDATE, {
            "message": "Approval response recorded",
            "approved": data.get("approved", False),
        })

    elif msg_type == MessageType.ANSWER:
        # Write answer for agent to pick up
        resp_file = STATE_DIR / "qa_response.json"
        resp_file.write_text(json.dumps({
            "answer": data.get("answer", ""),
            "question_id": data.get("question_id", ""),
            "timestamp": time.time(),
        }), encoding="utf-8")
        _ws_broadcast(MessageType.PHASE_UPDATE, {
            "message": "Answer received",
        })

    elif msg_type == MessageType.GUIDANCE:
        # Write runtime guidance for agent
        resp_file = STATE_DIR / "guidance.json"
        resp_file.write_text(json.dumps({
            "guidance": data.get("guidance", ""),
            "priority": data.get("priority", "normal"),
            "timestamp": time.time(),
        }), encoding="utf-8")
        _ws_broadcast(MessageType.PHASE_UPDATE, {
            "message": "Guidance sent to agent",
        })

    elif msg_type == MessageType.STOP:
        resp_file = STATE_DIR / "agent_control.json"
        resp_file.write_text(json.dumps({
            "command": "stop",
            "timestamp": time.time(),
        }), encoding="utf-8")
        _ws_broadcast(MessageType.PHASE_UPDATE, {"message": "Stop signal sent"})

    elif msg_type == MessageType.RESUME:
        resp_file = STATE_DIR / "agent_control.json"
        resp_file.write_text(json.dumps({
            "command": "resume",
            "timestamp": time.time(),
        }), encoding="utf-8")
        _ws_broadcast(MessageType.PHASE_UPDATE, {"message": "Resume signal sent"})


def _handle_websocket(handler):
    """Upgrade HTTP connection to WebSocket and handle messages."""
    key = handler.headers.get("Sec-WebSocket-Key", "")
    if not key:
        handler.send_error(400, "Missing WebSocket key")
        return

    accept = _ws_accept_key(key)
    response = (
        "HTTP/1.1 101 Switching Protocols\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        f"Sec-WebSocket-Accept: {accept}\r\n"
        "Access-Control-Allow-Origin: *\r\n"
        "\r\n"
    )
    handler.wfile.write(response.encode())
    handler.wfile.flush()

    sock = handler.request
    with _ws_lock:
        _ws_clients.append(sock)

    # Subscribe to event bus for this client
    q = event_bus.subscribe()

    # Sender thread: forward event bus messages as WebSocket frames
    def sender():
        try:
            while True:
                try:
                    event_type, data = q.get(timeout=30)
                    msg = json.dumps({"type": event_type, "payload": data}, default=str)
                    sock.sendall(_ws_encode_frame(msg))
                except queue.Empty:
                    # Send ping to keep alive
                    try:
                        sock.sendall(b"\x89\x00")  # Ping frame
                    except Exception:
                        break
                except Exception:
                    break
        except Exception:
            pass

    sender_thread = threading.Thread(target=sender, daemon=True)
    sender_thread.start()

    # Send typed connected message
    connected_msg = json.dumps({
        "type": MessageType.CONNECTED,
        "payload": {"status": "ok", "timestamp": time.time()}
    }, default=str)
    try:
        sock.sendall(_ws_encode_frame(connected_msg))
    except Exception:
        pass

    # Receiver loop: read frames and handle typed messages
    buf = b""
    try:
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            buf += chunk
            while buf:
                result = _ws_decode_frame(buf)
                if result is None:
                    break
                opcode, payload, consumed = result
                buf = buf[consumed:]
                if opcode == 0x08:  # Close
                    sock.sendall(b"\x88\x00")
                    raise ConnectionError("WS close")
                elif opcode == 0x09:  # Ping
                    sock.sendall(b"\x8A\x00")  # Pong
                elif opcode == 0x01:  # Text
                    _handle_ws_message(payload, sock)
    except Exception:
        pass
    finally:
        event_bus.unsubscribe(q)
        with _ws_lock:
            try:
                _ws_clients.remove(sock)
            except ValueError:
                pass


# ── Stats broadcaster thread ──

def _stats_broadcaster():
    """Push stats updates every 5 seconds to SSE and WebSocket subscribers."""
    while True:
        time.sleep(5)
        has_sse = event_bus.subscriber_count > 0
        has_ws = len(_ws_clients) > 0
        if has_sse or has_ws:
            try:
                data = get_overview()
                if has_sse:
                    event_bus.publish("stats", data)
                if has_ws:
                    _ws_broadcast("stats", data)
            except Exception:
                pass


_broadcaster_thread = threading.Thread(target=_stats_broadcaster, daemon=True)
_broadcaster_thread.start()


# ── API data helpers ──

def get_overview():
    """Dashboard overview KPI stats."""
    data = {
        "targets": 0, "findings": 0, "validated": 0, "attacks": 0,
        "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0,
        "top_vuln_types": [], "recent_findings": [], "waf_count": 0,
        "metrics": {},
    }

    if not VIPER_DB.exists():
        return data

    data["targets"] = _scalar(VIPER_DB, "SELECT COUNT(*) FROM targets")
    data["findings"] = _scalar(VIPER_DB, "SELECT COUNT(*) FROM findings")
    data["validated"] = _scalar(VIPER_DB, "SELECT COUNT(*) FROM findings WHERE validated=1")
    data["attacks"] = _scalar(VIPER_DB, "SELECT COUNT(*) FROM attack_history")

    for sev in ("critical", "high", "medium", "low", "info"):
        data[sev] = _scalar(
            VIPER_DB,
            "SELECT COUNT(*) FROM findings WHERE LOWER(severity)=?",
            (sev,),
        )

    data["top_vuln_types"] = _query(
        VIPER_DB,
        "SELECT vuln_type as type, COUNT(*) as count FROM findings "
        "GROUP BY vuln_type ORDER BY count DESC LIMIT 10",
    )

    data["recent_findings"] = _query(
        VIPER_DB,
        "SELECT f.id, f.vuln_type, f.severity, f.title, f.url, f.confidence, "
        "f.validated, f.found_at, t.domain "
        "FROM findings f JOIN targets t ON f.target_id=t.id "
        "ORDER BY f.found_at DESC LIMIT 20",
    )

    data["waf_count"] = _scalar(VIPER_DB, "SELECT COUNT(*) FROM waf_fingerprints")

    if METRICS_FILE.exists():
        try:
            data["metrics"] = json.loads(METRICS_FILE.read_text())
        except Exception:
            pass

    return data


def get_risk_score():
    """Compute an overall risk score 0-100 from findings."""
    if not VIPER_DB.exists():
        return {"score": 0, "grade": "A", "breakdown": {}}

    weights = {"critical": 25, "high": 15, "medium": 5, "low": 1, "info": 0}
    breakdown = {}
    raw = 0.0

    for sev, w in weights.items():
        count = _scalar(
            VIPER_DB,
            "SELECT COUNT(*) FROM findings WHERE LOWER(severity)=?",
            (sev,),
        )
        breakdown[sev] = count
        raw += count * w

    # Normalize: sigmoid-like curve, capped at 100
    score = min(100, round(100 * (1 - math.exp(-raw / 50)), 1))

    if score >= 80:
        grade = "F"
    elif score >= 60:
        grade = "D"
    elif score >= 40:
        grade = "C"
    elif score >= 20:
        grade = "B"
    else:
        grade = "A"

    return {"score": score, "grade": grade, "breakdown": breakdown, "raw_weight": raw}


def get_findings(severity=None, vuln_type=None, domain=None, page=1, limit=50):
    """Paginated, filterable findings."""
    if not VIPER_DB.exists():
        return {"findings": [], "total": 0, "page": page, "limit": limit, "pages": 0}

    where = ["1=1"]
    params = []

    if severity:
        where.append("LOWER(f.severity)=?")
        params.append(severity.lower())
    if vuln_type:
        where.append("LOWER(f.vuln_type)=?")
        params.append(vuln_type.lower())
    if domain:
        where.append("LOWER(t.domain) LIKE ?")
        params.append(f"%{domain.lower()}%")

    where_clause = " AND ".join(where)

    total = _scalar(
        VIPER_DB,
        f"SELECT COUNT(*) FROM findings f JOIN targets t ON f.target_id=t.id WHERE {where_clause}",
        params,
    )

    offset = (max(1, page) - 1) * limit
    rows = _query(
        VIPER_DB,
        f"SELECT f.*, t.domain FROM findings f "
        f"JOIN targets t ON f.target_id=t.id "
        f"WHERE {where_clause} "
        f"ORDER BY f.found_at DESC LIMIT ? OFFSET ?",
        params + [limit, offset],
    )

    return {
        "findings": rows,
        "total": total,
        "page": page,
        "limit": limit,
        "pages": max(1, math.ceil(total / max(1, limit))),
    }


def get_finding_detail(finding_id):
    """Single finding with full detail."""
    return _query(
        VIPER_DB,
        "SELECT f.*, t.domain, t.url as target_url FROM findings f "
        "JOIN targets t ON f.target_id=t.id WHERE f.id=?",
        (finding_id,),
        one=True,
    )


def get_findings_timeline():
    """Findings over time for area chart."""
    return _query(
        VIPER_DB,
        "SELECT DATE(found_at) as day, severity, COUNT(*) as count "
        "FROM findings GROUP BY day, severity ORDER BY day",
    )


def get_findings_by_type():
    """Findings grouped by vuln_type."""
    return _query(
        VIPER_DB,
        "SELECT vuln_type as type, COUNT(*) as count, "
        "SUM(CASE WHEN validated=1 THEN 1 ELSE 0 END) as validated "
        "FROM findings GROUP BY vuln_type ORDER BY count DESC",
    )


def get_findings_by_severity():
    """Findings grouped by severity."""
    return _query(
        VIPER_DB,
        "SELECT severity, COUNT(*) as count, "
        "SUM(CASE WHEN validated=1 THEN 1 ELSE 0 END) as validated "
        "FROM findings GROUP BY LOWER(severity) ORDER BY "
        "CASE LOWER(severity) WHEN 'critical' THEN 1 WHEN 'high' THEN 2 "
        "WHEN 'medium' THEN 3 WHEN 'low' THEN 4 ELSE 5 END",
    )


def get_findings_by_domain():
    """Findings grouped by target domain."""
    return _query(
        VIPER_DB,
        "SELECT t.domain, COUNT(*) as count, "
        "SUM(CASE WHEN f.validated=1 THEN 1 ELSE 0 END) as validated, "
        "MAX(f.found_at) as last_finding "
        "FROM findings f JOIN targets t ON f.target_id=t.id "
        "GROUP BY t.domain ORDER BY count DESC",
    )


def get_targets():
    """All scanned targets with finding counts."""
    rows = _query(
        VIPER_DB,
        "SELECT t.*, "
        "(SELECT COUNT(*) FROM findings WHERE target_id=t.id) as finding_count, "
        "(SELECT COUNT(*) FROM attack_history WHERE target_id=t.id) as attack_count "
        "FROM targets t ORDER BY t.last_scanned DESC",
    )
    for d in rows:
        try:
            d["technologies"] = json.loads(d.get("technologies") or "[]")
        except Exception:
            d["technologies"] = []
    return rows


def get_target_detail(domain):
    """Target detail by domain, with all its findings."""
    target = _query(
        VIPER_DB,
        "SELECT t.*, "
        "(SELECT COUNT(*) FROM findings WHERE target_id=t.id) as finding_count, "
        "(SELECT COUNT(*) FROM attack_history WHERE target_id=t.id) as attack_count "
        "FROM targets t WHERE LOWER(t.domain)=? LIMIT 1",
        (domain.lower(),),
        one=True,
    )
    if not target:
        return {}

    try:
        target["technologies"] = json.loads(target.get("technologies") or "[]")
    except Exception:
        target["technologies"] = []

    tid = target.get("id")
    target["findings"] = _query(
        VIPER_DB,
        "SELECT * FROM findings WHERE target_id=? ORDER BY found_at DESC",
        (tid,),
    )
    target["attacks"] = _query(
        VIPER_DB,
        "SELECT * FROM attack_history WHERE target_id=? ORDER BY timestamp DESC LIMIT 100",
        (tid,),
    )
    return target


def get_attack_stats():
    """Attack type success rates."""
    rows = _query(
        VIPER_DB,
        "SELECT attack_type, COUNT(*) as total, SUM(success) as wins, "
        "ROUND(AVG(response_time_ms), 1) as avg_time_ms "
        "FROM attack_history GROUP BY attack_type ORDER BY total DESC",
    )
    for d in rows:
        d["success_rate"] = round((d["wins"] or 0) / max(d["total"], 1) * 100, 1)
    return rows


def get_attack_history(limit=200):
    """Recent attack log with results."""
    return _query(
        VIPER_DB,
        "SELECT ah.*, t.domain FROM attack_history ah "
        "JOIN targets t ON ah.target_id=t.id "
        "ORDER BY ah.timestamp DESC LIMIT ?",
        (limit,),
    )


def get_attack_kill_chain():
    """Attack phases funnel data — how many attacks per phase/type and success."""
    rows = _query(
        VIPER_DB,
        "SELECT attack_type as phase, COUNT(*) as total, "
        "SUM(success) as successes, "
        "ROUND(AVG(response_time_ms), 1) as avg_time_ms "
        "FROM attack_history GROUP BY attack_type "
        "ORDER BY total DESC",
    )
    # Build funnel: ordered by volume descending
    funnel = []
    for r in rows:
        r["success_rate"] = round((r["successes"] or 0) / max(r["total"], 1) * 100, 1)
        funnel.append(r)
    return funnel


def get_evograph_stats():
    """EvoGraph summary stats."""
    if not EVOGRAPH_DB.exists():
        return {"available": False}

    tables = _tables(EVOGRAPH_DB)
    stats = {"available": True, "tables": tables}

    # Count sessions
    for tbl in ("hunt_sessions", "sessions"):
        if tbl in tables:
            stats["session_count"] = _scalar(EVOGRAPH_DB, f"SELECT COUNT(*) FROM {tbl}")
            break
    else:
        stats["session_count"] = 0

    # Count patterns (tech_attack_map rows are the learned patterns)
    for tbl in ("attack_patterns", "patterns", "tech_attack_map"):
        if tbl in tables:
            stats["pattern_count"] = _scalar(EVOGRAPH_DB, f"SELECT COUNT(*) FROM {tbl}")
            break
    else:
        stats["pattern_count"] = 0

    # Count edges (attack_history in evograph are the edges, or legacy tables)
    for tbl in ("pattern_edges", "edges", "attack_history"):
        if tbl in tables:
            stats["edge_count"] = _scalar(EVOGRAPH_DB, f"SELECT COUNT(*) FROM {tbl}")
            break
    else:
        stats["edge_count"] = 0

    # Attack count from viper db
    stats["total_attacks"] = _scalar(VIPER_DB, "SELECT COUNT(*) FROM attack_history")

    return stats


def get_evograph_sessions():
    """All EvoGraph sessions with rewards."""
    if not EVOGRAPH_DB.exists():
        return []

    tables = _tables(EVOGRAPH_DB)
    for tbl in ("hunt_sessions", "sessions"):
        if tbl in tables:
            return _query(EVOGRAPH_DB, f"SELECT * FROM {tbl} ORDER BY rowid DESC LIMIT 50")
    return []


def get_evograph_tech_map():
    """Tech stack to attack success rate mapping."""
    # Derive from viper.db: technologies x attack success
    rows = _query(
        VIPER_DB,
        "SELECT t.technologies, ah.attack_type, ah.success "
        "FROM attack_history ah JOIN targets t ON ah.target_id=t.id "
        "WHERE t.technologies IS NOT NULL AND t.technologies != '[]'",
    )

    tech_map = {}
    for r in rows:
        try:
            techs = json.loads(r.get("technologies") or "[]")
        except Exception:
            continue
        for tech in techs:
            if tech not in tech_map:
                tech_map[tech] = {"tech": tech, "attacks": 0, "successes": 0}
            tech_map[tech]["attacks"] += 1
            tech_map[tech]["successes"] += (r["success"] or 0)

    result = list(tech_map.values())
    for item in result:
        item["success_rate"] = round(
            item["successes"] / max(item["attacks"], 1) * 100, 1
        )
    result.sort(key=lambda x: x["attacks"], reverse=True)
    return result


def get_evograph_graph():
    """Node/edge data for attack graph visualization from evograph tables."""
    if not EVOGRAPH_DB.exists():
        return {"nodes": [], "edges": []}

    tables = _tables(EVOGRAPH_DB)
    nodes = []
    edges = []
    nid = 1

    # Legacy table support
    for tbl in ("attack_patterns", "patterns"):
        if tbl in tables:
            nodes = _query(EVOGRAPH_DB, f"SELECT * FROM {tbl} ORDER BY rowid DESC LIMIT 100")
            break
    for tbl in ("pattern_edges", "edges"):
        if tbl in tables:
            edges = _query(EVOGRAPH_DB, f"SELECT * FROM {tbl} ORDER BY rowid DESC LIMIT 200")
            break

    # Build graph from actual evograph tables if legacy tables are empty
    if not nodes and "tech_attack_map" in tables:
        tam_rows = _query(EVOGRAPH_DB, "SELECT * FROM tech_attack_map ORDER BY attempts DESC LIMIT 100")
        tech_ids = {}
        attack_ids = {}
        for row in tam_rows:
            tech = row.get("tech_signature", "")
            attack = row.get("attack_type", "")
            if tech and tech not in tech_ids:
                tech_ids[tech] = nid
                nodes.append({"id": nid, "label": tech, "group": "tech",
                              "size": 12})
                nid += 1
            if attack and attack not in attack_ids:
                attack_ids[attack] = nid
                nodes.append({"id": nid, "label": attack, "group": "attack",
                              "size": 8 + row.get("attempts", 0)})
                nid += 1
            if tech in tech_ids and attack in attack_ids:
                edges.append({
                    "from": tech_ids[tech], "to": attack_ids[attack],
                    "value": row.get("attempts", 1),
                    "success_rate": round(
                        (row.get("successes", 0) / max(row.get("attempts", 1), 1)) * 100, 1
                    ),
                })

    # Add session nodes if available
    if "sessions" in tables and not any(n.get("group") == "session" for n in nodes):
        sessions = _query(EVOGRAPH_DB, "SELECT * FROM sessions ORDER BY rowid DESC LIMIT 20")
        for s in sessions:
            sid = nid
            nid += 1
            nodes.append({
                "id": sid, "label": s.get("target", f"session-{s.get('id')}"),
                "group": "session", "size": 10,
                "findings": s.get("findings_count", 0),
                "reward": s.get("total_reward", 0),
            })

    return {"nodes": nodes, "edges": edges}


def get_react_traces():
    """All reasoning traces from ReACT-style agent."""
    # Check evograph db for traces (table is named reasoning_traces)
    if EVOGRAPH_DB.exists():
        tables = _tables(EVOGRAPH_DB)
        for tbl in ("reasoning_traces", "traces", "react_traces"):
            if tbl in tables:
                rows = _query(EVOGRAPH_DB, f"SELECT * FROM {tbl} ORDER BY rowid DESC LIMIT 50")
                if rows:
                    return rows

    # Fallback: check for hunt result JSON files in data/
    try:
        for jf in sorted(DATA_DIR.glob("*react*.json"), key=lambda p: p.stat().st_mtime, reverse=True)[:3]:
            data = json.loads(jf.read_text(encoding="utf-8", errors="replace"))
            if isinstance(data, dict) and "react_traces" in data:
                return data["react_traces"][:50]
    except Exception:
        pass

    # Derive from attack_history as trace-like steps
    return _query(
        VIPER_DB,
        "SELECT ah.id, ah.attack_type as action, ah.payload as input, "
        "ah.response_status as status, ah.success as result, "
        "ah.response_time_ms as duration_ms, ah.timestamp, t.domain as target "
        "FROM attack_history ah JOIN targets t ON ah.target_id=t.id "
        "ORDER BY ah.timestamp DESC LIMIT 100",
    )


def get_react_latest():
    """Latest reasoning trace with steps."""
    traces = get_react_traces()
    if not traces:
        return {"trace": None, "steps": []}

    latest = traces[0] if traces else None

    # If we have a trace_id, fetch steps
    if latest and "id" in latest:
        for tbl in ("reasoning_traces", "trace_steps", "react_steps", "steps"):
            if EVOGRAPH_DB.exists() and _table_exists(EVOGRAPH_DB, tbl):
                steps = _query(
                    EVOGRAPH_DB,
                    f"SELECT * FROM {tbl} WHERE trace_id=? ORDER BY rowid",
                    (latest["id"],),
                )
                if steps:
                    return {"trace": latest, "steps": steps}

    # Fallback: return latest attacks as "steps"
    steps = _query(
        VIPER_DB,
        "SELECT ah.attack_type as action, ah.payload as thought, "
        "ah.response_status as observation, ah.success as result, ah.timestamp "
        "FROM attack_history ah ORDER BY ah.timestamp DESC LIMIT 10",
    )
    return {"trace": latest, "steps": steps}


def get_recent_logs(lines=80):
    """Read last N lines from today's log file."""
    today = datetime.now().strftime("%Y%m%d")
    log_file = LOGS_DIR / f"viper_{today}.log"
    if not log_file.exists():
        yesterday = (datetime.now() - timedelta(days=1)).strftime("%Y%m%d")
        log_file = LOGS_DIR / f"viper_{yesterday}.log"
    if not log_file.exists():
        return []
    try:
        all_lines = log_file.read_text(encoding="utf-8", errors="replace").splitlines()
        return all_lines[-lines:]
    except Exception:
        return []


def get_state():
    """Read viper_state.json if available."""
    if STATE_FILE.exists():
        try:
            return json.loads(STATE_FILE.read_text())
        except Exception:
            return {}
    return {}


def get_attack_graph():
    """Attack graph data: nodes (targets, attacks, findings) and edges for vis.js/Sankey."""
    targets = get_targets()
    findings_result = get_findings(limit=200)
    # get_findings returns {"findings": [...], ...} dict — extract the list
    findings = findings_result.get("findings", []) if isinstance(findings_result, dict) else findings_result
    attacks = get_attack_stats()

    nodes = []
    edges = []
    nid = 1

    # Phase nodes for Sankey flow
    phases = {
        "recon": {"id": "recon", "label": "Recon", "group": "phase", "value": 0},
        "surface": {"id": "surface", "label": "Surface", "group": "phase", "value": 0},
        "scan": {"id": "scan", "label": "Scan", "group": "phase", "value": 0},
        "exploit": {"id": "exploit", "label": "Exploit", "group": "phase", "value": 0},
        "finding": {"id": "finding", "label": "Findings", "group": "phase", "value": 0},
    }

    total_targets = len(targets) if isinstance(targets, list) else 0
    total_attacks = sum(a.get("total", 0) for a in attacks) if attacks else 0
    total_findings = len(findings) if isinstance(findings, list) else 0

    phases["recon"]["value"] = total_targets
    phases["surface"]["value"] = max(1, int(total_targets * 2.5))
    phases["scan"]["value"] = max(1, int(total_attacks * 0.4))
    phases["exploit"]["value"] = total_attacks
    phases["finding"]["value"] = total_findings

    # Sankey links (from -> to -> value)
    sankey_links = [
        {"from": "recon", "to": "surface", "value": phases["surface"]["value"]},
        {"from": "surface", "to": "scan", "value": phases["scan"]["value"]},
        {"from": "scan", "to": "exploit", "value": phases["exploit"]["value"]},
        {"from": "exploit", "to": "finding", "value": phases["finding"]["value"]},
    ]

    # Target-level nodes for vis.js graph
    target_nodes = {}
    for t in (targets if isinstance(targets, list) else []):
        tid = nid
        nid += 1
        domain = t.get("domain", t.get("url", "target"))
        target_nodes[t.get("id", domain)] = tid
        nodes.append({
            "id": tid, "label": domain, "group": "target",
            "size": 15 + (t.get("finding_count", 0) * 2),
        })

    # Attack type nodes
    attack_nodes = {}
    for a in (attacks or []):
        aid = nid
        nid += 1
        attack_nodes[a["attack_type"]] = aid
        nodes.append({
            "id": aid, "label": a["attack_type"], "group": "attack",
            "size": 8 + (a.get("total", 0) * 0.5),
            "success_rate": a.get("success_rate", 0),
        })

    # Also build a domain→target_node_id lookup for fallback matching
    domain_to_node = {}
    for t in (targets if isinstance(targets, list) else []):
        d = t.get("domain", "")
        if d:
            domain_to_node[d] = target_nodes.get(t.get("id", d))

    # Finding nodes
    for f in (findings if isinstance(findings, list) else [])[:50]:
        fid = nid
        nid += 1
        nodes.append({
            "id": fid, "label": f.get("vuln_type", "finding"), "group": "finding",
            "severity": f.get("severity", "info"),
        })
        # Edge: target → finding (match by target_id int, or by domain string)
        linked = False
        tkey = f.get("target_id")
        if tkey is not None and tkey in target_nodes:
            edges.append({"from": target_nodes[tkey], "to": fid})
            linked = True
        if not linked:
            # Fallback: match by domain field (findings JOIN includes t.domain)
            fdomain = f.get("domain", "")
            if fdomain and fdomain in domain_to_node and domain_to_node[fdomain]:
                edges.append({"from": domain_to_node[fdomain], "to": fid})
                linked = True
        # Edge: attack_type → finding (match vuln_type to attack_type)
        vtype = f.get("vuln_type", "")
        if vtype and vtype in attack_nodes:
            edges.append({"from": attack_nodes[vtype], "to": fid})
        elif vtype:
            # Partial match: finding vuln_type may be substring of attack_type
            for atype, anode_id in attack_nodes.items():
                if vtype in atype or atype in vtype:
                    edges.append({"from": anode_id, "to": fid})
                    break

    return {
        "nodes": nodes,
        "edges": edges,
        "phases": phases,
        "sankey_links": sankey_links,
    }


def get_security_posture():
    """Compute radar chart data for security posture assessment."""
    findings = get_findings(limit=500)
    finding_list = findings if isinstance(findings, list) else []
    attacks = get_attack_stats()
    targets = get_targets()
    target_list = targets if isinstance(targets, list) else []

    total_findings = len(finding_list)
    total_attacks = sum(a.get("total", 0) for a in (attacks or []))
    total_success = sum(a.get("wins", 0) for a in (attacks or []))

    # Compute 6 axes (0-100 scale, higher = worse security)
    sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in finding_list:
        s = (f.get("severity") or "info").lower()
        sev_counts[s] = sev_counts.get(s, 0) + 1

    # Attack Surface: based on targets and endpoints discovered
    attack_surface = min(100, len(target_list) * 15 + total_findings * 2)

    # Vulnerability Density: findings per target
    vuln_density = min(100, int((total_findings / max(len(target_list), 1)) * 20))

    # Exploitability: success rate of attacks
    exploitability = min(100, int((total_success / max(total_attacks, 1)) * 100))

    # Config Security: based on config-related findings
    config_types = {"cors", "crlf", "open_redirect", "info_disclosure", "security_headers"}
    config_issues = sum(1 for f in finding_list if (f.get("vuln_type") or "").lower() in config_types)
    config_security = min(100, config_issues * 25)

    # Auth Strength: based on auth-related findings
    auth_types = {"auth_bypass", "idor", "csrf", "session_fixation", "brute_force"}
    auth_issues = sum(1 for f in finding_list if (f.get("vuln_type") or "").lower() in auth_types)
    auth_strength = min(100, auth_issues * 30)

    # Data Protection: based on injection/data-leak findings
    data_types = {"sqli", "sql_injection", "xss", "xxe", "lfi", "ssrf", "rce", "ssti"}
    data_issues = sum(1 for f in finding_list if (f.get("vuln_type") or "").lower() in data_types)
    data_protection = min(100, data_issues * 20)

    return {
        "labels": [
            "Attack Surface", "Vuln Density", "Exploitability",
            "Config Security", "Auth Strength", "Data Protection"
        ],
        "values": [
            attack_surface, vuln_density, exploitability,
            config_security, auth_strength, data_protection
        ],
        "risk_areas": {
            "attack_surface": attack_surface,
            "vuln_density": vuln_density,
            "exploitability": exploitability,
            "config_security": config_security,
            "auth_strength": auth_strength,
            "data_protection": data_protection,
        }
    }


def get_tech_heatmap():
    """Domain x attack type success rate heatmap matrix.

    Built from attack_history directly (domain as Y-axis, attack_type as X-axis)
    since targets.technologies is typically empty.
    """
    rows = _query(
        VIPER_DB,
        "SELECT t.domain, ah.attack_type, ah.success "
        "FROM attack_history ah JOIN targets t ON ah.target_id=t.id",
    )

    # Build matrix: domain -> attack_type -> {total, success}
    matrix_data = {}
    all_attack_types = set()
    all_domains = set()

    for r in rows:
        domain = r.get("domain", "unknown")
        atk = r.get("attack_type", "unknown")
        success = r.get("success", 0) or 0
        all_attack_types.add(atk)
        all_domains.add(domain)
        if domain not in matrix_data:
            matrix_data[domain] = {}
        if atk not in matrix_data[domain]:
            matrix_data[domain][atk] = {"total": 0, "success": 0}
        matrix_data[domain][atk]["total"] += 1
        matrix_data[domain][atk]["success"] += success

    # Sort attack types by total volume, take top 12
    atk_totals = {}
    for domain_data in matrix_data.values():
        for atk, cell in domain_data.items():
            atk_totals[atk] = atk_totals.get(atk, 0) + cell["total"]
    attack_types = sorted(atk_totals, key=lambda a: atk_totals[a], reverse=True)[:12]

    # Sort domains by total attacks, take top 15
    domain_totals = {}
    for domain, domain_data in matrix_data.items():
        domain_totals[domain] = sum(c["total"] for c in domain_data.values())
    domains = sorted(domain_totals, key=lambda d: domain_totals[d], reverse=True)[:15]

    heatmap = []
    for domain in domains:
        row = {"tech": domain, "rates": {}}
        for atk in attack_types:
            cell = matrix_data.get(domain, {}).get(atk, {"total": 0, "success": 0})
            rate = round(cell["success"] / max(cell["total"], 1) * 100, 1) if cell["total"] > 0 else None
            row["rates"][atk] = rate
        heatmap.append(row)

    return {
        "attack_types": attack_types,
        "technologies": domains,
        "matrix": heatmap,
    }


# ── VIPER 4.0 agent/session/triage helpers ──

def get_agent_status():
    """Current agent state from viper_state.json and control files."""
    state = get_state()
    status = {
        "phase": state.get("phase", "idle"),
        "target": state.get("current_target", state.get("target", "")),
        "progress": state.get("progress", 0),
        "status": state.get("status", "idle"),
        "started_at": state.get("started_at", ""),
        "elapsed": state.get("elapsed", 0),
        "current_action": state.get("current_action", ""),
        "todos": state.get("todos", []),
    }
    control_file = STATE_DIR / "agent_control.json"
    if control_file.exists():
        try:
            status["pending_command"] = json.loads(control_file.read_text())
        except Exception:
            pass
    return status


def get_agent_thinking():
    """Latest thinking/deep-think results from state files."""
    thinking = {"thoughts": [], "deep_think": None}
    thinking_file = STATE_DIR / "thinking.json"
    if thinking_file.exists():
        try:
            thinking["thoughts"] = json.loads(thinking_file.read_text())
        except Exception:
            pass
    deep_file = STATE_DIR / "deep_think.json"
    if deep_file.exists():
        try:
            thinking["deep_think"] = json.loads(deep_file.read_text())
        except Exception:
            pass
    if METRICS_FILE.exists():
        try:
            metrics = json.loads(METRICS_FILE.read_text())
            if "thinking" in metrics:
                thinking["metrics_thinking"] = metrics["thinking"]
        except Exception:
            pass
    return thinking


def get_triage_findings():
    """Triaged findings with priority scores."""
    if not VIPER_DB.exists():
        return {"findings": [], "total": 0}

    findings = _query(
        VIPER_DB,
        "SELECT f.*, t.domain FROM findings f "
        "JOIN targets t ON f.target_id=t.id "
        "ORDER BY CASE LOWER(f.severity) "
        "WHEN 'critical' THEN 1 WHEN 'high' THEN 2 "
        "WHEN 'medium' THEN 3 WHEN 'low' THEN 4 ELSE 5 END, "
        "f.confidence DESC, f.found_at DESC LIMIT 100",
    )

    sev_scores = {"critical": 100, "high": 75, "medium": 50, "low": 25, "info": 10}
    for f in findings:
        sev = (f.get("severity") or "info").lower()
        base = sev_scores.get(sev, 10)
        conf = f.get("confidence", 50) or 50
        validated_bonus = 20 if f.get("validated") else 0
        f["priority_score"] = min(100, base + int(conf * 0.2) + validated_bonus)

    return {"findings": findings, "total": len(findings)}


def get_codefix_status():
    """CodeFix remediation status from state file."""
    codefix = {"status": "idle", "fixes": [], "total": 0, "applied": 0}
    codefix_file = STATE_DIR / "codefix_status.json"
    if codefix_file.exists():
        try:
            codefix = json.loads(codefix_file.read_text())
        except Exception:
            pass
    return codefix


def get_sessions_list():
    """All past hunt sessions."""
    sessions = get_evograph_sessions()
    if sessions:
        return {"sessions": sessions, "total": len(sessions)}

    session_dir = STATE_DIR / "sessions"
    result = []
    if session_dir.exists():
        for sf in sorted(session_dir.glob("*.json"), key=lambda p: p.stat().st_mtime, reverse=True):
            try:
                result.append(json.loads(sf.read_text()))
            except Exception:
                pass
    return {"sessions": result, "total": len(result)}


def get_session_detail(session_id):
    """Session detail with full trace."""
    if EVOGRAPH_DB.exists():
        tables = _tables(EVOGRAPH_DB)
        for tbl in ("hunt_sessions", "sessions"):
            if tbl in tables:
                session = _query(
                    EVOGRAPH_DB,
                    f"SELECT * FROM {tbl} WHERE id=? OR rowid=?",
                    (session_id, session_id),
                    one=True,
                )
                if session:
                    for trace_tbl in ("reasoning_traces", "traces"):
                        if trace_tbl in tables:
                            session["traces"] = _query(
                                EVOGRAPH_DB,
                                f"SELECT * FROM {trace_tbl} WHERE session_id=? ORDER BY rowid",
                                (session_id,),
                            )
                            break
                    return session

    session_file = STATE_DIR / "sessions" / f"{session_id}.json"
    if session_file.exists():
        try:
            return json.loads(session_file.read_text())
        except Exception:
            pass
    return {}


# ── MIME types for static files ──

MIME_TYPES = {
    ".html": "text/html; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".js": "application/javascript; charset=utf-8",
    ".json": "application/json",
    ".png": "image/png",
    ".jpg": "image/jpeg",
    ".jpeg": "image/jpeg",
    ".gif": "image/gif",
    ".svg": "image/svg+xml",
    ".ico": "image/x-icon",
    ".woff": "font/woff",
    ".woff2": "font/woff2",
    ".ttf": "font/ttf",
    ".map": "application/json",
}


# ── HTTP Request Handler ──

class DashboardHandler(BaseHTTPRequestHandler):
    """Handle API, SSE, and static file requests."""

    def log_message(self, fmt, *args):
        pass  # Suppress default logging

    def _cors_headers(self):
        """Add CORS headers."""
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")

    def _json_response(self, data, status=200):
        body = json.dumps(data, default=str).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self._cors_headers()
        self.end_headers()
        self.wfile.write(body)

    def _html_response(self, html, status=200):
        body = html.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self._cors_headers()
        self.end_headers()
        self.wfile.write(body)

    def _serve_static(self, rel_path):
        """Serve a static file from the dashboard directory."""
        # Prevent path traversal
        safe = Path(DASHBOARD_DIR / rel_path).resolve()
        if not str(safe).startswith(str(DASHBOARD_DIR)):
            self.send_error(403, "Forbidden")
            return
        if not safe.is_file():
            self.send_error(404, "Not Found")
            return

        ext = safe.suffix.lower()
        mime = MIME_TYPES.get(ext, "application/octet-stream")

        try:
            content = safe.read_bytes()
            self.send_response(200)
            self.send_header("Content-Type", mime)
            self.send_header("Content-Length", str(len(content)))
            self._cors_headers()
            self.send_header("Cache-Control", "public, max-age=3600")
            self.end_headers()
            self.wfile.write(content)
        except Exception:
            self.send_error(500, "Internal Server Error")

    def _serve_file(self, filepath, content_type="text/html"):
        """Serve a static file by absolute path."""
        filepath = Path(filepath)
        if filepath.exists():
            content = filepath.read_bytes()
            self.send_response(200)
            self.send_header("Content-Type", f"{content_type}; charset=utf-8")
            self.send_header("Content-Length", str(len(content)))
            self._cors_headers()
            self.end_headers()
            self.wfile.write(content)
        else:
            self.send_error(404, f"File not found: {filepath.name}")

    def _handle_sse(self):
        """Server-Sent Events stream."""
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "keep-alive")
        self._cors_headers()
        self.end_headers()

        sub = event_bus.subscribe()
        try:
            # Send initial connected event
            self.wfile.write(b"event: connected\ndata: {\"status\":\"ok\"}\n\n")
            self.wfile.flush()

            while True:
                try:
                    event_type, data = sub.get(timeout=30)
                    payload = json.dumps(data, default=str)
                    msg = f"event: {event_type}\ndata: {payload}\n\n"
                    self.wfile.write(msg.encode("utf-8"))
                    self.wfile.flush()
                except queue.Empty:
                    # Send keepalive comment
                    self.wfile.write(b": keepalive\n\n")
                    self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError, OSError):
            pass
        finally:
            event_bus.unsubscribe(sub)

    def do_OPTIONS(self):
        """Handle CORS preflight."""
        self.send_response(204)
        self._cors_headers()
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_POST(self):
        path = urlparse(self.path).path
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length) if content_length else b""

        if path == "/api/settings":
            sm = _get_settings()
            if sm:
                try:
                    data = json.loads(body)
                    for k, v in data.items():
                        sm.set(k, v)
                    sm.save()
                    self._json_response({"status": "saved"})
                except Exception as e:
                    self._json_response({"error": str(e)}, status=400)
            else:
                self._json_response({"error": "Settings not available"}, status=500)

        elif path == "/api/agent/guidance":
            try:
                data = json.loads(body) if body else {}
                STATE_DIR.mkdir(parents=True, exist_ok=True)
                resp_file = STATE_DIR / "guidance.json"
                resp_file.write_text(json.dumps({
                    "guidance": data.get("guidance", ""),
                    "priority": data.get("priority", "normal"),
                    "timestamp": time.time(),
                }), encoding="utf-8")
                _ws_broadcast(MessageType.PHASE_UPDATE, {"message": "Guidance sent to agent"})
                self._json_response({"status": "sent"})
            except Exception as e:
                self._json_response({"error": str(e)}, status=400)

        elif path == "/api/agent/approve":
            try:
                data = json.loads(body) if body else {}
                STATE_DIR.mkdir(parents=True, exist_ok=True)
                resp_file = STATE_DIR / "approval_response.json"
                resp_file.write_text(json.dumps({
                    "approved": data.get("approved", False),
                    "reason": data.get("reason", ""),
                    "timestamp": time.time(),
                }), encoding="utf-8")
                _ws_broadcast(MessageType.PHASE_UPDATE, {
                    "message": "Approval response recorded",
                    "approved": data.get("approved", False),
                })
                self._json_response({"status": "recorded"})
            except Exception as e:
                self._json_response({"error": str(e)}, status=400)

        elif path == "/api/agent/answer":
            try:
                data = json.loads(body) if body else {}
                STATE_DIR.mkdir(parents=True, exist_ok=True)
                resp_file = STATE_DIR / "qa_response.json"
                resp_file.write_text(json.dumps({
                    "answer": data.get("answer", ""),
                    "question_id": data.get("question_id", ""),
                    "timestamp": time.time(),
                }), encoding="utf-8")
                _ws_broadcast(MessageType.PHASE_UPDATE, {"message": "Answer received"})
                self._json_response({"status": "received"})
            except Exception as e:
                self._json_response({"error": str(e)}, status=400)

        else:
            self.send_error(404)

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/") or "/"
        qs = parse_qs(parsed.query)

        # Helper to extract first query param
        def qp(name, default=None):
            vals = qs.get(name, [])
            return vals[0] if vals else default

        # ── WebSocket Upgrade ──
        if path == "/ws":
            upgrade = (self.headers.get("Upgrade") or "").lower()
            if upgrade == "websocket":
                _handle_websocket(self)
                return
            else:
                self.send_error(400, "WebSocket upgrade required")
                return

        # ── SSE Stream ──
        if path in ("/api/stream", "/api/events"):
            self._handle_sse()
            return

        # ── Overview ──
        if path == "/api/overview":
            self._json_response(get_overview())

        elif path == "/api/risk-score":
            self._json_response(get_risk_score())

        elif path == "/api/state":
            self._json_response(get_state())

        # ── VIPER 4.0 Agent Endpoints ──
        elif path == "/api/agent/status":
            self._json_response(get_agent_status())

        elif path == "/api/agent/thinking":
            self._json_response(get_agent_thinking())

        elif path == "/api/triage/findings":
            self._json_response(get_triage_findings())

        elif path == "/api/codefix/status":
            self._json_response(get_codefix_status())

        elif path == "/api/sessions/list":
            self._json_response(get_sessions_list())

        elif path.startswith("/api/sessions/") and path != "/api/sessions/list":
            sid = path.split("/api/sessions/", 1)[1]
            try:
                session_id = int(sid)
            except ValueError:
                session_id = sid
            result = get_session_detail(session_id)
            if result:
                self._json_response(result)
            else:
                self._json_response({"error": "Session not found"}, 404)

        # ── Findings ──
        elif path == "/api/findings":
            page = int(qp("page", "1"))
            limit = int(qp("limit", "50"))
            result = get_findings(
                severity=qp("severity"),
                vuln_type=qp("vuln_type"),
                domain=qp("domain"),
                page=page,
                limit=limit,
            )
            self._json_response(result)

        elif path == "/api/findings/timeline":
            self._json_response(get_findings_timeline())

        elif path == "/api/findings/by-type":
            self._json_response(get_findings_by_type())

        elif path == "/api/findings/by-severity":
            self._json_response(get_findings_by_severity())

        elif path == "/api/findings/by-domain":
            self._json_response(get_findings_by_domain())

        elif path.startswith("/api/findings/") and path != "/api/findings/":
            # /api/findings/:id — must be numeric
            segment = path.split("/")[-1]
            if segment.isdigit():
                result = get_finding_detail(int(segment))
                if result:
                    self._json_response(result)
                else:
                    self._json_response({"error": "Finding not found"}, 404)
            else:
                self.send_error(400, "Invalid finding ID")

        # ── Targets ──
        elif path == "/api/targets":
            self._json_response(get_targets())

        elif path.startswith("/api/targets/") and path != "/api/targets/":
            domain = path.split("/api/targets/", 1)[1]
            result = get_target_detail(domain)
            if result:
                self._json_response(result)
            else:
                self._json_response({"error": "Target not found"}, 404)

        # ── Attack Stats ──
        elif path == "/api/attacks/stats":
            self._json_response(get_attack_stats())

        elif path == "/api/attacks/history":
            limit = int(qp("limit", "200"))
            self._json_response(get_attack_history(limit=limit))

        elif path == "/api/attacks/kill-chain":
            self._json_response(get_attack_kill_chain())

        # ── Legacy attack endpoints (backwards compat) ──
        elif path in ("/api/attack-stats", "/api/attack_stats"):
            self._json_response(get_attack_stats())

        elif path == "/api/attack-history":
            limit = int(qp("limit", "200"))
            self._json_response(get_attack_history(limit=limit))

        # ── EvoGraph ──
        elif path == "/api/evograph/stats":
            self._json_response(get_evograph_stats())

        elif path == "/api/evograph/sessions":
            self._json_response(get_evograph_sessions())

        elif path == "/api/evograph/tech-map":
            self._json_response(get_evograph_tech_map())

        elif path == "/api/evograph/graph":
            self._json_response(get_evograph_graph())

        elif path in ("/api/evograph", "/api/evolution"):
            # Legacy combined endpoint
            self._json_response(get_evograph_stats())

        # ── New Phase 9 endpoints ──
        elif path == "/api/attack-graph":
            self._json_response(get_attack_graph())

        elif path == "/api/security-posture":
            self._json_response(get_security_posture())

        elif path == "/api/tech-heatmap":
            self._json_response(get_tech_heatmap())

        # ── ReACT ──
        elif path in ("/api/react/traces", "/api/react"):
            self._json_response(get_react_traces())

        elif path == "/api/react/latest":
            self._json_response(get_react_latest())

        # ── Logs ──
        elif path == "/api/logs":
            lines = int(qp("lines", "80"))
            self._json_response(get_recent_logs(lines=lines))

        # ── VIPER 4.0 API endpoints ──

        elif path == "/api/graph":
            ge = _get_graph_engine()
            if ge:
                graph_data = ge.to_vis_json()
                self._json_response(graph_data)
            else:
                self._json_response({"nodes": [], "edges": []})

        elif path == "/api/graph/stats":
            ge = _get_graph_engine()
            if ge:
                self._json_response(ge.stats())
            else:
                self._json_response({"total_nodes": 0, "total_edges": 0})

        elif path == "/api/graph/query":
            ge = _get_graph_engine()
            q = qp("q", "")
            if ge and q:
                results = ge.query(q)
                self._json_response({"query": q, "results": results})
            else:
                self._json_response({"query": q, "results": []})

        elif path == "/api/status":
            import shutil
            status = {
                "version": "4.0",
                "uptime_seconds": 0,
                "dashboard_started": getattr(self.server, '_start_time', None),
                "db_connected": VIPER_DB.exists() if VIPER_DB else False,
                "evograph_connected": EVOGRAPH_DB.exists() if EVOGRAPH_DB else False,
                "tools": {
                    tool: shutil.which(tool) is not None
                    for tool in ["nuclei", "httpx", "subfinder", "katana", "gau", "curl"]
                },
            }
            # Add DB stats if available
            try:
                db = _get_db()
                if db:
                    s = db.stats()
                    status["targets"] = s.get("targets", 0)
                    status["findings"] = s.get("findings", 0)
                    status["attacks"] = s.get("attacks", 0)
            except Exception:
                pass
            self._json_response(status)

        elif path == "/api/settings":
            sm = _get_settings()
            if sm:
                self._json_response(sm._settings)
            else:
                self._json_response({})

        elif path == "/api/triage":
            ge = _get_graph_engine()
            if ge:
                try:
                    from core.triage_engine import TriageEngine
                    te = TriageEngine(ge)
                    results = te.triage_sync()
                    self._json_response({"remediations": [r.to_dict() if hasattr(r, 'to_dict') else r for r in results]})
                except Exception as e:
                    self._json_response({"error": str(e)})
            else:
                self._json_response({"remediations": []})

        elif path == "/api/reports":
            # List HTML reports in reports/ directory
            reports = []
            if REPORTS_DIR.exists():
                for f in sorted(REPORTS_DIR.glob("*.html"), reverse=True):
                    reports.append({"name": f.name, "size": f.stat().st_size, "modified": f.stat().st_mtime})
            self._json_response({"reports": reports[:20]})

        # ── Sessions (legacy) ──
        elif path == "/api/sessions":
            self._json_response(get_evograph_sessions())

        elif path == "/api/timeline":
            self._json_response(get_findings_timeline())

        elif path.startswith("/api/session/"):
            sid = path.split("/")[-1]
            if sid.isdigit():
                result = get_target_detail_by_id(int(sid))
                self._json_response(result)
            else:
                self._json_response({"error": "Invalid session ID"}, 400)

        # ── VIPER 4.0 dashboard pages ──
        elif path == "/graph":
            self._serve_file(DASHBOARD_DIR / "graph_viz.html", "text/html")

        elif path == "/charts":
            self._serve_file(DASHBOARD_DIR / "charts.html", "text/html")

        elif path == "/chat":
            self._serve_file(DASHBOARD_DIR / "chat.html", "text/html")

        elif path == "/terminal":
            self._serve_file(DASHBOARD_DIR / "terminal.html", "text/html")

        elif path == "/settings":
            self._serve_file(DASHBOARD_DIR / "settings_ui.html", "text/html")

        # ── Static files / index ──
        elif path == "/":
            index = DASHBOARD_DIR / "index.html"
            if index.is_file():
                self._serve_static("index.html")
            else:
                self._html_response(_fallback_index())
        else:
            # Try to serve static file
            rel = path.lstrip("/")
            candidate = DASHBOARD_DIR / rel
            if candidate.is_file():
                self._serve_static(rel)
            else:
                # SPA fallback: serve index.html for non-API routes
                index = DASHBOARD_DIR / "index.html"
                if index.is_file() and not path.startswith("/api/"):
                    self._serve_static("index.html")
                else:
                    self.send_error(404)


def get_target_detail_by_id(target_id):
    """Get target detail by numeric ID (legacy session endpoint)."""
    target = _query(
        VIPER_DB,
        "SELECT * FROM targets WHERE id=?",
        (target_id,),
        one=True,
    )
    if not target:
        return {}
    try:
        target["technologies"] = json.loads(target.get("technologies") or "[]")
    except Exception:
        target["technologies"] = []

    target["findings"] = _query(
        VIPER_DB,
        "SELECT * FROM findings WHERE target_id=? ORDER BY found_at DESC",
        (target_id,),
    )
    target["attacks"] = _query(
        VIPER_DB,
        "SELECT * FROM attack_history WHERE target_id=? ORDER BY timestamp DESC LIMIT 100",
        (target_id,),
    )
    return target


def _fallback_index():
    """Minimal fallback HTML if no index.html exists yet."""
    return """<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>VIPER Dashboard</title>
<style>body{background:#0a0e17;color:#e2e8f0;font-family:system-ui;display:flex;
align-items:center;justify-content:center;height:100vh;margin:0}
.box{text-align:center;padding:40px;border:1px solid #1e293b;border-radius:12px;
background:#111827}h1{color:#6366f1;margin-bottom:16px}
p{color:#94a3b8;margin:8px 0}a{color:#818cf8}</style></head>
<body><div class="box"><h1>VIPER Dashboard</h1>
<p>Backend is running. Frontend not deployed yet.</p>
<p>API available at <a href="/api/overview">/api/overview</a></p>
<p>SSE stream at <a href="/api/stream">/api/stream</a></p>
</div></body></html>"""


# ── Public API for integration ──

def publish_event(event_type, data):
    """Publish an event to all SSE subscribers. Call from viper_core.py etc."""
    event_bus.publish(event_type, data)


def broadcast_event(event_type, data):
    """Called by viper_core.py to push events to dashboard.

    Broadcasts to both SSE subscribers and WebSocket clients.
    Also writes to a shared event queue file for cross-process communication.
    """
    # Push to SSE event bus
    event_bus.publish(event_type, data)
    # Push to WebSocket clients
    _ws_broadcast(event_type, data)
    # Write to shared event queue file for cross-process consumers
    try:
        STATE_DIR.mkdir(parents=True, exist_ok=True)
        queue_data = []
        if EVENT_QUEUE_FILE.exists():
            try:
                queue_data = json.loads(EVENT_QUEUE_FILE.read_text())
                if not isinstance(queue_data, list):
                    queue_data = []
            except Exception:
                queue_data = []
        queue_data.append({
            "type": event_type,
            "data": data,
            "timestamp": time.time(),
        })
        # Keep last 200 events
        if len(queue_data) > 200:
            queue_data = queue_data[-200:]
        EVENT_QUEUE_FILE.write_text(json.dumps(queue_data, default=str), encoding="utf-8")
    except Exception:
        pass


def start_dashboard(port=8080):
    """Start the dashboard in a background daemon thread (for integration with viper.py)."""
    server = ThreadedHTTPServer(("127.0.0.1", port), DashboardHandler)
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    return server


def main():
    port = 8080
    for flag in ("--dashboard-port", "--port"):
        if flag in sys.argv:
            idx = sys.argv.index(flag) + 1
            if idx < len(sys.argv):
                port = int(sys.argv[idx])
                break

    server = ThreadedHTTPServer(("127.0.0.1", port), DashboardHandler)
    print(f"VIPER Dashboard running at http://localhost:{port}")
    print(f"  DB: {VIPER_DB} ({'exists' if VIPER_DB.exists() else 'not found'})")
    print(f"  EvoGraph: {EVOGRAPH_DB} ({'exists' if EVOGRAPH_DB.exists() else 'not found'})")
    print(f"  Static: {DASHBOARD_DIR}")
    print(f"\nAPI endpoints:")
    print(f"  GET /api/overview           — KPI stats")
    print(f"  GET /api/risk-score         — Risk score (0-100)")
    print(f"  GET /api/findings           — Paginated findings")
    print(f"  GET /api/findings/:id       — Finding detail")
    print(f"  GET /api/findings/timeline  — Findings over time")
    print(f"  GET /api/findings/by-type   — Group by vuln type")
    print(f"  GET /api/findings/by-severity — Group by severity")
    print(f"  GET /api/findings/by-domain — Group by domain")
    print(f"  GET /api/targets            — All targets")
    print(f"  GET /api/targets/:domain    — Target detail")
    print(f"  GET /api/attacks/stats      — Attack success rates")
    print(f"  GET /api/attacks/history    — Attack log")
    print(f"  GET /api/attacks/kill-chain — Kill chain funnel")
    print(f"  GET /api/evograph/stats     — EvoGraph stats")
    print(f"  GET /api/evograph/sessions  — EvoGraph sessions")
    print(f"  GET /api/evograph/tech-map  — Tech->attack map")
    print(f"  GET /api/evograph/graph     — Graph nodes/edges")
    print(f"  GET /api/react/traces       — ReACT traces")
    print(f"  GET /api/react/latest       — Latest trace")
    print(f"  GET /api/logs               — Recent logs")
    print(f"  GET /api/stream             — SSE live stream")
    print(f"  GET /api/state              — Viper state")
    print(f"  GET /api/graph              — Attack graph (V4)")
    print(f"  GET /api/graph/stats        — Graph statistics (V4)")
    print(f"  GET /api/graph/query?q=     — Graph query (V4)")
    print(f"  GET /api/settings           — Settings (V4)")
    print(f"  POST /api/settings          — Save settings (V4)")
    print(f"  GET /api/triage             — Triage remediations (V4)")
    print(f"  GET /api/reports            — Report listing (V4)")
    print(f"  GET /api/agent/status       — Agent state (v4)")
    print(f"  GET /api/agent/thinking     — Deep-think results (v4)")
    print(f"  GET /api/triage/findings    — Triaged findings (v4)")
    print(f"  GET /api/codefix/status     — CodeFix status (v4)")
    print(f"  GET /api/sessions/list      — Hunt sessions (v4)")
    print(f"  GET /api/sessions/:id       — Session detail (v4)")
    print(f"  POST /api/agent/guidance    — Send guidance (v4)")
    print(f"  POST /api/agent/approve     — Approve/reject (v4)")
    print(f"  POST /api/agent/answer      — Answer question (v4)")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down dashboard.")
        server.server_close()


if __name__ == "__main__":
    main()
