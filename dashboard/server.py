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
import csv
import hashlib
import io
import json
import math
import os
import queue
import sqlite3
import struct
import subprocess
import sys
import threading
import time
import uuid
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
            # Populate graph from viper.db so Graph tab has real data
            _populate_graph_from_db(_graph_engine)
        except Exception:
            pass
    return _graph_engine


def _populate_graph_from_db(ge):
    """Populate the knowledge graph from viper.db findings/targets."""
    if not VIPER_DB.exists():
        return
    try:
        targets = _query(VIPER_DB, "SELECT * FROM targets LIMIT 200")
        for t in targets:
            domain = t.get("domain", t.get("url", ""))
            if domain:
                ge.add_target(domain)

        findings = _query(VIPER_DB,
            "SELECT f.*, t.domain, t.url as target_url FROM findings f "
            "LEFT JOIN targets t ON f.target_id = t.id LIMIT 500")
        for f in findings:
            domain = f.get("domain", "")
            vuln = f.get("vuln_type", f.get("type", "unknown"))
            sev = f.get("severity", "medium")
            url = f.get("url", f.get("target_url", ""))
            if domain and vuln:
                ge.add_finding(domain, vuln, severity=sev, url=url,
                               confidence=f.get("confidence", 0.5))

        # Add technologies if available
        techs = _query(VIPER_DB,
            "SELECT t.domain, ts.tech_name FROM tech_stack ts "
            "JOIN targets t ON ts.target_id = t.id LIMIT 200")
        for tech in techs:
            domain = tech.get("domain", "")
            name = tech.get("tech_name", "")
            if domain and name:
                try:
                    ge.add_technology(name, domain)
                except Exception:
                    pass

        logger.info("Graph populated from DB: %d nodes", len(ge.backend.graph.nodes) if hasattr(ge.backend, 'graph') else 0)
    except Exception as e:
        logger.debug("Graph population error: %s", e)

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
        conn = sqlite3.connect(str(db_path), check_same_thread=False, timeout=10)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA busy_timeout=5000")
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


# ── Log tailer thread (live log streaming) ──

def _log_tailer():
    """Tail today's VIPER log file and push new lines via WebSocket + SSE."""
    file_pos = 0
    current_date = ""
    while True:
        time.sleep(1.5)
        has_clients = len(_ws_clients) > 0 or event_bus.subscriber_count > 0
        if not has_clients:
            continue
        try:
            today = datetime.now().strftime("%Y%m%d")
            log_file = LOGS_DIR / f"viper_{today}.log"
            if not log_file.exists():
                file_pos = 0
                continue
            # Reset position on date change
            if today != current_date:
                current_date = today
                file_pos = 0
            file_size = log_file.stat().st_size
            if file_size <= file_pos:
                if file_size < file_pos:
                    file_pos = 0  # File was truncated/rotated
                continue
            with open(log_file, "r", encoding="utf-8", errors="replace") as f:
                f.seek(file_pos)
                new_lines = f.readlines()
                file_pos = f.tell()
            for line in new_lines[-50:]:  # Cap to 50 lines per batch
                line = line.rstrip()
                if not line:
                    continue
                # Parse log level from line format: [HH:MM:SS] [MODULE] [LEVEL] msg
                level = "INFO"
                for lv in ("ERROR", "WARN", "SUCCESS", "CRITICAL", "DEBUG"):
                    if f"[{lv}]" in line:
                        level = lv
                        break
                payload = {"text": line, "level": level, "timestamp": time.time()}
                if len(_ws_clients) > 0:
                    _ws_broadcast("log_line", payload)
                if event_bus.subscriber_count > 0:
                    event_bus.publish("log_line", payload)

                # ── Typed agent events for Agent Monitor ──
                _emit_typed_agent_event(line, time.time())
        except Exception:
            pass


_log_tailer_thread = threading.Thread(target=_log_tailer, daemon=True)
_log_tailer_thread.start()


# ── Agent Monitor: typed event emitter ──

import re as _re

# Agent color/name mapping
_AGENT_NAMES = {
    "recon": "recon_agent",
    "vuln": "vuln_agent",
    "exploit": "exploit_agent",
    "chain": "chain_agent",
    "react": "react_engine",
    "think": "think_engine",
}

# Patterns for typed event detection
_AGENT_PATTERNS = [
    (_re.compile(r"\[ReACT\]", _re.I), "react_step"),
    (_re.compile(r"\[STRATEGY\]|\[DeepThink\]|\[DEEP.?THINK\]", _re.I), "deep_think"),
    (_re.compile(r"\[\+\]|\[SUCCESS\]|\[FINDING\]|\[VULN\]", _re.I), "finding_new"),
    (_re.compile(r"\bPhase\b.*(?:RECON|SCAN|EXPLOIT|REPORT|ENUM)", _re.I), "phase_update"),
    (_re.compile(r"\[RECON\]|\brecon.?agent\b", _re.I), "agent_event"),
    (_re.compile(r"\[VULN\]|\bvuln.?agent\b", _re.I), "agent_event"),
    (_re.compile(r"\[EXPLOIT\]|\bexploit.?agent\b", _re.I), "agent_event"),
    (_re.compile(r"\[CHAIN\]|\bchain.?agent\b", _re.I), "agent_event"),
]

# Extract agent name from log line
_AGENT_TAG_RE = _re.compile(r"\[(RECON|VULN|EXPLOIT|CHAIN|ReACT|STRATEGY|DeepThink|THINK)\]", _re.I)
_TIMESTAMP_RE = _re.compile(r"(\d{2}:\d{2}:\d{2})")


def _detect_agent(line):
    """Detect which agent a log line belongs to."""
    m = _AGENT_TAG_RE.search(line)
    if m:
        tag = m.group(1).lower()
        if tag in ("strategy", "deepthink", "think"):
            return "think_engine"
        if tag == "react":
            return "react_engine"
        return _AGENT_NAMES.get(tag, tag + "_agent")
    for name in ("recon", "vuln", "exploit", "chain"):
        if name in line.lower():
            return _AGENT_NAMES[name]
    return None


def _emit_typed_agent_event(line, ts):
    """Parse a log line and emit typed WebSocket events for the Agent Monitor."""
    has_clients = len(_ws_clients) > 0 or event_bus.subscriber_count > 0
    if not has_clients:
        return

    agent = _detect_agent(line)
    ts_match = _TIMESTAMP_RE.search(line)
    time_str = ts_match.group(1) if ts_match else ""

    for pattern, event_type in _AGENT_PATTERNS:
        if pattern.search(line):
            payload = {
                "agent": agent or "system",
                "text": line,
                "event_type": event_type,
                "time": time_str,
                "timestamp": ts,
            }
            if len(_ws_clients) > 0:
                _ws_broadcast(event_type, payload)
            if event_bus.subscriber_count > 0:
                event_bus.publish(event_type, payload)
            break


def get_agent_monitor():
    """Build real-time agent monitor data from logs and DB."""
    state = get_state()
    metrics = state.get("metrics", {})
    agents_data = []

    agent_defs = [
        {"name": "recon_agent", "label": "RECON AGENT", "topic": "recon"},
        {"name": "vuln_agent", "label": "VULN AGENT", "topic": "vuln"},
        {"name": "exploit_agent", "label": "EXPLOIT AGENT", "topic": "exploit"},
        {"name": "chain_agent", "label": "CHAIN AGENT", "topic": "chain"},
    ]

    # Parse current state from the LAST 100 log lines (most reliable source)
    current_target = ""
    current_phase = "idle"
    status_str = "idle"
    current_action = ""
    last_cycle_time = ""
    try:
        today = datetime.now().strftime("%Y%m%d")
        log_file = LOGS_DIR / f"viper_{today}.log"
        if log_file.exists():
            recent = log_file.read_text(encoding="utf-8", errors="replace").splitlines()[-100:]
            for ln in reversed(recent):
                if "Full Hunt:" in ln and not current_target:
                    # Extract target from "VIPER Full Hunt: <target>"
                    import re as _re
                    m = _re.search(r"Full Hunt:\s*(.+?)(?:\s*===|\s*$)", ln)
                    if m:
                        current_target = m.group(1).strip()
                if "Phase" in ln and "===" in ln and current_phase == "idle":
                    m = _re.search(r"Phase\s+\d+[^:]*:\s*(.+?)(?:\s*===|\s*\()", ln)
                    if m:
                        current_phase = m.group(1).strip()
                        status_str = "running"
                if "Cycle complete" in ln:
                    status_str = "waiting"
                    break
                if "EXHAUSTION" in ln and "stopping" in ln.lower():
                    status_str = "exhausted"
                    break
                if "[ReACT]" in ln and "Action:" in ln:
                    m = _re.search(r"Action:\s*(.+)", ln)
                    if m:
                        current_action = m.group(1).strip()
    except Exception:
        pass

    started_at = metrics.get("start_time", "")
    progress = 0

    # Parse today's log for agent activity
    agent_activity = {}
    agent_findings = {}
    agent_last_seen = {}
    try:
        today = datetime.now().strftime("%Y%m%d")
        log_file = LOGS_DIR / f"viper_{today}.log"
        if log_file.exists():
            lines = log_file.read_text(encoding="utf-8", errors="replace").splitlines()[-500:]
            for ln in lines:
                agent = _detect_agent(ln)
                if agent:
                    agent_activity[agent] = agent_activity.get(agent, 0) + 1
                    agent_last_seen[agent] = ln
                    if any(tag in ln for tag in ("[+]", "[SUCCESS]", "[FINDING]", "found", "discovered")):
                        agent_findings[agent] = agent_findings.get(agent, 0) + 1
    except Exception:
        pass

    # Compute uptime from started_at
    uptime = 0
    if started_at:
        try:
            st = datetime.fromisoformat(started_at) if isinstance(started_at, str) else datetime.fromtimestamp(started_at)
            uptime = int((datetime.now() - st).total_seconds())
        except Exception:
            uptime = state.get("elapsed", 0)

    # Map phase to active agent
    phase_agent_map = {
        "recon": "recon_agent", "scan": "vuln_agent", "exploit": "exploit_agent",
        "report": "chain_agent", "enum": "recon_agent", "surface": "recon_agent",
        "vuln": "vuln_agent", "chain": "chain_agent",
    }
    active_agent = phase_agent_map.get(current_phase.lower().split("_")[0] if current_phase else "", "")

    for ad in agent_defs:
        is_active = ad["name"] == active_agent and status_str not in ("idle", "done", "error")
        a_status = "running" if is_active else ("idle" if status_str in ("idle", "done") else "standby")
        a_task = current_action if is_active else None
        a_phase = current_phase if is_active else None
        a_findings = agent_findings.get(ad["name"], 0)
        a_uptime = uptime if is_active else 0

        # Check DB findings count for this agent's topic
        if VIPER_DB.exists() and a_findings == 0:
            try:
                cnt = _scalar(VIPER_DB,
                    "SELECT COUNT(*) FROM findings WHERE vuln_type LIKE ? OR details LIKE ?",
                    (f"%{ad['topic']}%", f"%{ad['topic']}%"))
                a_findings = cnt or 0
            except Exception:
                pass

        agents_data.append({
            "name": ad["name"],
            "label": ad["label"],
            "topic": ad["topic"],
            "status": a_status,
            "current_task": a_task,
            "phase": a_phase,
            "progress": progress if is_active else 0,
            "findings": a_findings,
            "uptime": a_uptime,
            "activity_count": agent_activity.get(ad["name"], 0),
        })

    # Bus message stats
    bus_messages = sum(agent_activity.values())

    # Active scans count
    active_scans = 1 if status_str not in ("idle", "done", "error", "") else 0

    return {
        "agents": agents_data,
        "bus_messages": bus_messages,
        "active_scans": active_scans,
        "current_target": current_target,
        "current_phase": current_phase,
        "status": status_str,
        "progress": progress,
        "uptime": uptime,
    }


def get_react_current():
    """Return the current ReACT step for the visualizer."""
    result = {
        "step": 0, "total_steps": 0, "reward": 0, "q_table_size": 0,
        "think": "", "action": "", "observation": "", "step_reward": 0,
        "deep_think": None,
    }

    # Read from state files first
    react_file = STATE_DIR / "react_state.json"
    if react_file.exists():
        try:
            data = json.loads(react_file.read_text())
            result.update({
                "step": data.get("step", 0),
                "total_steps": data.get("total_steps", data.get("max_steps", 0)),
                "reward": data.get("total_reward", data.get("reward", 0)),
                "q_table_size": data.get("q_table_size", 0),
                "think": data.get("thought", data.get("think", "")),
                "action": data.get("action", ""),
                "observation": data.get("observation", ""),
                "step_reward": data.get("step_reward", 0),
            })
        except Exception:
            pass

    # Fall back to latest react trace
    if not result["action"]:
        latest = get_react_latest()
        if latest and latest.get("steps"):
            last_step = latest["steps"][-1] if latest["steps"] else {}
            result.update({
                "step": len(latest["steps"]),
                "think": last_step.get("thought", last_step.get("think", "")),
                "action": last_step.get("action", ""),
                "observation": last_step.get("observation", str(last_step.get("status", ""))),
                "step_reward": 1.0 if last_step.get("result") else -0.5,
            })
        trace = latest.get("trace") or {}
        if trace:
            result["total_steps"] = trace.get("total_steps", result["total_steps"])
            result["reward"] = trace.get("total_reward", result["reward"])

    # Deep think data
    deep_file = STATE_DIR / "deep_think.json"
    if deep_file.exists():
        try:
            result["deep_think"] = json.loads(deep_file.read_text())
        except Exception:
            pass

    # Q-table size from evograph
    if result["q_table_size"] == 0 and EVOGRAPH_DB.exists():
        try:
            for tbl in ("q_table", "qtable", "q_values"):
                if _table_exists(EVOGRAPH_DB, tbl):
                    result["q_table_size"] = _scalar(EVOGRAPH_DB, f"SELECT COUNT(*) FROM {tbl}") or 0
                    break
        except Exception:
            pass

    return result


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

    # Merge live metrics from viper_state.json (updated during scans)
    try:
        state = get_state()
        if state and "metrics" in state:
            m = state["metrics"]
            data["live"] = {
                "total_requests": m.get("total_requests", 0),
                "total_findings": m.get("total_findings", 0),
                "validated_findings": m.get("validated_findings", 0),
                "false_positives_caught": m.get("false_positives_caught", 0),
                "sessions_run": m.get("sessions_run", 0),
                "uptime_seconds": m.get("uptime_seconds", 0),
            }
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

    # Determine trend based on recent findings
    trend = "stable"
    try:
        recent_24h = _scalar(
            VIPER_DB,
            "SELECT COUNT(*) FROM findings WHERE found_at >= datetime('now', '-1 day')",
        )
        recent_48h = _scalar(
            VIPER_DB,
            "SELECT COUNT(*) FROM findings WHERE found_at >= datetime('now', '-2 day') AND found_at < datetime('now', '-1 day')",
        )
        if recent_24h > recent_48h:
            trend = "worsening"
        elif recent_24h < recent_48h:
            trend = "improving"
    except Exception:
        pass

    return {
        "score": score, "grade": grade, "breakdown": breakdown, "raw_weight": raw,
        "trend": trend,
        "critical": breakdown.get("critical", 0),
        "high": breakdown.get("high", 0),
        "medium": breakdown.get("medium", 0),
    }


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


# ── Sandboxed Terminal Execution ──
# Two modes:
#   LOCAL  — pentest tools only (nuclei, subfinder, curl, etc.), no system access
#   TARGET — full shell via SSH/session proxy to authorized remote target
#
# Target sessions are registered via POST /api/terminal/connect
# {target: "192.168.1.100", method: "ssh", user: "root", port: 22}

_TERMINAL_SESSIONS = {}  # session_id -> {target, method, ...}
_active_scans = {}  # scan_id -> {id, target, status, phase, findings, log}

# Hard blocks — NEVER allowed in any mode
_HARD_BLOCKED = [
    "rm -rf /", "mkfs", "dd if=/dev/zero", ":()", "fork bomb",
    "shutdown -h now", "init 0", "halt -f",
    # Host system attacks
    "powershell -enc", "reg add", "schtasks /create",
]

# Pentest tools allowed in local mode (no target session)
_LOCAL_ALLOWED = {
    # Recon
    "nmap", "naabu", "subfinder", "amass", "httpx", "katana", "gau",
    "hakrawler", "waybackurls", "ffuf", "gobuster", "dirb", "dirsearch",
    "nikto", "whatweb",
    # Scanners
    "nuclei", "sqlmap", "commix", "xsstrike", "dalfox", "tplmap",
    "wfuzz", "arjun", "paramspider",
    # Network
    "curl", "wget", "dig", "nslookup", "whois", "host", "traceroute",
    "ping", "nc", "netcat",
    # Exploitation
    "hydra", "medusa", "msfconsole", "msfvenom",
    # Crypto / encoding
    "base64", "openssl", "hashcat", "john",
    # Pipe utilities (allowed in pipelines)
    "jq", "grep", "head", "tail", "wc", "sort", "uniq", "awk", "sed",
    "tr", "cut", "tee", "xargs",
}


def _sandboxed_execute(cmd: str, session_id: str) -> dict:
    """Execute a command in pentest terminal.

    Two modes:
    - No target session: only pentest tools allowed (local recon against remote targets)
    - Target session active: full shell proxied to remote target via SSH

    Security:
    - Hard-blocked patterns always rejected
    - Local mode: allowlist-only, sensitive env stripped, temp cwd, 60s timeout
    - Target mode: proxied via SSH to remote host, never runs on host
    - Output capped at 50KB
    """
    import shlex
    import shutil as _shutil

    cmd_stripped = cmd.strip()
    if not cmd_stripped:
        return {"output": "", "exit_code": 0, "session_id": session_id}

    cmd_lower = cmd_stripped.lower()

    # Block shell metacharacters that enable command chaining/injection
    _SHELL_METACHARS = [";", "&&", "||", "$(", "`", "<(", ">(", ">>", ">{",
                        "${", "\\n", "\n"]
    for meta in _SHELL_METACHARS:
        if meta in cmd_stripped:
            return {
                "output": f"[BLOCKED] Shell metacharacter '{meta}' detected.\n"
                          "Commands must be single tools — no chaining (;), "
                          "substitution ($(...)), or redirection.\n"
                          "Use pipes (|) with allowed filter tools only.",
                "exit_code": -1, "session_id": session_id,
            }

    # Hard blocks — always
    for pattern in _HARD_BLOCKED:
        if pattern.lower() in cmd_lower:
            return {
                "output": f"[BLOCKED] '{pattern}' is never allowed.",
                "exit_code": -1, "session_id": session_id,
            }

    # Check if there's an active target session
    session = _TERMINAL_SESSIONS.get(session_id)

    if session and session.get("target"):
        # ── TARGET MODE: proxy command to remote host ──
        target = session["target"]
        method = session.get("method", "ssh")
        user = session.get("user", "root")
        port = session.get("port", 22)
        key_file = session.get("key_file")

        if method == "ssh":
            ssh_cmd = ["ssh", "-o", "StrictHostKeyChecking=no",
                       "-o", "ConnectTimeout=10"]
            if key_file:
                ssh_cmd += ["-i", key_file]
            ssh_cmd += ["-p", str(port), f"{user}@{target}", cmd_stripped]

            try:
                bash_path = _shutil.which("bash")
                full_cmd = " ".join(ssh_cmd)
                if bash_path:
                    result = subprocess.run(
                        [bash_path, "-c", full_cmd],
                        capture_output=True, text=True, timeout=60,
                    )
                else:
                    result = subprocess.run(
                        ssh_cmd, capture_output=True, text=True, timeout=60,
                    )
                output = (result.stdout + result.stderr)[:50000]
                return {
                    "output": output,
                    "exit_code": result.returncode,
                    "session_id": session_id,
                    "target": target,
                    "mode": "ssh",
                }
            except subprocess.TimeoutExpired:
                return {"output": "[TIMEOUT] SSH command exceeded 60s.", "exit_code": -1, "session_id": session_id}
            except Exception as e:
                return {"output": f"[SSH ERROR] {e}", "exit_code": -1, "session_id": session_id}
        else:
            return {"output": f"[ERROR] Unknown proxy method: {method}. Use 'ssh'.", "exit_code": -1, "session_id": session_id}

    # ── LOCAL MODE: pentest tools only ──
    # Parse the base command of each pipe segment
    pipe_parts = cmd_stripped.split("|")
    for i, part in enumerate(pipe_parts):
        part = part.strip()
        if not part:
            continue
        try:
            tokens = shlex.split(part)
        except ValueError:
            tokens = part.split()
        if not tokens:
            continue
        base_cmd = os.path.basename(tokens[0]).lower().replace(".exe", "")

        # First command in pipeline must be an allowed tool
        # Subsequent pipe commands can be utilities (grep, head, jq, etc.)
        if i == 0 and base_cmd not in _LOCAL_ALLOWED:
            return {
                "output": (
                    f"[LOCAL MODE] '{base_cmd}' is not a pentest tool.\n"
                    f"Allowed: {', '.join(sorted(list(_LOCAL_ALLOWED)[:25]))}...\n\n"
                    "To run commands ON a target, connect first:\n"
                    "  POST /api/terminal/connect {\"target\": \"192.168.1.100\", \"user\": \"root\"}\n"
                    "  Or type: !connect root@192.168.1.100"
                ),
                "exit_code": -1, "session_id": session_id,
            }
        elif i > 0 and base_cmd not in _LOCAL_ALLOWED:
            return {
                "output": f"[BLOCKED] '{base_cmd}' not allowed in pipe. Use: grep, head, tail, jq, sort, etc.",
                "exit_code": -1, "session_id": session_id,
            }

    # Execute locally with sandboxed env
    try:
        bash_path = _shutil.which("bash")
        env = os.environ.copy()
        go_bin = os.path.expanduser("~/go/bin")
        if os.path.isdir(go_bin):
            env["PATH"] = go_bin + os.pathsep + env.get("PATH", "")
        # Strip sensitive env vars
        for key in ["AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN", "GITHUB_TOKEN",
                     "ANTHROPIC_API_KEY", "OPENAI_API_KEY", "SHODAN_API_KEY"]:
            env.pop(key, None)

        import tempfile
        sandbox_dir = os.path.join(tempfile.gettempdir(), "viper_sandbox")
        os.makedirs(sandbox_dir, exist_ok=True)

        if bash_path:
            result = subprocess.run(
                [bash_path, "-c", cmd_stripped],
                capture_output=True, text=True,
                timeout=60, cwd=sandbox_dir, env=env,
            )
        else:
            result = subprocess.run(
                cmd_stripped, shell=True, capture_output=True, text=True,
                timeout=60, cwd=sandbox_dir, env=env,
            )
        output = (result.stdout + result.stderr)[:50000]
        return {"output": output, "exit_code": result.returncode, "session_id": session_id, "mode": "local"}
    except subprocess.TimeoutExpired:
        return {"output": "[TIMEOUT] Command exceeded 60s.", "exit_code": -1, "session_id": session_id}
    except Exception as e:
        return {"output": f"[ERROR] {e}", "exit_code": -1, "session_id": session_id}


# ── NLP Command Mapping for Terminal ──

NLP_COMMANDS = {
    "scan ports": "nmap -sV {target}",
    "port scan": "nmap -sV {target}",
    "find subdomains": "subfinder -d {target}",
    "subdomain enum": "subfinder -d {target}",
    "crawl website": "katana -u {target} -d 3",
    "crawl": "katana -u {target} -d 3",
    "spider": "katana -u {target} -d 3",
    "check headers": "curl -I {target}",
    "http headers": "curl -I {target}",
    "nuclei scan": "nuclei -u {target} -severity critical,high",
    "vulnerability scan": "nuclei -u {target} -severity critical,high",
    "vuln scan": "nuclei -u {target} -severity critical,high",
    "directory brute": "ffuf -u {target}/FUZZ -w wordlists/common.txt",
    "dir brute": "ffuf -u {target}/FUZZ -w wordlists/common.txt",
    "fuzz directories": "ffuf -u {target}/FUZZ -w wordlists/common.txt",
    "find urls": "gau {target}",
    "url discovery": "gau {target}",
    "get urls": "gau {target}",
    "whois": "whois {target}",
    "dns lookup": "dig {target} ANY",
    "dns records": "dig {target} ANY",
    "ssl check": "sslscan {target}",
    "ssl scan": "sslscan {target}",
    "tech detect": "httpx -u {target} -tech-detect",
    "detect technology": "httpx -u {target} -tech-detect",
    "screenshot": "gowitness single {target}",
    "take screenshot": "gowitness single {target}",
    "find js files": "katana -u {target} -d 2 -jc -ef css,png,jpg,gif,svg,woff",
    "js files": "katana -u {target} -d 2 -jc -ef css,png,jpg,gif,svg,woff",
    "check cors": "curl -s -I -H 'Origin: https://evil.com' {target} | grep -i access-control",
    "cors check": "curl -s -I -H 'Origin: https://evil.com' {target} | grep -i access-control",
    "find parameters": "paramspider -d {target}",
    "param discovery": "paramspider -d {target}",
    "xss scan": "dalfox url {target}",
    "sqli scan": "sqlmap -u {target} --batch --level 2",
    "sql injection": "sqlmap -u {target} --batch --level 2",
    "check waf": "wafw00f {target}",
    "waf detect": "wafw00f {target}",
}


def _nlp_to_command(query):
    """Convert natural language query to a shell command."""
    query_lower = query.lower().strip()

    # Extract target from query (last URL-like or IP-like token)
    tokens = query.split()
    target = ""
    for tok in reversed(tokens):
        if "." in tok or ":" in tok or "/" in tok:
            target = tok
            break

    # Try matching against NLP_COMMANDS
    best_match = None
    best_score = 0
    for key, cmd_template in NLP_COMMANDS.items():
        words = key.split()
        score = sum(1 for w in words if w in query_lower)
        if score > best_score:
            best_score = score
            best_match = (key, cmd_template)

    if best_match and best_score > 0:
        cmd = best_match[1].format(target=target) if target else best_match[1].replace(" {target}", "")
        return {
            "command": cmd,
            "explanation": f"Matched '{best_match[0]}' pattern. Uses {cmd.split()[0]} tool.",
            "confidence": min(1.0, best_score / len(best_match[0].split())),
        }

    return {
        "command": "",
        "explanation": "Could not map query to a known command. Try being more specific.",
        "confidence": 0,
    }


# ── Chat History Store ──

_chat_history = []  # In-memory chat history (persisted to state/chat_history.json)
_chat_lock = threading.Lock()

CHAT_HISTORY_FILE = STATE_DIR / "chat_history.json"


def _load_chat_history():
    """Load chat history from file."""
    global _chat_history
    if CHAT_HISTORY_FILE.exists():
        try:
            _chat_history = json.loads(CHAT_HISTORY_FILE.read_text())
        except Exception:
            _chat_history = []


def _save_chat_history():
    """Persist chat history to file."""
    try:
        STATE_DIR.mkdir(parents=True, exist_ok=True)
        CHAT_HISTORY_FILE.write_text(json.dumps(_chat_history[-500:], default=str), encoding="utf-8")
    except Exception:
        pass


# ── CodeFix Job Tracker ──

_codefix_jobs = {}  # job_id -> {status, finding_id, repo_path, started, result}
_codefix_lock = threading.Lock()


def _start_codefix_job(finding_id, repo_path):
    """Start a codefix job (stub — queues for processing)."""
    job_id = str(uuid.uuid4())[:8]
    with _codefix_lock:
        _codefix_jobs[job_id] = {
            "job_id": job_id,
            "status": "queued",
            "finding_id": finding_id,
            "repo_path": repo_path,
            "started": time.time(),
            "result": None,
        }
    # In a real implementation, this would dispatch to CypherFix engine
    # For now, simulate async processing
    def _run():
        time.sleep(2)
        with _codefix_lock:
            if job_id in _codefix_jobs:
                _codefix_jobs[job_id]["status"] = "completed"
                _codefix_jobs[job_id]["result"] = {
                    "patches": [],
                    "message": f"CodeFix analysis complete for finding #{finding_id}. No auto-patches generated yet — CypherFix engine integration pending.",
                }
    threading.Thread(target=_run, daemon=True).start()
    return job_id


def get_insights_charts():
    """Aggregated chart data for all insight charts — single endpoint."""
    result = {
        "cvss_distribution": [],
        "kill_chain": [],
        "tech_vulns": [],
        "timeline": [],
        "severity_pie": [],
        "top_vuln_types": [],
    }

    if not VIPER_DB.exists():
        return result

    # Severity pie
    for sev in ("critical", "high", "medium", "low", "info"):
        count = _scalar(VIPER_DB, "SELECT COUNT(*) FROM findings WHERE LOWER(severity)=?", (sev,))
        if count:
            result["severity_pie"].append({"severity": sev, "count": count})

    # CVSS distribution (buckets)
    try:
        rows = _query(VIPER_DB, "SELECT cvss_score FROM findings WHERE cvss_score IS NOT NULL")
        buckets = {f"{i}-{i+1}": 0 for i in range(0, 10)}
        for r in rows:
            score = float(r.get("cvss_score", 0) or 0)
            bucket_key = f"{int(score)}-{int(score)+1}" if score < 10 else "9-10"
            if bucket_key in buckets:
                buckets[bucket_key] += 1
        result["cvss_distribution"] = [{"range": k, "count": v} for k, v in buckets.items() if v > 0]
    except Exception:
        pass

    # Kill chain
    try:
        result["kill_chain"] = get_attack_kill_chain()
    except Exception:
        pass

    # Tech vulnerability counts
    try:
        tech_map = get_evograph_tech_map()
        if isinstance(tech_map, list):
            result["tech_vulns"] = tech_map[:20]
        elif isinstance(tech_map, dict) and "technologies" in tech_map:
            result["tech_vulns"] = tech_map["technologies"][:20]
    except Exception:
        pass

    # Timeline
    try:
        result["timeline"] = get_findings_timeline()
    except Exception:
        pass

    # Top vuln types
    try:
        by_type = get_findings_by_type()
        if isinstance(by_type, dict) and "types" in by_type:
            result["top_vuln_types"] = by_type["types"][:15]
        elif isinstance(by_type, list):
            result["top_vuln_types"] = by_type[:15]
    except Exception:
        pass

    return result


# Load chat history on module import
try:
    _load_chat_history()
except Exception:
    pass


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
            # No caching for HTML (ensures fresh dashboard on reload)
            if ext in ('.html', '.htm'):
                self.send_header("Cache-Control", "no-cache, no-store, must-revalidate")
                self.send_header("Pragma", "no-cache")
            else:
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

        # ── Chat endpoints ──
        elif path == "/api/chat/send":
            try:
                data = json.loads(body) if body else {}
                msg = data.get("message", "").strip()
                conv_id = data.get("conversation_id") or str(uuid.uuid4())[:8]
                if not msg:
                    self._json_response({"error": "Empty message"}, status=400)
                    return

                entry = {
                    "conversation_id": conv_id,
                    "role": "user",
                    "message": msg,
                    "timestamp": time.time(),
                }
                with _chat_lock:
                    _chat_history.append(entry)

                # Route through model_router for real AI response
                ai_response = None
                try:
                    from ai.model_router import ModelRouter
                    import asyncio
                    router = ModelRouter()
                    if router.is_available:
                        system = (
                            "You are VIPER, an autonomous bug bounty hunting AI assistant. "
                            "You help with security testing, vulnerability analysis, and penetration testing. "
                            "Be concise and actionable. You can suggest commands, analyze findings, "
                            "and help plan attack strategies. The user has authorized security testing."
                        )
                        loop = asyncio.new_event_loop()
                        try:
                            resp = loop.run_until_complete(router.complete(msg, system=system))
                            if resp and resp.text:
                                ai_response = resp.text
                        finally:
                            loop.close()
                except Exception as llm_err:
                    logger.debug("LLM chat failed: %s", llm_err)

                if not ai_response:
                    ai_response = f"[LLM unavailable] Received: '{msg[:100]}'. Try the terminal for direct command execution."
                ai_entry = {
                    "conversation_id": conv_id,
                    "role": "assistant",
                    "message": ai_response,
                    "timestamp": time.time(),
                }
                with _chat_lock:
                    _chat_history.append(ai_entry)
                    _save_chat_history()

                self._json_response({
                    "response": ai_response,
                    "conversation_id": conv_id,
                })
            except Exception as e:
                self._json_response({"error": str(e)}, status=400)

        elif path == "/api/chat/history":
            # POST variant for filtered history
            try:
                data = json.loads(body) if body else {}
                conv_id = data.get("conversation_id")
                with _chat_lock:
                    if conv_id:
                        msgs = [m for m in _chat_history if m.get("conversation_id") == conv_id]
                    else:
                        msgs = list(_chat_history[-100:])
                self._json_response({"messages": msgs, "total": len(msgs)})
            except Exception as e:
                self._json_response({"error": str(e)}, status=400)

        # ── Terminal endpoints (SANDBOXED — pentest tools only, remote targets only) ──
        elif path == "/api/terminal/execute":
            try:
                data = json.loads(body) if body else {}
                cmd = data.get("command", "").strip()
                session_id = data.get("session_id") or str(uuid.uuid4())[:8]
                if not cmd:
                    self._json_response({"error": "Empty command"}, status=400)
                    return

                # Handle !connect and !disconnect shortcuts
                if cmd.startswith("!connect "):
                    target_str = cmd[9:].strip()
                    user = "root"
                    port = 22
                    if "@" in target_str:
                        user, target_str = target_str.rsplit("@", 1)
                    if ":" in target_str:
                        target_str, port_str = target_str.rsplit(":", 1)
                        try: port = int(port_str)
                        except ValueError: pass
                    # Security: block localhost/self targeting
                    _blocked_targets = {"127.0.0.1", "localhost", "0.0.0.0", "::1",
                                        "host.docker.internal"}
                    if target_str.lower() in _blocked_targets or target_str.startswith("192.168.") is False and target_str.startswith("10.") is False and target_str.startswith("172.") is False:
                        pass  # Allow private IPs
                    if target_str.lower() in _blocked_targets:
                        self._json_response({
                            "output": f"[BLOCKED] Cannot connect to {target_str} — localhost/self targeting not allowed.",
                            "exit_code": -1, "session_id": session_id,
                        })
                        return
                    _TERMINAL_SESSIONS[session_id] = {
                        "target": target_str, "user": user, "port": port,
                        "method": "ssh", "key_file": None, "connected_at": time.time(),
                    }
                    self._json_response({
                        "output": f"[CONNECTED] Session proxied to {user}@{target_str}:{port} via SSH.\n"
                                  "All commands now execute on the remote target.\n"
                                  "Type '!disconnect' to return to local mode.",
                        "exit_code": 0, "session_id": session_id, "mode": "ssh",
                    })
                    return
                if cmd.strip() == "!disconnect":
                    _TERMINAL_SESSIONS.pop(session_id, None)
                    self._json_response({
                        "output": "[DISCONNECTED] Back to local pentest tool mode.",
                        "exit_code": 0, "session_id": session_id, "mode": "local",
                    })
                    return
                if cmd.strip() == "!status":
                    sess = _TERMINAL_SESSIONS.get(session_id)
                    if sess:
                        self._json_response({
                            "output": f"[TARGET MODE] Connected to {sess['user']}@{sess['target']}:{sess['port']} via {sess['method']}",
                            "exit_code": 0, "session_id": session_id,
                        })
                    else:
                        self._json_response({
                            "output": "[LOCAL MODE] Pentest tools only. Type '!connect user@target' to proxy to a remote host.",
                            "exit_code": 0, "session_id": session_id,
                        })
                    return

                result = _sandboxed_execute(cmd, session_id)
                self._json_response(result)
            except Exception as e:
                self._json_response({"error": str(e)}, status=400)

        elif path == "/api/terminal/connect":
            # Connect a terminal session to a remote target
            try:
                data = json.loads(body) if body else {}
                target = data.get("target", "").strip()
                session_id = data.get("session_id") or str(uuid.uuid4())[:8]
                if not target:
                    self._json_response({"error": "Target required"}, status=400)
                    return
                # Parse user@host format
                user = data.get("user", "root")
                if "@" in target:
                    user, target = target.rsplit("@", 1)
                port = int(data.get("port", 22))
                method = data.get("method", "ssh")
                key_file = data.get("key_file")

                _TERMINAL_SESSIONS[session_id] = {
                    "target": target,
                    "user": user,
                    "port": port,
                    "method": method,
                    "key_file": key_file,
                    "connected_at": time.time(),
                }
                self._json_response({
                    "status": "connected",
                    "session_id": session_id,
                    "target": target,
                    "user": user,
                    "method": method,
                    "message": f"Session {session_id} connected to {user}@{target}:{port} via {method}. "
                               "All commands will now execute on the remote target.",
                })
            except Exception as e:
                self._json_response({"error": str(e)}, status=400)

        elif path == "/api/terminal/disconnect":
            try:
                data = json.loads(body) if body else {}
                session_id = data.get("session_id", "")
                if session_id in _TERMINAL_SESSIONS:
                    del _TERMINAL_SESSIONS[session_id]
                self._json_response({"status": "disconnected", "session_id": session_id})
            except Exception as e:
                self._json_response({"error": str(e)}, status=400)

        elif path == "/api/scan/start":
            # Start a REAL VIPER hunt in a background thread
            try:
                data = json.loads(body) if body else {}
                target = data.get("target", "").strip()
                if not target:
                    self._json_response({"error": "Target URL required"}, status=400)
                    return
                scan_id = str(uuid.uuid4())[:8]
                _active_scans[scan_id] = {
                    "id": scan_id, "target": target, "status": "starting",
                    "started_at": time.time(), "phase": "init", "progress": 0,
                    "findings": 0, "log": [],
                }

                def _run_scan():
                    import asyncio
                    scan = _active_scans[scan_id]
                    try:
                        scan["status"] = "running"
                        _ws_broadcast("scan_started", {"scan_id": scan_id, "target": target})
                        event_bus.publish("scan_started", {"scan_id": scan_id, "target": target})

                        from viper_core import ViperCore
                        loop = asyncio.new_event_loop()
                        asyncio.set_event_loop(loop)
                        v = ViperCore()

                        # Hook into VIPER's log to broadcast events
                        orig_log = v.log
                        def hooked_log(msg, level="INFO"):
                            orig_log(msg, level)
                            scan["log"].append(msg)
                            scan["log"] = scan["log"][-200:]
                            # Detect phase changes
                            if "Phase" in msg and "===" in msg:
                                import re as _re
                                m = _re.search(r"Phase\s+\d+[^:]*:\s*(.+?)(?:\s*===|\s*\()", msg)
                                if m:
                                    scan["phase"] = m.group(1).strip()
                                    _ws_broadcast("phase_update", {"phase": scan["phase"], "scan_id": scan_id})
                            if "[+]" in msg or "[SUCCESS]" in msg:
                                scan["findings"] += 1
                                _ws_broadcast("finding_new", {"text": msg, "scan_id": scan_id})
                            _ws_broadcast("log_line", {"text": msg, "level": level, "scan_id": scan_id})
                        v.log = hooked_log

                        result = loop.run_until_complete(v.full_hunt(target, max_minutes=15))
                        loop.close()

                        scan["status"] = "completed"
                        scan["result"] = {
                            "findings": len(result.get("findings", [])),
                            "requests": result.get("total_requests", 0),
                        }
                        _ws_broadcast("scan_completed", {"scan_id": scan_id, "findings": scan["findings"], "target": target})
                    except Exception as e:
                        scan["status"] = "error"
                        scan["error"] = str(e)
                        _ws_broadcast("scan_error", {"scan_id": scan_id, "error": str(e)})

                t = threading.Thread(target=_run_scan, daemon=True)
                t.start()
                self._json_response({"scan_id": scan_id, "status": "started", "target": target})
            except Exception as e:
                self._json_response({"error": str(e)}, status=400)

        elif path == "/api/scan/status":
            try:
                data = json.loads(body) if body else {}
                scan_id = data.get("scan_id", "")
                scan = _active_scans.get(scan_id)
                if scan:
                    self._json_response(scan)
                else:
                    self._json_response({"error": "Scan not found"}, status=404)
            except Exception as e:
                self._json_response({"error": str(e)}, status=400)

        elif path == "/api/terminal/nlp":
            try:
                data = json.loads(body) if body else {}
                query = data.get("query", "").strip()
                if not query:
                    self._json_response({"error": "Empty query"}, status=400)
                    return
                result = _nlp_to_command(query)
                self._json_response(result)
            except Exception as e:
                self._json_response({"error": str(e)}, status=400)

        # ── CodeFix endpoints ──
        elif path == "/api/codefix/run":
            try:
                data = json.loads(body) if body else {}
                finding_id = data.get("finding_id")
                repo_path = data.get("repo_path", str(PROJECT_ROOT))
                if finding_id is None:
                    self._json_response({"error": "finding_id required"}, status=400)
                    return
                job_id = _start_codefix_job(finding_id, repo_path)
                self._json_response({"status": "started", "job_id": job_id})
            except Exception as e:
                self._json_response({"error": str(e)}, status=400)

        # ── Export endpoints ──
        elif path == "/api/export/excel":
            try:
                # Export findings as CSV
                findings_data = get_triage_findings()
                findings = findings_data.get("findings", [])

                output = io.StringIO()
                if findings:
                    fieldnames = ["id", "severity", "vuln_type", "url", "description",
                                  "confidence", "validated", "domain", "priority_score", "found_at"]
                    writer = csv.DictWriter(output, fieldnames=fieldnames, extrasaction="ignore")
                    writer.writeheader()
                    for f in findings:
                        writer.writerow(f)

                csv_bytes = output.getvalue().encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "text/csv; charset=utf-8")
                self.send_header("Content-Disposition", "attachment; filename=viper_findings.csv")
                self.send_header("Content-Length", str(len(csv_bytes)))
                self._cors_headers()
                self.end_headers()
                self.wfile.write(csv_bytes)
            except Exception as e:
                self._json_response({"error": str(e)}, status=500)

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

        elif path == "/api/agents/status":
            # v5: Multi-agent subsystem status
            agent_status = {"available": False, "agents": [], "bus_stats": {}}
            try:
                from core.agent_bus import AgentBus
                from core.agent_registry import AgentRegistry
                agent_status["available"] = True
                # Show registered agent types
                agent_status["agent_types"] = [
                    {"name": "ReconAgent", "topic": "recon", "description": "Subdomain enum, tech fingerprint, asset discovery"},
                    {"name": "VulnAgent", "topic": "vuln", "description": "Tree-of-Thought hypothesis generation"},
                    {"name": "ExploitAgent", "topic": "exploit", "description": "Non-destructive PoC development"},
                    {"name": "ChainAgent", "topic": "chain", "description": "Attack chain discovery + cross-target correlation"},
                ]
            except ImportError:
                pass
            self._json_response(agent_status)

        elif path == "/api/agents/monitor":
            # v5: Real-time agent monitor data
            self._json_response(get_agent_monitor())

        elif path == "/api/scans":
            # List all active/recent scans
            scans = sorted(_active_scans.values(), key=lambda s: s.get("started_at", 0), reverse=True)
            self._json_response({"scans": scans[:20]})

        elif path == "/api/react/current":
            # v5: Current ReACT step for visualizer
            self._json_response(get_react_current())

        elif path == "/api/v5/modules":
            # v5: Module availability status
            modules = {}
            mod_checks = {
                "agent_bus": "core.agent_bus",
                "agent_registry": "core.agent_registry",
                "oauth_fuzzer": "core.oauth_fuzzer",
                "websocket_fuzzer": "core.websocket_fuzzer",
                "race_engine": "core.race_engine",
                "logic_modeler": "core.logic_modeler",
                "failure_analyzer": "core.failure_analyzer",
                "cross_target_correlator": "core.cross_target_correlator",
                "genetic_fuzzer": "core.fuzzer",
                "fingerprint_randomizer": "core.stealth",
                "human_timing": "core.rate_limiter",
                "chain_of_custody": "core.chain_of_custody",
                "cvss_v4": "core.reporter",
                "finding_stream": "core.finding_stream",
            }
            for name, mod_path in mod_checks.items():
                try:
                    __import__(mod_path)
                    modules[name] = True
                except ImportError:
                    modules[name] = False
            self._json_response({"version": "5.0", "modules": modules, "total": sum(modules.values()), "of": len(modules)})

        elif path == "/api/v5/failure-lessons":
            # v5: Failure analyzer lessons
            lessons = {"total": 0, "lessons": [], "waf_stats": {}}
            try:
                from core.failure_analyzer import FailureAnalyzer
                fa = FailureAnalyzer()
                stats = fa.get_stats()
                lessons["total"] = stats["total_lessons"]
                lessons["waf_stats"] = stats["waf_detections"]
                lessons["attack_types"] = stats["attack_types"]
                lessons["lessons"] = [l.to_dict() for l in fa.lessons[-20:]]
            except Exception:
                pass
            self._json_response(lessons)

        elif path == "/api/v5/evolution":
            # v5: Attack evolution graph
            evolution = {"nodes": [], "edges": []}
            try:
                from core.evograph import EvoGraph
                evo = EvoGraph()
                evolution = evo.export_attack_evolution()
                evo.close()
            except Exception:
                pass
            self._json_response(evolution)

        elif path == "/api/status":
            import shutil
            status = {
                "version": "5.0",
                "uptime_seconds": 0,
                "dashboard_started": getattr(self.server, '_start_time', None),
                "db_connected": VIPER_DB.exists() if VIPER_DB else False,
                "evograph_connected": EVOGRAPH_DB.exists() if EVOGRAPH_DB else False,
                "tools": {
                    tool: shutil.which(tool) is not None
                    for tool in ["nuclei", "httpx", "subfinder", "katana", "gau", "curl"]
                },
                "v5_modules": {},
            }
            # Check v5 module availability
            for mod_name in ["core.agent_bus", "core.oauth_fuzzer", "core.race_engine",
                             "core.failure_analyzer", "core.chain_of_custody", "core.finding_stream"]:
                try:
                    __import__(mod_name)
                    status["v5_modules"][mod_name.split(".")[-1]] = True
                except ImportError:
                    status["v5_modules"][mod_name.split(".")[-1]] = False
            # Add DB stats
            try:
                rows = _query(VIPER_DB, "SELECT COUNT(*) as c FROM targets")
                status["targets"] = rows[0]["c"] if rows else 0
                rows = _query(VIPER_DB, "SELECT COUNT(*) as c FROM findings")
                status["findings"] = rows[0]["c"] if rows else 0
                rows = _query(VIPER_DB, "SELECT COUNT(*) as c FROM attacks")
                status["attacks"] = rows[0]["c"] if rows else 0
            except Exception:
                status["targets"] = 0
                status["findings"] = 0
                status["attacks"] = 0
            # Add live state from viper_state.json
            try:
                state_data = get_state()
                if state_data and "metrics" in state_data:
                    m = state_data["metrics"]
                    status["live_metrics"] = {
                        "total_requests": m.get("total_requests", 0),
                        "total_findings": m.get("total_findings", 0),
                        "validated_findings": m.get("validated_findings", 0),
                        "false_positives_caught": m.get("false_positives_caught", 0),
                        "sessions_run": m.get("sessions_run", 0),
                    }
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

        # ── New interactive dashboard API endpoints ──
        elif path == "/api/chat/history":
            with _chat_lock:
                msgs = list(_chat_history[-100:])
            self._json_response({"messages": msgs, "total": len(msgs)})

        elif path == "/api/insights/charts":
            self._json_response(get_insights_charts())

        elif path.startswith("/api/codefix/status/"):
            job_id = path.split("/api/codefix/status/", 1)[1]
            with _codefix_lock:
                job = _codefix_jobs.get(job_id)
            if job:
                self._json_response(job)
            else:
                self._json_response({"error": "Job not found"}, 404)

        # ── VIPER 4.0 dashboard pages ──
        elif path == "/graph":
            self._serve_file(DASHBOARD_DIR / "graph_viz.html", "text/html")

        elif path == "/charts":
            self._serve_file(DASHBOARD_DIR / "charts.html", "text/html")

        elif path == "/chat":
            self._serve_file(DASHBOARD_DIR / "chat.html", "text/html")

        elif path == "/chat-v2":
            self._serve_file(DASHBOARD_DIR / "chat_v2.html", "text/html")

        elif path == "/terminal":
            self._serve_file(DASHBOARD_DIR / "terminal.html", "text/html")

        elif path == "/terminal-v2":
            self._serve_file(DASHBOARD_DIR / "terminal_v2.html", "text/html")

        elif path == "/insights-v2":
            self._serve_file(DASHBOARD_DIR / "insights_v2.html", "text/html")

        elif path == "/cypherfix-v2":
            self._serve_file(DASHBOARD_DIR / "cypherfix_v2.html", "text/html")

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
    print(f"VIPER 5.0 Dashboard running at http://localhost:{port}")
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
    print(f"  GET /api/status             — System status (V5)")
    print(f"  GET /api/agents/status      — Multi-agent status (V5)")
    print(f"  GET /api/v5/modules         — V5 module availability")
    print(f"  GET /api/v5/failure-lessons — Failure analysis lessons (V5)")
    print(f"  GET /api/v5/evolution       — Attack evolution graph (V5)")
    print(f"  GET /api/agent/status       — Agent state (v4)")
    print(f"  GET /api/agent/thinking     — Deep-think results (v4)")
    print(f"  GET /api/triage/findings    — Triaged findings (v4)")
    print(f"  GET /api/codefix/status     — CodeFix status (v4)")
    print(f"  GET /api/sessions/list      — Hunt sessions (v4)")
    print(f"  GET /api/sessions/:id       — Session detail (v4)")
    print(f"  POST /api/agent/guidance    — Send guidance (v4)")
    print(f"  POST /api/agent/approve     — Approve/reject (v4)")
    print(f"  POST /api/agent/answer      — Answer question (v4)")
    print(f"  POST /api/chat/send         — Send chat message (v4)")
    print(f"  GET  /api/chat/history      — Chat history (v4)")
    print(f"  POST /api/terminal/execute  — Execute command (v4)")
    print(f"  POST /api/terminal/nlp      — NLP to command (v4)")
    print(f"  GET  /api/insights/charts   — Aggregated charts (v4)")
    print(f"  POST /api/codefix/run       — Start codefix job (v4)")
    print(f"  GET  /api/codefix/status/:id— Codefix job status (v4)")
    print(f"  POST /api/export/excel      — Export CSV (v4)")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down dashboard.")
        server.server_close()


if __name__ == "__main__":
    main()
