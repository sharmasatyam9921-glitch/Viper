#!/usr/bin/env python3
"""
VIPER Dashboard v2 - Complete Command Center

Shows:
- Tools used & their status
- Tool progress (installation, usage)
- Automation level
- ML models active
- Deployed agents
- Current target
- Future targets (queue)
- Attacks in progress
- All reports (paginated)
- Natas/CTF progress
- Real-time activity
"""

import asyncio
import json
import os
from datetime import datetime
from pathlib import Path
from aiohttp import web
import aiohttp_cors

# Paths
HACKAGENT_DIR = Path(__file__).parent.parent
REPORTS_DIR = HACKAGENT_DIR / "reports"
LOGS_DIR = HACKAGENT_DIR / "logs"
PROGRAMS_DIR = HACKAGENT_DIR / "programs"
STATE_FILE = HACKAGENT_DIR / "viper_state.json"
TARGETS_FILE = HACKAGENT_DIR / "targets.json"
LEARNINGS_FILE = HACKAGENT_DIR / "learnings.json"
TOOLS_FILE = HACKAGENT_DIR / "tools-installed.json"
AGENTS_FILE = HACKAGENT_DIR / "agents.json"

# Ensure directories exist
REPORTS_DIR.mkdir(exist_ok=True)
LOGS_DIR.mkdir(exist_ok=True)

clients = []


def load_json(path: Path, default=None):
    if path.exists():
        try:
            return json.loads(path.read_text())
        except:
            pass
    return default or {}


def get_live_state():
    return load_json(STATE_FILE, {
        "active": False, "target": None, "phase": "idle",
        "progress": 0, "events": [], "tool": None, "current_task": None
    })


def get_tools():
    """Get all tools with usage stats"""
    data = load_json(TOOLS_FILE, {})
    tools = []
    
    # Go tools
    for name, info in data.get("go_tools", {}).items():
        tools.append({
            "name": name,
            "type": "go",
            "status": info.get("status", "installed"),
            "version": info.get("version", "?"),
            "purpose": info.get("purpose", ""),
            "usage_count": info.get("usage_count", 0)
        })
    
    # Python tools
    for name, info in data.get("python_tools", {}).items():
        tools.append({
            "name": name,
            "type": "python",
            "status": info.get("status", "installed"),
            "version": info.get("version", "?"),
            "purpose": info.get("purpose", ""),
            "usage_count": info.get("usage_count", 0)
        })
    
    # Cloned tools
    for name, info in data.get("cloned_tools", {}).items():
        tools.append({
            "name": name,
            "type": "cloned",
            "status": info.get("status", "cloned"),
            "path": info.get("path", ""),
            "purpose": info.get("purpose", ""),
            "usage_count": info.get("usage_count", 0)
        })
    
    return tools


def get_automation_level():
    """Calculate VIPER's automation level"""
    tools = get_tools()
    targets = load_json(TARGETS_FILE, {}).get("targets", [])
    learnings = load_json(LEARNINGS_FILE, {})
    state = load_json(STATE_FILE, {})
    
    score = 0
    max_score = 100
    
    # Tools installed (max 30)
    score += min(30, len(tools) * 1.5)
    
    # Targets configured (max 15)
    score += min(15, len(targets) * 3)
    
    # Patterns learned (max 20)
    patterns = len(learnings.get("patterns", []))
    score += min(20, patterns * 2)
    
    # Reports generated (max 20)
    reports = len(list(REPORTS_DIR.glob("*.md")))
    score += min(20, reports / 50)
    
    # Active scanning capability (max 15)
    if state.get("active"):
        score += 10
    if tools:
        score += 5
    
    return {
        "score": int(score),
        "max": max_score,
        "level": "Novice" if score < 25 else "Apprentice" if score < 50 else "Hunter" if score < 75 else "Elite",
        "tools_count": len(tools),
        "patterns_learned": patterns,
        "targets_configured": len(targets)
    }


def get_ml_models():
    """Get ML models VIPER uses"""
    # These are the ML capabilities VIPER has/could have
    return [
        {"name": "Pattern Recognition", "status": "active", "accuracy": "Learning", "purpose": "Identify vuln patterns"},
        {"name": "False Positive Filter", "status": "planned", "accuracy": "N/A", "purpose": "Reduce noise"},
        {"name": "Exploit Predictor", "status": "planned", "accuracy": "N/A", "purpose": "Suggest exploits"},
        {"name": "Risk Scorer", "status": "planned", "accuracy": "N/A", "purpose": "Prioritize findings"}
    ]


def get_agents():
    """Get deployed/available agents"""
    agents = load_json(AGENTS_FILE, {"agents": []}).get("agents", [])

    # VIPER 5.0 agent roster (v5 multi-agent bus + legacy agents)
    defaults = [
        {"name": "ReconAgent", "status": "ready", "purpose": "Subdomain enum, tech fingerprint, asset discovery", "deployed": False, "version": "v5", "topic": "recon"},
        {"name": "VulnAgent", "status": "ready", "purpose": "Tree-of-Thought vulnerability hypothesis generation", "deployed": False, "version": "v5", "topic": "vuln"},
        {"name": "ExploitAgent", "status": "ready", "purpose": "Non-destructive PoC development & validation", "deployed": False, "version": "v5", "topic": "exploit"},
        {"name": "ChainAgent", "status": "ready", "purpose": "Attack chain discovery + cross-target correlation", "deployed": False, "version": "v5", "topic": "chain"},
        {"name": "WebCrawler", "status": "ready", "purpose": "Spider web applications", "deployed": False, "version": "v4"},
        {"name": "ReportWriter", "status": "ready", "purpose": "Generate CVSS v4.0 reports", "deployed": False, "version": "v5"}
    ]

    # Check v5 agent bus availability
    try:
        from core.agent_bus import AgentBus
        for agent in defaults:
            if agent.get("version") == "v5":
                agent["bus_available"] = True
    except ImportError:
        pass

    return agents if agents else defaults


def get_targets():
    """Get current and queued targets"""
    data = load_json(TARGETS_FILE, {"targets": []})
    targets = data.get("targets", [])
    
    current = None
    queued = []
    completed = []
    
    for t in targets:
        status = t.get("status", "queued")
        if status == "active" or status == "scanning":
            current = t
        elif status == "completed":
            completed.append(t)
        else:
            queued.append(t)
    
    return {
        "current": current,
        "queued": queued[:10],  # Next 10
        "completed": completed[:10],
        "total_queued": len(queued),
        "total_completed": len(completed)
    }


def get_reports(page=1, per_page=20, search=None):
    """Get paginated reports"""
    all_reports = []
    
    for f in sorted(REPORTS_DIR.glob("*.md"), key=lambda x: x.stat().st_mtime, reverse=True):
        if search and search.lower() not in f.name.lower():
            continue
        
        stat = f.stat()
        try:
            content = f.read_text(encoding='utf-8', errors='ignore')[:1000]
        except:
            content = ""
        
        # Count severities
        critical = content.count("CRITICAL") + content.count("🔴")
        high = content.count("HIGH") + content.count("🟠")
        medium = content.count("MEDIUM") + content.count("🟡")
        
        all_reports.append({
            "name": f.name,
            "size": stat.st_size,
            "modified": datetime.fromtimestamp(stat.st_mtime).isoformat(),
            "critical": critical,
            "high": high,
            "medium": medium,
            "preview": content[:300]
        })
    
    total = len(all_reports)
    start = (page - 1) * per_page
    end = start + per_page
    
    return {
        "reports": all_reports[start:end],
        "total": total,
        "page": page,
        "per_page": per_page,
        "total_pages": (total + per_page - 1) // per_page
    }


def get_attacks():
    """Get recent attack activity"""
    state = get_live_state()
    events = state.get("events", [])
    
    attacks = []
    for e in events:
        if e.get("type") in ["vuln", "attack", "exploit"]:
            attacks.append(e)
    
    return attacks[:20]


def get_ctf_progress():
    """Get all CTF/wargame progress"""
    progress = {}
    
    # Natas
    natas_file = PROGRAMS_DIR / "natas" / "progress.json"
    if natas_file.exists():
        data = load_json(natas_file)
        passwords = data.get("passwords", {})
        progress["natas"] = {
            "levels_solved": len(passwords) - 1,
            "current_level": max(int(k) for k in passwords.keys()) if passwords else 0,
            "total_levels": 34,
            "last_updated": data.get("last_updated")
        }
    
    # Add more CTFs here as VIPER plays them
    
    return progress


def get_stats():
    """Get comprehensive stats"""
    state = load_json(STATE_FILE, {})
    tools = get_tools()
    automation = get_automation_level()
    reports = get_reports()
    ctf = get_ctf_progress()
    
    return {
        "total_scans": state.get("total_scans", 0),
        "total_findings": state.get("total_findings", 0),
        "total_bounties": state.get("total_bounties", 0),
        "tools_count": len(tools),
        "reports_count": reports["total"],
        "automation_level": automation,
        "patterns_learned": automation["patterns_learned"],
        "ctf_progress": ctf
    }


# ========== API Routes ==========

async def api_dashboard(request):
    return web.json_response({
        "stats": get_stats(),
        "live_state": get_live_state(),
        "tools": get_tools()[:20],
        "targets": get_targets(),
        "reports": get_reports(page=1, per_page=5)["reports"],
        "agents": get_agents(),
        "ml_models": get_ml_models(),
        "attacks": get_attacks()
    })


async def api_tools(request):
    return web.json_response({"tools": get_tools()})


async def api_targets(request):
    return web.json_response(get_targets())


async def api_reports(request):
    page = int(request.query.get("page", 1))
    per_page = int(request.query.get("per_page", 20))
    search = request.query.get("search")
    return web.json_response(get_reports(page, per_page, search))


async def api_report_detail(request):
    name = request.match_info.get('name')
    path = REPORTS_DIR / name
    if path.exists():
        return web.json_response({
            "name": name,
            "content": path.read_text(encoding='utf-8', errors='ignore')
        })
    return web.json_response({"error": "Not found"}, status=404)


async def api_agents(request):
    return web.json_response({"agents": get_agents()})


async def api_ml_models(request):
    return web.json_response({"models": get_ml_models()})


async def api_automation(request):
    return web.json_response(get_automation_level())


async def api_ctf(request):
    return web.json_response(get_ctf_progress())


async def api_live(request):
    return web.json_response(get_live_state())


async def api_attacks(request):
    return web.json_response({"attacks": get_attacks()})


# ========== HTML Dashboard ==========

DASHBOARD_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>🐍 VIPER Command Center</title>
    <style>
        :root {
            --bg-dark: #0a0a0f;
            --bg-card: #12121a;
            --border: #2a2a3a;
            --accent: #00ff88;
            --accent-dim: #00aa5c;
            --danger: #ff4444;
            --warning: #ffaa00;
            --info: #4488ff;
            --text: #e0e0e0;
            --text-dim: #888;
        }
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Segoe UI', system-ui, sans-serif;
            background: var(--bg-dark);
            color: var(--text);
            min-height: 100vh;
        }
        .header {
            background: linear-gradient(135deg, #1a1a2e 0%, #0f3d0f 100%);
            padding: 15px 25px;
            border-bottom: 2px solid var(--accent);
            display: flex;
            justify-content: space-between;
            align-items: center;
            position: sticky;
            top: 0;
            z-index: 100;
        }
        .header h1 { font-size: 24px; display: flex; align-items: center; gap: 10px; }
        .status-badge {
            padding: 6px 14px;
            border-radius: 15px;
            font-size: 13px;
            font-weight: 600;
        }
        .status-badge.online { background: var(--accent); color: black; }
        .status-badge.scanning { background: var(--warning); color: black; animation: pulse 1s infinite; }
        @keyframes pulse { 50% { opacity: 0.7; } }
        
        .container { padding: 20px; display: grid; gap: 20px; }
        
        /* Live Status Bar */
        .live-bar {
            background: linear-gradient(90deg, #1a1a2e, #0f2f0f);
            border: 1px solid var(--accent);
            border-radius: 10px;
            padding: 15px 20px;
            display: none;
        }
        .live-bar.active { display: block; }
        .live-bar .row { display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 15px; }
        .live-bar .stat { text-align: center; }
        .live-bar .stat .label { font-size: 11px; color: var(--text-dim); }
        .live-bar .stat .value { font-size: 16px; font-weight: 600; color: var(--accent); }
        .progress-track { flex: 1; min-width: 200px; height: 8px; background: var(--border); border-radius: 4px; }
        .progress-fill { height: 100%; background: var(--accent); border-radius: 4px; transition: width 0.3s; }
        
        /* Stats Grid */
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 15px;
        }
        .stat-card {
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 10px;
            padding: 15px;
            text-align: center;
        }
        .stat-card .value { font-size: 28px; font-weight: 700; color: var(--accent); }
        .stat-card .label { font-size: 12px; color: var(--text-dim); margin-top: 5px; }
        .stat-card.warning .value { color: var(--warning); }
        .stat-card.danger .value { color: var(--danger); }
        
        /* Main Grid */
        .main-grid {
            display: grid;
            grid-template-columns: repeat(3, 1fr);
            gap: 20px;
        }
        @media (max-width: 1200px) { .main-grid { grid-template-columns: 1fr 1fr; } }
        @media (max-width: 800px) { .main-grid { grid-template-columns: 1fr; } }
        
        .card {
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 10px;
            overflow: hidden;
        }
        .card.span-2 { grid-column: span 2; }
        @media (max-width: 800px) { .card.span-2 { grid-column: span 1; } }
        
        .card-header {
            padding: 12px 15px;
            border-bottom: 1px solid var(--border);
            display: flex;
            justify-content: space-between;
            align-items: center;
            background: rgba(0,255,136,0.03);
        }
        .card-header h2 { font-size: 14px; font-weight: 600; }
        .card-body { padding: 15px; max-height: 350px; overflow-y: auto; }
        
        /* Tools */
        .tool-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(100px, 1fr)); gap: 8px; }
        .tool-item {
            background: #1a1a2e;
            padding: 8px;
            border-radius: 6px;
            text-align: center;
            font-size: 12px;
            border-left: 3px solid var(--border);
        }
        .tool-item.go { border-left-color: #00acd7; }
        .tool-item.python { border-left-color: #3776ab; }
        .tool-item.cloned { border-left-color: #ff6600; }
        
        /* Targets */
        .target-item {
            padding: 10px;
            border-bottom: 1px solid var(--border);
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .target-item:last-child { border-bottom: none; }
        .target-item .name { font-weight: 500; }
        .target-item .type {
            font-size: 11px;
            padding: 2px 8px;
            border-radius: 10px;
            background: var(--border);
        }
        .target-item .type.bounty { background: #00aa5c; color: black; }
        .target-item .type.training { background: #4488ff; color: white; }
        
        /* Reports */
        .report-item {
            padding: 10px;
            border-bottom: 1px solid var(--border);
            cursor: pointer;
            transition: background 0.2s;
        }
        .report-item:hover { background: rgba(0,255,136,0.05); }
        .report-item .name { font-weight: 500; font-size: 13px; margin-bottom: 4px; }
        .report-item .meta { font-size: 11px; color: var(--text-dim); display: flex; gap: 10px; }
        .sev { padding: 1px 6px; border-radius: 3px; font-size: 10px; font-weight: 600; }
        .sev.critical { background: var(--danger); }
        .sev.high { background: #ff8800; }
        .sev.medium { background: #ffcc00; color: black; }
        
        /* Agents */
        .agent-item {
            padding: 10px;
            border-bottom: 1px solid var(--border);
            display: flex;
            justify-content: space-between;
        }
        .agent-item .status { font-size: 11px; padding: 2px 8px; border-radius: 10px; }
        .agent-item .status.ready { background: var(--accent); color: black; }
        .agent-item .status.deployed { background: var(--warning); color: black; }
        .agent-item .status.planned { background: var(--border); }
        
        /* ML Models */
        .ml-item { padding: 10px; border-bottom: 1px solid var(--border); }
        .ml-item .row { display: flex; justify-content: space-between; }
        .ml-item .purpose { font-size: 11px; color: var(--text-dim); }
        
        /* Automation Meter */
        .automation-meter {
            padding: 15px;
            text-align: center;
        }
        .meter-circle {
            width: 120px;
            height: 120px;
            border-radius: 50%;
            border: 8px solid var(--border);
            margin: 0 auto 10px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 32px;
            font-weight: 700;
            color: var(--accent);
            position: relative;
        }
        .meter-circle::after {
            content: '%';
            font-size: 14px;
            position: absolute;
            bottom: 25px;
            right: 25px;
        }
        .meter-label { font-size: 18px; font-weight: 600; margin-bottom: 5px; }
        .meter-sub { font-size: 12px; color: var(--text-dim); }
        
        /* CTF Progress */
        .ctf-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(40px, 1fr)); gap: 5px; }
        .ctf-level {
            padding: 6px;
            text-align: center;
            border-radius: 4px;
            font-size: 11px;
            font-weight: 600;
            background: #1a1a2e;
        }
        .ctf-level.solved { background: var(--accent); color: black; }
        .ctf-level.current { background: var(--warning); color: black; animation: pulse 1s infinite; }
        
        /* Pagination */
        .pagination { display: flex; justify-content: center; gap: 5px; padding: 10px; }
        .pagination button {
            padding: 5px 12px;
            border: 1px solid var(--border);
            background: var(--bg-card);
            color: var(--text);
            border-radius: 4px;
            cursor: pointer;
        }
        .pagination button:hover { border-color: var(--accent); }
        .pagination button.active { background: var(--accent); color: black; }
        
        /* Modal */
        .modal {
            display: none;
            position: fixed;
            inset: 0;
            background: rgba(0,0,0,0.85);
            z-index: 1000;
            padding: 30px;
            overflow-y: auto;
        }
        .modal.active { display: flex; justify-content: center; align-items: flex-start; }
        .modal-content {
            width: 100%;
            max-width: 900px;
            background: var(--bg-card);
            border-radius: 10px;
            border: 1px solid var(--accent);
        }
        .modal-header {
            padding: 15px;
            border-bottom: 1px solid var(--border);
            display: flex;
            justify-content: space-between;
        }
        .modal-body { padding: 15px; }
        .modal-body pre {
            background: #0a0a0f;
            padding: 15px;
            border-radius: 8px;
            overflow-x: auto;
            white-space: pre-wrap;
            font-family: monospace;
            font-size: 12px;
            max-height: 70vh;
            overflow-y: auto;
        }
        .close-btn { background: none; border: none; color: var(--text); font-size: 24px; cursor: pointer; }
    </style>
</head>
<body>
    <div class="header">
        <h1><span>🐍</span> VIPER Command Center</h1>
        <div class="status-badge online" id="statusBadge">● Online</div>
    </div>
    
    <div class="container">
        <!-- Live Status Bar -->
        <div class="live-bar" id="liveBar">
            <div class="row">
                <div class="stat">
                    <div class="label">TARGET</div>
                    <div class="value" id="liveTarget">--</div>
                </div>
                <div class="stat">
                    <div class="label">TASK</div>
                    <div class="value" id="liveTask">--</div>
                </div>
                <div class="stat">
                    <div class="label">TOOL</div>
                    <div class="value" id="liveTool">--</div>
                </div>
                <div class="stat">
                    <div class="label">PHASE</div>
                    <div class="value" id="livePhase">--</div>
                </div>
                <div class="progress-track">
                    <div class="progress-fill" id="liveProgress" style="width: 0%"></div>
                </div>
                <div class="stat">
                    <div class="value" id="liveProgressPct">0%</div>
                </div>
            </div>
        </div>
        
        <!-- Stats Grid -->
        <div class="stats-grid">
            <div class="stat-card">
                <div class="value" id="statTools">0</div>
                <div class="label">🔧 Tools</div>
            </div>
            <div class="stat-card">
                <div class="value" id="statReports">0</div>
                <div class="label">📄 Reports</div>
            </div>
            <div class="stat-card">
                <div class="value" id="statFindings">0</div>
                <div class="label">🐛 Findings</div>
            </div>
            <div class="stat-card">
                <div class="value" id="statPatterns">0</div>
                <div class="label">🧠 Patterns</div>
            </div>
            <div class="stat-card">
                <div class="value" id="statBounties">$0</div>
                <div class="label">💰 Bounties</div>
            </div>
            <div class="stat-card">
                <div class="value" id="statNatas">0</div>
                <div class="label">🎮 Natas Level</div>
            </div>
        </div>
        
        <!-- Main Grid -->
        <div class="main-grid">
            <!-- Automation Level -->
            <div class="card">
                <div class="card-header"><h2>⚡ Automation Level</h2></div>
                <div class="card-body">
                    <div class="automation-meter">
                        <div class="meter-circle" id="autoScore">0</div>
                        <div class="meter-label" id="autoLevel">Novice</div>
                        <div class="meter-sub" id="autoSub">Tools: 0 | Patterns: 0 | Targets: 0</div>
                    </div>
                </div>
            </div>
            
            <!-- Tools -->
            <div class="card">
                <div class="card-header">
                    <h2>🔧 Tools</h2>
                    <span id="toolCount" style="color: var(--text-dim); font-size: 12px;"></span>
                </div>
                <div class="card-body">
                    <div class="tool-grid" id="toolGrid"></div>
                </div>
            </div>
            
            <!-- Agents -->
            <div class="card">
                <div class="card-header"><h2>🤖 Agents</h2></div>
                <div class="card-body" style="padding: 0;">
                    <div id="agentList"></div>
                </div>
            </div>
            
            <!-- Current Target -->
            <div class="card">
                <div class="card-header"><h2>🎯 Current Target</h2></div>
                <div class="card-body" id="currentTarget">
                    <div style="color: var(--text-dim);">No active target</div>
                </div>
            </div>
            
            <!-- Target Queue -->
            <div class="card">
                <div class="card-header">
                    <h2>📋 Target Queue</h2>
                    <span id="queueCount" style="color: var(--text-dim); font-size: 12px;"></span>
                </div>
                <div class="card-body" style="padding: 0;">
                    <div id="targetQueue"></div>
                </div>
            </div>
            
            <!-- ML Models -->
            <div class="card">
                <div class="card-header"><h2>🧠 ML Models</h2></div>
                <div class="card-body" style="padding: 0;">
                    <div id="mlModels"></div>
                </div>
            </div>
            
            <!-- CTF Progress -->
            <div class="card span-2">
                <div class="card-header"><h2>🎮 CTF Progress - Natas</h2></div>
                <div class="card-body">
                    <div class="ctf-grid" id="ctfGrid"></div>
                </div>
            </div>
            
            <!-- Activity Feed -->
            <div class="card">
                <div class="card-header"><h2>📡 Activity</h2></div>
                <div class="card-body" style="padding: 0;">
                    <div id="activityFeed"></div>
                </div>
            </div>
            
            <!-- Reports -->
            <div class="card span-2">
                <div class="card-header">
                    <h2>📄 Reports</h2>
                    <input type="text" id="reportSearch" placeholder="Search..." 
                        style="background: #1a1a2e; border: 1px solid var(--border); padding: 5px 10px; border-radius: 5px; color: var(--text); font-size: 12px;">
                </div>
                <div class="card-body" style="padding: 0;">
                    <div id="reportList"></div>
                    <div class="pagination" id="reportPagination"></div>
                </div>
            </div>
        </div>
    </div>
    
    <!-- Modal -->
    <div class="modal" id="modal">
        <div class="modal-content">
            <div class="modal-header">
                <h2 id="modalTitle">Report</h2>
                <button class="close-btn" onclick="closeModal()">×</button>
            </div>
            <div class="modal-body">
                <pre id="modalContent"></pre>
            </div>
        </div>
    </div>
    
    <script>
        let currentReportPage = 1;
        
        async function loadDashboard() {
            try {
                const resp = await fetch('/api/dashboard');
                const data = await resp.json();
                
                // Stats
                document.getElementById('statTools').textContent = data.stats.tools_count;
                document.getElementById('statReports').textContent = data.stats.reports_count;
                document.getElementById('statFindings').textContent = data.stats.total_findings;
                document.getElementById('statPatterns').textContent = data.stats.patterns_learned;
                document.getElementById('statBounties').textContent = '$' + (data.stats.total_bounties || 0);
                
                // Natas
                const natas = data.stats.ctf_progress?.natas;
                document.getElementById('statNatas').textContent = natas?.current_level || 0;
                
                // Automation
                const auto = data.stats.automation_level;
                document.getElementById('autoScore').textContent = auto.score;
                document.getElementById('autoLevel').textContent = auto.level;
                document.getElementById('autoSub').textContent = 
                    `Tools: ${auto.tools_count} | Patterns: ${auto.patterns_learned} | Targets: ${auto.targets_configured}`;
                
                // Live state
                updateLiveState(data.live_state);
                
                // Tools
                const toolGrid = document.getElementById('toolGrid');
                toolGrid.innerHTML = data.tools.map(t => 
                    `<div class="tool-item ${t.type}">${t.name}</div>`
                ).join('');
                document.getElementById('toolCount').textContent = data.tools.length + ' installed';
                
                // Agents
                const agentList = document.getElementById('agentList');
                agentList.innerHTML = data.agents.map(a => `
                    <div class="agent-item">
                        <div>
                            <div style="font-weight: 500;">${a.name}</div>
                            <div style="font-size: 11px; color: var(--text-dim);">${a.purpose}</div>
                        </div>
                        <span class="status ${a.status}">${a.status}</span>
                    </div>
                `).join('');
                
                // Targets
                const targets = data.targets;
                document.getElementById('queueCount').textContent = targets.total_queued + ' queued';
                
                if (targets.current) {
                    document.getElementById('currentTarget').innerHTML = `
                        <div style="font-weight: 600; font-size: 16px; color: var(--accent);">${targets.current.name}</div>
                        <div style="margin-top: 5px;">${targets.current.url || targets.current.domain || ''}</div>
                        <div style="margin-top: 5px;"><span class="target-type ${targets.current.type}">${targets.current.type}</span></div>
                    `;
                }
                
                document.getElementById('targetQueue').innerHTML = targets.queued.map(t => `
                    <div class="target-item">
                        <div class="name">${t.name}</div>
                        <span class="type ${t.type}">${t.type}</span>
                    </div>
                `).join('') || '<div style="padding: 15px; color: var(--text-dim);">No targets queued</div>';
                
                // ML Models
                document.getElementById('mlModels').innerHTML = data.ml_models.map(m => `
                    <div class="ml-item">
                        <div class="row">
                            <span>${m.name}</span>
                            <span class="status ${m.status}">${m.status}</span>
                        </div>
                        <div class="purpose">${m.purpose}</div>
                    </div>
                `).join('');
                
                // CTF Grid
                if (natas) {
                    let ctfHtml = '';
                    for (let i = 0; i <= 34; i++) {
                        const cls = i < natas.current_level ? 'solved' : i === natas.current_level ? 'current' : '';
                        ctfHtml += `<div class="ctf-level ${cls}">${i}</div>`;
                    }
                    document.getElementById('ctfGrid').innerHTML = ctfHtml;
                }
                
                // Activity
                const events = data.live_state.events || [];
                document.getElementById('activityFeed').innerHTML = events.slice(0, 15).map(e => `
                    <div class="target-item">
                        <div class="name">${e.message}</div>
                        <span style="font-size: 11px; color: var(--text-dim);">${new Date(e.time).toLocaleTimeString()}</span>
                    </div>
                `).join('') || '<div style="padding: 15px; color: var(--text-dim);">No recent activity</div>';
                
                // Reports (initial load)
                loadReports(1);
                
            } catch (e) {
                console.error('Dashboard load error:', e);
            }
        }
        
        function updateLiveState(state) {
            const bar = document.getElementById('liveBar');
            const badge = document.getElementById('statusBadge');
            
            if (state && state.active) {
                bar.classList.add('active');
                badge.textContent = '● Scanning';
                badge.className = 'status-badge scanning';
                
                document.getElementById('liveTarget').textContent = state.target || '--';
                document.getElementById('liveTask').textContent = state.current_task || '--';
                document.getElementById('liveTool').textContent = state.tool || '--';
                document.getElementById('livePhase').textContent = state.phase || '--';
                document.getElementById('liveProgress').style.width = (state.progress || 0) + '%';
                document.getElementById('liveProgressPct').textContent = (state.progress || 0) + '%';
            } else {
                bar.classList.remove('active');
                badge.textContent = '● Online';
                badge.className = 'status-badge online';
            }
        }
        
        async function loadReports(page) {
            currentReportPage = page;
            const search = document.getElementById('reportSearch').value;
            const resp = await fetch(`/api/reports?page=${page}&per_page=15&search=${encodeURIComponent(search)}`);
            const data = await resp.json();
            
            document.getElementById('reportList').innerHTML = data.reports.map(r => `
                <div class="report-item" onclick="viewReport('${r.name}')">
                    <div class="name">${r.name}</div>
                    <div class="meta">
                        <span>${new Date(r.modified).toLocaleDateString()}</span>
                        ${r.critical ? `<span class="sev critical">${r.critical} CRIT</span>` : ''}
                        ${r.high ? `<span class="sev high">${r.high} HIGH</span>` : ''}
                        ${r.medium ? `<span class="sev medium">${r.medium} MED</span>` : ''}
                    </div>
                </div>
            `).join('') || '<div style="padding: 15px;">No reports found</div>';
            
            // Pagination
            let pagHtml = '';
            const maxPages = Math.min(10, data.total_pages);
            const startPage = Math.max(1, page - 4);
            const endPage = Math.min(data.total_pages, startPage + maxPages - 1);
            
            if (page > 1) pagHtml += `<button onclick="loadReports(${page-1})">←</button>`;
            for (let i = startPage; i <= endPage; i++) {
                pagHtml += `<button class="${i === page ? 'active' : ''}" onclick="loadReports(${i})">${i}</button>`;
            }
            if (page < data.total_pages) pagHtml += `<button onclick="loadReports(${page+1})">→</button>`;
            pagHtml += `<span style="margin-left: 10px; color: var(--text-dim);">${data.total} total</span>`;
            
            document.getElementById('reportPagination').innerHTML = pagHtml;
        }
        
        async function viewReport(name) {
            const resp = await fetch(`/api/reports/${name}`);
            const data = await resp.json();
            document.getElementById('modalTitle').textContent = name;
            document.getElementById('modalContent').textContent = data.content;
            document.getElementById('modal').classList.add('active');
        }
        
        function closeModal() {
            document.getElementById('modal').classList.remove('active');
        }
        
        // Search
        document.getElementById('reportSearch').addEventListener('input', () => loadReports(1));
        
        // Close modal on escape
        document.addEventListener('keydown', e => { if (e.key === 'Escape') closeModal(); });
        
        // Init
        loadDashboard();
        setInterval(loadDashboard, 10000); // Refresh every 10s
    </script>
</body>
</html>
"""


async def index(request):
    return web.Response(text=DASHBOARD_HTML, content_type='text/html')


@web.middleware
async def security_middleware(request, handler):
    response = await handler(request)
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    return response


def create_app():
    app = web.Application(middlewares=[security_middleware])
    cors = aiohttp_cors.setup(app, defaults={
        "*": aiohttp_cors.ResourceOptions(allow_credentials=True, expose_headers="*", allow_headers="*")
    })
    
    app.router.add_get('/', index)
    app.router.add_get('/api/dashboard', api_dashboard)
    app.router.add_get('/api/tools', api_tools)
    app.router.add_get('/api/targets', api_targets)
    app.router.add_get('/api/reports', api_reports)
    app.router.add_get('/api/reports/{name}', api_report_detail)
    app.router.add_get('/api/agents', api_agents)
    app.router.add_get('/api/ml', api_ml_models)
    app.router.add_get('/api/automation', api_automation)
    app.router.add_get('/api/ctf', api_ctf)
    app.router.add_get('/api/live', api_live)
    app.router.add_get('/api/attacks', api_attacks)
    
    for route in list(app.router.routes()):
        cors.add(route)
    
    return app


if __name__ == '__main__':
    print("🐍 VIPER Command Center v2")
    print("Starting on http://localhost:8889")
    app = create_app()
    web.run_app(app, host='127.0.0.1', port=8889, print=None)
