#!/usr/bin/env python3
"""
VIPER Dashboard - Pure Red Team Offensive Security Dashboard
Port 8889 - No SENTINEL (that's on 8888)
"""

import asyncio
import json
import sys
from datetime import datetime
from pathlib import Path
from aiohttp import web

HACKAGENT_DIR = Path(__file__).parent.parent
sys.path.insert(0, str(HACKAGENT_DIR.parent / "security-agent" / "scripts"))
from secure_headers import add_security_headers

HTML = '''<!DOCTYPE html>
<html>
<head>
    <title>🐍 VIPER - Red Team Dashboard</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Consolas', 'Courier New', monospace;
            background: linear-gradient(135deg, #0a0a0a 0%, #1a0a0a 100%);
            color: #ff6600;
            min-height: 100vh;
            padding: 20px;
        }
        .header {
            text-align: center;
            padding: 20px;
            border-bottom: 2px solid #ff4400;
            margin-bottom: 20px;
        }
        .header h1 {
            font-size: 36px;
            color: #ff4400;
            text-shadow: 0 0 20px #ff4400, 0 0 40px #ff2200;
        }
        .header .subtitle {
            color: #ff8844;
            margin-top: 5px;
        }
        .grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(350px, 1fr));
            gap: 20px;
        }
        .panel {
            background: rgba(30, 10, 10, 0.9);
            border: 1px solid #ff4400;
            border-radius: 10px;
            padding: 20px;
            box-shadow: 0 0 15px rgba(255, 68, 0, 0.2);
        }
        .panel h2 {
            color: #ff6600;
            border-bottom: 1px solid #442200;
            padding-bottom: 10px;
            margin-bottom: 15px;
            font-size: 16px;
        }
        .stats {
            display: flex;
            justify-content: space-around;
            flex-wrap: wrap;
            gap: 10px;
        }
        .stat {
            text-align: center;
            padding: 15px;
            background: rgba(50, 20, 10, 0.8);
            border-radius: 8px;
            min-width: 90px;
            border: 1px solid #331100;
        }
        .stat .val {
            font-size: 28px;
            font-weight: bold;
            text-shadow: 0 0 10px currentColor;
        }
        .stat .lbl {
            color: #aa6633;
            font-size: 11px;
            margin-top: 5px;
        }
        .stat.green .val { color: #00ff00; }
        .stat.red .val { color: #ff4444; }
        .stat.orange .val { color: #ff8800; }
        .stat.yellow .val { color: #ffff00; }
        
        .attack-grid {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(200px, 1fr));
            gap: 8px;
            max-height: 300px;
            overflow-y: auto;
        }
        .attack-item {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 8px 12px;
            background: rgba(40, 15, 10, 0.8);
            border-radius: 5px;
            border-left: 3px solid #333;
            font-size: 12px;
        }
        .attack-item.success { border-left-color: #00ff00; }
        .attack-item.partial { border-left-color: #ffaa00; }
        .attack-item.fail { border-left-color: #ff3333; }
        .attack-name { color: #ccaa88; }
        .attack-stats { 
            display: flex;
            gap: 8px;
            font-size: 11px;
        }
        .attack-stats .success { color: #00ff00; }
        .attack-stats .fail { color: #ff4444; }
        
        .log {
            background: #0a0505;
            border: 1px solid #331100;
            border-radius: 5px;
            padding: 10px;
            height: 250px;
            overflow-y: auto;
            font-size: 11px;
            font-family: monospace;
        }
        .log-entry {
            padding: 3px 0;
            border-left: 3px solid #333;
            padding-left: 8px;
            margin: 2px 0;
        }
        .log-entry.vuln { border-color: #00ff00; color: #00ff00; }
        .log-entry.info { border-color: #666; color: #888; }
        .log-entry.error { border-color: #ff0000; color: #ff6666; }
        .log-entry.success { border-color: #00ff00; color: #88ff88; }
        
        .target-list {
            max-height: 150px;
            overflow-y: auto;
        }
        .target {
            padding: 8px;
            background: rgba(40, 15, 10, 0.6);
            border-radius: 5px;
            margin-bottom: 5px;
            font-size: 12px;
            border-left: 3px solid #ff4400;
        }
        .target .url { color: #ffaa66; }
        .target .status { color: #888; font-size: 10px; }
        
        .findings-table {
            width: 100%;
            border-collapse: collapse;
            font-size: 11px;
        }
        .findings-table th {
            background: #331100;
            color: #ff8844;
            padding: 8px;
            text-align: left;
        }
        .findings-table td {
            padding: 6px 8px;
            border-bottom: 1px solid #221100;
        }
        .findings-table tr:hover { background: rgba(255, 68, 0, 0.1); }
        .severity-critical { color: #ff0000; font-weight: bold; }
        .severity-high { color: #ff4400; }
        .severity-medium { color: #ffaa00; }
        .severity-low { color: #88ff88; }
        
        .status-bar {
            text-align: center;
            padding: 10px;
            background: rgba(255, 68, 0, 0.1);
            border-radius: 8px;
            margin-bottom: 20px;
            border: 1px solid #ff4400;
        }
        .status-bar.running { border-color: #00ff00; background: rgba(0, 255, 0, 0.1); }
        .status-bar.stopped { border-color: #ff0000; background: rgba(255, 0, 0, 0.1); }
        
        .refresh { text-align: center; color: #553322; font-size: 11px; margin-top: 20px; }
        
        ::-webkit-scrollbar { width: 6px; }
        ::-webkit-scrollbar-track { background: #1a0a0a; }
        ::-webkit-scrollbar-thumb { background: #ff4400; border-radius: 3px; }
    </style>
</head>
<body>
    <div class="header">
        <h1>🐍 VIPER</h1>
        <div class="subtitle">Autonomous Red Team Agent</div>
    </div>
    
    <div id="status-bar" class="status-bar">
        <span id="status-text">Connecting...</span>
    </div>
    
    <div class="grid">
        <div class="panel">
            <h2>📊 Hunt Statistics</h2>
            <div class="stats">
                <div class="stat orange"><div class="val" id="requests">-</div><div class="lbl">Requests</div></div>
                <div class="stat green"><div class="val" id="findings">-</div><div class="lbl">Findings</div></div>
                <div class="stat yellow"><div class="val" id="targets">-</div><div class="lbl">Targets</div></div>
                <div class="stat"><div class="val" id="uptime">-</div><div class="lbl">Uptime</div></div>
            </div>
        </div>
        
        <div class="panel">
            <h2>🎯 Current Targets</h2>
            <div class="target-list" id="targets-list">
                <div class="target"><span class="status">Loading...</span></div>
            </div>
        </div>
        
        <div class="panel" style="grid-column: 1 / -1;">
            <h2>⚔️ Attack Success Rates</h2>
            <div class="attack-grid" id="attacks"></div>
        </div>
        
        <div class="panel">
            <h2>🔥 Recent Findings</h2>
            <table class="findings-table">
                <thead>
                    <tr><th>Type</th><th>Target</th><th>Severity</th></tr>
                </thead>
                <tbody id="findings-table"></tbody>
            </table>
        </div>
        
        <div class="panel">
            <h2>📜 Live Activity</h2>
            <div class="log" id="log"></div>
        </div>
    </div>
    
    <div class="refresh">Auto-refresh: 3s | <span id="ts">-</span></div>
    
    <script>
        async function refresh() {
            try {
                const r = await fetch('/api/status');
                const d = await r.json();
                
                // Status bar
                const bar = document.getElementById('status-bar');
                const statusText = document.getElementById('status-text');
                if (d.viper && d.viper.running) {
                    bar.className = 'status-bar running';
                    statusText.innerHTML = '🟢 VIPER ACTIVE — Hunting in progress';
                } else {
                    bar.className = 'status-bar stopped';
                    statusText.innerHTML = '🔴 VIPER STOPPED';
                }
                
                // Stats
                if (d.viper) {
                    document.getElementById('requests').textContent = d.viper.requests || 0;
                    document.getElementById('findings').textContent = d.viper.findings || 0;
                    document.getElementById('uptime').textContent = d.viper.uptime || '-';
                    document.getElementById('targets').textContent = d.viper.target_count || 0;
                }
                
                // Attacks
                const attacks = document.getElementById('attacks');
                if (d.viper && d.viper.attacks) {
                    attacks.innerHTML = Object.entries(d.viper.attacks).map(([name, stats]) => {
                        const rate = stats.attempts > 0 ? (stats.successes / stats.attempts * 100) : 0;
                        let cls = 'fail';
                        if (rate > 50) cls = 'success';
                        else if (rate > 0) cls = 'partial';
                        return `<div class="attack-item ${cls}">
                            <span class="attack-name">${name}</span>
                            <span class="attack-stats">
                                <span class="success">✓${stats.successes}</span>
                                <span class="fail">✗${stats.attempts - stats.successes}</span>
                            </span>
                        </div>`;
                    }).join('');
                }
                
                // Targets
                const targetsList = document.getElementById('targets-list');
                if (d.targets && d.targets.length > 0) {
                    targetsList.innerHTML = d.targets.slice(0, 5).map(t => 
                        `<div class="target">
                            <div class="url">${t.url || t}</div>
                            <div class="status">${t.status || 'queued'}</div>
                        </div>`
                    ).join('');
                } else {
                    targetsList.innerHTML = '<div class="target"><span class="status">No targets loaded</span></div>';
                }
                
                // Findings table
                const findingsTable = document.getElementById('findings-table');
                if (d.findings && d.findings.length > 0) {
                    findingsTable.innerHTML = d.findings.slice(0, 10).map(f => {
                        const sevClass = 'severity-' + (f.severity || 'medium').toLowerCase();
                        return `<tr>
                            <td>${f.type || f.name || 'unknown'}</td>
                            <td style="color:#888;max-width:150px;overflow:hidden;text-overflow:ellipsis;">${f.target || '-'}</td>
                            <td class="${sevClass}">${(f.severity || 'MEDIUM').toUpperCase()}</td>
                        </tr>`;
                    }).join('');
                } else {
                    findingsTable.innerHTML = '<tr><td colspan="3" style="color:#666;">No findings yet</td></tr>';
                }
                
                // Log
                const log = document.getElementById('log');
                if (d.logs && d.logs.length > 0) {
                    log.innerHTML = d.logs.slice(-30).map(l => {
                        let cls = 'info';
                        if (l.includes('[VULN]') || l.includes('FOUND')) cls = 'vuln';
                        else if (l.includes('[ERROR]')) cls = 'error';
                        else if (l.includes('[SUCCESS]') || l.includes('[+]')) cls = 'success';
                        return `<div class="log-entry ${cls}">${l}</div>`;
                    }).join('');
                    log.scrollTop = log.scrollHeight;
                }
                
                document.getElementById('ts').textContent = new Date().toLocaleTimeString();
            } catch(e) {
                document.getElementById('status-bar').className = 'status-bar stopped';
                document.getElementById('status-text').innerHTML = '⚠️ Connection error';
                console.error(e);
            }
        }
        refresh();
        setInterval(refresh, 3000);
    </script>
</body>
</html>'''


async def get_viper_status():
    """Get VIPER status from various sources"""
    status = {
        'viper': {
            'running': False,
            'requests': 0,
            'findings': 0,
            'uptime': '-',
            'target_count': 0,
            'attacks': {}
        },
        'targets': [],
        'findings': [],
        'logs': []
    }
    
    # Check if viper_core is running
    try:
        import subprocess
        result = subprocess.run(
            ['powershell', '-Command', "Get-Process python -ErrorAction SilentlyContinue | Where-Object { $_.CommandLine -like '*viper_core*' }"],
            capture_output=True, text=True, timeout=5
        )
        status['viper']['running'] = 'viper_core' in result.stdout or len(result.stdout.strip()) > 0
    except:
        pass
    
    # Load metrics
    metrics_file = HACKAGENT_DIR / "core" / "viper_metrics.json"
    if metrics_file.exists():
        try:
            with open(metrics_file) as f:
                metrics = json.load(f)
                status['viper']['requests'] = metrics.get('total_requests', 0)
                status['viper']['findings'] = metrics.get('total_findings', 0)
                status['viper']['attacks'] = metrics.get('attacks', {})
                
                # Calculate uptime
                start = metrics.get('start_time')
                if start:
                    try:
                        start_dt = datetime.fromisoformat(start)
                        delta = datetime.now() - start_dt
                        hours, rem = divmod(int(delta.total_seconds()), 3600)
                        mins, _ = divmod(rem, 60)
                        status['viper']['uptime'] = f"{hours}h {mins}m"
                    except:
                        pass
        except:
            pass
    
    # Load targets
    targets_file = HACKAGENT_DIR / "targets.json"
    if targets_file.exists():
        try:
            with open(targets_file) as f:
                data = json.load(f)
                targets = data if isinstance(data, list) else data.get('targets', [])
                status['targets'] = targets[:10]
                status['viper']['target_count'] = len(targets)
        except:
            pass
    
    # Load recent findings from knowledge
    knowledge_file = HACKAGENT_DIR / "core" / "viper_knowledge.json"
    if knowledge_file.exists():
        try:
            with open(knowledge_file) as f:
                knowledge = json.load(f)
                vulns = knowledge.get('vulnerabilities', [])
                status['findings'] = vulns[-20:] if vulns else []
        except:
            pass
    
    # Load recent logs
    today = datetime.now().strftime("%Y%m%d")
    log_file = HACKAGENT_DIR / "logs" / f"viper_{today}.log"
    if log_file.exists():
        try:
            with open(log_file, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
                status['logs'] = [l.strip() for l in lines[-50:] if l.strip()]
        except:
            pass
    
    status['timestamp'] = datetime.now().isoformat()
    return status


async def handle_index(request):
    return web.Response(text=HTML, content_type='text/html')


async def handle_status(request):
    return web.json_response(await get_viper_status())


async def handle_findings(request):
    """Get detailed findings"""
    findings = []
    knowledge_file = HACKAGENT_DIR / "core" / "viper_knowledge.json"
    if knowledge_file.exists():
        try:
            with open(knowledge_file) as f:
                knowledge = json.load(f)
                findings = knowledge.get('vulnerabilities', [])
        except:
            pass
    return web.json_response({'findings': findings})


async def main():
    app = web.Application(middlewares=[add_security_headers])
    app.router.add_get('/', handle_index)
    app.router.add_get('/api/status', handle_status)
    app.router.add_get('/api/findings', handle_findings)
    
    runner = web.AppRunner(app)
    await runner.setup()
    await web.TCPSite(runner, '0.0.0.0', 8889).start()
    print("[*] VIPER Dashboard: http://localhost:8889")
    print("[*] Pure Red Team - No SENTINEL (use :8888 for blue team)")
    
    while True:
        await asyncio.sleep(3600)


if __name__ == '__main__':
    asyncio.run(main())
