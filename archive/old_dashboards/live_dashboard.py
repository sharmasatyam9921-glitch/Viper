#!/usr/bin/env python3
"""
HackAgent Live Dashboard - Watch bug hunting in real-time
Uses a shared state file that the scanner updates
"""

import http.server
import logging

logger = logging.getLogger("viper.live_dashboard")
import socketserver
import json
import os
from pathlib import Path
from datetime import datetime

PORT = 8889
STATE_FILE = Path(__file__).parent / "state.json"

def get_state():
    """Read current state from file"""
    if STATE_FILE.exists():
        try:
            return json.loads(STATE_FILE.read_text())
        except Exception as e:  # noqa: BLE001
            pass
    return {
        "phase": "idle",
        "target": "",
        "program": "",
        "stats": {"requests": 0, "endpoints": 0, "vulns": 0, "start_time": None},
        "events": [],
        "findings": [],
        "learning": None
    }

HTML = """<!DOCTYPE html>
<html>
<head>
    <title>VIPER - Red Team</title>
    <meta charset="UTF-8">
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Courier New', monospace;
            background: #0a0a0a;
            color: #00ff00;
            min-height: 100vh;
        }
        .header {
            background: linear-gradient(90deg, #1a1a2e, #16213e);
            padding: 20px;
            border-bottom: 2px solid #00ff00;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .header h1 { text-shadow: 0 0 10px #00ff00; }
        .status { padding: 5px 15px; border-radius: 20px; font-weight: bold; }
        .status.hunting { background: #00ff00; color: black; animation: pulse 1s infinite; }
        .status.idle { background: #333; color: #888; }
        @keyframes pulse { 0%,100% { opacity: 1; } 50% { opacity: 0.5; } }
        
        .container { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; padding: 20px; }
        .full { grid-column: 1 / -1; }
        
        .panel {
            background: #111;
            border: 1px solid #333;
            border-radius: 8px;
            padding: 15px;
        }
        .panel h2 {
            color: #00ff00;
            border-bottom: 1px solid #333;
            padding-bottom: 10px;
            margin-bottom: 10px;
            font-size: 14px;
        }
        
        .stats-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 10px; }
        .stat { background: #1a1a1a; padding: 15px; border-radius: 5px; text-align: center; }
        .stat .value { font-size: 28px; color: #00ff00; text-shadow: 0 0 5px #00ff00; }
        .stat .label { color: #666; font-size: 11px; margin-top: 5px; }
        
        .phases { display: flex; gap: 5px; margin: 15px 0; }
        .phase {
            flex: 1; padding: 8px; background: #1a1a1a;
            border-radius: 5px; text-align: center; font-size: 12px; opacity: 0.3;
        }
        .phase.active { opacity: 1; background: #0f3d0f; border: 1px solid #00ff00; }
        .phase.done { opacity: 0.7; background: #1a3d1a; }
        
        .events { height: 300px; overflow-y: auto; font-size: 12px; }
        .event { padding: 5px 10px; border-left: 3px solid #333; margin-bottom: 3px; }
        .event.recon { border-color: #0088ff; }
        .event.scan { border-color: #ffaa00; }
        .event.found { border-color: #00ff00; background: #0a1a0a; }
        .event.vuln { border-color: #ff0000; background: #1a0a0a; }
        .event.info { border-color: #888; }
        .event.error { border-color: #ff0000; }
        .event .time { color: #666; font-size: 10px; }
        
        .findings { max-height: 400px; overflow-y: auto; }
        .finding {
            background: #1a0a0a;
            border: 1px solid #ff0000;
            padding: 15px;
            margin-bottom: 10px;
            border-radius: 5px;
        }
        .finding.critical { border-color: #ff0000; }
        .finding.high { border-color: #ff4400; }
        .finding.medium { border-color: #ffaa00; }
        .finding.low { border-color: #ffff00; }
        
        .severity {
            display: inline-block;
            padding: 2px 8px;
            border-radius: 3px;
            font-size: 11px;
            font-weight: bold;
        }
        .severity.critical { background: #ff0000; color: white; }
        .severity.high { background: #ff4400; color: white; }
        .severity.medium { background: #ffaa00; color: black; }
        .severity.low { background: #ffff00; color: black; }
        
        .target-info { background: #1a1a1a; padding: 15px; border-radius: 5px; margin-bottom: 15px; }
        .target-info .url { font-size: 18px; color: #00ff00; }
        .target-info .program { color: #888; margin-top: 5px; }
        
        pre { background: #0a0a0a; padding: 10px; border-radius: 5px; overflow-x: auto; font-size: 11px; margin-top: 10px; }
        code { color: #ffaa00; }
        
        .learning {
            background: #1a1a2e;
            border-left: 3px solid #0088ff;
            padding: 15px;
            margin-top: 10px;
        }
        .learning h4 { color: #0088ff; margin-bottom: 10px; }
        
        .no-data { color: #666; text-align: center; padding: 40px; }
    </style>
</head>
<body>
    <div class="header">
        <h1>🐍 VIPER Live</h1>
        <div class="status idle" id="status">IDLE</div>
    </div>
    
    <div class="container">
        <div class="panel full">
            <div class="target-info">
                <div class="url" id="target">Waiting for scan...</div>
                <div class="program" id="program">Start a hunt to see live updates</div>
            </div>
            <div class="phases">
                <div class="phase" id="p-recon">RECON</div>
                <div class="phase" id="p-enum">ENUMERATE</div>
                <div class="phase" id="p-scan">SCAN</div>
                <div class="phase" id="p-exploit">EXPLOIT</div>
                <div class="phase" id="p-report">REPORT</div>
            </div>
            <div class="stats-grid">
                <div class="stat"><div class="value" id="s-requests">0</div><div class="label">Requests</div></div>
                <div class="stat"><div class="value" id="s-endpoints">0</div><div class="label">Endpoints</div></div>
                <div class="stat"><div class="value" id="s-vulns">0</div><div class="label">Vulns Found</div></div>
                <div class="stat"><div class="value" id="s-time">0:00</div><div class="label">Elapsed</div></div>
            </div>
        </div>
        
        <div class="panel">
            <h2>📡 LIVE ACTIVITY</h2>
            <div class="events" id="events"><div class="no-data">No activity yet...</div></div>
        </div>
        
        <div class="panel">
            <h2>🎯 FINDINGS</h2>
            <div class="findings" id="findings"><div class="no-data">No vulnerabilities found yet...</div></div>
        </div>
        
        <div class="panel full">
            <h2>📚 LEARNING NOTES</h2>
            <div id="learning">
                <div class="learning">
                    <h4>How HackAgent Works</h4>
                    <p>When I hunt a target, you'll see:</p>
                    <ul style="margin-left: 20px; margin-top: 10px; color: #888;">
                        <li><strong>RECON</strong> - Fingerprinting tech stack, headers</li>
                        <li><strong>ENUMERATE</strong> - Finding endpoints, APIs</li>
                        <li><strong>SCAN</strong> - Testing for vulnerabilities</li>
                        <li><strong>EXPLOIT</strong> - Proving the bug works</li>
                        <li><strong>REPORT</strong> - Writing it up for bounty</li>
                    </ul>
                </div>
            </div>
        </div>
    </div>
    
    <script>
        let startTime = null;
        
        function refresh() {
            fetch('/api/state')
                .then(r => r.json())
                .then(data => {
                    // Status
                    const status = document.getElementById('status');
                    if (data.phase && data.phase !== 'idle') {
                        status.textContent = 'HUNTING';
                        status.className = 'status hunting';
                    } else {
                        status.textContent = 'IDLE';
                        status.className = 'status idle';
                    }
                    
                    // Target
                    if (data.target) {
                        document.getElementById('target').textContent = data.target;
                        document.getElementById('program').textContent = data.program || 'Custom Target';
                    }
                    
                    // Phases
                    const phases = ['recon', 'enum', 'scan', 'exploit', 'report'];
                    const currentIdx = phases.indexOf(data.phase);
                    phases.forEach((p, i) => {
                        const el = document.getElementById('p-' + p);
                        el.className = 'phase';
                        if (i < currentIdx) el.classList.add('done');
                        if (i === currentIdx) el.classList.add('active');
                    });
                    
                    // Stats
                    if (data.stats) {
                        document.getElementById('s-requests').textContent = data.stats.requests || 0;
                        document.getElementById('s-endpoints').textContent = data.stats.endpoints || 0;
                        document.getElementById('s-vulns').textContent = data.stats.vulns || 0;
                        
                        if (data.stats.start_time) {
                            const start = new Date(data.stats.start_time);
                            const elapsed = Math.floor((Date.now() - start.getTime()) / 1000);
                            const min = Math.floor(elapsed / 60);
                            const sec = elapsed % 60;
                            document.getElementById('s-time').textContent = min + ':' + sec.toString().padStart(2, '0');
                        }
                    }
                    
                    // Events
                    if (data.events && data.events.length > 0) {
                        const eventsEl = document.getElementById('events');
                        eventsEl.innerHTML = data.events.slice(-50).reverse().map(e => {
                            const time = new Date(e.time).toLocaleTimeString();
                            return `<div class="event ${e.type}">
                                <span class="time">[${time}]</span> ${e.msg}
                            </div>`;
                        }).join('');
                    }
                    
                    // Findings
                    if (data.findings && data.findings.length > 0) {
                        const findingsEl = document.getElementById('findings');
                        findingsEl.innerHTML = data.findings.map(f => 
                            `<div class="finding ${f.severity}">
                                <span class="severity ${f.severity}">${f.severity.toUpperCase()}</span>
                                <strong> ${f.type}</strong><br>
                                <small>${f.location}</small>
                                ${f.payload ? `<pre><code>${f.payload}</code></pre>` : ''}
                            </div>`
                        ).join('');
                    }
                    
                    // Learning
                    if (data.learning) {
                        document.getElementById('learning').innerHTML = 
                            `<div class="learning">
                                <h4>${data.learning.title}</h4>
                                <p>${data.learning.explanation}</p>
                                ${data.learning.code ? `<pre><code>${data.learning.code}</code></pre>` : ''}
                            </div>`;
                    }
                })
                .catch(err => console.log('Refresh error:', err));
        }
        
        setInterval(refresh, 500);  // Poll every 500ms for live feel
        refresh();
    </script>
</body>
</html>
"""

class Handler(http.server.SimpleHTTPRequestHandler):
    def add_security_headers(self):
        """Add security headers to all responses"""
        self.send_header('X-Frame-Options', 'DENY')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('X-XSS-Protection', '1; mode=block')
        self.send_header('Content-Security-Policy', "default-src 'self' 'unsafe-inline'")
        self.send_header('Referrer-Policy', 'strict-origin-when-cross-origin')
    
    def do_GET(self):
        if self.path == '/':
            self.send_response(200)
            self.send_header('Content-type', 'text/html; charset=utf-8')
            self.add_security_headers()
            self.end_headers()
            self.wfile.write(HTML.encode('utf-8'))
        elif self.path == '/api/state':
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.add_security_headers()
            self.end_headers()
            state = get_state()
            self.wfile.write(json.dumps(state).encode('utf-8'))
        else:
            self.send_error(404)
    
    def log_message(self, format, *args):
        pass  # Suppress logging


def run_server():
    with socketserver.TCPServer(("", PORT), Handler) as httpd:
        print(f"Dashboard: http://localhost:{PORT}")
        httpd.serve_forever()


if __name__ == "__main__":
    print("=" * 50)
    print("HackAgent Live Dashboard")
    print("=" * 50)
    run_server()
