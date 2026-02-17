#!/usr/bin/env python3
"""
HackAgent - Hunt a target with LIVE dashboard updates
"""

import requests
import json
import re
import time
from datetime import datetime
from pathlib import Path

TARGET = "http://localhost:1999"  # Attacking framework Gateway!
STATE_FILE = Path(__file__).parent / "dashboard" / "state.json"

# State that syncs to dashboard
state = {
    "phase": "idle",
    "target": TARGET,
    "program": "SELF-HACK - framework Gateway",
    "stats": {"requests": 0, "endpoints": 0, "vulns": 0, "start_time": None},
    "events": [],
    "findings": [],
    "learning": None
}

def save_state():
    """Save state to file for dashboard to read"""
    STATE_FILE.write_text(json.dumps(state, indent=2))

def log(msg, event_type="info"):
    """Log event to console and dashboard"""
    # Remove emojis for console output
    clean_msg = msg.encode('ascii', 'ignore').decode('ascii')
    print(f"[{event_type.upper()}] {clean_msg}")
    state["events"].append({
        "time": datetime.now().isoformat(),
        "msg": msg,
        "type": event_type
    })
    # Keep last 100 events
    state["events"] = state["events"][-100:]
    save_state()
    time.sleep(0.1)  # Small delay so dashboard can show each step

def finding(vuln_type, severity, location, payload="", explanation=""):
    """Record a vulnerability finding"""
    f = {
        "type": vuln_type,
        "severity": severity,
        "location": location,
        "payload": payload,
        "explanation": explanation,
        "time": datetime.now().isoformat()
    }
    state["findings"].append(f)
    state["stats"]["vulns"] = len(state["findings"])
    log(f"🚨 VULNERABILITY: {vuln_type} ({severity})", "vuln")
    save_state()

def learn(title, explanation, code=""):
    """Set learning note for dashboard"""
    state["learning"] = {"title": title, "explanation": explanation, "code": code}
    save_state()

def req(method, url, **kwargs):
    """Make request and track stats"""
    state["stats"]["requests"] += 1
    save_state()
    try:
        if method == "GET":
            return requests.get(url, timeout=10, **kwargs)
        elif method == "POST":
            return requests.post(url, timeout=10, **kwargs)
    except Exception as e:
        log(f"Request failed: {e}", "error")
        return None

def phase(name):
    """Set current phase"""
    state["phase"] = name
    log(f"=== PHASE: {name.upper()} ===", "recon")
    save_state()


def main():
    print("=" * 60)
    print("HACKAGENT - Live Bug Hunting")
    print(f"Target: {TARGET}")
    print(f"Dashboard: http://localhost:8889")
    print("=" * 60)
    
    # Initialize state
    state["stats"]["start_time"] = datetime.now().isoformat()
    state["target"] = TARGET
    state["events"] = []
    state["findings"] = []
    save_state()
    
    time.sleep(1)  # Let dashboard catch up
    
    # ==================== RECON ====================
    phase("recon")
    
    log("🔍 Starting reconnaissance...")
    time.sleep(0.5)
    
    r = req("GET", TARGET)
    if not r:
        log("❌ Target unreachable!", "error")
        return
    
    log(f"✓ Target responded: HTTP {r.status_code}", "found")
    log(f"✓ Server: {r.headers.get('Server', 'Hidden')}", "found")
    
    learn(
        "Step 1: Reconnaissance",
        "First I probe the target to see what technologies it uses. "
        "I check the HTTP headers and HTML source for clues. "
        "This helps me know what attacks might work.",
        "GET / HTTP/1.1\\nHost: target.com\\n\\n# Look for:\\n- Server header\\n- X-Powered-By\\n- Framework signatures"
    )
    
    # Tech fingerprinting
    body = r.text
    time.sleep(0.3)
    
    if "dash" in body.lower():
        log("🎯 Framework: Plotly Dash (Python)", "found")
    
    if "react" in body.lower():
        log("🎯 Frontend: React.js", "found")
    
    # Extract versions
    dash_ver = re.search(r'dash_version":"([^"]+)', body)
    if dash_ver:
        log(f"🎯 Dash Version: {dash_ver.group(1)}", "found")
        
    python_ver = re.search(r'python_version":"([^"]+)', body)
    if python_ver:
        ver = python_ver.group(1)[:25]
        log(f"🎯 Python: {ver}...", "found")
    
    time.sleep(0.5)
    
    # Check security headers
    log("🔒 Checking security headers...", "scan")
    
    security_headers = {
        "X-Frame-Options": "Clickjacking protection",
        "X-Content-Type-Options": "MIME sniffing",
        "Content-Security-Policy": "XSS protection",
        "Strict-Transport-Security": "HTTPS enforcement"
    }
    
    missing = []
    for header, desc in security_headers.items():
        time.sleep(0.2)
        if header not in r.headers:
            missing.append(header)
            log(f"⚠️ Missing: {header}", "scan")
    
    if missing:
        finding(
            "Missing Security Headers",
            "low",
            TARGET,
            f"Missing: {', '.join(missing)}",
            "Headers protect against clickjacking, XSS, etc."
        )
        
        learn(
            "Security Headers",
            f"This app is missing {len(missing)} security headers. "
            "These headers tell browsers how to protect users. "
            "Without them, attacks like clickjacking are possible.",
            "# Add to server config:\\nX-Frame-Options: DENY\\nContent-Security-Policy: default-src 'self'"
        )
    
    # ==================== ENUMERATE ====================
    phase("enum")
    
    log("📂 Enumerating endpoints...", "info")
    time.sleep(0.3)
    
    endpoints = [
        "/_dash-layout",
        "/_dash-dependencies", 
        "/_dash-update-component",
        "/api/",
        "/admin/",
        "/debug/",
        "/.env",
        "/config/"
    ]
    
    found_eps = []
    for ep in endpoints:
        r = req("GET", TARGET + ep)
        time.sleep(0.15)
        if r and r.status_code == 200:
            found_eps.append(ep)
            state["stats"]["endpoints"] += 1
            log(f"✓ Found: {ep} ({len(r.content)} bytes)", "found")
            save_state()
    
    learn(
        "Step 2: Enumeration",
        f"I found {len(found_eps)} accessible endpoints by trying common paths. "
        "Dash apps expose internal APIs like /_dash-layout that reveal the app structure. "
        "This information helps find attack vectors.",
        "# Common Dash endpoints:\\n/_dash-layout\\n/_dash-dependencies\\n/_dash-update-component"
    )
    
    # Check Dash internals
    log("🔬 Analyzing Dash internals...", "scan")
    time.sleep(0.3)
    
    r = req("GET", TARGET + "/_dash-layout")
    if r and r.status_code == 200:
        try:
            layout = r.json()
            layout_str = json.dumps(layout)
            
            # Extract component IDs
            ids = re.findall(r'"id":\s*"([^"]+)"', layout_str)
            log(f"🎯 Found {len(ids)} component IDs", "found")
            
            if "Store" in layout_str:
                log("🎯 Found client-side data stores", "found")
                
        except:
            pass
    
    r = req("GET", TARGET + "/_dash-dependencies")
    if r and r.status_code == 200:
        try:
            deps = r.json()
            log(f"🎯 Found {len(deps)} callbacks exposed", "found")
            
            finding(
                "Internal API Exposure",
                "low",
                TARGET + "/_dash-dependencies",
                f"Exposes {len(deps)} callback definitions",
                "Reveals app structure to attackers"
            )
        except:
            pass
    
    # ==================== SCAN ====================
    phase("scan")
    
    log("🔥 Scanning for vulnerabilities...", "info")
    time.sleep(0.5)
    
    learn(
        "Step 3: Vulnerability Scanning",
        "Now I test for actual security bugs. I'll check for debug mode, "
        "injection vulnerabilities, and misconfigurations. "
        "Each test is designed to find specific weaknesses.",
        "# Test categories:\\n- Debug/Dev mode\\n- Injection (SQLi, XSS)\\n- Access control\\n- Info disclosure"
    )
    
    # Test debug mode
    log("Testing for debug mode...", "scan")
    time.sleep(0.3)
    
    r = req("GET", TARGET + "/_dash-debug-menu")
    if r and r.status_code == 200:
        finding(
            "Debug Mode Enabled",
            "medium",
            TARGET + "/_dash-debug-menu",
            "Debug menu is accessible",
            "Debug mode can leak sensitive info and allow code execution"
        )
        
        learn(
            "Debug Mode Vulnerability",
            "The app has debug mode enabled! This is dangerous because: "
            "1) It shows detailed error messages with code 2) May allow hot reloading "
            "3) Could expose internal state. Always disable in production!",
            "# In Dash:\\napp.run_server(debug=False)"
        )
    
    # Test for XSS in callbacks
    log("Testing callback injection...", "scan")
    time.sleep(0.3)
    
    xss_payload = {"output": "test.children", "inputs": [{"id": "test", "property": "value", "value": "<script>alert(1)</script>"}]}
    r = req("POST", TARGET + "/_dash-update-component", json=xss_payload)
    if r:
        log(f"Callback test: HTTP {r.status_code}", "scan")
    
    # ==================== REPORT ====================
    phase("report")
    
    log("📝 Generating report...", "info")
    time.sleep(0.5)
    
    learn(
        "Scan Complete!",
        f"Found {state['stats']['vulns']} vulnerabilities in {state['stats']['requests']} requests. "
        f"Discovered {state['stats']['endpoints']} endpoints. "
        "The main issues are missing security headers and exposed debug features. "
        "These should be fixed before production deployment.",
        "# Remediation:\\n1. Add security headers\\n2. Disable debug mode\\n3. Restrict /_dash-* endpoints"
    )
    
    print("\n" + "=" * 60)
    print("SCAN COMPLETE")
    print("=" * 60)
    print(f"Target: {TARGET}")
    print(f"Requests: {state['stats']['requests']}")
    print(f"Endpoints: {state['stats']['endpoints']}")
    print(f"Vulnerabilities: {state['stats']['vulns']}")
    
    if state["findings"]:
        print("\nFINDINGS:")
        for i, f in enumerate(state["findings"], 1):
            print(f"  {i}. [{f['severity'].upper()}] {f['type']}")
    
    # Save report
    report_dir = Path(__file__).parent / "reports"
    report_dir.mkdir(exist_ok=True)
    report_path = report_dir / f"scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    report_path.write_text(json.dumps({
        "target": TARGET,
        "scan_time": state["stats"]["start_time"],
        "findings": state["findings"],
        "stats": state["stats"],
        "events": state["events"]
    }, indent=2))
    print(f"\nReport: {report_path}")


if __name__ == "__main__":
    main()

