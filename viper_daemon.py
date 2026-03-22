#!/usr/bin/env python3
"""
VIPER Autonomous Daemon
Runs continuously, scanning targets and hunting vulnerabilities.
"""
import asyncio
import json
import time
from datetime import datetime
from pathlib import Path
try:
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client
    MCP_AVAILABLE = True
except ImportError:
    MCP_AVAILABLE = False
    ClientSession = None

HACKAGENT_DIR = Path(__file__).parent
STATE_FILE = HACKAGENT_DIR / "viper_daemon_state.json"
FINDINGS_DIR = HACKAGENT_DIR / "findings"
FINDINGS_DIR.mkdir(exist_ok=True)

# Targets to scan (add more as we go)
TARGETS = [
    {
        "name": "Juice Shop Demo",
        "url": "https://demo.owasp-juice.shop",
        "scope": ["demo.owasp-juice.shop"],
        "endpoints": [
            "/rest/products/search?q=test",
            "/rest/user/login",
            "/api/Users",
            "/api/Products",
            "/api/Feedbacks"
        ]
    }
]

class VIPERDaemon:
    def __init__(self):
        self.state = self.load_state()
        self.findings = []
        self.session = None
    
    def load_state(self) -> dict:
        if STATE_FILE.exists():
            return json.loads(STATE_FILE.read_text())
        return {
            "scans_completed": 0,
            "vulns_found": 0,
            "last_scan": None,
            "targets_scanned": []
        }
    
    def save_state(self):
        STATE_FILE.write_text(json.dumps(self.state, indent=2))
    
    def log(self, msg: str):
        ts = datetime.now().strftime("%H:%M:%S")
        print(f"[{ts}] {msg}")
    
    def get_server_params(self):
        return StdioServerParameters(
            command="python",
            args=["mcp_server.py"],
            cwd=str(HACKAGENT_DIR)
        )
    
    async def call_tool(self, session, tool: str, args: dict) -> dict:
        try:
            result = await session.call_tool(tool, arguments=args)
            return json.loads(result.content[0].text)
        except Exception as e:
            return {"error": str(e)}
    
    async def scan_target(self, session, target: dict):
        self.log(f"Scanning: {target['name']}")
        target_findings = []
        
        # Test each endpoint for SQLi and XSS
        for endpoint in target.get("endpoints", []):
            url = target["url"] + endpoint
            
            # Extract param from URL
            if "?" in url and "=" in url:
                param = url.split("?")[1].split("=")[0]
                
                # SQLi test
                self.log(f"  SQLi test: {endpoint}")
                result = await self.call_tool(session, "test_sqli", {
                    "url": url,
                    "param": param
                })
                
                for test in result.get("tests", []):
                    if test.get("error_based") or test.get("status_code") == 500:
                        finding = {
                            "type": "SQL Injection",
                            "severity": "critical",
                            "url": url,
                            "param": param,
                            "payload": test.get("payload"),
                            "evidence": f"Status {test.get('status_code')}, error_based={test.get('error_based')}",
                            "timestamp": datetime.now().isoformat()
                        }
                        target_findings.append(finding)
                        self.log(f"    [!] SQLi found: {test.get('payload')[:30]}...")
                
                # XSS test
                self.log(f"  XSS test: {endpoint}")
                result = await self.call_tool(session, "test_xss", {
                    "url": url,
                    "param": param
                })
                
                for test in result.get("tests", []):
                    if test.get("reflected") and not test.get("encoded"):
                        finding = {
                            "type": "Cross-Site Scripting (XSS)",
                            "severity": "high",
                            "url": url,
                            "param": param,
                            "payload": test.get("payload"),
                            "evidence": "Payload reflected without encoding",
                            "timestamp": datetime.now().isoformat()
                        }
                        target_findings.append(finding)
                        self.log(f"    [!] XSS found: {test.get('payload')[:30]}...")
        
        return target_findings
    
    async def run_scan_cycle(self):
        self.log("=== Starting scan cycle ===")
        
        all_findings = []
        
        # Connect to MCP server
        async with stdio_client(self.get_server_params()) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                
                for target in TARGETS:
                    findings = await self.scan_target(session, target)
                    all_findings.extend(findings)
                    
                    # Update state
                    self.state["scans_completed"] += 1
                    self.state["vulns_found"] += len(findings)
                    if target["name"] not in self.state["targets_scanned"]:
                        self.state["targets_scanned"].append(target["name"])
        
        self.state["last_scan"] = datetime.now().isoformat()
        self.save_state()
        
        # Save findings
        if all_findings:
            findings_file = FINDINGS_DIR / f"scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            findings_file.write_text(json.dumps(all_findings, indent=2))
            self.log(f"Saved {len(all_findings)} findings to {findings_file.name}")
        
        return all_findings
    
    async def run_forever(self, interval_minutes: int = 30):
        """Run continuous scanning with interval between cycles."""
        self.log(f"VIPER Daemon starting (interval: {interval_minutes}min)")
        
        while True:
            try:
                findings = await self.run_scan_cycle()
                self.log(f"Cycle complete. Found {len(findings)} vulns. Total: {self.state['vulns_found']}")
            except Exception as e:
                self.log(f"Error in scan cycle: {e}")
            
            self.log(f"Sleeping {interval_minutes} minutes...")
            await asyncio.sleep(interval_minutes * 60)
    
    async def run_once(self):
        """Run a single scan cycle."""
        return await self.run_scan_cycle()


async def main():
    import sys
    daemon = VIPERDaemon()
    
    if len(sys.argv) > 1 and sys.argv[1] == "--daemon":
        # Run continuously
        interval = int(sys.argv[2]) if len(sys.argv) > 2 else 30
        await daemon.run_forever(interval_minutes=interval)
    else:
        # Run once
        findings = await daemon.run_once()
        print(f"\n=== Summary ===")
        print(f"Vulnerabilities found: {len(findings)}")
        for f in findings:
            print(f"  [{f['severity'].upper()}] {f['type']} @ {f['url']}")


if __name__ == "__main__":
    asyncio.run(main())
