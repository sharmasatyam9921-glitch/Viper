#!/usr/bin/env python3
"""
VIPER Status Reporter - Updates dashboard state in real-time

Usage:
    from viper_status import ViperStatus
    
    status = ViperStatus()
    status.start_scan("https://target.com")
    status.set_phase("recon", tool="subfinder")
    status.log_event("Found 15 subdomains")
    status.set_progress(25)
    status.end_scan()
"""

import json
from datetime import datetime
from pathlib import Path
from typing import Optional, List

STATE_FILE = Path(__file__).parent / "viper_state.json"

class ViperStatus:
    def __init__(self):
        self.state = self._load()
    
    def _load(self) -> dict:
        if STATE_FILE.exists():
            return json.loads(STATE_FILE.read_text())
        return self._default_state()
    
    def _default_state(self) -> dict:
        return {
            "active": False,
            "target": None,
            "phase": "idle",
            "tool": None,
            "progress": 0,
            "events": [],
            "last_action": None,
            "current_task": None,
            "start_time": None
        }
    
    def _save(self):
        STATE_FILE.write_text(json.dumps(self.state, indent=2, default=str))
    
    def start_scan(self, target: str, task: str = "Full Scan"):
        """Start a new scan"""
        self.state = self._default_state()
        self.state["active"] = True
        self.state["target"] = target
        self.state["current_task"] = task
        self.state["start_time"] = datetime.now().isoformat()
        self.state["phase"] = "starting"
        self.log_event(f"Starting {task} on {target}")
        self._save()
    
    def set_phase(self, phase: str, tool: Optional[str] = None, detail: str = None):
        """Update current phase"""
        self.state["phase"] = phase
        self.state["tool"] = tool
        self.state["last_action"] = datetime.now().isoformat()
        if detail:
            self.log_event(f"{phase}: {detail}")
        elif tool:
            self.log_event(f"{phase} using {tool}")
        self._save()
    
    def set_progress(self, percent: int):
        """Update progress percentage"""
        self.state["progress"] = min(100, max(0, percent))
        self._save()
    
    def log_event(self, message: str, event_type: str = "info"):
        """Add event to activity feed"""
        event = {
            "time": datetime.now().isoformat(),
            "type": event_type,
            "message": message
        }
        self.state["events"].insert(0, event)
        self.state["events"] = self.state["events"][:50]  # Keep last 50
        self._save()
    
    def log_finding(self, title: str, severity: str = "info"):
        """Log a vulnerability finding"""
        self.log_event(f"[{severity.upper()}] {title}", "vuln")
    
    def end_scan(self, findings_count: int = 0):
        """End the current scan"""
        duration = ""
        if self.state["start_time"]:
            start = datetime.fromisoformat(self.state["start_time"])
            duration = f" ({(datetime.now() - start).seconds}s)"
        
        self.log_event(f"Scan complete{duration} - {findings_count} findings")
        self.state["active"] = False
        self.state["phase"] = "complete"
        self.state["progress"] = 100
        self._save()
    
    def idle(self):
        """Set to idle state"""
        self.state["active"] = False
        self.state["phase"] = "idle"
        self.state["tool"] = None
        self.state["target"] = None
        self.state["progress"] = 0
        self._save()


# Singleton for easy import
_status = None

def get_status() -> ViperStatus:
    global _status
    if _status is None:
        _status = ViperStatus()
    return _status


# Quick helpers
def start(target: str, task: str = "Scan"):
    get_status().start_scan(target, task)

def phase(name: str, tool: str = None, detail: str = None):
    get_status().set_phase(name, tool, detail)

def progress(percent: int):
    get_status().set_progress(percent)

def log(message: str, event_type: str = "info"):
    get_status().log_event(message, event_type)

def finding(title: str, severity: str = "info"):
    get_status().log_finding(title, severity)

def done(findings: int = 0):
    get_status().end_scan(findings)

def idle():
    get_status().idle()


if __name__ == "__main__":
    # Demo
    import time
    
    start("https://example.com", "Recon Scan")
    time.sleep(0.5)
    
    phase("recon", "subfinder", "Enumerating subdomains")
    progress(10)
    time.sleep(0.5)
    
    log("Found 12 subdomains")
    progress(25)
    
    phase("probing", "httpx", "Checking live hosts")
    progress(40)
    time.sleep(0.5)
    
    finding("Open redirect on login.example.com", "medium")
    progress(60)
    
    phase("scanning", "nuclei", "Running vulnerability checks")
    progress(80)
    time.sleep(0.5)
    
    finding("SQL Injection in /api/users", "high")
    
    done(2)
    print("Demo complete - check viper_state.json")
