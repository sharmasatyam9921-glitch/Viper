#!/usr/bin/env python3
"""
VIPER Agentic Run - Completely autonomous CTF solving
No human assistance. VIPER decides everything.
"""
import sys
sys.stdout.reconfigure(encoding='utf-8')
sys.path.insert(0, 'core')

from agentic_viper import AgenticVIPER
import json
from pathlib import Path
from datetime import datetime

def run_agentic():
    """Let VIPER loose on Natas - fully autonomous"""
    
    print("="*60)
    print("VIPER AGENTIC AI - AUTONOMOUS CTF SOLVER")
    print("="*60)
    print("No human help. VIPER thinks and acts alone.")
    print()
    
    # Start with level 0 credentials
    passwords = {0: "natas0"}
    current_level = 0
    max_level = 34
    
    results = {
        "start": datetime.now().isoformat(),
        "levels": {},
        "total_solved": 0
    }
    
    while current_level <= max_level:
        if current_level not in passwords:
            print(f"\n[STUCK] No password for level {current_level}")
            break
        
        url = f"http://natas{current_level}.natas.labs.overthewire.org"
        user = f"natas{current_level}"
        passwd = passwords[current_level]
        
        print(f"\n{'='*60}")
        print(f"LEVEL {current_level}")
        print(f"{'='*60}")
        
        viper = AgenticVIPER()
        result = viper.hack(url, goal="find_password", auth=(user, passwd), max_attempts=30)
        
        results["levels"][current_level] = {
            "success": result["success"],
            "password": result.get("password"),
            "findings": len(result.get("findings", [])),
            "techniques": result.get("techniques_tried", [])
        }
        
        if result["success"] and result.get("password"):
            print(f"\n[SOLVED] Level {current_level} -> {result['password']}")
            passwords[current_level + 1] = result["password"]
            results["total_solved"] += 1
            current_level += 1
        else:
            print(f"\n[FAILED] Level {current_level} - VIPER couldn't crack it")
            # Try a few more times with different approaches
            break
    
    results["end"] = datetime.now().isoformat()
    results["final_level"] = current_level
    results["passwords"] = passwords
    
    # Save results
    report_path = Path("reports/viper_agentic_results.json")
    report_path.parent.mkdir(exist_ok=True)
    report_path.write_text(json.dumps(results, indent=2))
    
    print("\n" + "="*60)
    print("FINAL RESULTS")
    print("="*60)
    print(f"Levels solved: {results['total_solved']}")
    print(f"Highest level: {current_level}")
    print(f"Report: {report_path}")
    
    return results

if __name__ == "__main__":
    run_agentic()
