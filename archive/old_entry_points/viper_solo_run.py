#!/usr/bin/env python3
"""
VIPER Solo Run - No human assistance
Let the agent solve Natas levels completely autonomously
"""
import sys
sys.stdout.reconfigure(encoding='utf-8')
sys.path.insert(0, 'core')

from autonomous_agent import VIPERAgent
import json
from pathlib import Path
from datetime import datetime

# All Natas passwords (VIPER will try to find the next one each time)
passwords = {
    0: "natas0",
    1: "0nzCigAq7t2iALyvU9xcHlYN4MlkIwlq",
    2: "TguMNxKo1DSa1tujBLuZJnDUlCcUAPlI",
    3: "3gqisGdR0pjm6tpkDKdIWO2hSvchLeYH",
    4: "QryZXc2e0zahULdHrtHxzyYkj59kUxLQ",
    5: "0n35PkggAPm2zbEpOU802c0x0Msn1ToK",
    6: "0RoJwHdSKWFTYR5WuiAewauSuNaBXned",
    7: "bmg8SvU1LizuWjx3y7xkNERkHxGre0GS",
    8: "xcoXLmzMkoIP9D7hlgPlh9XD7OgLAe5Q",
    9: "ZE1ck82lmdGIoErlhQgWND6j2Wzz6b6t",
    10: "t7I5VHvpa14sJTUGV0cbEsbYfFP2dmOu",
}

def run_solo():
    """Run VIPER autonomously through Natas"""
    
    results = {
        "start_time": datetime.now().isoformat(),
        "levels_attempted": 0,
        "levels_solved": 0,
        "findings": [],
        "passwords_found": {}
    }
    
    print("="*60)
    print("VIPER SOLO RUN - NO HUMAN ASSISTANCE")
    print("="*60)
    print()
    
    for level in range(len(passwords)):
        if level not in passwords:
            break
            
        url = f"http://natas{level}.natas.labs.overthewire.org"
        user = f"natas{level}"
        passwd = passwords[level]
        
        print(f"\n{'='*60}")
        print(f"LEVEL {level}: {url}")
        print(f"{'='*60}")
        
        results["levels_attempted"] += 1
        
        try:
            agent = VIPERAgent()
            findings = agent.attack(url, credentials=(user, passwd), max_attempts=50)
            
            if findings:
                results["findings"].extend([{
                    "level": level,
                    "vulnerability": f.vulnerability,
                    "payload": f.payload,
                    "severity": f.severity
                } for f in findings])
                
                # Check if we extracted next password
                for f in findings:
                    if f.extracted_data and len(f.extracted_data) == 32:
                        print(f"\n[EXTRACTED] Password found: {f.extracted_data}")
                        results["passwords_found"][level+1] = f.extracted_data
                        results["levels_solved"] += 1
                
                print(f"\n[RESULT] {len(findings)} vulnerabilities found")
            else:
                print(f"\n[RESULT] No vulnerabilities found")
                
        except Exception as e:
            print(f"\n[ERROR] {e}")
    
    results["end_time"] = datetime.now().isoformat()
    
    # Save results
    report_path = Path("reports/viper_solo_run.json")
    report_path.parent.mkdir(exist_ok=True)
    report_path.write_text(json.dumps(results, indent=2))
    
    print("\n" + "="*60)
    print("FINAL RESULTS")
    print("="*60)
    print(f"Levels attempted: {results['levels_attempted']}")
    print(f"Levels solved (password extracted): {results['levels_solved']}")
    print(f"Total findings: {len(results['findings'])}")
    print(f"Report saved: {report_path}")
    
    return results

if __name__ == "__main__":
    run_solo()
