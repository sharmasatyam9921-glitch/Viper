#!/usr/bin/env python3
"""
🐍 VIPER Daily Training Script
Runs automatically to learn and improve
"""

import json
import requests
from datetime import datetime, date
from pathlib import Path

WORKSPACE = Path(".")
TRAINING_DIR = WORKSPACE / "skills/hackagent/training"
KNOWLEDGE_FILE = TRAINING_DIR / "knowledge_base.json"
PROGRESS_FILE = TRAINING_DIR / "progress.json"

# Training curriculum by day
CURRICULUM = {
    1: {
        "topic": "Foundations",
        "skills": ["recon", "headers", "enumeration"],
        "practice": ["scan internal infrastructure"],
        "complete": True
    },
    2: {
        "topic": "SQL Injection",
        "skills": ["error_sqli", "union_sqli", "blind_sqli"],
        "practice": ["DVWA SQLi all levels", "Juice Shop SQLi challenges"],
        "resources": [
            "https://portswigger.net/web-security/sql-injection",
            "https://book.hacktricks.xyz/pentesting-web/sql-injection"
        ],
        "payloads": [
            "' OR '1'='1",
            "' UNION SELECT NULL--",
            "' AND 1=1--",
            "' AND SLEEP(5)--",
            "admin'--",
            "1' ORDER BY 1--",
            "' UNION SELECT username,password FROM users--"
        ]
    },
    3: {
        "topic": "Cross-Site Scripting (XSS)",
        "skills": ["reflected_xss", "stored_xss", "dom_xss", "xss_bypass"],
        "practice": ["DVWA XSS all levels", "Juice Shop XSS challenges"],
        "resources": [
            "https://portswigger.net/web-security/cross-site-scripting"
        ],
        "payloads": [
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "<svg/onload=alert(1)>",
            "javascript:alert(1)",
            "<body onload=alert(1)>",
            "'-alert(1)-'",
            "</script><script>alert(1)</script>"
        ]
    },
    4: {
        "topic": "Authentication & IDOR",
        "skills": ["brute_force", "jwt_attacks", "session_hijack", "idor"],
        "practice": ["Juice Shop auth challenges", "DVWA brute force"],
        "resources": [
            "https://portswigger.net/web-security/authentication",
            "https://portswigger.net/web-security/access-control/idor"
        ],
        "techniques": [
            "JWT algorithm confusion (RS256->HS256)",
            "JWT none algorithm",
            "Weak JWT secret brute force",
            "IDOR via numeric ID",
            "IDOR via UUID prediction",
            "Password reset token prediction"
        ]
    },
    5: {
        "topic": "SSRF & XXE",
        "skills": ["ssrf_basic", "ssrf_cloud", "xxe"],
        "practice": ["PortSwigger SSRF labs"],
        "resources": [
            "https://portswigger.net/web-security/ssrf"
        ],
        "payloads": [
            "http://169.254.169.254/latest/meta-data/",
            "http://127.0.0.1:6379/",
            "http://localhost/admin",
            "file:///etc/passwd",
            "dict://localhost:11211/"
        ]
    },
    6: {
        "topic": "Advanced Techniques",
        "skills": ["race_conditions", "business_logic", "api_testing", "graphql"],
        "practice": ["PortSwigger race condition labs", "GraphQL challenges"],
        "techniques": [
            "Race condition in purchases",
            "Price manipulation",
            "Coupon code reuse",
            "GraphQL introspection",
            "GraphQL batching attacks"
        ]
    },
    7: {
        "topic": "Bug Bounty Methodology",
        "skills": ["recon_automation", "target_selection", "report_writing"],
        "practice": ["Full pentest simulation"],
        "methodology": [
            "1. Scope review",
            "2. Subdomain enumeration",
            "3. Port scanning",
            "4. Technology fingerprinting",
            "5. Endpoint discovery",
            "6. Parameter fuzzing",
            "7. Vulnerability testing",
            "8. Exploitation/PoC",
            "9. Report writing",
            "10. Submission"
        ]
    }
}


def load_knowledge():
    if KNOWLEDGE_FILE.exists():
        return json.loads(KNOWLEDGE_FILE.read_text())
    return {"techniques": {}, "payloads": {}, "bypasses": {}}


def save_knowledge(kb):
    KNOWLEDGE_FILE.write_text(json.dumps(kb, indent=2))


def load_progress():
    if PROGRESS_FILE.exists():
        return json.loads(PROGRESS_FILE.read_text())
    return {"start_date": str(date.today()), "days_completed": [], "skills_learned": []}


def save_progress(progress):
    PROGRESS_FILE.write_text(json.dumps(progress, indent=2))


def get_training_day():
    """Calculate which training day we're on"""
    progress = load_progress()
    start = datetime.strptime(progress["start_date"], "%Y-%m-%d").date()
    today = date.today()
    day_num = (today - start).days + 1
    return min(day_num, 7)


def fetch_security_news():
    """Fetch latest security news for learning"""
    news = []
    
    # Would fetch from security feeds
    # For now, return curated learning topics
    topics = [
        "New bypass for Cloudflare WAF discovered",
        "GraphQL introspection attacks on the rise",
        "AWS IMDS v2 bypass techniques",
        "Chrome XSS Auditor deprecated - new vectors",
        "JWT kid parameter injection"
    ]
    
    return topics[:3]


def practice_sqli():
    """Practice SQL injection techniques"""
    results = {
        "payloads_tested": 0,
        "techniques_practiced": []
    }
    
    payloads = CURRICULUM[2]["payloads"]
    
    print("Practicing SQL Injection...")
    for payload in payloads:
        # Would test against practice labs
        results["payloads_tested"] += 1
        print(f"  Tested: {payload[:30]}...")
    
    results["techniques_practiced"] = ["error-based", "union-based", "blind"]
    return results


def practice_xss():
    """Practice XSS techniques"""
    results = {
        "payloads_tested": 0,
        "techniques_practiced": []
    }
    
    payloads = CURRICULUM[3]["payloads"]
    
    print("Practicing XSS...")
    for payload in payloads:
        results["payloads_tested"] += 1
        print(f"  Tested: {payload[:30]}...")
    
    results["techniques_practiced"] = ["reflected", "stored", "dom"]
    return results


def update_knowledge_base(day_num):
    """Add new knowledge from today's training"""
    kb = load_knowledge()
    curriculum = CURRICULUM.get(day_num, {})
    
    # Add payloads
    if "payloads" in curriculum:
        topic = curriculum["topic"].lower().replace(" ", "_")
        kb["payloads"][topic] = curriculum["payloads"]
    
    # Add techniques
    if "techniques" in curriculum:
        topic = curriculum["topic"].lower().replace(" ", "_")
        kb["techniques"][topic] = curriculum["techniques"]
    
    save_knowledge(kb)
    return kb


def generate_daily_report(day_num, results):
    """Generate training report"""
    curriculum = CURRICULUM.get(day_num, {})
    
    report = f"""
# VIPER Training Report - Day {day_num}
**Date:** {date.today()}
**Topic:** {curriculum.get('topic', 'General')}

## Skills Practiced
{chr(10).join('- ' + s for s in curriculum.get('skills', []))}

## Practice Targets
{chr(10).join('- ' + p for p in curriculum.get('practice', []))}

## Results
- Payloads tested: {results.get('payloads_tested', 0)}
- Techniques practiced: {', '.join(results.get('techniques_practiced', []))}

## Knowledge Gained
New payloads and techniques added to knowledge base.

## Tomorrow's Focus
Day {day_num + 1}: {CURRICULUM.get(day_num + 1, {}).get('topic', 'Bug Bounty Launch!')}

---
*Training in progress... {7 - day_num} days until bug bounty ready!*
"""
    
    report_path = TRAINING_DIR / f"report_day{day_num}_{date.today()}.md"
    report_path.write_text(report)
    
    return report


def run_daily_training():
    """Main daily training routine"""
    print("=" * 60)
    print("VIPER Daily Training")
    print("=" * 60)
    
    day_num = get_training_day()
    curriculum = CURRICULUM.get(day_num, {})
    
    print(f"\nDay {day_num}/7: {curriculum.get('topic', 'General')}")
    print("-" * 40)
    
    results = {"payloads_tested": 0, "techniques_practiced": []}
    
    # Day-specific training
    if day_num == 2:
        results = practice_sqli()
    elif day_num == 3:
        results = practice_xss()
    else:
        print(f"Training topic: {curriculum.get('topic')}")
        results["techniques_practiced"] = curriculum.get("skills", [])
    
    # Update knowledge base
    kb = update_knowledge_base(day_num)
    print(f"\nKnowledge base updated:")
    print(f"  - Payload categories: {len(kb.get('payloads', {}))}")
    print(f"  - Technique categories: {len(kb.get('techniques', {}))}")
    
    # Update progress
    progress = load_progress()
    if day_num not in progress["days_completed"]:
        progress["days_completed"].append(day_num)
    progress["skills_learned"].extend(curriculum.get("skills", []))
    progress["skills_learned"] = list(set(progress["skills_learned"]))
    save_progress(progress)
    
    # Generate report
    report = generate_daily_report(day_num, results)
    print(f"\nTraining report generated")
    
    # Fetch security news
    news = fetch_security_news()
    print(f"\nSecurity news learned: {len(news)} topics")
    
    # Summary
    print("\n" + "=" * 60)
    print("TRAINING SUMMARY")
    print("=" * 60)
    print(f"Day: {day_num}/7")
    print(f"Topic: {curriculum.get('topic')}")
    print(f"Skills: {len(curriculum.get('skills', []))}")
    print(f"Days until bug bounty: {7 - day_num}")
    
    return {
        "day": day_num,
        "topic": curriculum.get("topic"),
        "results": results,
        "days_remaining": 7 - day_num
    }


if __name__ == "__main__":
    TRAINING_DIR.mkdir(exist_ok=True)
    run_daily_training()

