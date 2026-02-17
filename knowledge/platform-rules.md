# Bug Bounty Platform Rules - HackAgent Knowledge Base

## Golden Rules (ALL Platforms)

### MUST Follow:
1. **Read the entire program policy** before testing
2. **Stay in scope** - only test listed assets
3. **No DoS/DDoS** - never impact availability
4. **No data exfiltration** - never access real user data
5. **Report privately** - never disclose publicly
6. **One vuln per report** - don't combine unrelated issues
7. **Wait for response** - don't retest until asked
8. **Be professional** - clear, respectful communication

### Common Exclusions (Usually Out of Scope):
- Social engineering / phishing
- Physical attacks
- DoS/DDoS
- Spam
- Self-XSS
- Login/logout CSRF
- Missing best practices (no direct security impact)
- Rate limiting issues (unless exploitable)
- Clickjacking on static pages
- Missing security headers (low impact)
- Vulnerabilities requiring unlikely user interaction

---

## HackerOne

### Platform Overview
- Largest bug bounty platform
- Mix of public and private programs
- Reputation system (signal)
- API available for automation

### Reputation System
- **Signal:** Quality of reports (higher = better)
- **Impact:** How critical your findings are
- **Reputation:** Overall standing

### Report Requirements
- Clear, concise title
- Detailed description
- Step-by-step reproduction
- Proof of Concept (PoC)
- Impact assessment
- Browser/environment info

### Status Flow
```
New → Triaged → Bounty/Informative/Duplicate/N/A → Resolved
```

### Best Practices
- Complete your profile
- Start with public programs
- Focus on quality over quantity
- Respond quickly to requests
- Build reputation before private invites

---

## Bugcrowd

### Platform Overview
- Second largest platform
- Skills-based ranking
- Managed programs (Bugcrowd triages)
- Good for beginners

### Ranking System
- Points based on findings
- Skills tags (web, mobile, API, etc.)
- Leaderboards

### P1-P5 Severity Levels
- **P1 (Critical):** RCE, Auth bypass, SQLi with data access
- **P2 (Severe):** Stored XSS, significant IDOR
- **P3 (Moderate):** Reflected XSS, limited IDOR
- **P4 (Low):** Self-XSS, low-impact info disclosure
- **P5 (Informative):** Best practice issues

### Report Template
```
Title: [Vuln Type] - [Location]
Severity: P1/P2/P3/P4/P5
URL: [Affected URL]
Description: [What you found]
Steps: [How to reproduce]
Impact: [What could happen]
Remediation: [How to fix]
```

---

## Intigriti

### Platform Overview
- European platform
- Growing program list
- Good payouts

### Levels
- **Starter** → **Explorer** → **Expert** → **Master**

### Unique Features
- Leaderboard resets periodically
- Bug bounty challenges
- Live events

---

## Direct Programs (No Platform)

### Google VRP
- URL: https://bughunters.google.com
- Scope: Google products, Android, Chrome
- Rewards: $100 - $250,000+
- Very competitive

### Microsoft MSRC
- URL: https://msrc.microsoft.com
- Scope: Windows, Azure, Office, etc.
- Rewards: $500 - $100,000+
- Quarterly bonuses

### GitHub Security Lab
- URL: https://securitylab.github.com
- Scope: GitHub products
- Rewards: $617 - $30,000+

---

## Safe Harbor Language

Most programs include safe harbor, meaning:
- No legal action if you follow rules
- Good faith testing is protected
- Report responsibly = immunity

**Example Safe Harbor:**
> "We will not pursue civil action or initiate a complaint to law enforcement for accidental, good faith violations of this policy."

**If missing:** Be extra careful, document everything.

---

## Program Selection Criteria

### Good First Programs:
- [ ] Public (not invite-only)
- [ ] Clear scope definition
- [ ] Responsive (check response time stats)
- [ ] Safe harbor included
- [ ] Accepts wide range of vulns
- [ ] No "duplicates paid" complaints

### Red Flags:
- No safe harbor
- Very low payouts
- High duplicate rate
- Long response times
- Vague scope
- "We may pay bounty" (not guaranteed)

---

## Automated Testing Rules

### When Allowed:
- Check program policy for "automated tools" section
- Respect rate limits (usually <10 req/sec)
- Don't hammer servers
- Avoid fuzzing unless explicitly allowed

### When NOT Allowed:
- "No automated testing" in policy
- "Manual testing only"
- Rate limit specified

### Safe Automated Activities:
- Subdomain enumeration (passive)
- Port scanning (light, slow)
- Nuclei (with low rate)
- Directory brute force (slow)

### Never Automate:
- Heavy fuzzing
- Password brute force
- DoS-like scans
- Exploits

---

## Report Writing Tips

### Good Report:
1. **Title:** Specific, includes vuln type and location
2. **Summary:** One paragraph explaining the issue
3. **Severity:** CVSS score or platform rating
4. **Steps:** Numbered, reproducible
5. **PoC:** Working code/screenshot/video
6. **Impact:** Business impact, not just technical
7. **Fix:** Suggest remediation

### Bad Report:
- "I found SQLi on your site"
- Screenshot with no context
- One-line description
- Requesting money immediately
- Aggressive/demanding tone

### Response Etiquette:
- Be patient (7-14 days normal)
- Answer questions completely
- Provide additional info if asked
- Don't argue about severity publicly
- Accept N/A gracefully, learn from it

---

## Tracking P&L

```markdown
## Bug Bounty P&L Tracker

### 2026 Summary
| Month | Reports | Accepted | Bounties | Total |
|-------|---------|----------|----------|-------|
| Feb   | 0       | 0        | 0        | $0    |

### Reports Log
| Date | Program | Vuln | Status | Bounty |
|------|---------|------|--------|--------|
| ...  | ...     | ...  | ...    | ...    |
```

Track every report to learn what works!
