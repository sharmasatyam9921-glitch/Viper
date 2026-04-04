#!/usr/bin/env python3
"""Intentionally Vulnerable Test Server for VIPER Testing.

A lightweight HTTP server with KNOWN vulnerabilities for validating
VIPER's attack detection capabilities. No Docker required.

Vulnerabilities included:
  1. Reflected XSS in /search?q=
  2. SQL injection in /users?id=
  3. CORS misconfiguration (reflects any origin)
  4. Missing security headers (no CSP, no X-Frame-Options)
  5. Directory listing at /files/
  6. CSRF token in response
  7. Open redirect at /redirect?url=
  8. Server-Side Template Injection in /template?name=
  9. Debug endpoint at /debug
 10. .env file exposure at /.env
 11. Git exposure at /.git/HEAD
 12. LFI in /view?file=
 13. Header injection in /header?host=
 14. Information disclosure via error messages

Run: python tests/vuln_server.py
Test: python viper.py http://localhost:9999 --full --time 5

Each vulnerability has a unique marker that VIPER's attack patterns should detect.
"""

import json
import os
import re
import sys
import threading
import urllib.parse
from http.server import HTTPServer, BaseHTTPRequestHandler
from datetime import datetime


class VulnHandler(BaseHTTPRequestHandler):
    """Intentionally vulnerable HTTP handler."""

    def log_message(self, format, *args):
        # Suppress default logging
        pass

    def _send(self, status, body, content_type="text/html", extra_headers=None):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        # Intentionally NO security headers (vuln #4)
        if extra_headers:
            for k, v in extra_headers.items():
                self.send_header(k, v)
        self.end_headers()
        if isinstance(body, str):
            body = body.encode("utf-8")
        self.wfile.write(body)

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        qs = urllib.parse.parse_qs(parsed.query)

        # ── Vuln 1: Reflected XSS ──
        if path == "/search":
            q = qs.get("q", [""])[0]
            # Directly reflects user input (no sanitization)
            body = f"""<html><body>
            <h1>Search Results</h1>
            <p>You searched for: {q}</p>
            <form><input name="q" value="{q}"><button>Search</button></form>
            </body></html>"""
            self._send(200, body)

        # ── Vuln 2: SQL Injection (simulated) ──
        elif path == "/users":
            uid = qs.get("id", ["1"])[0]
            if "'" in uid or "OR" in uid.upper() or "--" in uid:
                # Simulate SQL error disclosure
                body = f"""<html><body>
                <h1>Database Error</h1>
                <p>You have an error in your SQL syntax; check the manual that
                corresponds to your MySQL server version for the right syntax
                to use near '{uid}' at line 1</p>
                <p>Query: SELECT * FROM users WHERE id={uid}</p>
                </body></html>"""
                self._send(500, body)
            else:
                body = f"""<html><body><h1>User Profile</h1>
                <p>User ID: {uid}</p><p>Name: Test User</p>
                </body></html>"""
                self._send(200, body)

        # ── Vuln 3: CORS Misconfiguration ──
        elif path == "/api/data":
            origin = self.headers.get("Origin", "")
            headers = {
                "Access-Control-Allow-Origin": origin or "*",
                "Access-Control-Allow-Credentials": "true",
            }
            self._send(200, '{"data": "sensitive"}', "application/json", headers)

        # ── Vuln 5: Directory Listing ──
        elif path == "/files/" or path == "/files":
            body = """<html><body><h1>Index of /files/</h1>
            <pre><a href="../">../</a>
            <a href="backup.sql">backup.sql</a>         2024-01-15 14:30  1.2M
            <a href="config.yml">config.yml</a>         2024-01-15 14:30  856
            <a href="users.csv">users.csv</a>           2024-01-15 14:30  45K
            </pre></body></html>"""
            self._send(200, body)

        # ── Vuln 6: CSRF Token Leak ──
        elif path in ("/login", "/account", "/profile", "/settings"):
            body = f"""<html><body>
            <h1>Login</h1>
            <form method="POST" action="/login">
                <input type="hidden" name="csrf_token" value="abc123secrettoken456">
                <input type="hidden" name="_token" value="csrf_leak_789xyz">
                <input name="username" placeholder="Username">
                <input name="password" type="password" placeholder="Password">
                <button type="submit">Login</button>
            </form>
            </body></html>"""
            self._send(200, body)

        # ── Vuln 7: Open Redirect ──
        elif path == "/redirect":
            url = qs.get("url", [""])[0]
            if url:
                self._send(302, f"Redirecting to {url}", extra_headers={"Location": url})
            else:
                self._send(200, "<html><body>Redirect service</body></html>")

        # ── Vuln 8: SSTI (simulated) ──
        elif path == "/template":
            name = qs.get("name", ["World"])[0]
            # Simulate template rendering that evaluates expressions
            result = name
            if "{{" in name and "}}" in name:
                expr = re.search(r"\{\{(.+?)\}\}", name)
                if expr:
                    try:
                        result = str(eval(expr.group(1)))
                    except Exception:
                        result = name
            body = f"""<html><body>
            <h1>Hello, {result}!</h1>
            <p>Welcome to our template service.</p>
            </body></html>"""
            self._send(200, body)

        # ── Vuln 9: Debug Endpoint ──
        elif path in ("/debug", "/debug/vars", "/_debug", "/server-status"):
            body = json.dumps({
                "debug": True,
                "environment": "production",
                "python_version": sys.version,
                "database": "mysql://root:password@localhost:3306/app",
                "secret_key": "super_secret_key_12345",
                "api_key": "sk-test-12345abcdef",
                "uptime": "45 days",
            }, indent=2)
            self._send(200, body, "application/json")

        # ── Vuln 10: .env Exposure ──
        elif path == "/.env":
            body = """DB_HOST=localhost
DB_USER=root
DB_PASSWORD=supersecret123
API_KEY=sk-prod-abc123def456
SECRET_KEY=django-insecure-key-12345
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
"""
            self._send(200, body, "text/plain")

        # ── Vuln 11: Git Exposure ──
        elif path == "/.git/HEAD":
            self._send(200, "ref: refs/heads/main\n", "text/plain")
        elif path == "/.git/config":
            body = """[core]
    repositoryformatversion = 0
    filemode = true
[remote "origin"]
    url = https://github.com/company/secret-app.git
    fetch = +refs/heads/*:refs/remotes/origin/*
"""
            self._send(200, body, "text/plain")

        # ── Vuln 12: LFI (simulated) ──
        elif path == "/view":
            filename = qs.get("file", [""])[0]
            if "etc/passwd" in filename or "win.ini" in filename:
                body = "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
                self._send(200, body, "text/plain")
            elif filename:
                self._send(200, f"<html><body>Viewing: {filename}</body></html>")
            else:
                self._send(200, "<html><body>File viewer - use ?file=</body></html>")

        # ── Vuln 13: Header Injection ──
        elif path == "/header":
            host = qs.get("host", [""])[0]
            body = f"""<html><head>
            <link rel="canonical" href="http://{host or 'localhost'}/header">
            </head><body>
            <p>Host: {host or self.headers.get('Host', 'localhost')}</p>
            </body></html>"""
            self._send(200, body)

        # ── Vuln 14: Error Information Disclosure ──
        elif path == "/error":
            body = """<html><body>
            <h1>Application Error</h1>
            <p>Traceback (most recent call last):</p>
            <pre>
  File "/app/views.py", line 42, in handle_request
    result = db.execute("SELECT * FROM users WHERE id=" + user_id)
  File "/usr/lib/python3.10/sqlite3/dbapi2.py", line 62, in execute
    return self._conn.execute(sql)
sqlite3.OperationalError: near "OR": syntax error
            </pre>
            <p>Python 3.10.12, Django 4.2.1, SQLite 3.39.4</p>
            </body></html>"""
            self._send(500, body)

        # ── robots.txt ──
        elif path == "/robots.txt":
            body = """User-agent: *
Disallow: /admin/
Disallow: /backup/
Disallow: /debug/
Disallow: /.env
Disallow: /.git/
"""
            self._send(200, body, "text/plain")

        # ── Root ──
        elif path == "/" or path == "":
            body = """<html>
            <head><title>Test Application</title></head>
            <body>
            <h1>Welcome to Test App</h1>
            <nav>
                <a href="/search?q=test">Search</a> |
                <a href="/users?id=1">Users</a> |
                <a href="/login">Login</a> |
                <a href="/files/">Files</a> |
                <a href="/template?name=World">Template</a> |
                <a href="/view?file=readme.txt">View File</a> |
                <a href="/redirect?url=https://example.com">Redirect</a>
            </nav>
            <form action="/search" method="GET">
                <input name="q" placeholder="Search...">
                <button>Go</button>
            </form>
            </body></html>"""
            self._send(200, body)

        else:
            self._send(404, f"<html><body><h1>404 Not Found</h1><p>{path}</p></body></html>")

    def do_POST(self):
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length).decode("utf-8", errors="replace")
        self.do_GET()  # Same handling for POST

    def do_OPTIONS(self):
        """CORS preflight — accepts everything."""
        origin = self.headers.get("Origin", "*")
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", origin)
        self.send_header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "*")
        self.send_header("Access-Control-Allow-Credentials", "true")
        self.end_headers()


def start_server(port=9999, background=False):
    """Start the vulnerable test server."""
    server = HTTPServer(("127.0.0.1", port), VulnHandler)
    print(f"[VulnServer] Started on http://localhost:{port}")
    print(f"[VulnServer] 14 vulnerabilities active")
    print(f"[VulnServer] Test with: python viper.py http://localhost:{port} --full --time 5")
    if background:
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        return server
    else:
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            print("\n[VulnServer] Shutting down")
            server.shutdown()


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 9999
    start_server(port)
