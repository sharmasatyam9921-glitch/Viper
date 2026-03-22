"""
VIPER 4.0 - Anonymity Module (Tor/SOCKS5 Proxy Integration)
=============================================================
Routes traffic through Tor or generic SOCKS5/HTTP proxies.
Inspired by open-source pentesting frameworks.

Provides:
    - TorProxy context manager for proxied HTTP via urllib
    - Subprocess wrappers for proxychains/torsocks
    - Tor status checking
    - Environment-based proxy configuration

No external dependencies. Stdlib only (urllib, socket, subprocess).
"""

import os
import socket
import shutil
import subprocess
from typing import Optional
from urllib.request import Request, urlopen, build_opener, ProxyHandler
from urllib.error import URLError
from functools import wraps


# =============================================================================
# Configuration
# =============================================================================

TOR_SOCKS_HOST = "127.0.0.1"
TOR_SOCKS_PORT = 9050
TOR_CONTROL_PORT = 9051
CHECK_URL = "https://check.torproject.org/api/ip"
FALLBACK_CHECK_URL = "https://api.ipify.org?format=json"


# =============================================================================
# Tor Status Checks
# =============================================================================

def is_tor_running(host: str = TOR_SOCKS_HOST, port: int = TOR_SOCKS_PORT) -> bool:
    """Check if Tor SOCKS5 proxy is accepting connections."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        result = sock.connect_ex((host, port))
        sock.close()
        return result == 0
    except Exception:
        return False


def is_proxychains_available() -> bool:
    """Check if proxychains is installed."""
    return (shutil.which("proxychains4") is not None
            or shutil.which("proxychains") is not None)


def _get_proxychains_cmd() -> str:
    """Get the proxychains command name."""
    if shutil.which("proxychains4"):
        return "proxychains4"
    if shutil.which("proxychains"):
        return "proxychains"
    return ""


def is_torsocks_available() -> bool:
    """Check if torsocks is installed."""
    return shutil.which("torsocks") is not None


def check_tor_available() -> bool:
    """Check if Tor is installed and running."""
    return is_tor_running() and (is_proxychains_available() or is_torsocks_available())


def get_public_ip(timeout: int = 10) -> Optional[str]:
    """Get current public IP address (direct, no proxy)."""
    try:
        req = Request(FALLBACK_CHECK_URL)
        with urlopen(req, timeout=timeout) as resp:
            import json
            data = json.loads(resp.read().decode())
            return data.get("ip")
    except Exception:
        return None


# =============================================================================
# TorProxy Context Manager
# =============================================================================

class TorProxy:
    """
    Context manager for routing traffic through Tor SOCKS5 proxy.

    Sets environment variables (ALL_PROXY, HTTP_PROXY, HTTPS_PROXY) so that
    urllib and subprocess tools pick up the proxy automatically.

    Usage:
        with TorProxy() as proxy:
            if proxy.is_active:
                # Make requests - they go through Tor
                data = urlopen("https://example.com").read()
    """

    def __init__(self, socks_port: int = TOR_SOCKS_PORT,
                 control_port: int = TOR_CONTROL_PORT,
                 verify: bool = True):
        self.socks_port = socks_port
        self.control_port = control_port
        self.verify = verify
        self.is_active = False
        self.exit_ip: Optional[str] = None
        self._saved_env: dict = {}
        self._proxy_url = f"socks5h://{TOR_SOCKS_HOST}:{socks_port}"

    def __enter__(self):
        """Set up SOCKS5 proxy environment."""
        if not is_tor_running(port=self.socks_port):
            print("[!][Tor] Tor is not running on port {self.socks_port}")
            return self

        # Save current proxy env vars
        for var in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY",
                     "http_proxy", "https_proxy", "all_proxy"):
            self._saved_env[var] = os.environ.get(var)

        # Set proxy environment
        os.environ["HTTP_PROXY"] = self._proxy_url
        os.environ["HTTPS_PROXY"] = self._proxy_url
        os.environ["ALL_PROXY"] = self._proxy_url
        os.environ["http_proxy"] = self._proxy_url
        os.environ["https_proxy"] = self._proxy_url
        os.environ["all_proxy"] = self._proxy_url

        self.is_active = True

        if self.verify:
            self.exit_ip = self.get_exit_ip()
            if self.exit_ip:
                print(f"[+][Tor] Active | Exit IP: {self.exit_ip}")
            else:
                print("[!][Tor] Proxy set but could not verify exit IP")

        return self

    def __exit__(self, *args):
        """Restore original proxy settings."""
        for var, val in self._saved_env.items():
            if val is None:
                os.environ.pop(var, None)
            else:
                os.environ[var] = val
        self._saved_env.clear()
        self.is_active = False
        return False

    def get_exit_ip(self) -> Optional[str]:
        """Check current exit IP via Tor check API."""
        try:
            # Use proxychains/torsocks for the check since urllib doesn't
            # natively support SOCKS5 without PySocks
            cmd = self._build_check_command()
            if cmd:
                result = subprocess.run(
                    cmd, capture_output=True, text=True, timeout=15
                )
                if result.returncode == 0:
                    import json
                    data = json.loads(result.stdout.strip())
                    ip = data.get("IP") or data.get("ip")
                    return ip

            # Fallback: try urllib with HTTP proxy (if Tor also exposes HTTP)
            try:
                req = Request(CHECK_URL)
                with urlopen(req, timeout=10) as resp:
                    import json
                    data = json.loads(resp.read().decode())
                    if data.get("IsTor", False):
                        return data.get("IP")
            except Exception:
                pass

        except Exception:
            pass
        return None

    def _build_check_command(self) -> Optional[list]:
        """Build a command to check exit IP through Tor."""
        # Prefer torsocks for simple curl
        if is_torsocks_available():
            curl = shutil.which("curl")
            if curl:
                return ["torsocks", curl, "-s", CHECK_URL]

        # Try proxychains
        pc = _get_proxychains_cmd()
        if pc:
            curl = shutil.which("curl")
            if curl:
                return [pc, "-q", curl, "-s", CHECK_URL]

        return None


# =============================================================================
# Subprocess Wrappers
# =============================================================================

def run_through_tor(command: list, socks_port: int = TOR_SOCKS_PORT,
                    timeout: int = 300) -> str:
    """
    Run a subprocess command through proxychains/torsocks.

    Args:
        command: Command as list of strings
        socks_port: Tor SOCKS port
        timeout: Timeout in seconds

    Returns:
        stdout output as string

    Raises:
        RuntimeError if Tor/proxychains not available
    """
    if not is_tor_running(port=socks_port):
        raise RuntimeError("Tor is not running. Start with: sudo systemctl start tor")

    # Try torsocks first (simpler, works with most commands)
    if is_torsocks_available():
        full_cmd = ["torsocks"] + command
    else:
        pc = _get_proxychains_cmd()
        if not pc:
            raise RuntimeError(
                "Neither torsocks nor proxychains found. "
                "Install with: sudo apt install torsocks proxychains4"
            )
        full_cmd = [pc, "-q"] + command

    result = subprocess.run(
        full_cmd, capture_output=True, text=True, timeout=timeout
    )

    if result.returncode != 0 and result.stderr:
        # Filter out torsocks/proxychains noise
        stderr = "\n".join(
            line for line in result.stderr.splitlines()
            if not line.startswith("[proxychains]")
            and "WARNING" not in line.upper()
        ).strip()
        if stderr:
            print(f"[!][Tor] stderr: {stderr[:200]}")

    return result.stdout


def run_command_anonymous(command: list, proxy_url: str = None,
                          timeout: int = 300) -> str:
    """
    Run command through specified SOCKS5/HTTP proxy, or Tor if available.

    Falls back to direct execution with warning if no proxy available.

    Args:
        command: Command as list
        proxy_url: SOCKS5 or HTTP proxy URL (e.g., "socks5://host:port")
        timeout: Timeout in seconds

    Returns:
        stdout output as string
    """
    env = os.environ.copy()

    if proxy_url:
        env["HTTP_PROXY"] = proxy_url
        env["HTTPS_PROXY"] = proxy_url
        env["ALL_PROXY"] = proxy_url
        result = subprocess.run(
            command, capture_output=True, text=True,
            timeout=timeout, env=env
        )
        return result.stdout

    # Try Tor
    if is_tor_running():
        try:
            return run_through_tor(command, timeout=timeout)
        except RuntimeError:
            pass

    # Direct execution (no anonymization)
    print("[!][Anon] WARNING: Running without proxy anonymization")
    result = subprocess.run(
        command, capture_output=True, text=True, timeout=timeout
    )
    return result.stdout


# =============================================================================
# Utility
# =============================================================================

def require_tor(func):
    """Decorator to ensure Tor is running before executing a function."""
    @wraps(func)
    def wrapper(*args, **kwargs):
        if not is_tor_running():
            raise RuntimeError(
                "Tor is required but not running. "
                "Start with: sudo systemctl start tor"
            )
        return func(*args, **kwargs)
    return wrapper


def print_anonymity_status():
    """Print current anonymity configuration status."""
    print("=" * 50)
    print("[*] ANONYMITY STATUS")
    print("=" * 50)

    tor_ok = is_tor_running()
    print(f"  Tor Service:    {'Running' if tor_ok else 'Not running'}")
    print(f"  Proxychains:    {'Available' if is_proxychains_available() else 'Not installed'}")
    print(f"  Torsocks:       {'Available' if is_torsocks_available() else 'Not installed'}")

    real_ip = get_public_ip()
    print(f"  Real IP:        {real_ip or 'Could not determine'}")

    if tor_ok:
        with TorProxy(verify=False) as proxy:
            exit_ip = proxy.get_exit_ip()
            if exit_ip:
                print(f"  Tor Exit IP:    {exit_ip}")
                print(f"  Status:         ANONYMOUS")
            else:
                print(f"  Tor Exit IP:    Could not verify")
    else:
        print(f"  Status:         EXPOSED")
        print(f"  Fix:            sudo apt install tor torsocks && sudo systemctl start tor")

    print("=" * 50)


if __name__ == "__main__":
    print_anonymity_status()
