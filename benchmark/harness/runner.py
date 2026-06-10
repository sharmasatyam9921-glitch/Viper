"""Run VIPER once against a single challenge target.

Invokes the real CLI as a subprocess for process isolation:

    python viper.py <target_url> --full --no-guardrail --output <tmp.json> --time <N>

Each challenge gets its own --output file so scoring is challenge-isolated and
never contaminated by a shared findings DB. The subprocess is hard-killed
(process tree) if it overruns the wall-clock budget.
"""

from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any, Optional

from .models import Challenge, RunResult

# Repo root = two levels up from this file (benchmark/harness/runner.py).
REPO_ROOT = Path(__file__).resolve().parents[2]
VIPER_PY = REPO_ROOT / "viper.py"

_IS_WIN = os.name == "nt"
_TAIL = 4000  # chars of stdout/stderr kept for the report


def _tail(s: str, n: int = _TAIL) -> str:
    s = s or ""
    return s if len(s) <= n else s[-n:]


def _normalize_findings(raw: Any) -> list[dict[str, Any]]:
    """Pull the findings list out of VIPER's --output JSON.

    The writer dumps the whole `result` dict; findings live under
    result["findings"], but tolerate a few shapes defensively.
    """
    if isinstance(raw, list):
        items = raw
    elif isinstance(raw, dict):
        items = raw.get("findings")
        if items is None:
            for k in ("results", "vulnerabilities", "vulns"):
                if isinstance(raw.get(k), list):
                    items = raw[k]
                    break
        if items is None:
            items = []
    else:
        items = []
    out: list[dict[str, Any]] = []
    for it in items:
        if isinstance(it, dict):
            out.append(it)
    return out


class ViperRunner:
    def __init__(
        self,
        *,
        python: Optional[str] = None,
        time_minutes: int = 10,
        extra_args: Optional[list[str]] = None,
        verbose: bool = True,
    ):
        self.python = python or sys.executable
        self.time_minutes = time_minutes
        self.extra_args = list(extra_args or [])
        self.verbose = verbose

    def _log(self, msg: str) -> None:
        if self.verbose:
            print(f"    [viper] {msg}", flush=True)

    def build_cmd(self, target_url: str, output_path: str,
                  challenge: Challenge) -> list[str]:
        cmd = [
            self.python, str(VIPER_PY), target_url,
            "--full", "--no-guardrail",
            "--output", output_path,
            "--time", str(self.time_minutes),
        ]
        cmd += self.extra_args
        cmd += list(challenge.viper_args)
        return cmd

    def run(self, challenge: Challenge, target_url: str) -> RunResult:
        out_fd, out_path = tempfile.mkstemp(
            prefix=f"viper_bench_{challenge.id}_", suffix=".json")
        os.close(out_fd)
        # Remove the empty temp file so a missing-output is detectable later.
        try:
            os.unlink(out_path)
        except OSError:
            pass

        cmd = self.build_cmd(target_url, out_path, challenge)
        self._log(" ".join(cmd))
        res = RunResult(challenge_id=challenge.id, target_url=target_url,
                        output_json_path=out_path)

        # Hard wall-clock cap = VIPER's own budget + 3 min slack for setup/teardown.
        wall_timeout = self.time_minutes * 60 + 180
        start = time.time()

        popen_kwargs: dict[str, Any] = dict(
            cwd=str(REPO_ROOT),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        if _IS_WIN:
            popen_kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP
        else:
            popen_kwargs["start_new_session"] = True

        proc = subprocess.Popen(cmd, **popen_kwargs)
        try:
            stdout, stderr = proc.communicate(timeout=wall_timeout)
            res.exit_code = proc.returncode
        except subprocess.TimeoutExpired:
            res.timed_out = True
            self._log(f"wall-clock timeout ({wall_timeout}s) — killing process tree")
            self._kill_tree(proc)
            try:
                stdout, stderr = proc.communicate(timeout=30)
            except Exception:
                stdout, stderr = "", ""
        except Exception as e:
            res.error = f"subprocess error: {e}"
            stdout, stderr = "", ""
            self._kill_tree(proc)

        res.duration_s = time.time() - start
        res.stdout_tail = _tail(stdout)
        res.stderr_tail = _tail(stderr)

        # Parse the per-challenge output JSON if VIPER managed to write it.
        if os.path.exists(out_path):
            try:
                with open(out_path, "r", encoding="utf-8") as fh:
                    res.findings = _normalize_findings(json.load(fh))
                self._log(f"parsed {len(res.findings)} finding(s) from output JSON")
            except Exception as e:
                res.error = (res.error + f"; output parse error: {e}").strip("; ")
        else:
            self._log("no output JSON written (timeout or crash before report)")

        return res

    def _kill_tree(self, proc: subprocess.Popen) -> None:
        if proc.poll() is not None:
            return
        try:
            if _IS_WIN:
                subprocess.run(
                    ["taskkill", "/F", "/T", "/PID", str(proc.pid)],
                    capture_output=True, text=True, timeout=30,
                )
            else:
                os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
        except Exception as e:
            self._log(f"kill error (ignored): {e}")
            try:
                proc.kill()
            except Exception:
                pass
