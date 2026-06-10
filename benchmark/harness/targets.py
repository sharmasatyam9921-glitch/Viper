"""Bring challenge targets up and down.

Supports three target types:
  external        — nothing to start; just health-check the URL.
  docker_image    — `docker run -d -p host:container <image>`.
  docker_compose  — `docker compose -f <file> up -d` in a directory.

Every target is health-polled (HTTP GET) before VIPER is unleashed, so a slow
container boot doesn't get scored as "VIPER found nothing".
"""

from __future__ import annotations

import subprocess
import time
import urllib.error
import urllib.request
from contextlib import contextmanager
from typing import Iterator, Optional

from .models import Target


class TargetError(RuntimeError):
    pass


def _run(cmd: list[str], timeout: int = 180) -> subprocess.CompletedProcess:
    return subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=timeout,
    )


def _http_ok(url: str) -> bool:
    try:
        req = urllib.request.Request(url, method="GET",
                                     headers={"User-Agent": "viper-benchmark"})
        with urllib.request.urlopen(req, timeout=5) as resp:
            # Any HTTP answer means the server is listening. Auth walls (401/403)
            # and app error pages (500) still count as "up".
            return 200 <= resp.status < 600
    except urllib.error.HTTPError:
        return True  # server answered, just not 2xx — it's up
    except Exception:
        return False


def wait_healthy(url: str, timeout: int = 120, interval: float = 2.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        if _http_ok(url):
            return True
        time.sleep(interval)
    return False


class TargetManager:
    """Starts/stops a single challenge target and yields its base URL.

    Use as a context manager via `manage()`. On exit it tears the target down
    unless `keep` is set (handy for debugging a failing challenge).
    """

    def __init__(self, target: Target, *, keep: bool = False, verbose: bool = True):
        self.t = target
        self.keep = keep
        self.verbose = verbose
        self._container_id: Optional[str] = None
        self._compose_up = False

    def _log(self, msg: str) -> None:
        if self.verbose:
            print(f"    [target] {msg}", flush=True)

    # -- lifecycle ---------------------------------------------------------

    def start(self) -> str:
        if self.t.type == "external":
            url = self.t.url
        elif self.t.type == "docker_image":
            url = self._start_docker_image()
        elif self.t.type == "docker_compose":
            url = self._start_docker_compose()
        else:
            raise TargetError(f"unknown target type: {self.t.type!r}")

        if not url:
            raise TargetError("target produced no URL")

        health_url = url.rstrip("/") + "/" + self.t.health_path.lstrip("/")
        self._log(f"waiting for {health_url} ...")
        if not wait_healthy(health_url, timeout=self.t.health_timeout):
            self.stop()
            raise TargetError(f"target never became healthy: {health_url}")
        self._log("healthy")
        return url

    def _start_docker_image(self) -> str:
        if not self.t.image:
            raise TargetError("docker_image target missing 'image'")
        host = self.t.host_port or self.t.container_port
        cont = self.t.container_port or self.t.host_port
        if not (host and cont):
            raise TargetError("docker_image target needs container_port (and host_port)")
        cmd = ["docker", "run", "-d", "--rm", "-p", f"{host}:{cont}"]
        for k, v in self.t.env.items():
            cmd += ["-e", f"{k}={v}"]
        cmd += list(self.t.run_args)
        cmd.append(self.t.image)
        self._log(f"docker run {self.t.image} ({host}->{cont})")
        proc = _run(cmd)
        if proc.returncode != 0:
            raise TargetError(f"docker run failed: {proc.stderr.strip()}")
        self._container_id = proc.stdout.strip()
        return self.t.url or f"http://localhost:{host}"

    def _start_docker_compose(self) -> str:
        if not self.t.compose_dir and not self.t.compose_file:
            raise TargetError("docker_compose target needs compose_dir or compose_file")
        cmd = ["docker", "compose"]
        if self.t.compose_file:
            cmd += ["-f", self.t.compose_file]
        cmd += ["up", "-d"]
        if self.t.service:
            cmd.append(self.t.service)
        self._log(f"docker compose up ({self.t.compose_file or self.t.compose_dir})")
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=600,
            cwd=self.t.compose_dir or None,
        )
        if proc.returncode != 0:
            raise TargetError(f"docker compose up failed: {proc.stderr.strip()}")
        self._compose_up = True
        if not self.t.url:
            raise TargetError("docker_compose target needs an explicit 'url'")
        return self.t.url

    def stop(self) -> None:
        if self.keep:
            self._log("keeping target alive (--keep-targets)")
            return
        try:
            if self._container_id:
                self._log("stopping container")
                _run(["docker", "stop", self._container_id], timeout=60)
                self._container_id = None
            if self._compose_up:
                self._log("docker compose down")
                cmd = ["docker", "compose"]
                if self.t.compose_file:
                    cmd += ["-f", self.t.compose_file]
                cmd += ["down", "-v"]
                subprocess.run(cmd, capture_output=True, text=True,
                               timeout=300, cwd=self.t.compose_dir or None)
                self._compose_up = False
        except Exception as e:  # teardown must never crash the run
            self._log(f"teardown error (ignored): {e}")

    @contextmanager
    def manage(self) -> Iterator[str]:
        url = self.start()
        try:
            yield url
        finally:
            self.stop()
