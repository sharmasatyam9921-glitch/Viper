#!/usr/bin/env python3
"""Single-command launcher for the VIPER dashboard.

Starts the headless API (:8080) and the Next.js UI (:3000) together, waits for
the API to answer, opens the browser, and shuts both down cleanly on Ctrl+C.
This is the one command to run the dashboard:

    python dashboard/launch.py            # dev mode (hot reload)
    python dashboard/launch.py --prod     # production build + start
    python dashboard/launch.py --no-open  # don't open a browser

Ports are overridable via VIPER_PORT (API) and VIPER_UI_PORT (UI).
"""
from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
import time
import urllib.request
import webbrowser
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
WEBAPP = ROOT / "dashboard" / "webapp"
SERVER = ROOT / "dashboard" / "server.py"
API_PORT = int(os.environ.get("VIPER_PORT", "8080"))
UI_PORT = int(os.environ.get("VIPER_UI_PORT", "3000"))
IS_WIN = os.name == "nt"


def _npm() -> str:
    return shutil.which("npm") or ("npm.cmd" if IS_WIN else "npm")


def _popen(cmd, cwd, env=None):
    kw: dict = {"cwd": str(cwd)}
    if env:
        merged = os.environ.copy()
        merged.update(env)
        kw["env"] = merged
    # New process group so the launcher owns Ctrl+C; children are torn down
    # explicitly via _kill (taskkill tree on Windows).
    if IS_WIN:
        kw["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP
    return subprocess.Popen(cmd, **kw)


def _kill(proc) -> None:
    if proc is None or proc.poll() is not None:
        return
    try:
        if IS_WIN:
            subprocess.run(
                ["taskkill", "/F", "/T", "/PID", str(proc.pid)],
                capture_output=True,
            )
        else:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
    except Exception:
        pass


def _wait_health(timeout: int = 40) -> bool:
    url = f"http://127.0.0.1:{API_PORT}/api/health"
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=2) as r:
                if r.status == 200:
                    return True
        except Exception:
            time.sleep(0.5)
    return False


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Launch the VIPER dashboard (API + UI)."
    )
    ap.add_argument("--prod", action="store_true",
                    help="Build and serve the UI in production mode.")
    ap.add_argument("--no-open", action="store_true",
                    help="Do not open a browser.")
    args = ap.parse_args()

    if not WEBAPP.exists():
        print(f"[launch] webapp not found at {WEBAPP}", file=sys.stderr)
        return 1

    npm = _npm()
    if not (WEBAPP / "node_modules").exists():
        print("[launch] installing webapp dependencies (first run)…")
        subprocess.run([npm, "install"], cwd=str(WEBAPP), check=True)

    procs: list = []
    try:
        # 1) Headless API on :8080
        print(f"[launch] starting API  -> http://localhost:{API_PORT}")
        procs.append(_popen([sys.executable, str(SERVER)], ROOT))

        # 2) Next.js UI on :3000 (Next honours the PORT env var for dev+start)
        ui_env = {"PORT": str(UI_PORT)}
        if args.prod:
            print("[launch] building UI (production)…")
            subprocess.run([npm, "run", "build"], cwd=str(WEBAPP), check=True)
            ui_cmd = [npm, "run", "start"]
        else:
            ui_cmd = [npm, "run", "dev"]
        print(f"[launch] starting UI   -> http://localhost:{UI_PORT}")
        procs.append(_popen(ui_cmd, WEBAPP, env=ui_env))

        # 3) Wait for the API, then open the UI.
        if _wait_health():
            print("[launch] API healthy.")
        else:
            print("[launch] WARNING: API health check timed out (continuing).")
        if not args.no_open:
            webbrowser.open(f"http://localhost:{UI_PORT}/")

        print("[launch] dashboard up. Press Ctrl+C to stop both.")
        # Block until either child exits, then tear the other one down too.
        while True:
            for p in procs:
                if p.poll() is not None:
                    print(f"[launch] process pid {p.pid} exited "
                          f"(code {p.returncode}); shutting down.")
                    return p.returncode or 0
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[launch] stopping…")
        return 0
    finally:
        for p in reversed(procs):
            _kill(p)


if __name__ == "__main__":
    raise SystemExit(main())
