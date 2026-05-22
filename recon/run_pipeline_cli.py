"""
CLI runner invoked by the dashboard to execute the recon pipeline in a
fresh subprocess. Bypasses Windows threading + asyncio + subprocess
issues that occur when running inside the dashboard's threaded HTTP
server.

Usage:
    python recon/run_pipeline_cli.py <args_json_path> <result_json_path>

Reads target/phases/settings from the args JSON file, runs the pipeline,
writes a JSON-serializable result to the result file. Exits 0 on success.
"""

import asyncio
import json
import sys
import traceback
from pathlib import Path

# Make project root importable so `from recon.pipeline import ...` works
# regardless of where this script is invoked from.
_PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))


def main() -> int:
    if len(sys.argv) != 3:
        print("usage: run_pipeline_cli.py <args.json> <result.json>",
              file=sys.stderr)
        return 2

    args_path = Path(sys.argv[1])
    result_path = Path(sys.argv[2])

    try:
        args = json.loads(args_path.read_text(encoding="utf-8"))
    except Exception as exc:
        _write_error(result_path, f"Failed to read args: {exc}")
        return 2

    target = args.get("target")
    phases = args.get("phases")
    settings = args.get("settings") or {}

    if not target:
        _write_error(result_path, "No target specified")
        return 2

    try:
        from recon.pipeline import ReconPipeline

        pipeline = ReconPipeline(settings=settings)
        result = asyncio.run(pipeline.run(target, phases=phases))

        out = {
            "phases_run": list(result.phases_run),
            "phase_timings": dict(result.phase_timings),
            "parallel_groups": list(result.parallel_groups),
            "subdomains": list(result.subdomains),
            "live_hosts": list(result.live_hosts),
            "open_ports": {k: list(v) for k, v in result.open_ports.items()},
            "vulnerabilities": [
                v if isinstance(v, dict) else dict(v)
                for v in result.vulnerabilities
            ],
            "passive_cves": list(result.passive_cves),
            "ip_mode": bool(result.ip_mode),
            "errors": list(result.errors),
        }
        result_path.write_text(json.dumps(out, default=str), encoding="utf-8")
        return 0

    except Exception as exc:
        tb = traceback.format_exc()
        _write_error(result_path, f"{exc}\n{tb}")
        return 1


def _write_error(result_path: Path, msg: str) -> None:
    try:
        result_path.write_text(
            json.dumps({
                "phases_run": [],
                "phase_timings": {},
                "parallel_groups": [],
                "errors": [{"phase": "cli_runner", "error": msg[:2000]}],
            }),
            encoding="utf-8",
        )
    except Exception:
        pass


if __name__ == "__main__":
    sys.exit(main())
