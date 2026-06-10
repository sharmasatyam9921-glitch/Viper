"""Run all OWASP Agentic + LLM Top 10 testers against a ``ChatTarget``.

Public entry points:

* ``AIHunter(target).run_all()`` — high-level façade.
* ``run_all_testers(target, *, only=..., skip=...)`` — coroutine for
  swarm workers.
* ``python -m core.ai_hunter`` — CLI runner.

Each tester is wrapped in a per-tester try/except so one broken module
can never break the run.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import sys
from typing import Awaitable, Callable, Optional

from . import (
    prompt_injection, system_prompt_leak, info_disclosure, output_handling,
    memory_poisoning, tool_misuse, privilege_compromise, resource_overload,
    cascading_hallucinations, goal_manipulation, deceptive_behaviors,
    untraceability, identity_spoofing, hitl_overwhelming,
)
from .detector import detect_ai_endpoint
from .probes import ChatTarget

logger = logging.getLogger("viper.ai_hunter.orchestrator")

# Per-run runtime knobs passed to testers that support them.
_RUN_KWARGS: dict[str, dict] = {}


def _wrap_prompt_injection(target):
    return prompt_injection.run(target, **_RUN_KWARGS.get("prompt_injection", {}))


# (name, owasp_id, runner). Order is tester-priority (high-signal first).
TESTERS: list[tuple[str, str, Callable[[ChatTarget], Awaitable[list[dict]]]]] = [
    ("prompt_injection",          "LLM01",       _wrap_prompt_injection),
    ("system_prompt_leak",        "LLM07",       system_prompt_leak.run),
    ("info_disclosure",           "LLM02",       info_disclosure.run),
    ("output_handling",           "LLM05",       output_handling.run),
    ("tool_misuse",               "AGENTIC_T2",  tool_misuse.run),
    ("privilege_compromise",      "AGENTIC_T3",  privilege_compromise.run),
    ("identity_spoofing",         "AGENTIC_T9",  identity_spoofing.run),
    ("goal_manipulation",         "AGENTIC_T6",  goal_manipulation.run),
    ("memory_poisoning",          "AGENTIC_T1",  memory_poisoning.run),
    ("deceptive_behaviors",       "AGENTIC_T7",  deceptive_behaviors.run),
    ("untraceability",            "AGENTIC_T8",  untraceability.run),
    ("hitl_overwhelming",         "AGENTIC_T10", hitl_overwhelming.run),
    ("cascading_hallucinations",  "AGENTIC_T5",  cascading_hallucinations.run),
    ("resource_overload",         "AGENTIC_T4",  resource_overload.run),
]


class AIHunter:
    """Convenience façade. Use the module-level coroutines when you need
    finer control."""

    def __init__(self, target: ChatTarget, *,
                 only: Optional[list[str]] = None,
                 skip: Optional[list[str]] = None,
                 concurrency: int = 3,
                 use_llm_gen: bool = False,
                 toolkit_max: int = 25,
                 adaptive_variants: int = 5):
        self.target = target
        self.only = set(only) if only else None
        self.skip = set(skip) if skip else set()
        self.concurrency = max(1, concurrency)
        self.use_llm_gen = use_llm_gen
        self.toolkit_max = toolkit_max
        self.adaptive_variants = adaptive_variants

    async def run_all(self) -> list[dict]:
        return await run_all_testers(
            self.target,
            only=list(self.only) if self.only else None,
            skip=list(self.skip),
            concurrency=self.concurrency,
            use_llm_gen=self.use_llm_gen,
            toolkit_max=self.toolkit_max,
            adaptive_variants=self.adaptive_variants,
        )


async def run_all_testers(
    target: ChatTarget, *,
    only: Optional[list[str]] = None,
    skip: Optional[list[str]] = None,
    concurrency: int = 3,
    use_llm_gen: bool = False,
    toolkit_max: int = 25,
    adaptive_variants: int = 5,
) -> list[dict]:
    """Run every tester (or just those in ``only``, minus those in
    ``skip``). Returns the flat list of findings (each one already a
    swarm-worker-shaped dict).
    """
    only_set = set(only) if only else None
    skip_set = set(skip or [])
    sem = asyncio.Semaphore(concurrency)
    out: list[dict] = []

    # Stash per-tester runtime knobs (read by the wrapper above)
    _RUN_KWARGS["prompt_injection"] = {
        "use_llm_gen": use_llm_gen,
        "toolkit_max": toolkit_max,
        "adaptive_variants": adaptive_variants,
    }

    async def _wrap(name: str, owasp: str, runner) -> None:
        if only_set is not None and name not in only_set:
            return
        if name in skip_set:
            return
        async with sem:
            try:
                findings = await runner(target)
            except Exception as exc:  # noqa: BLE001
                logger.warning("tester %s raised %s", name, exc, exc_info=True)
                return
            for f in findings or []:
                # Stamp originating tester (useful for triage)
                f.setdefault("tester", name)
                f.setdefault("owasp_id", owasp)
                out.append(f)

    await asyncio.gather(*[
        _wrap(n, o, r) for (n, o, r) in TESTERS
    ])
    return out


# ── CLI ─────────────────────────────────────────────────────────────────

def _parse_args(argv: Optional[list[str]] = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="python -m core.ai_hunter",
        description="OWASP Top 10 for Agentic AI black-box tester",
    )
    p.add_argument("url", help="Target chat / LLM endpoint URL")
    p.add_argument("--template", default=None,
                   help="JSON request template with {prompt} marker(s)")
    p.add_argument("--response-path", default=None,
                   help="Dotted path to assistant text in response JSON")
    p.add_argument("--method", default="POST")
    p.add_argument("--header", "-H", action="append", default=[],
                   help="Extra header, repeatable. Format: 'Name: value'")
    p.add_argument("--auth-token", default=None,
                   help="Bearer token (added as Authorization header)")
    p.add_argument("--session-header", default=None,
                   help="Header name for the conversation/session id")
    p.add_argument("--timeout", type=float, default=15.0)
    p.add_argument("--detect", action="store_true",
                   help="Auto-detect request template + response path")
    p.add_argument("--only", default=None,
                   help="Comma-separated tester names to run")
    p.add_argument("--skip", default=None,
                   help="Comma-separated tester names to skip")
    p.add_argument("--concurrency", type=int, default=3)
    p.add_argument("--llm-gen", action="store_true",
                   help="Enable LLM-driven adaptive bypass generation on refusals "
                        "(uses ai.model_router; falls back to template-only "
                        "if no LLM is reachable)")
    p.add_argument("--toolkit-max", type=int, default=25,
                   help="Max attacks from the embedded injection toolkit "
                        "(default: 25 of 63)")
    p.add_argument("--adaptive-variants", type=int, default=5,
                   help="Number of LLM-generated bypass variants when --llm-gen "
                        "fires (default: 5)")
    p.add_argument("--output", "-o", default=None,
                   help="Write findings JSON to this path (default: stdout)")
    p.add_argument("--verbose", "-v", action="store_true")
    return p.parse_args(argv)


def _parse_headers(items: list[str]) -> dict[str, str]:
    out = {}
    for h in items:
        if ":" not in h:
            continue
        k, v = h.split(":", 1)
        out[k.strip()] = v.strip()
    return out


async def _main_async(args: argparse.Namespace) -> int:
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s — %(message)s",
        datefmt="%H:%M:%S",
    )

    template = None
    response_path = args.response_path
    if args.template:
        try:
            template = json.loads(args.template)
        except json.JSONDecodeError as e:
            print(f"--template is not valid JSON: {e}", file=sys.stderr)
            return 2

    if args.detect or template is None:
        det = await detect_ai_endpoint(args.url, timeout_s=args.timeout,
                                        auth_token=args.auth_token)
        if not det.is_ai:
            print(f"[!] Target doesn't look like an AI endpoint "
                  f"(confidence {det.confidence:.2f}). Pass --template "
                  f"explicitly to override.", file=sys.stderr)
        else:
            print(f"[+] Detected AI endpoint (confidence {det.confidence:.2f}). "
                  f"Template={det.request_template} response_path={det.response_path}",
                  file=sys.stderr)
            if template is None:
                template = det.request_template
            if response_path is None:
                response_path = det.response_path

    target = ChatTarget(
        url=args.url,
        method=args.method,
        headers=_parse_headers(args.header),
        request_template=template,
        response_path=response_path,
        session_header=args.session_header,
        auth_token=args.auth_token,
        timeout_s=args.timeout,
    )

    only = [s.strip() for s in args.only.split(",")] if args.only else None
    skip = [s.strip() for s in args.skip.split(",")] if args.skip else None

    findings = await run_all_testers(
        target, only=only, skip=skip,
        concurrency=args.concurrency,
        use_llm_gen=args.llm_gen,
        toolkit_max=args.toolkit_max,
        adaptive_variants=args.adaptive_variants,
    )

    payload = {
        "target": args.url,
        "findings_count": len(findings),
        "findings": findings,
    }
    text = json.dumps(payload, indent=2, default=str)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(text)
        print(f"[+] {len(findings)} findings written to {args.output}",
              file=sys.stderr)
    else:
        print(text)
    return 0 if findings == [] else 1  # exit 1 = at least one finding


def main(argv: Optional[list[str]] = None) -> int:
    args = _parse_args(argv)
    try:
        return asyncio.run(_main_async(args))
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
