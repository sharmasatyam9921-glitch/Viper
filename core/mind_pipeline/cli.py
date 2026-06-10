"""``python -m core.mind_pipeline`` — operator CLI.

Subcommands:
  stats               Print store stats (counts by outcome, provider, purpose).
  query <substring>   Search traces by user_prompt substring or trace id.
  show <trace_id>     Pretty-print a single trace.
  export <out.jsonl>  Dump success traces to JSONL training corpus.
  index <out.pkl>     Build the similarity index for fast fallback.
  link <trace_id>     Manually link an outcome (success / failure / noise).
  replay <trace_id>   Re-run a past trace's user_prompt through MindPipeline.

All commands operate on the default store unless ``--db <path>`` is
passed.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import sys
from pathlib import Path

from .pipeline import MindPipeline
from .store import MindStore, get_store, OUTCOME_SUCCESS, OUTCOME_FAILURE, OUTCOME_NOISE
from .trainer import export_training_corpus, build_similarity_index
from .feedback import apply_outcome


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(prog="python -m core.mind_pipeline")
    p.add_argument("--db", default=None,
                   help="Path to mind_pipeline.db (default: data/mind_pipeline.db)")
    p.add_argument("-v", "--verbose", action="store_true")
    sub = p.add_subparsers(dest="cmd", required=True)

    sub.add_parser("stats", help="Print store stats")

    q = sub.add_parser("query", help="Search traces")
    q.add_argument("needle", help="Substring to search in user_prompt or trace id")
    q.add_argument("--limit", type=int, default=20)

    s = sub.add_parser("show", help="Print one trace")
    s.add_argument("trace_id")

    e = sub.add_parser("export", help="Export success traces to JSONL")
    e.add_argument("out", help="Output JSONL file")
    e.add_argument("--purpose", default=None)
    e.add_argument("--min-score", type=float, default=0.5)
    e.add_argument("--include-pending", action="store_true")

    i = sub.add_parser("index", help="Build similarity index for fast fallback")
    i.add_argument("out", help="Output .pkl file")

    lk = sub.add_parser("link", help="Manually link an outcome to a trace")
    lk.add_argument("trace_id")
    lk.add_argument("--confirmed", choices=["true", "false"], default="true",
                    help="Was the finding/decision confirmed?")
    lk.add_argument("--finding-id", default=None)
    lk.add_argument("--severity", default="medium")

    rp = sub.add_parser("replay", help="Re-run a trace's prompt through MindPipeline")
    rp.add_argument("trace_id")

    return p.parse_args(argv)


def _print_stats(store: MindStore) -> None:
    print("=" * 60)
    print("Mind Pipeline — Store Stats")
    print("=" * 60)
    s = store.stats()
    for k, v in s.items():
        print(f"  {k:24} {v}")
    print()
    print("By provider:")
    for prov, n in store.provider_breakdown().items():
        print(f"  {prov:24} {n}")
    print()
    print("By purpose (top 10):")
    for purp, n in list(store.purpose_breakdown().items())[:10]:
        print(f"  {purp:24} {n}")


def _print_trace(t) -> None:
    """Pretty-print one trace."""
    print(f"┌── Trace {t.id}")
    print(f"│ ts={t.ts:.0f}  hunt={t.hunt_id}  agent={t.agent_id}  phase={t.phase}")
    print(f"│ purpose={t.purpose}  provider={t.provider}  model={t.model}")
    print(f"│ latency_ms={t.latency_ms}  tokens={t.input_tokens}/{t.output_tokens}")
    print(f"│ success={t.success}  outcome={t.outcome}  score={t.feedback_score}")
    if t.finding_id:
        print(f"│ finding_id={t.finding_id}")
    if t.error:
        print(f"│ error={t.error}")
    sys_preview = (t.system_prompt or "")[:200].replace("\n", " ")
    user_preview = (t.user_prompt or "")[:400].replace("\n", " ")
    resp_preview = (t.response or "")[:400].replace("\n", " ")
    print(f"│ system : {sys_preview!r}")
    print(f"│ user   : {user_preview!r}")
    print(f"│ resp   : {resp_preview!r}")
    print("└──")


def _cmd_query(store: MindStore, needle: str, limit: int) -> None:
    # Quick: search trace id exact match first
    direct = store.get(needle)
    if direct is not None:
        _print_trace(direct)
        return
    # Substring search across user_prompt
    needle_lc = needle.lower()
    matches = [t for t in store.list(limit=2000)
               if needle_lc in (t.user_prompt or "").lower()
               or needle_lc in (t.response or "").lower()][:limit]
    print(f"Found {len(matches)} trace(s) matching {needle!r}:")
    for t in matches:
        print(f"  {t.id}  {t.purpose:24} outcome={t.outcome:8} "
              f"score={t.feedback_score}  prompt={(t.user_prompt or '')[:80]!r}")


async def _cmd_replay(store: MindStore, trace_id: str) -> None:
    t = store.get(trace_id)
    if t is None:
        print(f"No such trace: {trace_id}", file=sys.stderr)
        return
    print(f"Replaying {trace_id} through MindPipeline …")
    mind = MindPipeline(store=store)
    resp = await mind.complete(
        prompt=t.user_prompt or "",
        system=t.system_prompt or "",
        purpose=t.purpose,
        hunt_id=t.hunt_id,
        agent_id=t.agent_id,
        phase=t.phase,
    )
    print(f"new trace_id   : {resp.trace_id}")
    print(f"provider       : {resp.provider}")
    print(f"used_fallback  : {resp.used_fallback}")
    if resp.used_fallback:
        print(f"fallback_score : {resp.fallback_score}")
        print(f"source_trace   : {resp.fallback_source_trace_id}")
    print(f"response (200) : {resp.content[:200]!r}")


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s — %(message)s",
        datefmt="%H:%M:%S",
    )
    store = get_store(db_path=args.db) if args.db else get_store()

    if args.cmd == "stats":
        _print_stats(store)
        return 0

    if args.cmd == "query":
        _cmd_query(store, args.needle, args.limit)
        return 0

    if args.cmd == "show":
        t = store.get(args.trace_id)
        if t is None:
            print(f"No such trace: {args.trace_id}", file=sys.stderr)
            return 2
        _print_trace(t)
        return 0

    if args.cmd == "export":
        summary = export_training_corpus(
            args.out, store=store, purpose=args.purpose,
            min_score=args.min_score, include_pending=args.include_pending,
        )
        print(json.dumps(summary, indent=2))
        return 0

    if args.cmd == "index":
        summary = build_similarity_index(args.out, store=store)
        print(json.dumps(summary, indent=2))
        return 0

    if args.cmd == "link":
        confirmed = args.confirmed == "true"
        tag = apply_outcome(
            args.trace_id, store=store,
            finding_confirmed=confirmed,
            finding_id=args.finding_id,
            finding_severity=args.severity,
        )
        if tag is None:
            print(f"No such trace: {args.trace_id}", file=sys.stderr)
            return 2
        print(f"linked: outcome={tag.outcome} score={tag.score:.2f} "
              f"reason={tag.reason!r}")
        return 0

    if args.cmd == "replay":
        asyncio.run(_cmd_replay(store, args.trace_id))
        return 0

    return 2


if __name__ == "__main__":
    raise SystemExit(main())
