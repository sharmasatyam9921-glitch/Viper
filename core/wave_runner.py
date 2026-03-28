#!/usr/bin/env python3
"""
VIPER Wave Runner — Parallel multi-strategy hunting.

Spawns N independent ViperCore instances ("waves"), each with a different
attack focus and rate limit. Findings are merged and deduplicated at the end.

Usage:
    runner = WaveRunner(num_waves=3, max_minutes_per_wave=10)
    result = await runner.run("https://target.com")
"""

import asyncio
import json
import logging
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional, Any, Set, Tuple

logger = logging.getLogger("viper.wave_runner")

# ---------------------------------------------------------------------------
# Strategy definitions
# ---------------------------------------------------------------------------

STRATEGIES = [
    {
        "name": "aggressive",
        "description": "High-speed injection attacks (SQLi, XSS, SSTI, CMDi)",
        "focus": ["sqli", "xss", "ssti", "cmdi", "rce", "xxe"],
        "rps": 8,
    },
    {
        "name": "stealth",
        "description": "Logic/auth bugs at low rate (IDOR, auth bypass, CORS, open redirect)",
        "focus": ["idor", "auth_bypass", "cors", "open_redirect", "crlf", "host_header_injection"],
        "rps": 2,
    },
    {
        "name": "recon_heavy",
        "description": "Exposure and information leak hunting",
        "focus": ["git_exposure", "env_file", "debug_endpoints", "source_maps",
                  "backup_files", "directory_listing", "robots_txt"],
        "rps": 5,
    },
    {
        "name": "injection",
        "description": "Deep injection variants (error/union/blind SQLi, XXE, CRLF)",
        "focus": ["sqli_error", "sqli_union", "sqli_blind", "xxe", "crlf",
                  "host_header_injection", "ssti", "server_side_request_forgery"],
        "rps": 5,
    },
    {
        "name": "api_hunter",
        "description": "API-specific attacks (GraphQL, JWT, verb tampering, IDOR enum)",
        "focus": ["graphql_introspection", "jwt_none_alg", "verb_tampering",
                  "idor", "mass_assignment", "api_key_exposure"],
        "rps": 5,
    },
]


@dataclass
class WaveResult:
    """Result from a single wave execution."""
    wave_id: int
    strategy: str
    findings: List[Dict] = field(default_factory=list)
    error: Optional[str] = None
    elapsed_seconds: float = 0.0
    requests_made: int = 0


@dataclass
class WaveRunnerResult:
    """Aggregated result from all waves."""
    findings: List[Dict] = field(default_factory=list)
    waves_completed: int = 0
    waves_failed: int = 0
    total_raw_findings: int = 0
    total_deduped_findings: int = 0
    elapsed_seconds: float = 0.0
    wave_results: List[WaveResult] = field(default_factory=list)

    def to_dict(self) -> Dict:
        return {
            "findings": self.findings,
            "waves_completed": self.waves_completed,
            "waves_failed": self.waves_failed,
            "total_raw": self.total_raw_findings,
            "total_deduped": self.total_deduped_findings,
            "elapsed_seconds": self.elapsed_seconds,
            "waves": [
                {
                    "id": w.wave_id,
                    "strategy": w.strategy,
                    "findings": len(w.findings),
                    "error": w.error,
                    "elapsed": w.elapsed_seconds,
                    "requests": w.requests_made,
                }
                for w in self.wave_results
            ],
        }


# ---------------------------------------------------------------------------
# Wave Runner
# ---------------------------------------------------------------------------


class WaveRunner:
    """Parallel multi-strategy scanner. Spawns N independent hunt instances."""

    def __init__(
        self,
        num_waves: int = 3,
        max_minutes_per_wave: int = 10,
        max_total_rps: Optional[int] = None,
    ):
        """
        Args:
            num_waves: Number of parallel waves (1-5). Clamped to available strategies.
            max_minutes_per_wave: Time budget per wave in minutes.
            max_total_rps: Maximum total RPS across all waves. If set, individual
                           wave RPS is scaled down proportionally.
        """
        self.num_waves = min(max(1, num_waves), len(STRATEGIES))
        self.max_minutes = max_minutes_per_wave
        self.max_total_rps = max_total_rps
        self._results: List[WaveResult] = []

    def _select_strategies(self) -> List[Dict]:
        """Select strategies for this run."""
        strategies = STRATEGIES[: self.num_waves]

        # Scale RPS if total exceeds max
        if self.max_total_rps:
            total_rps = sum(s["rps"] for s in strategies)
            if total_rps > self.max_total_rps:
                scale = self.max_total_rps / total_rps
                strategies = [
                    {**s, "rps": max(1, int(s["rps"] * scale))}
                    for s in strategies
                ]
        return strategies

    async def run(
        self,
        target_url: str,
        scope=None,
        full: bool = True,
    ) -> WaveRunnerResult:
        """
        Run N parallel hunts with different strategies.

        Args:
            target_url: Target to scan.
            scope: Optional BugBountyScope for scope enforcement.
            full: If True, run full_hunt per wave. If False, run quick hunt.

        Returns:
            WaveRunnerResult with deduplicated findings.
        """
        strategies = self._select_strategies()
        start = time.time()

        logger.info(
            "WaveRunner: launching %d waves against %s (budget: %d min/wave)",
            len(strategies), target_url, self.max_minutes,
        )
        for i, s in enumerate(strategies):
            logger.info("  Wave %d: %s (%s) @ %d rps", i, s["name"], s["description"], s["rps"])

        tasks = [
            self._run_wave(wave_id=i, target_url=target_url, strategy=s, scope=scope, full=full)
            for i, s in enumerate(strategies)
        ]

        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Collect wave results
        wave_results: List[WaveResult] = []
        all_findings: List[Dict] = []

        for i, r in enumerate(results):
            if isinstance(r, WaveResult):
                wave_results.append(r)
                all_findings.extend(r.findings)
            elif isinstance(r, Exception):
                wave_results.append(WaveResult(
                    wave_id=i,
                    strategy=strategies[i]["name"],
                    error=str(r),
                ))
                logger.error("Wave %d failed: %s", i, r)

        deduped = self._dedup_findings(all_findings)
        elapsed = time.time() - start

        completed = sum(1 for w in wave_results if w.error is None)
        failed = sum(1 for w in wave_results if w.error is not None)

        logger.info(
            "WaveRunner: done in %.1fs | %d waves (%d ok, %d failed) | %d raw -> %d deduped findings",
            elapsed, len(wave_results), completed, failed, len(all_findings), len(deduped),
        )

        return WaveRunnerResult(
            findings=deduped,
            waves_completed=completed,
            waves_failed=failed,
            total_raw_findings=len(all_findings),
            total_deduped_findings=len(deduped),
            elapsed_seconds=elapsed,
            wave_results=wave_results,
        )

    async def _run_wave(
        self,
        wave_id: int,
        target_url: str,
        strategy: Dict,
        scope,
        full: bool,
    ) -> WaveResult:
        """Run a single wave with a specific strategy."""
        from viper_core import ViperCore

        start = time.time()
        name = strategy["name"]
        logger.info("[Wave %d/%s] Starting", wave_id, name)

        viper = ViperCore()

        # Configure rate limit if HackerHTTPClient is available
        if viper.http_client:
            viper.http_client.default_rps = float(strategy["rps"])

        # Tag EvoGraph session with wave_id
        if viper.evograph:
            try:
                viper._evograph_session_id = f"wave_{wave_id}_{name}"
            except Exception:
                pass

        # Bias the knowledge/Q-table toward this strategy's focus attacks
        _bias_knowledge(viper, strategy["focus"])

        try:
            if full:
                result = await viper.full_hunt(
                    target_url=target_url,
                    scope=scope,
                    max_minutes=self.max_minutes,
                )
            else:
                import aiohttp
                async with aiohttp.ClientSession(
                    connector=aiohttp.TCPConnector(ssl=False)
                ) as viper.session:
                    result = await viper.hunt(
                        target_url=target_url,
                        max_minutes=self.max_minutes,
                    )

            findings = result.get("findings", [])

            # Tag findings with wave metadata
            for f in findings:
                f["wave_id"] = wave_id
                f["wave_strategy"] = name

            elapsed = time.time() - start
            logger.info(
                "[Wave %d/%s] Complete: %d findings in %.1fs",
                wave_id, name, len(findings), elapsed,
            )

            return WaveResult(
                wave_id=wave_id,
                strategy=name,
                findings=findings,
                elapsed_seconds=elapsed,
                requests_made=result.get("phases", {}).get("manual", {}).get("requests", 0),
            )

        except Exception as e:
            elapsed = time.time() - start
            logger.error("[Wave %d/%s] Error after %.1fs: %s", wave_id, name, elapsed, e)
            return WaveResult(
                wave_id=wave_id,
                strategy=name,
                error=str(e),
                elapsed_seconds=elapsed,
            )

    def _dedup_findings(self, findings: List[Dict]) -> List[Dict]:
        """Remove duplicate findings by (url, vuln_type, payload) tuple."""
        seen: Set[Tuple[str, str, str]] = set()
        unique: List[Dict] = []
        for f in findings:
            url = f.get("url", "")
            vtype = f.get("vuln_type", f.get("attack", f.get("type", "")))
            payload = f.get("payload", "")
            key = (url, vtype, payload)
            if key not in seen:
                seen.add(key)
                unique.append(f)
        return unique


def _bias_knowledge(viper, focus_attacks: List[str]):
    """
    Bias the ViperCore's knowledge/Q-table so it prioritizes
    this wave's focus attacks.
    """
    if not hasattr(viper, "knowledge") or not viper.knowledge:
        return

    # Boost Q-values for focus attacks
    if hasattr(viper, "_brain") and viper._brain and hasattr(viper._brain, "q_table"):
        brain = viper._brain
        for state in list(brain.q_table.keys()):
            for attack in focus_attacks:
                if attack in brain.q_table.get(state, {}):
                    brain.q_table[state][attack] = brain.q_table[state].get(attack, 0) + 5.0

    # Reorder knowledge attack priority
    if hasattr(viper.knowledge, "attacks") and isinstance(viper.knowledge.attacks, dict):
        for attack_name in focus_attacks:
            if attack_name in viper.knowledge.attacks:
                atk = viper.knowledge.attacks[attack_name]
                if hasattr(atk, "priority"):
                    atk.priority = max(0, atk.priority - 50)


# ═══════════════════════════════════════════════════════════════════════
# TOOL WAVE EXECUTOR — Parallel tool execution for orchestrator plans
# ═══════════════════════════════════════════════════════════════════════


@dataclass
class ToolWaveResult:
    """Result from executing a single tool within a wave."""
    tool_name: str
    tool_args: Dict
    success: bool = False
    output: str = ""
    error: Optional[str] = None
    elapsed_seconds: float = 0.0
    wave_index: int = 0
    action_index: int = 0


@dataclass
class WavePlanResult:
    """Result from executing an entire wave plan (multiple waves sequentially)."""
    waves_executed: int = 0
    total_actions: int = 0
    successful: int = 0
    failed: int = 0
    elapsed_seconds: float = 0.0
    results: List[ToolWaveResult] = field(default_factory=list)
    deduplicated: bool = False

    def to_dict(self) -> Dict:
        return {
            "waves_executed": self.waves_executed,
            "total_actions": self.total_actions,
            "successful": self.successful,
            "failed": self.failed,
            "elapsed_seconds": self.elapsed_seconds,
            "results": [
                {
                    "tool": r.tool_name,
                    "success": r.success,
                    "output_len": len(r.output),
                    "error": r.error,
                    "elapsed": r.elapsed_seconds,
                    "wave": r.wave_index,
                }
                for r in self.results
            ],
        }


class ToolWaveExecutor:
    """
    Parallel tool executor for the orchestrator's plan_tools action.

    Supports:
      - plan_waves(): group independent actions into parallel "waves"
      - execute_wave(): run all actions in one wave concurrently
      - execute_plan(): run all waves sequentially, each wave's tools in parallel
      - Deduplication of results across waves
      - Per-tool timeout (default 60s) and per-wave timeout (default 300s)
      - Progress callbacks for dashboard streaming
    """

    def __init__(
        self,
        tool_executor=None,
        tool_timeout: float = 60.0,
        wave_timeout: float = 300.0,
        progress_callback: Optional[Any] = None,
    ):
        """
        Args:
            tool_executor: Callable or object with async execute(tool_name, tool_args) -> dict.
                           If None, actions are simulated (dry run).
            tool_timeout: Max seconds per individual tool execution.
            wave_timeout: Max seconds per wave (all parallel tools combined).
            progress_callback: Optional async callable(event_type, data) for streaming.
        """
        self.tool_executor = tool_executor
        self.tool_timeout = tool_timeout
        self.wave_timeout = wave_timeout
        self.progress_callback = progress_callback
        self._seen_outputs: Set[str] = set()  # For cross-wave dedup

    def plan_waves(self, actions: List[Dict]) -> List[List[Dict]]:
        """
        Group independent actions into parallel "waves".

        Actions with no data dependency on each other go in the same wave.
        Sequential dependencies (where one action's output feeds another) create new waves.

        Dependency detection:
          - If action B's tool_args reference action A's tool_name or output placeholder,
            B depends on A and goes in a later wave.
          - Actions with explicit "depends_on" field are grouped after their dependency.
          - All other actions are independent and grouped in wave 0.

        Args:
            actions: List of action dicts, each with at minimum:
                     {"tool": "name", "tool_args": {}, "reasoning": "...", "priority": N}
                     Optional: {"depends_on": "tool_name_or_index"}

        Returns:
            List of waves, where each wave is a list of action dicts.
        """
        if not actions:
            return []

        # Tag each action with its index for tracking
        for i, a in enumerate(actions):
            a["_idx"] = i

        # Build dependency graph
        # action_index -> set of action_indices it depends on
        deps: Dict[int, set] = {i: set() for i in range(len(actions))}

        # Check explicit depends_on
        tool_index_map: Dict[str, int] = {}
        for i, a in enumerate(actions):
            tool = a.get("tool", a.get("tool_name", ""))
            if tool and tool != "auto":
                tool_index_map[tool] = i

        for i, a in enumerate(actions):
            dep = a.get("depends_on")
            if dep is not None:
                if isinstance(dep, int) and 0 <= dep < len(actions):
                    deps[i].add(dep)
                elif isinstance(dep, str) and dep in tool_index_map:
                    deps[i].add(tool_index_map[dep])

            # Heuristic: check if tool_args reference another action's tool output
            args_str = str(a.get("tool_args", {})).lower()
            for j, other in enumerate(actions):
                if j == i:
                    continue
                other_tool = other.get("tool", other.get("tool_name", ""))
                if other_tool and other_tool != "auto":
                    # If args reference another tool's name as a data source
                    if f"${other_tool}" in args_str or f"from_{other_tool}" in args_str:
                        deps[i].add(j)

        # Topological sort into waves (Kahn's algorithm)
        waves: List[List[Dict]] = []
        assigned: Set[int] = set()
        remaining = set(range(len(actions)))

        while remaining:
            # Find all actions whose dependencies are satisfied
            ready = []
            for i in remaining:
                if deps[i].issubset(assigned):
                    ready.append(i)

            if not ready:
                # Circular dependency — break by taking highest priority unassigned
                remaining_list = sorted(remaining, key=lambda i: actions[i].get("priority", 99))
                ready = [remaining_list[0]]
                logger.warning(f"Circular dependency detected, forcing action {ready[0]} into new wave")

            # Sort ready actions by priority within the wave
            ready.sort(key=lambda i: actions[i].get("priority", 99))

            wave = [actions[i] for i in ready]
            waves.append(wave)

            for i in ready:
                assigned.add(i)
                remaining.discard(i)

        logger.info(f"Planned {len(waves)} waves from {len(actions)} actions: "
                     f"{[len(w) for w in waves]}")
        return waves

    async def execute_wave(self, wave: List[Dict], wave_index: int = 0) -> List[ToolWaveResult]:
        """
        Run all actions in a wave concurrently via asyncio.gather().

        Args:
            wave: List of action dicts to execute in parallel.
            wave_index: Index of this wave for tracking/logging.

        Returns:
            List of ToolWaveResult for each action.
        """
        if not wave:
            return []

        # Emit wave_start callback
        if self.progress_callback:
            try:
                await self.progress_callback("wave_start", {
                    "wave_index": wave_index,
                    "num_actions": len(wave),
                    "tools": [a.get("tool", a.get("tool_name", "?")) for a in wave],
                })
            except Exception:
                pass

        async def _exec_one(action: Dict, action_index: int) -> ToolWaveResult:
            tool_name = action.get("tool", action.get("tool_name", "unknown"))
            tool_args = action.get("tool_args", {})
            start = time.time()

            result = ToolWaveResult(
                tool_name=tool_name,
                tool_args=tool_args,
                wave_index=wave_index,
                action_index=action_index,
            )

            if not self.tool_executor:
                # Dry run mode
                result.success = True
                result.output = f"[DRY RUN] Would execute {tool_name} with {tool_args}"
                result.elapsed_seconds = 0.0
                return result

            try:
                # Per-tool timeout
                exec_coro = self._invoke_tool(tool_name, tool_args)
                raw = await asyncio.wait_for(exec_coro, timeout=self.tool_timeout)

                if isinstance(raw, dict):
                    result.success = raw.get("success", False)
                    result.output = raw.get("output", str(raw))
                    result.error = raw.get("error")
                elif isinstance(raw, str):
                    result.success = True
                    result.output = raw
                else:
                    result.success = bool(raw)
                    result.output = str(raw) if raw else ""

            except asyncio.TimeoutError:
                result.success = False
                result.error = f"Tool '{tool_name}' timed out after {self.tool_timeout}s"
                result.output = result.error
                logger.warning(f"[Wave {wave_index}] {result.error}")

            except Exception as exc:
                result.success = False
                result.error = str(exc)
                result.output = f"Error: {exc}"
                logger.error(f"[Wave {wave_index}] Tool {tool_name} failed: {exc}")

            result.elapsed_seconds = time.time() - start

            # Emit per-tool callback
            if self.progress_callback:
                try:
                    await self.progress_callback("tool_complete", {
                        "wave_index": wave_index,
                        "action_index": action_index,
                        "tool_name": tool_name,
                        "success": result.success,
                        "elapsed": result.elapsed_seconds,
                    })
                except Exception:
                    pass

            return result

        # Execute all actions in parallel with per-wave timeout
        tasks = [_exec_one(action, i) for i, action in enumerate(wave)]

        try:
            results = await asyncio.wait_for(
                asyncio.gather(*tasks, return_exceptions=True),
                timeout=self.wave_timeout,
            )
        except asyncio.TimeoutError:
            logger.warning(f"[Wave {wave_index}] Entire wave timed out after {self.wave_timeout}s")
            # Collect whatever completed
            results = []
            for t in tasks:
                if t.done():
                    results.append(t.result())
                else:
                    t.cancel()
                    results.append(ToolWaveResult(
                        tool_name="?", tool_args={},
                        success=False, error=f"Wave timeout ({self.wave_timeout}s)",
                        wave_index=wave_index,
                    ))

        # Unwrap exceptions from gather
        final_results = []
        for i, r in enumerate(results):
            if isinstance(r, ToolWaveResult):
                final_results.append(r)
            elif isinstance(r, Exception):
                final_results.append(ToolWaveResult(
                    tool_name=wave[i].get("tool", "?") if i < len(wave) else "?",
                    tool_args=wave[i].get("tool_args", {}) if i < len(wave) else {},
                    success=False,
                    error=str(r),
                    output=f"Error: {r}",
                    wave_index=wave_index,
                    action_index=i,
                ))
            else:
                final_results.append(r)

        # Emit wave_complete callback
        ok = sum(1 for r in final_results if r.success)
        fail = sum(1 for r in final_results if not r.success)
        if self.progress_callback:
            try:
                await self.progress_callback("wave_complete", {
                    "wave_index": wave_index,
                    "successful": ok,
                    "failed": fail,
                    "total": len(final_results),
                })
            except Exception:
                pass

        logger.info(f"[Wave {wave_index}] Complete: {ok} ok, {fail} failed out of {len(final_results)}")
        return final_results

    async def execute_plan(self, waves: List[List[Dict]]) -> WavePlanResult:
        """
        Execute all waves sequentially, each wave's tools in parallel.

        Deduplicates results across waves (same tool+args = skip in later wave).

        Args:
            waves: List of waves from plan_waves().

        Returns:
            WavePlanResult with aggregated results.
        """
        start = time.time()
        all_results: List[ToolWaveResult] = []
        self._seen_outputs.clear()

        for wave_idx, wave in enumerate(waves):
            # Deduplicate: skip actions already executed with same tool+args
            deduped_wave = []
            for action in wave:
                key = self._action_key(action)
                if key not in self._seen_outputs:
                    deduped_wave.append(action)
                else:
                    logger.info(f"[Wave {wave_idx}] Skipping duplicate: {key}")

            if not deduped_wave:
                logger.info(f"[Wave {wave_idx}] All actions deduplicated, skipping")
                continue

            wave_results = await self.execute_wave(deduped_wave, wave_index=wave_idx)

            # Track seen outputs for cross-wave dedup
            for r in wave_results:
                key = self._action_key({"tool": r.tool_name, "tool_args": r.tool_args})
                self._seen_outputs.add(key)

            all_results.extend(wave_results)

        elapsed = time.time() - start
        ok = sum(1 for r in all_results if r.success)
        fail = sum(1 for r in all_results if not r.success)

        result = WavePlanResult(
            waves_executed=len(waves),
            total_actions=len(all_results),
            successful=ok,
            failed=fail,
            elapsed_seconds=elapsed,
            results=all_results,
            deduplicated=True,
        )

        logger.info(f"Plan complete: {len(waves)} waves, {ok}/{len(all_results)} ok in {elapsed:.1f}s")
        return result

    async def _invoke_tool(self, tool_name: str, tool_args: Dict) -> Dict:
        """Invoke a tool via the tool_executor. Supports multiple executor interfaces."""
        if hasattr(self.tool_executor, "execute"):
            # Standard executor with execute(name, args) or execute(name, args, phase)
            import inspect
            sig = inspect.signature(self.tool_executor.execute)
            params = list(sig.parameters.keys())
            if len(params) >= 3:
                return await self.tool_executor.execute(tool_name, tool_args, "exploitation")
            return await self.tool_executor.execute(tool_name, tool_args)
        elif callable(self.tool_executor):
            return await self.tool_executor(tool_name, tool_args)
        else:
            raise RuntimeError(f"tool_executor has no execute() method and is not callable")

    @staticmethod
    def _action_key(action: Dict) -> str:
        """Create a dedup key from tool name + sorted args."""
        tool = action.get("tool", action.get("tool_name", "?"))
        args = action.get("tool_args", {})
        # Sort args for consistent hashing
        try:
            args_str = json.dumps(args, sort_keys=True, default=str)
        except Exception:
            args_str = str(args)
        return f"{tool}:{args_str}"
