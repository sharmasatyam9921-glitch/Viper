#!/usr/bin/env python3
"""
VIPER Model Router - Provider-Agnostic LLM Abstraction

Routes LLM calls through LiteLLM for multi-provider support.
Supports OpenAI, Anthropic, DeepSeek, Ollama, and any LiteLLM-compatible model.

Configuration via environment variables:
    VIPER_MODEL            - Default model (e.g., "anthropic/claude-sonnet-4-20250514")
    VIPER_TRIAGE_MODEL     - Model for finding triage/validation
    VIPER_REASONING_MODEL  - Model for ReACT reasoning steps
    VIPER_FALLBACK_MODELS  - Comma-separated fallback chain
    VIPER_API_BASE         - Custom API base URL (for local/proxy setups)
    VIPER_MAX_TOKENS       - Default max tokens (default: 1024)
    VIPER_TEMPERATURE      - Default temperature (default: 0.3)
    VIPER_RATE_LIMIT       - Max requests per minute per provider (default: 30)
"""

import asyncio
import json
import logging
import os
import re
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional

logger = logging.getLogger("viper.model_router")

# Default models if none configured
DEFAULT_MODEL = "anthropic/claude-sonnet-4-20250514"
DEFAULT_FALLBACKS = ["ollama/deepseek-r1:14b", "openai/gpt-4o", "deepseek/deepseek-chat"]


@dataclass
class ModelResponse:
    """Standardized response from any LLM provider."""
    text: str
    model: str
    provider: str
    usage: Dict[str, int] = field(default_factory=dict)
    latency_ms: float = 0.0
    cost_estimate: float = 0.0

    def extract_json(self, pattern: str = r'[\[{].*[\]}]') -> Optional[Any]:
        """Extract JSON from the response text."""
        match = re.search(pattern, self.text, re.DOTALL)
        if match:
            try:
                return json.loads(match.group())
            except json.JSONDecodeError:
                pass
        return None

    def extract_json_array(self) -> Optional[List]:
        """Extract a JSON array from the response."""
        return self.extract_json(r'\[.*\]')

    def extract_json_object(self) -> Optional[Dict]:
        """Extract a JSON object from the response."""
        return self.extract_json(r'\{.*\}')


@dataclass
class _RateLimiter:
    """Simple sliding-window rate limiter."""
    max_rpm: int = 30
    _timestamps: List[float] = field(default_factory=list)

    def acquire(self) -> bool:
        """Return True if request is allowed, False if rate-limited."""
        now = time.monotonic()
        window = now - 60.0
        self._timestamps = [t for t in self._timestamps if t > window]
        if len(self._timestamps) >= self.max_rpm:
            return False
        self._timestamps.append(now)
        return True

    @property
    def wait_time(self) -> float:
        """Seconds until the next request slot opens."""
        if not self._timestamps or len(self._timestamps) < self.max_rpm:
            return 0.0
        return max(0.0, self._timestamps[0] + 60.0 - time.monotonic())


class UsageTracker:
    """Tracks token usage and estimated costs across providers."""

    # Approximate cost per 1K tokens (input, output) in USD
    COST_TABLE: Dict[str, tuple] = {
        "anthropic/claude-sonnet-4-20250514": (0.003, 0.015),
        "anthropic/claude-haiku-4-5-20251001": (0.001, 0.005),
        "openai/gpt-4o": (0.005, 0.015),
        "openai/gpt-4o-mini": (0.00015, 0.0006),
        "deepseek/deepseek-chat": (0.00014, 0.00028),
    }

    def __init__(self):
        self.total_input_tokens: int = 0
        self.total_output_tokens: int = 0
        self.total_cost: float = 0.0
        self.calls_by_model: Dict[str, int] = {}
        self.errors_by_model: Dict[str, int] = {}

    def record(self, model: str, usage: Dict[str, int], cost: float = 0.0):
        self.total_input_tokens += usage.get("prompt_tokens", 0)
        self.total_output_tokens += usage.get("completion_tokens", 0)
        self.total_cost += cost
        self.calls_by_model[model] = self.calls_by_model.get(model, 0) + 1

    def record_error(self, model: str):
        self.errors_by_model[model] = self.errors_by_model.get(model, 0) + 1

    def estimate_cost(self, model: str, usage: Dict[str, int]) -> float:
        rates = self.COST_TABLE.get(model, (0.001, 0.005))
        inp = usage.get("prompt_tokens", 0) / 1000.0 * rates[0]
        out = usage.get("completion_tokens", 0) / 1000.0 * rates[1]
        return inp + out

    def summary(self) -> Dict[str, Any]:
        return {
            "total_input_tokens": self.total_input_tokens,
            "total_output_tokens": self.total_output_tokens,
            "total_cost_usd": round(self.total_cost, 6),
            "calls_by_model": dict(self.calls_by_model),
            "errors_by_model": dict(self.errors_by_model),
        }


class ModelRouter:
    """
    Provider-agnostic LLM router with multiple backends.

    Priority order:
    1. Claude CLI (OAuth — free, uses existing claude login)
    2. LiteLLM (paid API — any provider)
    3. Ollama (free local models)

    Handles model selection, fallback chains, rate limiting,
    and usage tracking for all VIPER LLM calls.
    """

    def __init__(self):
        self.default_model = os.environ.get("VIPER_MODEL", DEFAULT_MODEL)
        self.triage_model = os.environ.get("VIPER_TRIAGE_MODEL", self.default_model)
        self.reasoning_model = os.environ.get("VIPER_REASONING_MODEL", self.default_model)

        fallback_str = os.environ.get("VIPER_FALLBACK_MODELS", "")
        self.fallback_models: List[str] = (
            [m.strip() for m in fallback_str.split(",") if m.strip()]
            if fallback_str else list(DEFAULT_FALLBACKS)
        )

        self.api_base = os.environ.get("VIPER_API_BASE")
        self.max_tokens = int(os.environ.get("VIPER_MAX_TOKENS", "1024"))
        self.temperature = float(os.environ.get("VIPER_TEMPERATURE", "0.3"))
        max_rpm = int(os.environ.get("VIPER_RATE_LIMIT", "30"))

        self._rate_limiters: Dict[str, _RateLimiter] = {}
        self._default_rpm = max_rpm
        self.usage = UsageTracker()
        self._litellm = None

        # Claude CLI OAuth backend
        self._claude_cli = None
        self._cli_available = None  # None = not checked yet
        self.use_cli = os.environ.get("VIPER_USE_CLI", "true").lower() in ("true", "1", "yes")

    def _get_limiter(self, provider: str) -> _RateLimiter:
        if provider not in self._rate_limiters:
            self._rate_limiters[provider] = _RateLimiter(max_rpm=self._default_rpm)
        return self._rate_limiters[provider]

    @staticmethod
    def _provider_from_model(model: str) -> str:
        """Extract provider name from model string (e.g., 'anthropic/claude-...' -> 'anthropic')."""
        if "/" in model:
            return model.split("/", 1)[0]
        return "unknown"

    def _ensure_litellm(self):
        """Lazy-load litellm to avoid import cost when not needed."""
        if self._litellm is None:
            try:
                import litellm
                litellm.suppress_debug_info = True
                self._litellm = litellm
            except ImportError:
                raise ImportError(
                    "litellm is required for ModelRouter. Install with: pip install litellm"
                )

    # ── Claude CLI OAuth Backend ──────────────────────────────────────────
    def _find_claude_cli(self) -> Optional[str]:
        """Find the claude CLI binary (uses OAuth — no API key needed)."""
        if self._claude_cli is not None:
            return self._claude_cli

        import shutil
        from pathlib import Path

        cli = shutil.which("claude")
        if cli:
            self._claude_cli = cli
            return cli

        # Windows: check npm global
        npm_path = Path.home() / "AppData" / "Roaming" / "npm" / "claude.cmd"
        if npm_path.exists():
            self._claude_cli = str(npm_path)
            return self._claude_cli

        self._claude_cli = ""  # Mark as not found (empty string, not None)
        return ""

    def _cli_is_available(self) -> bool:
        """Check if Claude CLI is available and authenticated."""
        if self._cli_available is not None:
            return self._cli_available

        cli = self._find_claude_cli()
        if not cli:
            self._cli_available = False
            return False

        # Quick health check
        import subprocess
        try:
            result = subprocess.run(
                [cli, "-p", "--model", "haiku", "--output-format", "json",
                 "--max-turns", "1", "--dangerously-skip-permissions",
                 "--no-session-persistence",
                 "--append-system-prompt", "Respond with exactly: ok"],
                input="ping",
                capture_output=True, text=True, timeout=30, encoding="utf-8",
            )
            if result.returncode == 0 and "ok" in result.stdout.lower():
                self._cli_available = True
                logger.info("Claude CLI OAuth: available")
                return True
        except Exception as e:
            logger.warning(f"Claude CLI check failed: {e}")

        self._cli_available = False
        return False

    async def _try_cli(
        self, prompt: str, system: str, model: str, max_tokens: int
    ) -> Optional[ModelResponse]:
        """Call Claude via CLI subprocess using OAuth auth (no API key needed)."""
        cli = self._find_claude_cli()
        if not cli:
            return None

        # Map model names to CLI model flags
        cli_model = "haiku"  # Default to cheap/fast
        model_lower = model.lower() if model else ""
        if "sonnet" in model_lower:
            cli_model = "sonnet"
        elif "opus" in model_lower:
            cli_model = "opus"
        elif "haiku" in model_lower:
            cli_model = "haiku"

        # Check rate limit
        limiter = self._get_limiter("cli")
        if not limiter.acquire():
            return None

        full_prompt = f"{system}\n\n---\n\n{prompt}" if system else prompt

        cmd = [
            cli, "-p",
            "--model", cli_model,
            "--output-format", "json",
            "--max-turns", "1",
            "--dangerously-skip-permissions",
            "--no-session-persistence",
            "--append-system-prompt", "Respond ONLY with the requested format. No tool use.",
        ]

        import subprocess
        start = time.monotonic()
        try:
            loop = asyncio.get_event_loop()
            result = await loop.run_in_executor(
                None,
                lambda: subprocess.run(
                    cmd, input=full_prompt,
                    capture_output=True, text=True,
                    timeout=90, encoding="utf-8",
                )
            )

            if result.returncode != 0:
                logger.warning(f"CLI error (rc={result.returncode}): {result.stderr[:200]}")
                return None

            latency = (time.monotonic() - start) * 1000

            # Parse CLI JSON output
            try:
                output = json.loads(result.stdout)
                text = output.get("result", "")
            except json.JSONDecodeError:
                text = result.stdout.strip()

            if not text:
                return None

            usage_data = {"prompt_tokens": len(full_prompt) // 4, "completion_tokens": len(text) // 4}
            self.usage.record(f"cli/{cli_model}", usage_data, 0.0)  # Free!

            logger.info(f"CLI ({cli_model}): {len(text)} chars, {latency:.0f}ms")
            return ModelResponse(
                text=text,
                model=f"cli/{cli_model}",
                provider="cli",
                usage=usage_data,
                latency_ms=latency,
                cost_estimate=0.0,  # OAuth = free
            )

        except subprocess.TimeoutExpired:
            logger.error("CLI timed out after 90s")
            return None
        except Exception as e:
            logger.error(f"CLI call failed: {e}")
            return None

    # ── Direct Ollama Backend (bypasses LiteLLM for local models) ─────────
    async def _try_ollama_direct(
        self, model: str, prompt: str, system: str, max_tokens: int
    ) -> Optional[ModelResponse]:
        """Call Ollama directly via HTTP API (avoids LiteLLM issues with reasoning models)."""
        import urllib.request

        # Strip ollama/ prefix
        ollama_model = model.replace("ollama/", "")
        ollama_url = os.environ.get("OLLAMA_HOST", "http://localhost:11434")

        full_prompt = f"{system}\n\n{prompt}" if system else prompt

        body = json.dumps({
            "model": ollama_model,
            "prompt": full_prompt,
            "stream": False,
            "options": {"num_predict": max_tokens},
        }).encode()

        limiter = self._get_limiter("ollama")
        if not limiter.acquire():
            return None

        start = time.monotonic()
        try:
            loop = asyncio.get_event_loop()
            def _fetch():
                req = urllib.request.Request(
                    f"{ollama_url}/api/generate",
                    data=body,
                    headers={"Content-Type": "application/json"},
                )
                with urllib.request.urlopen(req, timeout=90) as r:
                    return json.loads(r.read().decode())

            data = await loop.run_in_executor(None, _fetch)
            latency = (time.monotonic() - start) * 1000

            text = data.get("response", "").strip()
            thinking = data.get("thinking", "")

            # DeepSeek R1 may put everything in thinking with empty response
            if not text and thinking:
                # Extract the useful conclusion from thinking
                text = thinking.strip()
                # If thinking has a conclusion after reasoning, use that
                if "\n\n" in text:
                    text = text.split("\n\n")[-1].strip()

            if not text:
                return None

            # Approximate token counts
            prompt_tokens = data.get("prompt_eval_count", len(full_prompt) // 4)
            completion_tokens = data.get("eval_count", len(text) // 4)
            usage_data = {"prompt_tokens": prompt_tokens, "completion_tokens": completion_tokens}

            self.usage.record(model, usage_data, 0.0)
            logger.info(f"Ollama ({ollama_model}): {len(text)} chars, {latency:.0f}ms")

            return ModelResponse(
                text=text,
                model=model,
                provider="ollama",
                usage=usage_data,
                latency_ms=latency,
                cost_estimate=0.0,
            )

        except Exception as e:
            logger.warning(f"Ollama direct failed: {e}")
            return None

    async def complete(
        self,
        prompt: str,
        system: str = "",
        model: Optional[str] = None,
        max_tokens: Optional[int] = None,
        temperature: Optional[float] = None,
        json_mode: bool = False,
    ) -> Optional[ModelResponse]:
        """
        Send a completion request with automatic fallback.

        Args:
            prompt: User message content.
            system: System prompt.
            model: Model to use (defaults to VIPER_MODEL).
            max_tokens: Override default max tokens.
            temperature: Override default temperature.
            json_mode: Request JSON output format if provider supports it.

        Returns:
            ModelResponse on success, None if all models fail.
        """
        target_model = model or self.default_model
        effective_max_tokens = max_tokens or self.max_tokens

        # Priority 1: Claude CLI (OAuth — free, no API key needed)
        if self.use_cli and self._cli_is_available():
            result = await self._try_cli(
                prompt=prompt,
                system=system,
                model=target_model,
                max_tokens=effective_max_tokens,
            )
            if result is not None:
                return result
            logger.info("CLI failed, falling back to API/Ollama")

        # Priority 2: Direct Ollama (for local models — bypasses LiteLLM issues)
        models_to_try = [target_model] + [
            m for m in self.fallback_models if m != target_model
        ]

        for m in models_to_try:
            if m.startswith("ollama/"):
                result = await self._try_ollama_direct(
                    model=m,
                    prompt=prompt,
                    system=system,
                    max_tokens=effective_max_tokens,
                )
                if result is not None:
                    return result
                continue

            # Priority 3: LiteLLM (paid API)
            result = await self._try_model(
                model=m,
                prompt=prompt,
                system=system,
                max_tokens=effective_max_tokens,
                temperature=temperature if temperature is not None else self.temperature,
                json_mode=json_mode,
            )
            if result is not None:
                return result

        logger.error("All models failed for request (CLI + Ollama + API)")
        return None

    async def _try_model(
        self,
        model: str,
        prompt: str,
        system: str,
        max_tokens: int,
        temperature: float,
        json_mode: bool,
    ) -> Optional[ModelResponse]:
        """Attempt a single model call with rate limiting."""
        self._ensure_litellm()
        provider = self._provider_from_model(model)
        limiter = self._get_limiter(provider)

        # Wait for rate limit slot
        if not limiter.acquire():
            wait = limiter.wait_time
            if wait > 10:
                logger.warning(f"Rate limited on {provider}, skipping to fallback")
                return None
            await asyncio.sleep(wait)
            if not limiter.acquire():
                return None

        messages = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})

        kwargs: Dict[str, Any] = {
            "model": model,
            "messages": messages,
            "max_tokens": max_tokens,
            "temperature": temperature,
        }
        if self.api_base:
            kwargs["api_base"] = self.api_base
        if json_mode:
            kwargs["response_format"] = {"type": "json_object"}

        start = time.monotonic()
        try:
            response = await self._litellm.acompletion(**kwargs)
            latency = (time.monotonic() - start) * 1000

            text = response.choices[0].message.content or ""
            usage_data = {}
            if hasattr(response, "usage") and response.usage:
                usage_data = {
                    "prompt_tokens": getattr(response.usage, "prompt_tokens", 0) or 0,
                    "completion_tokens": getattr(response.usage, "completion_tokens", 0) or 0,
                }

            cost = self.usage.estimate_cost(model, usage_data)
            self.usage.record(model, usage_data, cost)

            return ModelResponse(
                text=text,
                model=model,
                provider=provider,
                usage=usage_data,
                latency_ms=latency,
                cost_estimate=cost,
            )

        except Exception as e:
            self.usage.record_error(model)
            logger.warning(f"Model {model} failed: {e}")
            return None

    # ── Per-task model routing ─────────────────────────────────────────
    # Maps task types to optimal model tiers. Each tier resolves to a
    # concrete model via environment variables or sensible defaults.
    # Override any mapping with VIPER_TASK_<TASK>_MODEL env var.

    TASK_MODEL_MAP: Dict[str, str] = {
        # Fast/cheap — high volume, low complexity
        "recon": "haiku",
        "classification": "haiku",
        "tech_detect": "haiku",
        "crawl_analysis": "haiku",
        # Balanced — moderate complexity
        "reasoning": "sonnet",
        "triage": "sonnet",
        "scan_analysis": "sonnet",
        "attack_planning": "sonnet",
        "finding_validation": "sonnet",
        # Best quality — complex analysis, high stakes
        "deep_analysis": "opus",
        "report_writing": "opus",
        "exploit_dev": "opus",
        "chain_analysis": "opus",
        "ciso_report": "opus",
        # Default fallback
        "default": "sonnet",
    }

    # Token limits per task type (override with max_tokens param)
    TASK_TOKEN_LIMITS: Dict[str, int] = {
        "recon": 512,
        "classification": 256,
        "tech_detect": 256,
        "crawl_analysis": 512,
        "reasoning": 1024,
        "triage": 1024,
        "scan_analysis": 1024,
        "attack_planning": 2048,
        "finding_validation": 1024,
        "deep_analysis": 4096,
        "report_writing": 4096,
        "exploit_dev": 2048,
        "chain_analysis": 2048,
        "ciso_report": 4096,
        "default": 1024,
    }

    def _resolve_task_model(self, task: str) -> str:
        """Resolve a task type to a concrete model string.

        Resolution order:
        1. VIPER_TASK_<TASK>_MODEL env var (e.g., VIPER_TASK_RECON_MODEL)
        2. Existing specific model env vars (VIPER_TRIAGE_MODEL, etc.)
        3. TASK_MODEL_MAP tier -> concrete model mapping
        4. Default model
        """
        # 1. Task-specific env var override
        env_key = f"VIPER_TASK_{task.upper()}_MODEL"
        env_model = os.environ.get(env_key)
        if env_model:
            return env_model

        # 2. Legacy env vars for backward compatibility
        legacy_map = {
            "triage": self.triage_model,
            "reasoning": self.reasoning_model,
        }
        if task in legacy_map:
            return legacy_map[task]

        # 3. Tier-based resolution from TASK_MODEL_MAP
        tier = self.TASK_MODEL_MAP.get(task, self.TASK_MODEL_MAP.get("default", "sonnet"))

        # Map tier names to concrete models
        tier_to_model = {
            "haiku": os.environ.get("VIPER_HAIKU_MODEL", "anthropic/claude-haiku-4-5-20251001"),
            "sonnet": os.environ.get("VIPER_SONNET_MODEL", self.default_model),
            "opus": os.environ.get("VIPER_OPUS_MODEL", "anthropic/claude-opus-4-20250514"),
        }

        return tier_to_model.get(tier, self.default_model)

    async def complete_for_task(
        self,
        task: str,
        prompt: str,
        system: str = "",
        max_tokens: Optional[int] = None,
        temperature: Optional[float] = None,
        json_mode: bool = False,
    ) -> Optional[ModelResponse]:
        """
        Route to the appropriate model based on task type.

        Supports 15 task types across 3 tiers (haiku/sonnet/opus).
        Override routing with VIPER_TASK_<TASK>_MODEL env vars.

        Args:
            task: Task type — one of: recon, classification, tech_detect,
                  crawl_analysis, reasoning, triage, scan_analysis,
                  attack_planning, finding_validation, deep_analysis,
                  report_writing, exploit_dev, chain_analysis, ciso_report,
                  default.
            prompt: User message.
            system: System prompt.
            max_tokens: Override default max tokens for this task.
            temperature: Override default temperature.
            json_mode: Request JSON output.

        Returns:
            ModelResponse on success, None if all models fail.
        """
        model = self._resolve_task_model(task)
        effective_max_tokens = max_tokens or self.TASK_TOKEN_LIMITS.get(task, self.max_tokens)

        logger.debug(f"Task '{task}' routed to model '{model}' (max_tokens={effective_max_tokens})")

        return await self.complete(
            prompt=prompt,
            system=system,
            model=model,
            max_tokens=effective_max_tokens,
            temperature=temperature,
            json_mode=json_mode,
        )

    @property
    def is_available(self) -> bool:
        """Check if at least one LLM backend is available."""
        # Claude CLI OAuth (free — no API key needed, uses existing login)
        if self.use_cli and self._cli_is_available():
            return True
        # API keys
        env_keys = [
            "ANTHROPIC_API_KEY", "OPENAI_API_KEY", "DEEPSEEK_API_KEY",
            "VIPER_API_KEY", "VIPER_API_BASE",
        ]
        if any(os.environ.get(k) for k in env_keys):
            return True
        # Ollama (usually no key needed)
        if "ollama" in self.default_model.lower():
            return True
        return False
