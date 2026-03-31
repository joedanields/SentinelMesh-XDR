"""Abstract base agent for the SentinelMesh XDR multi-agent AI system."""

from __future__ import annotations

import asyncio
import json
import time
from abc import ABC, abstractmethod
from collections import deque
from dataclasses import dataclass, field
from typing import Any, Deque, Dict, List, Optional

import httpx
import structlog

logger = structlog.get_logger(__name__)

OLLAMA_BASE_URL = "http://localhost:11434"
OLLAMA_TIMEOUT = 60.0
DEFAULT_MODEL = "llama3"
FALLBACK_MODEL = "llama3:8b"
MAX_RETRIES = 2
CONTEXT_WINDOW_SIZE = 10


@dataclass
class AgentResult:
    """Standardised result returned by every agent."""

    agent_name: str
    success: bool
    data: Dict[str, Any]
    confidence: float
    elapsed_seconds: float
    model_used: str
    fallback_used: bool = False
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "agent_name": self.agent_name,
            "success": self.success,
            "data": self.data,
            "confidence": self.confidence,
            "elapsed_seconds": self.elapsed_seconds,
            "model_used": self.model_used,
            "fallback_used": self.fallback_used,
            "error": self.error,
        }


class BaseAgent(ABC):
    """
    Abstract base for all SentinelMesh XDR AI agents.

    Subclasses implement:
      - analyze(input_data)   – main entry point
      - build_prompt(input_data) – returns (system_prompt, user_prompt)
      - parse_response(raw)   – converts LLM text → dict
    """

    def __init__(
        self,
        name: str,
        description: str,
        model_name: str = DEFAULT_MODEL,
    ) -> None:
        self.name = name
        self.description = description
        self.model_name = model_name
        self._context: Deque[Dict[str, str]] = deque(maxlen=CONTEXT_WINDOW_SIZE)
        self._metrics: Dict[str, Any] = {
            "total_calls": 0,
            "success_calls": 0,
            "fallback_calls": 0,
            "total_elapsed": 0.0,
        }
        self._log = logger.bind(agent=name)

    # ------------------------------------------------------------------
    # Abstract interface
    # ------------------------------------------------------------------

    @abstractmethod
    async def analyze(self, input_data: Any) -> AgentResult:
        """Analyse input_data and return an AgentResult."""

    @abstractmethod
    def build_prompt(self, input_data: Any) -> tuple[str, str]:
        """Return (system_prompt, user_prompt) for the given input."""

    @abstractmethod
    def parse_response(self, raw_text: str) -> Dict[str, Any]:
        """Parse the raw LLM response text into a structured dict."""

    # ------------------------------------------------------------------
    # Ollama HTTP client
    # ------------------------------------------------------------------

    async def _call_ollama(
        self,
        system_prompt: str,
        user_prompt: str,
        model: Optional[str] = None,
    ) -> str:
        """Call Ollama /api/generate and return the response text."""
        model = model or self.model_name
        prompt = f"<|system|>\n{system_prompt}\n<|user|>\n{user_prompt}\n<|assistant|>\n"

        payload = {
            "model": model,
            "prompt": prompt,
            "stream": False,
            "options": {
                "temperature": 0.1,
                "top_p": 0.9,
                "num_predict": 2048,
            },
        }

        async with httpx.AsyncClient(timeout=OLLAMA_TIMEOUT) as client:
            response = await client.post(
                f"{OLLAMA_BASE_URL}/api/generate",
                json=payload,
            )
            response.raise_for_status()
            data = response.json()
            return data.get("response", "")

    async def _call_with_retry(
        self, system_prompt: str, user_prompt: str
    ) -> tuple[str, str, bool]:
        """
        Try primary model, fall back to simpler model on failure.
        Returns (response_text, model_used, fallback_used).
        """
        last_exc: Optional[Exception] = None
        for attempt in range(MAX_RETRIES):
            try:
                text = await self._call_ollama(system_prompt, user_prompt, self.model_name)
                return text, self.model_name, False
            except Exception as exc:  # noqa: BLE001
                last_exc = exc
                self._log.warning(
                    "ollama_call_failed",
                    attempt=attempt + 1,
                    model=self.model_name,
                    error=str(exc),
                )
                await asyncio.sleep(0.5 * (attempt + 1))

        # Fallback to simpler model
        if FALLBACK_MODEL != self.model_name:
            try:
                text = await self._call_ollama(system_prompt, user_prompt, FALLBACK_MODEL)
                return text, FALLBACK_MODEL, True
            except Exception as exc:  # noqa: BLE001
                last_exc = exc
                self._log.warning("fallback_model_also_failed", error=str(exc))

        raise RuntimeError(f"All Ollama attempts failed: {last_exc}") from last_exc

    # ------------------------------------------------------------------
    # JSON parsing helpers
    # ------------------------------------------------------------------

    def _extract_json(self, text: str) -> Dict[str, Any]:
        """Extract and parse JSON from LLM output (handles markdown fences)."""
        # Strip markdown code fences
        for fence in ("```json", "```"):
            if fence in text:
                parts = text.split(fence)
                if len(parts) >= 3:
                    text = parts[1].strip()
                    break

        # Find first { ... } block
        start = text.find("{")
        end = text.rfind("}") + 1
        if start != -1 and end > start:
            try:
                return json.loads(text[start:end])
            except json.JSONDecodeError:
                pass

        # Last resort – try full text
        try:
            return json.loads(text.strip())
        except json.JSONDecodeError:
            return {}

    def _calculate_confidence(self, parsed: Dict[str, Any], required_keys: List[str]) -> float:
        """
        Heuristic confidence: fraction of required keys present
        multiplied by any explicit confidence value found.
        """
        if not required_keys:
            return 0.5
        present = sum(1 for k in required_keys if k in parsed and parsed[k] is not None)
        structural = present / len(required_keys)
        explicit = float(parsed.get("confidence", structural))
        # Clamp to [0, 1]
        return max(0.0, min(1.0, (structural + explicit) / 2))

    # ------------------------------------------------------------------
    # Context window management
    # ------------------------------------------------------------------

    def _add_to_context(self, role: str, content: str) -> None:
        self._context.append({"role": role, "content": content})

    def get_context(self) -> List[Dict[str, str]]:
        return list(self._context)

    def clear_context(self) -> None:
        self._context.clear()

    # ------------------------------------------------------------------
    # Metrics
    # ------------------------------------------------------------------

    def get_metrics(self) -> Dict[str, Any]:
        total = self._metrics["total_calls"] or 1
        return {
            "agent": self.name,
            "total_calls": self._metrics["total_calls"],
            "success_rate": self._metrics["success_calls"] / total,
            "fallback_rate": self._metrics["fallback_calls"] / total,
            "avg_elapsed_seconds": self._metrics["total_elapsed"] / total,
        }

    # ------------------------------------------------------------------
    # Protected run helper used by subclasses
    # ------------------------------------------------------------------

    async def _run_analysis(
        self,
        input_data: Any,
        required_keys: List[str],
        fallback_fn: Any = None,
    ) -> AgentResult:
        """
        Template-method helper: calls Ollama, parses response, builds AgentResult.
        Calls fallback_fn(input_data) when Ollama is unavailable.
        """
        t0 = time.monotonic()
        self._metrics["total_calls"] += 1

        system_prompt, user_prompt = self.build_prompt(input_data)
        self._add_to_context("user", user_prompt)

        try:
            raw_text, model_used, fallback_used = await self._call_with_retry(
                system_prompt, user_prompt
            )
            self._add_to_context("assistant", raw_text)

            parsed = self.parse_response(raw_text)
            if not parsed:
                raise ValueError("Empty parsed response")

            confidence = self._calculate_confidence(parsed, required_keys)
            if fallback_used:
                self._metrics["fallback_calls"] += 1

            self._metrics["success_calls"] += 1
            elapsed = time.monotonic() - t0
            self._metrics["total_elapsed"] += elapsed

            self._log.info(
                "analysis_complete",
                confidence=round(confidence, 3),
                elapsed=round(elapsed, 3),
                model=model_used,
            )

            return AgentResult(
                agent_name=self.name,
                success=True,
                data=parsed,
                confidence=confidence,
                elapsed_seconds=elapsed,
                model_used=model_used,
                fallback_used=fallback_used,
            )

        except Exception as exc:  # noqa: BLE001
            elapsed = time.monotonic() - t0
            self._metrics["total_elapsed"] += elapsed
            self._log.warning("ollama_unavailable", error=str(exc))

            if fallback_fn is not None:
                try:
                    fallback_data = fallback_fn(input_data)
                    self._metrics["success_calls"] += 1
                    self._metrics["fallback_calls"] += 1
                    return AgentResult(
                        agent_name=self.name,
                        success=True,
                        data=fallback_data,
                        confidence=0.4,
                        elapsed_seconds=time.monotonic() - t0,
                        model_used="rule_based_fallback",
                        fallback_used=True,
                    )
                except Exception as fb_exc:  # noqa: BLE001
                    self._log.error("fallback_fn_failed", error=str(fb_exc))

            return AgentResult(
                agent_name=self.name,
                success=False,
                data={},
                confidence=0.0,
                elapsed_seconds=elapsed,
                model_used="none",
                fallback_used=False,
                error=str(exc),
            )
