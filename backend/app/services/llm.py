import json
import logging
import random
import threading
import time
from typing import Any, Type, TypeVar
import requests
from pydantic import BaseModel, ValidationError

from app.core.config import settings

logger = logging.getLogger("llm_service")

T = TypeVar("T", bound=BaseModel)
_GROQ_REQUEST_LOCK = threading.Lock()


class LLMService:
    """
    Unified LLM Service supporting Groq, OpenAI, and Gemini APIs.
    Supports structured JSON generation, exponential backoff, and Pydantic parsing.
    """

    def __init__(self):
        self.provider = settings.LLM_PROVIDER.lower() if settings.LLM_PROVIDER else "groq"
        self.enabled = settings.LLM_ENABLED
        self.groq_api_key = settings.GROQ_API_KEY
        self.openai_api_key = settings.OPENAI_API_KEY
        self.gemini_api_key = settings.GEMINI_API_KEY
        self.primary_model = getattr(settings, "GROQ_MODEL", "openai/gpt-oss-120b")
        self.fallback_model = getattr(settings, "GROQ_FALLBACK_MODEL", "openai/gpt-oss-20b")
        self.max_retries = min(1, max(0, getattr(settings, "LLM_MAX_RETRIES", 1)))
        self.base_delay = getattr(settings, "LLM_BASE_RETRY_DELAY", 2.0)
        self.max_delay = min(10.0, max(0.0, getattr(settings, "LLM_MAX_RETRY_DELAY", 10.0)))
        self.max_input_chars = getattr(settings, "MAX_LLM_INPUT_CHARS", 12000)
        self._metrics_lock = threading.Lock()
        self._metrics: dict[str, Any] = {}
        self.reset_metrics()

    def reset_metrics(self) -> None:
        reason = None
        if not self.enabled:
            reason = "llm_disabled"
        elif not self.is_configured():
            reason = "llm_not_configured"
        self._metrics = {
            "llm_used": False,
            "fallback_used": reason is not None,
            "fallback_reason": reason,
            "llm_call_count": 0,
            "rate_limit_count": 0,
            "retry_count": 0,
            "fallback_count": 1 if reason else 0,
        }

    def metrics_snapshot(self) -> dict[str, Any]:
        with self._metrics_lock:
            return dict(self._metrics)

    def _increment_metric(self, name: str, amount: int = 1) -> None:
        with self._metrics_lock:
            self._metrics[name] = self._metrics.get(name, 0) + amount

    def _mark_llm_success(self) -> None:
        with self._metrics_lock:
            self._metrics["llm_used"] = True

    def mark_fallback(self, reason: str) -> None:
        with self._metrics_lock:
            self._metrics["fallback_used"] = True
            self._metrics["fallback_count"] = self._metrics.get("fallback_count", 0) + 1
            if not self._metrics.get("fallback_reason"):
                self._metrics["fallback_reason"] = reason

    def is_configured(self) -> bool:
        if not self.enabled:
            return False
        if self.provider == "groq":
            return bool(self.groq_api_key and self.groq_api_key.strip())
        elif self.provider == "openai":
            return bool(self.openai_api_key and self.openai_api_key.strip())
        elif self.provider == "gemini":
            return bool(self.gemini_api_key and self.gemini_api_key.strip())
        return False

    def invoke(
        self,
        prompt: str,
        system_prompt: str | None = None,
        json_output: bool = True,
        model: str | None = None,
        temperature: float = 0.1,
        agent_name: str | None = None,
    ) -> str:
        """
        Invoke the configured LLM provider. Returns raw string response.
        """
        if not self.is_configured():
            logger.warning("LLM provider %s is not configured (missing API key).", self.provider)
            raise RuntimeError(f"LLM provider '{self.provider}' API key is not configured.")

        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})

        if self.provider == "groq":
            return self._call_groq(
                messages,
                model=model,
                json_output=json_output,
                temperature=temperature,
                agent_name=agent_name,
            )
        elif self.provider == "openai":
            return self._call_openai(messages, model=model or "gpt-4o-mini", json_output=json_output, temperature=temperature)
        elif self.provider == "gemini":
            return self._call_gemini(prompt=prompt, system_prompt=system_prompt, model=model or "gemini-1.5-flash")
        else:
            raise ValueError(f"Unsupported LLM provider: {self.provider}")

    def _call_groq(
        self,
        messages: list[dict[str, str]],
        model: str | None = None,
        json_output: bool = True,
        temperature: float = 0.1,
        agent_name: str | None = None,
    ) -> str:
        with _GROQ_REQUEST_LOCK:
            url = "https://api.groq.com/openai/v1/chat/completions"
            headers = {
                "Authorization": f"Bearer {self.groq_api_key}",
                "Content-Type": "application/json",
            }
            primary = model or self.primary_model
            models_to_try = [primary]
            if self.fallback_model and self.fallback_model != primary:
                models_to_try.append(self.fallback_model)

            def compact_messages(msgs: list[dict[str, str]], max_chars: int) -> list[dict[str, str]]:
                compacted = []
                for message in msgs:
                    content = message.get("content", "")
                    if len(content) > max_chars:
                        half = max_chars // 2
                        content = content[:half] + "\n...[compacted]...\n" + content[-half:]
                    compacted.append({"role": message.get("role", "user"), "content": content})
                return compacted

            current_messages = compact_messages(messages, self.max_input_chars)
            for model_index, current_model in enumerate(models_to_try):
                logger.info("[LLM] agent=%s model=%s", agent_name or "llm", current_model)
                rate_limit_retries = 0
                compacted = False

                while True:
                    payload: dict[str, Any] = {
                        "model": current_model,
                        "messages": current_messages,
                        "temperature": temperature,
                    }
                    if json_output:
                        payload["response_format"] = {"type": "json_object"}

                    try:
                        self._increment_metric("llm_call_count")
                        response = requests.post(url, headers=headers, json=payload, timeout=25)
                    except requests.RequestException as exc:
                        self.mark_fallback("groq_unavailable")
                        raise RuntimeError("Groq request unavailable") from exc

                    if response.status_code == 200:
                        self._mark_llm_success()
                        data = response.json()
                        return data["choices"][0]["message"]["content"]

                    if response.status_code == 429:
                        self._increment_metric("rate_limit_count")
                        if model_index == 0 and rate_limit_retries < self.max_retries:
                            retry_after = response.headers.get("Retry-After") or response.headers.get("retry-after")
                            try:
                                retry_delay = float(retry_after) if retry_after else self.base_delay * (2 ** rate_limit_retries)
                            except ValueError:
                                retry_delay = self.base_delay * (2 ** rate_limit_retries)
                            delay = min(10.0, self.max_delay, max(0.0, retry_delay) + random.uniform(0.1, 0.5))
                            rate_limit_retries += 1
                            self._increment_metric("retry_count")
                            logger.warning("[LLM] rate_limited retry=%d/1 delay=%.1fs", rate_limit_retries, delay)
                            time.sleep(delay)
                            continue

                        if model_index == 0 and len(models_to_try) > 1:
                            self.mark_fallback("groq_rate_limit")
                            logger.info("[LLM] fallback model=%s", models_to_try[1])
                            break
                        self.mark_fallback("groq_rate_limit")
                        logger.warning("[LLM] fallback -> deterministic agent=%s", agent_name or "llm")
                        raise RuntimeError("Groq rate limit persisted after the bounded retry")

                    error_text = response.text.lower()
                    oversized = response.status_code == 413 or (
                        response.status_code == 400
                        and any(term in error_text for term in ("context_length_exceeded", "too large", "reduce"))
                    )
                    if oversized:
                        if compacted:
                            self.mark_fallback("context_length_exceeded")
                            raise RuntimeError("Groq request remained too large after compaction")
                        logger.warning("[LLM] compacting oversized request agent=%s", agent_name or "llm")
                        current_messages = compact_messages(messages, max(1000, min(4000, self.max_input_chars // 3)))
                        compacted = True
                        continue

                    if response.status_code == 404:
                        self.mark_fallback("model_not_found")
                        logger.error("[LLM] model_not_found model=%s", current_model)
                        raise RuntimeError(f"Groq model configuration error: '{current_model}' was not found")

                    self.mark_fallback("groq_request_failed")
                    logger.warning("[LLM] request failed agent=%s status=%d", agent_name or "llm", response.status_code)
                    raise RuntimeError(f"Groq request failed with HTTP {response.status_code}")

            raise RuntimeError("Groq primary and single fallback model were rate limited")

    def _call_openai(
        self,
        messages: list[dict[str, str]],
        model: str,
        json_output: bool,
        temperature: float,
    ) -> str:
        url = "https://api.openai.com/v1/chat/completions"
        headers = {
            "Authorization": f"Bearer {self.openai_api_key}",
            "Content-Type": "application/json",
        }
        payload: dict[str, Any] = {
            "model": model,
            "messages": messages,
            "temperature": temperature,
        }
        if json_output:
            payload["response_format"] = {"type": "json_object"}

        response = requests.post(url, headers=headers, json=payload, timeout=30)
        response.raise_for_status()
        data = response.json()
        return data["choices"][0]["message"]["content"]

    def _call_gemini(
        self,
        prompt: str,
        system_prompt: str | None,
        model: str,
    ) -> str:
        url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent?key={self.gemini_api_key}"
        headers = {"Content-Type": "application/json"}
        contents = []
        if system_prompt:
            contents.append({"role": "user", "parts": [{"text": f"System Instruction: {system_prompt}"}]})
        contents.append({"role": "user", "parts": [{"text": prompt}]})

        response = requests.post(url, headers=headers, json={"contents": contents}, timeout=30)
        response.raise_for_status()
        data = response.json()
        return data["candidates"][0]["content"]["parts"][0]["text"]

    def invoke_structured(
        self,
        prompt: str,
        response_model: Type[T],
        system_prompt: str | None = None,
        model: str | None = None,
        agent_name: str | None = None,
    ) -> T:
        """
        Invoke LLM and parse the output directly into a Pydantic model.
        Retries once if JSON validation fails.
        """
        json_instruction = (
            "\n\nReturn ONLY a valid JSON object strictly matching this schema:\n"
            f"{json.dumps(response_model.model_json_schema(), indent=2)}\n"
            "Do NOT include any markdown backticks (```json), preamble, or extra text."
        )
        full_system_prompt = (system_prompt or "") + json_instruction

        for attempt in range(2):
            current_prompt = prompt
            if attempt == 1:
                current_prompt = prompt + "\n\nCRITICAL: Return ONLY valid, parseable JSON matching the schema strictly."
                logger.warning("LLM JSON validation failed for agent=%s. Retrying once with strict output instruction...", agent_name or "structured")

            raw_response = self.invoke(
                prompt=current_prompt,
                system_prompt=full_system_prompt.strip(),
                json_output=True,
                model=model,
                agent_name=agent_name,
            )

            cleaned = raw_response.strip()
            if cleaned.startswith("```json"):
                cleaned = cleaned[7:]
            if cleaned.startswith("```"):
                cleaned = cleaned[3:]
            if cleaned.endswith("```"):
                cleaned = cleaned[:-3]
            cleaned = cleaned.strip()

            try:
                data = json.loads(cleaned)
                return response_model.model_validate(data)
            except (json.JSONDecodeError, ValidationError) as err:
                if attempt == 1:
                    logger.warning("Structured JSON parsing failed twice for agent=%s: %s", agent_name or "structured", err)
                    self.mark_fallback("json_validation_failed")
                    raise RuntimeError(f"JSON validation failed for {response_model.__name__}: {err}") from err


llm_service = LLMService()
