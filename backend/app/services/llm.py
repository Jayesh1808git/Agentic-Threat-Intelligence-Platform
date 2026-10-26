import hashlib
import json
import logging
import random
import threading
import time
from pathlib import Path
from typing import Any, Type, TypeVar
import requests
from pydantic import BaseModel, ValidationError

from app.core.config import settings

logger = logging.getLogger("llm_service")

T = TypeVar("T", bound=BaseModel)
_GROQ_REQUEST_LOCK = threading.Lock()
_LAST_GROQ_REQUEST_AT = 0.0


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
        self.primary_model = getattr(settings, "GROQ_MODEL", "openai/gpt-oss-20b")
        self.fallback_model = getattr(settings, "GROQ_FALLBACK_MODEL", "openai/gpt-oss-20b")
        self.max_retries = max(1, getattr(settings, "LLM_MAX_RETRIES", 3))
        self.base_delay = getattr(settings, "LLM_BASE_RETRY_DELAY", 2.0)
        self.max_delay = max(0.0, getattr(settings, "LLM_MAX_RETRY_DELAY", 60.0))
        rpm = max(1, getattr(settings, "LLM_RATE_LIMIT_RPM", 30))
        # Proactive spacing: keep at least 60/RPM seconds between requests
        # but no less than the explicit setting.
        interval_from_rpm = 60.0 / rpm
        self.min_request_interval = max(
            interval_from_rpm,
            getattr(settings, "LLM_MIN_REQUEST_INTERVAL_SECONDS", 2.0),
        )
        self.max_input_chars = getattr(settings, "MAX_LLM_INPUT_CHARS", 12000)
        self.cache_enabled = getattr(settings, "LLM_CACHE_ENABLED", True)
        self.cache_dir = Path(getattr(settings, "LLM_CACHE_DIR", ".llm_cache"))
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

        cache_key = self._cache_key(messages, model, json_output, temperature)
        cached_response = self._read_cache(cache_key)
        if cached_response is not None:
            return cached_response

        if self.provider == "groq":
            result = self._call_groq(
                messages,
                model=model,
                json_output=json_output,
                temperature=temperature,
                agent_name=agent_name,
            )
        elif self.provider == "openai":
            result = self._call_openai(messages, model=model or "gpt-4o-mini", json_output=json_output, temperature=temperature)
        elif self.provider == "gemini":
            result = self._call_gemini(prompt=prompt, system_prompt=system_prompt, model=model or "gemini-1.5-flash")
        else:
            raise ValueError(f"Unsupported LLM provider: {self.provider}")

        self._write_cache(cache_key, result)
        return result

    def _cache_key(
        self,
        messages: list[dict[str, str]],
        model: str | None,
        json_output: bool,
        temperature: float,
    ) -> str:
        key_data = json.dumps(
            {
                "provider": self.provider,
                "model": model or self.primary_model,
                "messages": messages,
                "json_output": json_output,
                "temperature": temperature,
            },
            sort_keys=True,
        )
        return hashlib.sha256(key_data.encode("utf-8")).hexdigest()

    def _read_cache(self, key: str) -> str | None:
        if not self.cache_enabled:
            return None
        cache_path = self.cache_dir / f"{key}.txt"
        try:
            return cache_path.read_text(encoding="utf-8") if cache_path.is_file() else None
        except OSError:
            logger.warning("Unable to read LLM response cache at %s", cache_path)
            return None

    def _write_cache(self, key: str, response: str) -> None:
        if not self.cache_enabled:
            return
        cache_path = self.cache_dir / f"{key}.txt"
        try:
            cache_path.parent.mkdir(parents=True, exist_ok=True)
            cache_path.write_text(response, encoding="utf-8")
        except OSError:
            logger.warning("Unable to write LLM response cache at %s", cache_path)

    def _call_groq(
        self,
        messages: list[dict[str, str]],
        model: str | None = None,
        json_output: bool = True,
        temperature: float = 0.1,
        agent_name: str | None = None,
    ) -> str:
        global _LAST_GROQ_REQUEST_AT
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

                while True:
                    payload: dict[str, Any] = {
                        "model": current_model,
                        "messages": current_messages,
                        "temperature": temperature,
                    }
                    if json_output:
                        payload["response_format"] = {"type": "json_object"}

                    try:
                        elapsed = time.monotonic() - _LAST_GROQ_REQUEST_AT
                        wait_time = self.min_request_interval - elapsed
                        if wait_time > 0:
                            time.sleep(wait_time)
                        _LAST_GROQ_REQUEST_AT = time.monotonic()
                        self._increment_metric("llm_call_count")
                        response = requests.post(url, headers=headers, json=payload, timeout=60)
                    except requests.RequestException as exc:
                        self.mark_fallback("groq_unavailable")
                        raise RuntimeError("Groq request unavailable") from exc

                    if response.status_code == 200:
                        self._mark_llm_success()
                        data = response.json()
                        return data["choices"][0]["message"]["content"]

                    if response.status_code == 429:
                        self._increment_metric("rate_limit_count")
                        rate_limit_retries += 1

                        retry_after = self._resolve_retry_after(
                            response.headers,
                            attempt=rate_limit_retries,
                        )

                        logger.warning(
                            "[LLM] 429 rate-limited agent=%s model=%s "
                            "retry=%d/%d sleep=%.1fs "
                            "remaining_requests=%s reset_requests=%s "
                            "remaining_tokens=%s reset_tokens=%s",
                            agent_name or "llm",
                            current_model,
                            rate_limit_retries,
                            self.max_retries,
                            retry_after,
                            response.headers.get("x-ratelimit-remaining-requests"),
                            response.headers.get("x-ratelimit-reset-requests"),
                            response.headers.get("x-ratelimit-remaining-tokens"),
                            response.headers.get("x-ratelimit-reset-tokens"),
                        )

                        if rate_limit_retries <= self.max_retries:
                            self._increment_metric("retry_count")
                            time.sleep(retry_after)
                            _LAST_GROQ_REQUEST_AT = time.monotonic()
                            continue  # retry same model

                        # Exhausted retries for this model — try fallback
                        logger.warning(
                            "[LLM] Exhausted %d retries on model=%s. Moving to next model.",
                            self.max_retries,
                            current_model,
                        )
                        break  # break inner while → next model in for-loop

                    # Any other non-200 status: log and move to next model
                    logger.warning(
                        "[LLM] Unexpected status=%d agent=%s model=%s body=%s",
                        response.status_code,
                        agent_name or "llm",
                        current_model,
                        response.text[:200],
                    )
                    break  # break inner while → next model

            self.mark_fallback("all_models_failed")
            raise RuntimeError(
                f"All LLM models exhausted (rate-limited or error) for agent={agent_name}. "
                "Check Groq RPM quota or increase LLM_RATE_LIMIT_RPM spacing."
            )

    def _resolve_retry_after(
        self,
        headers: Any,
        attempt: int,
    ) -> float:
        """
        Determine how many seconds to wait after a 429 response.

        Priority:
        1. ``retry-after`` header (integer seconds or float).
        2. ``x-ratelimit-reset-requests`` header (seconds until request quota resets).
        3. Exponential backoff: base_delay * 2^(attempt-1) + small jitter, capped at max_delay.
        """
        # --- retry-after header ---
        retry_after_raw = headers.get("retry-after")
        if retry_after_raw is not None:
            try:
                wait = float(retry_after_raw)
                if wait > 0:
                    return min(wait + 0.5, self.max_delay)  # tiny buffer
            except (ValueError, TypeError):
                pass

        # --- x-ratelimit-reset-requests header (e.g. "1.5s" or "60") ---
        reset_raw = headers.get("x-ratelimit-reset-requests")
        if reset_raw is not None:
            try:
                reset_str = str(reset_raw).rstrip("s")
                wait = float(reset_str)
                if 0 < wait <= self.max_delay:
                    return wait + 0.5
            except (ValueError, TypeError):
                pass

        # --- exponential backoff with jitter ---
        delay = min(self.base_delay * (2 ** (attempt - 1)), self.max_delay)
        jitter = random.uniform(0.0, min(1.0, delay * 0.1))
        return delay + jitter

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
        json_schema_override: dict[str, Any] | None = None,
    ) -> T:
        """
        Invoke LLM and parse the output directly into a Pydantic model.
        Retries once if JSON validation fails.
        """
        schema = (
            json_schema_override
            if json_schema_override is not None
            else response_model.model_json_schema()
        )
        json_instruction = (
            "\n\nReturn ONLY a valid JSON object strictly matching this schema:\n"
            f"{json.dumps(schema, indent=2)}\n"
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
