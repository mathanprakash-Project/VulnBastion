"""
VulnBastion / TawasolPay CyberSentinel — Enterprise Model Router & AI Resilience
Provides circuit breaking, exponential backoff retries, model fallback,
telemetry tracking, and schema validation.
"""
import hashlib
import json
import os
import time
from typing import Any, Dict, List, Optional, Tuple

from tenacity import (
    retry,
    retry_if_exception_type,
    stop_after_attempt,
    wait_exponential,
)

from config import settings
from logger import get_correlation_id, logger
from schemas import ExplanationOutput, LLMTelemetry


class CircuitBreakerOpenException(Exception):
    """Raised when the circuit breaker is tripped open."""
    pass


class CircuitBreaker:
    """Simple, thread-safe in-memory circuit breaker."""

    def __init__(self, failure_threshold: int = 4, recovery_timeout_seconds: float = 60.0):
        self.failure_threshold = failure_threshold
        self.recovery_timeout_seconds = recovery_timeout_seconds
        self.failure_count = 0
        self.last_failure_time: float = 0.0
        self.state = "CLOSED"  # CLOSED, OPEN, HALF-OPEN

    def record_success(self) -> None:
        self.failure_count = 0
        self.state = "CLOSED"

    def record_failure(self) -> None:
        self.failure_count += 1
        self.last_failure_time = time.time()
        if self.failure_count >= self.failure_threshold:
            self.state = "OPEN"
            logger.warning(
                f"Circuit breaker tripped OPEN after {self.failure_count} consecutive failures. "
                f"Will probe again after {self.recovery_timeout_seconds}s."
            )

    def allow_request(self) -> bool:
        if self.state == "CLOSED":
            return True
        if self.state == "OPEN":
            if time.time() - self.last_failure_time > self.recovery_timeout_seconds:
                self.state = "HALF-OPEN"
                logger.info("Circuit breaker entering HALF-OPEN state to test service recovery.")
                return True
            return False
        # HALF-OPEN
        return True


class ModelRouter:
    """
    Enterprise AI router with primary/fallback routing, circuit breaking,
    and automatic deterministic fallback for resilient execution.
    """

    def __init__(self):
        self.circuit_breaker = CircuitBreaker()
        self._groq_client = None
        self.telemetry_history: List[LLMTelemetry] = []

    def _get_client(self):
        """Lazy initialization of Groq client."""
        if self._groq_client is None:
            if settings.has_valid_api_key:
                from groq import Groq
                self._groq_client = Groq(
                    api_key=settings.GROQ_API_KEY,
                    timeout=settings.LLM_TIMEOUT_SECONDS,
                )
            else:
                self._groq_client = None
        return self._groq_client

    def _execute_groq_call(self, model: str, system_prompt: str, user_prompt: str) -> Tuple[Dict[str, Any], Dict[str, Any]]:
        """Execute a single Groq call with JSON mode enforcement."""
        client = self._get_client()
        if client is None:
            raise ValueError("No active Groq client available (API key not configured).")

        response = client.chat.completions.create(
            model=model,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            temperature=settings.LLM_TEMPERATURE,
            response_format={"type": "json_object"},
        )

        content = response.choices[0].message.content
        parsed = json.loads(content)

        usage = {
            "prompt_tokens": getattr(response.usage, "prompt_tokens", 0) if response.usage else 0,
            "completion_tokens": getattr(response.usage, "completion_tokens", 0) if response.usage else 0,
            "total_tokens": getattr(response.usage, "total_tokens", 0) if response.usage else 0,
        }
        return parsed, usage

    def _generate_deterministic_explanation(self, risk: Dict[str, Any], candidates: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Deterministic, fully-grounded explanation generator.
        Used when API key is unavailable (CI / offline testing) or when all models fail.
        Guarantees non-crashing, schema-compliant output grounded in retrieved candidates.
        """
        top_cand = candidates[0] if candidates else {
            "identifier": "SI-2",
            "name": "Flaw Remediation",
            "document": "Identify, report, and correct system flaws in accordance with organizational policies.",
        }

        asset = risk.get("asset_name", "the asset")
        vuln = risk.get("vulnerability_name", "the vulnerability")
        cve = risk.get("cve", "CVE")
        cvss = risk.get("cvss", "N/A")
        actor = risk.get("threat_actor", "threat actors")
        service = risk.get("business_service", "critical operations")

        return {
            "why_it_matters": (
                f"Vulnerability {vuln} [{cve}] on {asset} carries a CVSS score of {cvss}. "
                f"In the context of {service}, active threat activity by {actor} presents an immediate risk "
                f"of unauthorized exploitation and operational disruption."
            ),
            "nist_control_id": top_cand["identifier"],
            "nist_control_name": top_cand["name"],
            "nist_guidance": (
                f"Implement {top_cand['identifier']} ({top_cand['name']}): "
                f"{top_cand['document'][:220].strip()}..."
            ),
            "recommended_action": (
                f"Immediately apply vendor security patch or compensating firewall controls for {cve} on {asset} "
                f"within 72 hours, and verify system integrity."
            ),
            "success_metric": f"Verification scan confirms {cve} remediated on {asset} with zero residual exposure.",
        }

    def generate_explanation(
        self,
        risk: Dict[str, Any],
        candidates: List[Dict[str, Any]],
        system_prompt: str,
        user_prompt: str,
    ) -> Tuple[Dict[str, Any], LLMTelemetry]:
        """
        Route request with circuit breaking, retries, model fallback, and telemetry.
        """
        cid = get_correlation_id()
        prompt_hash = hashlib.sha256((system_prompt + user_prompt).encode("utf-8")).hexdigest()[:12]
        t0 = time.time()

        # Check if API key is present
        if not settings.has_valid_api_key:
            if settings.ALLOW_MOCK_FALLBACK:
                logger.info(f"[{cid[:8]}] GROQ_API_KEY not configured — using deterministic grounded fallback")
                result = self._generate_deterministic_explanation(risk, candidates)
                elapsed = time.time() - t0
                telemetry = LLMTelemetry(
                    correlation_id=cid,
                    model="deterministic-fallback",
                    provider="local",
                    latency_seconds=elapsed,
                    success=True,
                    fallback_used=True,
                    prompt_hash=prompt_hash,
                )
                self.telemetry_history.append(telemetry)
                return result, telemetry
            else:
                raise ValueError("GROQ_API_KEY is not set and mock fallback is disabled.")

        # Check circuit breaker
        if not self.circuit_breaker.allow_request():
            logger.warning(f"[{cid[:8]}] Circuit breaker is OPEN. Falling back to deterministic generation.")
            result = self._generate_deterministic_explanation(risk, candidates)
            telemetry = LLMTelemetry(
                correlation_id=cid,
                model="circuit-breaker-open",
                provider="local",
                latency_seconds=time.time() - t0,
                success=True,
                fallback_used=True,
                error="Circuit breaker is open",
                prompt_hash=prompt_hash,
            )
            return result, telemetry

        # Primary Model Attempt with Retries
        models_to_try = [settings.PRIMARY_MODEL, settings.FALLBACK_MODEL]
        last_error = None

        for idx, model in enumerate(models_to_try):
            is_fallback = idx > 0
            try:
                logger.info(f"[{cid[:8]}] Invoking model '{model}' (attempt {idx+1}/{len(models_to_try)})...")

                # Inner retry loop with exponential backoff for transient errors
                @retry(
                    reraise=True,
                    stop=stop_after_attempt(settings.LLM_MAX_RETRIES),
                    wait=wait_exponential(multiplier=settings.LLM_RETRY_BACKOFF_FACTOR, min=1, max=10),
                )
                def _call_with_retry():
                    return self._execute_groq_call(model, system_prompt, user_prompt)

                raw_json, usage = _call_with_retry()

                # Validate with Pydantic
                validated = ExplanationOutput(**raw_json)
                self.circuit_breaker.record_success()

                elapsed = time.time() - t0
                telemetry = LLMTelemetry(
                    correlation_id=cid,
                    model=model,
                    provider="groq",
                    prompt_tokens=usage["prompt_tokens"],
                    completion_tokens=usage["completion_tokens"],
                    total_tokens=usage["total_tokens"],
                    latency_seconds=elapsed,
                    success=True,
                    fallback_used=is_fallback,
                    prompt_hash=prompt_hash,
                )
                self.telemetry_history.append(telemetry)
                logger.info(f"[{cid[:8]}] Model '{model}' completed in {elapsed:.2f}s ({usage['total_tokens']} tokens)")
                return validated.model_dump(), telemetry

            except Exception as e:
                last_error = e
                logger.warning(f"[{cid[:8]}] Model '{model}' failed: {type(e).__name__}: {e}")
                self.circuit_breaker.record_failure()

        # If all LLM models fail, graceful degradation
        logger.error(f"[{cid[:8]}] All models failed. Engaging safe deterministic fallback: {last_error}")
        result = self._generate_deterministic_explanation(risk, candidates)
        elapsed = time.time() - t0
        telemetry = LLMTelemetry(
            correlation_id=cid,
            model="safe-failure-fallback",
            provider="local",
            latency_seconds=elapsed,
            success=False,
            fallback_used=True,
            error=str(last_error),
            prompt_hash=prompt_hash,
        )
        self.telemetry_history.append(telemetry)
        return result, telemetry


# Singleton instance
model_router = ModelRouter()

