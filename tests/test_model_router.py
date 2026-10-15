"""
Unit tests for ModelRouter, CircuitBreaker, and Fallback Mechanisms.
"""
import pytest
from model_router import CircuitBreaker, ModelRouter
from schemas import ExplanationOutput


def test_circuit_breaker_transitions():
    cb = CircuitBreaker(failure_threshold=3, recovery_timeout_seconds=0.1)

    assert cb.state == "CLOSED"
    assert cb.allow_request() is True

    # Record 2 failures -> remains CLOSED
    cb.record_failure()
    cb.record_failure()
    assert cb.state == "CLOSED"

    # 3rd failure -> trips OPEN
    cb.record_failure()
    assert cb.state == "OPEN"
    assert cb.allow_request() is False

    # After recovery timeout -> HALF-OPEN
    import time
    time.sleep(0.15)
    assert cb.allow_request() is True
    assert cb.state == "HALF-OPEN"

    # Success in HALF-OPEN -> resets to CLOSED
    cb.record_success()
    assert cb.state == "CLOSED"
    assert cb.failure_count == 0


def test_model_router_deterministic_fallback(sample_risk_dict, sample_candidates):
    router = ModelRouter()
    result = router._generate_deterministic_explanation(sample_risk_dict, sample_candidates)

    # Validate output schema
    validated = ExplanationOutput(**result)
    assert validated.nist_control_id == "SI-2"
    assert validated.nist_control_name == "Flaw Remediation"
    assert len(validated.why_it_matters) >= 20
    assert len(validated.recommended_action) >= 15
    assert len(validated.success_metric) >= 10


def test_model_router_schema_validation(sample_risk_dict, sample_candidates):
    router = ModelRouter()
    output, telemetry = router.generate_explanation(
        risk=sample_risk_dict,
        candidates=sample_candidates,
        system_prompt="system",
        user_prompt="user",
    )

    assert output["nist_control_id"] in ["SI-2", "SC-7"]
    assert telemetry.success is True
    assert telemetry.latency_seconds >= 0.0

