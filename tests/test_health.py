"""
Unit tests for System Health & Readiness Diagnostics.
"""
import pytest
from health import check_health


def test_system_health_check():
    health = check_health()

    assert health.status in ["healthy", "degraded"]
    assert health.data_files_available is True
    assert health.vector_db_ready is True
    assert "data_files" in health.details
    assert "chromadb" in health.details
    assert "llm" in health.details

