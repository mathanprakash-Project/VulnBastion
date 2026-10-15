"""
Integration tests for FastAPI endpoints using TestClient.
"""
import pytest
from fastapi.testclient import TestClient
from api import app

client = TestClient(app)


def test_health_endpoint():
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] in ["healthy", "degraded"]
    assert data["data_files_available"] is True
    assert data["vector_db_ready"] is True


def test_list_risks_endpoint():
    response = client.get("/api/v1/risks?skip=0&limit=5")
    assert response.status_code == 200
    data = response.json()
    assert "total_count" in data
    assert data["limit"] == 5
    assert len(data["data"]) <= 5
    assert data["total_count"] >= 100


def test_filter_risks_endpoint():
    response = client.get("/api/v1/risks?environment=Production&min_risk_score=7.0")
    assert response.status_code == 200
    data = response.json()
    for item in data["data"]:
        assert item["environment"].lower() == "production"
        assert item["risk_score"] >= 7.0


def test_top_risks_endpoint():
    response = client.get("/api/v1/risks/top?n=3")
    assert response.status_code == 200
    data = response.json()
    assert data["top_n"] == 3
    assert len(data["risks"]) == 3
    # Top risks should be sorted descending
    scores = [r["risk_score"] for r in data["risks"]]
    assert scores == sorted(scores, reverse=True)


def test_explain_risk_endpoint(sample_risk_dict):
    response = client.post("/api/v1/risks/explain", json=sample_risk_dict)
    assert response.status_code == 200
    data = response.json()
    assert data["success"] is True
    assert "explanation" in data
    assert "execution_history" in data
    assert len(data["execution_history"]) >= 4


def test_telemetry_endpoint():
    response = client.get("/api/v1/telemetry")
    assert response.status_code == 200
    data = response.json()
    assert "total_calls" in data
    assert "total_tokens" in data
    assert "avg_latency_seconds" in data


def test_background_jobs_endpoints():
    # Submit job
    response = client.post("/api/v1/jobs/analyze-all?top_n=2")
    assert response.status_code == 200
    job = response.json()
    assert "job_id" in job
    assert job["status"] in ["QUEUED", "PROCESSING", "COMPLETED"]

    # Poll status
    job_id = job["job_id"]
    get_res = client.get(f"/api/v1/jobs/{job_id}")
    assert get_res.status_code == 200
    assert get_res.json()["job_id"] == job_id

    # List jobs
    list_res = client.get("/api/v1/jobs")
    assert list_res.status_code == 200
    assert len(list_res.json()) >= 1

    # Dead-letter queue
    dlq_res = client.get("/api/v1/jobs/queue/dead-letter")
    assert dlq_res.status_code == 200
    assert isinstance(dlq_res.json(), list)

