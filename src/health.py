"""
VulnBastion / TawasolPay CyberSentinel — System Health & Readiness Verification
Provides readiness and liveness diagnostics for container orchestrators and monitoring.
"""
import os
from typing import Any, Dict

from config import settings
from logger import logger
from schemas import HealthStatus


def check_health() -> HealthStatus:
    """Run comprehensive health checks across all system dependencies."""
    details: Dict[str, Any] = {}

    # 1. Check Raw Data Files
    required_raw_files = [
        settings.ASSETS_FILE,
        settings.VULNERABILITIES_FILE,
        settings.THREAT_INTEL_FILE,
        settings.BUSINESS_SERVICES_FILE,
    ]
    missing_files = []
    for f in required_raw_files:
        p = settings.RAW_DATA_DIR / f
        if not p.exists():
            missing_files.append(f)

    # Check external NIST catalog
    nist_path = settings.EXTERNAL_DATA_DIR / settings.NIST_CATALOG_FILE
    if not nist_path.exists():
        missing_files.append(settings.NIST_CATALOG_FILE)

    data_ok = len(missing_files) == 0
    details["data_files"] = {
        "status": "ok" if data_ok else "degraded",
        "missing": missing_files,
        "raw_dir": str(settings.RAW_DATA_DIR),
    }

    # 2. Check Vector DB
    chroma_ok = False
    doc_count = 0
    try:
        import chromadb
        client = chromadb.PersistentClient(path=str(settings.CHROMA_DIR))
        existing = [c.name for c in client.list_collections()]
        if settings.COLLECTION_NAME in existing:
            col = client.get_collection(settings.COLLECTION_NAME)
            doc_count = col.count()
            chroma_ok = doc_count > 0
        details["chromadb"] = {
            "status": "ok" if chroma_ok else "uninitialized",
            "collection": settings.COLLECTION_NAME,
            "document_count": doc_count,
            "path": str(settings.CHROMA_DIR),
        }
    except Exception as e:
        details["chromadb"] = {
            "status": "error",
            "error": str(e),
        }

    # 3. Check LLM Configuration
    has_api_key = settings.has_valid_api_key
    details["llm"] = {
        "api_key_configured": has_api_key,
        "primary_model": settings.PRIMARY_MODEL,
        "fallback_model": settings.FALLBACK_MODEL,
        "mock_fallback_enabled": settings.ALLOW_MOCK_FALLBACK,
    }

    overall_healthy = data_ok and chroma_ok

    return HealthStatus(
        status="healthy" if overall_healthy else "degraded",
        version="1.0.0",
        data_files_available=data_ok,
        vector_db_ready=chroma_ok,
        llm_configured=has_api_key or settings.ALLOW_MOCK_FALLBACK,
        details=details,
    )


if __name__ == "__main__":
    status = check_health()
    import json
    print(json.dumps(status.model_dump(), indent=2))

