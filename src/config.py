"""
VulnBastion / TawasolPay CyberSentinel — Enterprise Configuration
Centralized, validated settings with environment variable support.
"""
from pathlib import Path
from typing import Dict, List, Optional
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


# Project directory roots
_SRC_DIR = Path(__file__).resolve().parent
_PROJECT_ROOT = _SRC_DIR.parent


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=str(_PROJECT_ROOT / ".env"),
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # Environment
    ENVIRONMENT: str = Field(default="development", description="Runtime environment (development, test, production)")
    DEBUG: bool = Field(default=False, description="Enable debug logging and diagnostics")

    # Paths
    PROJECT_ROOT: Path = Field(default=_PROJECT_ROOT)
    SRC_DIR: Path = Field(default=_SRC_DIR)
    DATA_DIR: Path = Field(default=_PROJECT_ROOT / "data")
    RAW_DATA_DIR: Path = Field(default=_PROJECT_ROOT / "data" / "raw")
    EXTERNAL_DATA_DIR: Path = Field(default=_PROJECT_ROOT / "data" / "external")
    CHROMA_DIR: Path = Field(default=_PROJECT_ROOT / "data" / "chroma_nist")
    OUTPUT_DIR: Path = Field(default=_PROJECT_ROOT)

    # Data Source Filenames
    ASSETS_FILE: str = "assets.csv"
    VULNERABILITIES_FILE: str = "vulnerabilities.csv"
    THREAT_INTEL_FILE: str = "threat_intelligence.csv"
    BUSINESS_SERVICES_FILE: str = "business_services.csv"
    REMEDIATION_FILE: str = "remediation_guidance.csv"
    NIST_CATALOG_FILE: str = "NIST_SP-800-53_rev5_catalog_load.csv"
    CISA_KEV_FILE: str = "known_exploited_vulnerabilities.csv"

    # External APIs
    CISA_KEV_URL: str = "https://www.cisa.gov/sites/default/files/csv/known_exploited_vulnerabilities.csv"
    CISA_KEV_TIMEOUT_SECONDS: int = 15

    # LLM Settings
    GROQ_API_KEY: Optional[str] = Field(default=None, description="Groq API key")
    PRIMARY_MODEL: str = Field(default="llama-3.3-70b-versatile", description="Primary Groq model")
    FALLBACK_MODEL: str = Field(default="llama-3.1-8b-instant", description="Fallback model if primary fails")
    LLM_TEMPERATURE: float = Field(default=0.2, ge=0.0, le=1.0)
    LLM_TIMEOUT_SECONDS: float = Field(default=30.0, gt=0.0)
    LLM_MAX_RETRIES: int = Field(default=3, ge=1)
    LLM_RETRY_BACKOFF_FACTOR: float = Field(default=1.5, ge=1.0)
    ALLOW_MOCK_FALLBACK: bool = Field(
        default=True, 
        description="Allow deterministic mock response when no API key is provided (for CI and offline dev)"
    )

    # RAG Settings
    EMBEDDING_MODEL: str = "BAAI/bge-small-en-v1.5"
    COLLECTION_NAME: str = "nist_800_53"
    TOP_K_PER_QUERY: int = 3
    BATCH_SIZE: int = 100
    BGE_QUERY_PREFIX: str = "Represent this sentence for searching relevant passages: "

    # Scoring Dimension Weights (sum to 1.0)
    DIMENSION_WEIGHTS: Dict[str, float] = {
        "threat": 0.30,
        "exposure": 0.25,
        "criticality": 0.25,
        "severity": 0.10,
        "hygiene": 0.10,
    }

    # Telemetry and Observability
    LOG_LEVEL: str = Field(default="INFO")
    STRUCTURED_LOGS: bool = Field(default=False, description="Output JSON formatted logs")
    CHROMA_TELEMETRY: bool = False

    # Security, Auth & RBAC
    REQUIRE_AUTH: bool = Field(default=False, description="Enforce API Key authentication and RBAC")
    API_KEYS: Dict[str, str] = Field(
        default_factory=lambda: {
            "dev-admin-key": "admin",
            "dev-analyst-key": "analyst",
            "dev-viewer-key": "viewer",
        },
        description="Map of API Key to assigned Role (viewer, analyst, admin)"
    )
    RATE_LIMIT_PER_MINUTE: int = Field(default=120, description="Max requests per minute per client IP")

    # Background Job Worker
    WORKER_MAX_CONCURRENT_JOBS: int = Field(default=4, description="Max concurrent background jobs")
    WORKER_JOB_TIMEOUT_SECONDS: int = Field(default=120, description="Max seconds before job times out")
    WORKER_MAX_RETRIES: int = Field(default=3, description="Max retries before moving to Dead-Letter Queue")

    @property
    def has_valid_api_key(self) -> bool:
        """Check if a non-placeholder Groq API key is present."""
        if not self.GROQ_API_KEY:
            return False
        cleaned = self.GROQ_API_KEY.strip()
        return bool(cleaned and not cleaned.startswith("your_actual") and len(cleaned) > 10)


# Global settings singleton
settings = Settings()

