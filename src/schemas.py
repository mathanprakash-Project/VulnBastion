"""
VulnBastion / TawasolPay CyberSentinel — Data Schemas & Validation Models
Pydantic V2 models ensuring robust contracts across pipeline layers.
"""
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field, field_validator


# ----------------------------- Data Ingestion Schemas -----------------------------

class AssetRecord(BaseModel):
    model_config = ConfigDict(extra="ignore")

    asset_id: str
    asset_name: str
    asset_type: str = "Server"
    environment: str = "Production"
    owner_team: Optional[str] = None
    business_service: str
    internet_exposed: str = "No"
    criticality: str = "Medium"
    data_classification: str = "Internal Confidential"
    edr_installed: str = "No"
    last_seen_days: float = 0.0
    location: Optional[str] = "UAE"
    vendor_product: Optional[str] = None


class VulnerabilityRecord(BaseModel):
    model_config = ConfigDict(extra="ignore")

    vuln_id: str
    asset_id: str
    vulnerability_name: str
    cve: str
    severity: str = "Medium"
    cvss: float = Field(default=5.0, ge=0.0, le=10.0)
    exploit_available: str = "No"
    patch_available: str = "Yes"
    days_open: float = 0.0
    asset_exposure: Optional[str] = "Internal"
    auth_required: str = "No"
    status: str = "Open"
    affected_component: Optional[str] = None


class ThreatIntelligenceRecord(BaseModel):
    model_config = ConfigDict(extra="ignore")

    intel_id: str
    threat_actor: str = "Unknown"
    campaign_name: Optional[str] = None
    target_sector: Optional[str] = None
    target_region: Optional[str] = None
    matched_cve_or_control: Optional[str] = None
    exploit_maturity: Optional[str] = None
    active_last_seen: Optional[str] = None
    ransomware_association: str = "No"
    confidence: Optional[str] = "Medium"
    summary: Optional[str] = None


class BusinessServiceRecord(BaseModel):
    model_config = ConfigDict(extra="ignore")

    business_service: str
    business_owner: Optional[str] = None
    business_impact: Optional[str] = None
    customer_facing: str = "No"
    compliance_scope: str = "None"
    revenue_impact: str = "Low"
    rto_hours: float = 24.0
    depends_on: Optional[str] = None
    risk_appetite: str = "Medium"


# ----------------------------- Scored Risk Schema -----------------------------

class ScoredRisk(BaseModel):
    """Full enriched risk record with multi-dimensional scores."""
    model_config = ConfigDict(extra="allow")

    # Identifiers
    asset_name: str
    vulnerability_name: str
    cve: str
    cvss: float
    severity: str

    # Context
    environment: str
    business_service: str
    internet_exposed: str
    edr_installed: str
    days_open: float
    data_classification: str
    compliance_scope: str
    customer_facing: str
    threat_actor: str
    campaign_name: str
    knownRansomwareCampaignUse: str
    exploit_available: str
    patch_available: str

    # Scores
    threat_score: float = Field(ge=0.0, le=10.0)
    exposure_score: float = Field(ge=0.0, le=10.0)
    criticality_score: float = Field(ge=0.0, le=10.0)
    severity_score: float = Field(ge=0.0, le=10.0)
    hygiene_score: float = Field(ge=0.0, le=10.0)
    risk_score: float = Field(ge=0.0, le=10.0)


# ----------------------------- RAG Retrieval Schema -----------------------------

class NISTControlCandidate(BaseModel):
    """A single NIST SP 800-53 candidate retrieved from ChromaDB."""
    model_config = ConfigDict(extra="ignore")

    identifier: str
    name: str
    document: str
    distance: Optional[float] = None
    family: Optional[str] = None

    @field_validator("identifier")
    @classmethod
    def validate_identifier(cls, v: str) -> str:
        clean = v.strip()
        if not clean or len(clean) < 2:
            raise ValueError("NIST Control identifier must be non-empty")
        return clean


# ----------------------------- LLM Explanation Schemas -----------------------------

class ExplanationOutput(BaseModel):
    """Validated structured output from the LLM explainer."""
    model_config = ConfigDict(populate_by_name=True, extra="allow")

    why_it_matters: str = Field(
        ..., min_length=20, description="2-3 sentences citing specific evidence and business impact"
    )
    nist_control_id: str = Field(
        ..., min_length=2, description="Exact control identifier from retrieved candidates (e.g., SI-2)"
    )
    nist_control_name: str = Field(
        ..., min_length=2, description="Exact name from retrieved candidates"
    )
    nist_guidance: str = Field(
        ..., min_length=15, description="Paraphrased guidance grounded in control text"
    )
    recommended_action: str = Field(
        ..., min_length=15, description="Specific, doable action for the security team this week"
    )
    success_metric: str = Field(
        ..., min_length=10, description="Measurable validation metric"
    )
    validation_warning: bool = Field(default=False, alias="_validation_warning")
    candidates_considered: List[str] = Field(default_factory=list, alias="_candidates_considered")


class BriefingEntry(BaseModel):
    """Complete briefing item combining risk metadata and LLM explanation."""
    rank: int = Field(ge=1)
    asset: Optional[str] = None
    vulnerability: Optional[str] = None
    cve: Optional[str] = None
    risk_score: float
    explanation: ExplanationOutput


# ----------------------------- Telemetry & Observability Schemas -----------------------------

class LLMTelemetry(BaseModel):
    """Telemetry record for a single LLM invocation."""
    correlation_id: str
    model: str
    provider: str = "groq"
    prompt_tokens: int = 0
    completion_tokens: int = 0
    total_tokens: int = 0
    latency_seconds: float
    success: bool
    fallback_used: bool = False
    error: Optional[str] = None
    prompt_hash: Optional[str] = None
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class HealthStatus(BaseModel):
    """System health check response."""
    status: str = "healthy"
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    version: str = "1.0.0"
    data_files_available: bool
    vector_db_ready: bool
    llm_configured: bool
    details: Dict[str, Any] = Field(default_factory=dict)
