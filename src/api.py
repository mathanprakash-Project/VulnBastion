"""
VulnBastion / TawasolPay CyberSentinel — Enterprise REST API
FastAPI backend providing OpenAPI docs, paginated risk queries, on-demand scoring,
agentic explanation workflows, telemetry, and evaluation endpoints.
"""
import sys
from pathlib import Path
_SRC_DIR = Path(__file__).resolve().parent
if str(_SRC_DIR) not in sys.path:
    sys.path.insert(0, str(_SRC_DIR))

from typing import Any, Dict, List, Optional
import pandas as pd
from fastapi import Depends, FastAPI, HTTPException, Query, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from auth import check_rate_limit, get_current_user, require_role, UserIdentity
from config import settings
from data_pipeline import DataIngestionEngine
from evaluator import EvaluationResult, RAGEvaluator
from health import check_health
from jobs import Job, job_manager
from logger import get_correlation_id, logger, set_correlation_id
from model_router import model_router
from risk_engine import RiskScoringEngine
from schemas import HealthStatus
from workflow import RemediationWorkflow, WorkflowState

# ----------------------------- FastAPI Application -----------------------------

app = FastAPI(
    title="TawasolPay CyberSentinel API",
    description="Enterprise Multi-Dimensional Cyber Risk Scoring & NIST SP 800-53 RAG Platform",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ----------------------------- In-Memory State Cache -----------------------------

_cached_master_df: Optional[pd.DataFrame] = None
_cached_scored_df: Optional[pd.DataFrame] = None


def get_scored_data() -> pd.DataFrame:
    """Load and score dataset with lazy caching."""
    global _cached_master_df, _cached_scored_df
    if _cached_scored_df is None:
        logger.info("Initializing in-memory scored dataset cache...")
        engine = DataIngestionEngine()
        _cached_master_df = engine.build_master_risk_table()
        scorer = RiskScoringEngine(_cached_master_df)
        _cached_scored_df = scorer.compute_scores()
    return _cached_scored_df


# ----------------------------- Response Schemas -----------------------------

class PaginatedRisksResponse(BaseModel):
    total_count: int
    skip: int
    limit: int
    data: List[Dict[str, Any]]


class TopRisksResponse(BaseModel):
    scoring_version: str = "1.0"
    weights: Dict[str, float]
    top_n: int
    risks: List[Dict[str, Any]]


class TelemetrySummaryResponse(BaseModel):
    total_calls: int
    total_tokens: int
    fallback_calls: int
    avg_latency_seconds: float
    records: List[Dict[str, Any]]

# ----------------------------- Background Task Definitions -----------------------------

def _execute_bulk_analysis(top_n: int = 5, progress_callback=None):
    from explainer import explain_top_risks, save_briefing
    df = get_scored_data()
    engine = RiskScoringEngine(df)
    engine.df = df
    top_df = engine.get_top_risks(n=top_n)
    records = top_df.to_dict(orient="records")

    if progress_callback:
        progress_callback(0.2)

    json_results, human_text = explain_top_risks(records)
    if progress_callback:
        progress_callback(0.8)

    save_briefing(json_results, human_text, str(settings.OUTPUT_DIR))
    if progress_callback:
        progress_callback(1.0)

    return {
        "risks_analyzed": len(json_results),
        "top_n": top_n,
        "completed_at": str(pd.Timestamp.now().isoformat()),
    }


# ----------------------------- Endpoints -----------------------------

@app.get(
    "/health",
    response_model=HealthStatus,
    tags=["Diagnostics"],
    summary="System health and readiness diagnostics",
)
def get_health():
    """Returns readiness diagnostics of CSV datasets, ChromaDB index, and LLM configuration."""
    return check_health()


@app.get(
    "/api/v1/risks",
    response_model=PaginatedRisksResponse,
    tags=["Risk Register"],
    summary="Query paginated and filtered vulnerabilities",
    dependencies=[Depends(check_rate_limit)],
)
def list_risks(
    skip: int = Query(0, ge=0, description="Offset for pagination"),
    limit: int = Query(20, ge=1, le=100, description="Page size"),
    business_service: Optional[str] = Query(None, description="Filter by business service name"),
    environment: Optional[str] = Query(None, description="Filter by environment (Production, Staging, Development)"),
    severity: Optional[str] = Query(None, description="Filter by CVSS severity category"),
    min_risk_score: Optional[float] = Query(None, ge=0.0, le=10.0, description="Minimum calculated risk score"),
    user: UserIdentity = Depends(require_role("viewer")),
):
    """Retrieve full risk register with filtering by service, environment, severity, and score threshold."""
    df = get_scored_data().copy()

    if business_service:
        df = df[df["business_service"].str.contains(business_service, case=False, na=False)]
    if environment:
        df = df[df["environment"].str.lower() == environment.lower()]
    if severity:
        df = df[df["severity"].str.lower() == severity.lower()]
    if min_risk_score is not None:
        df = df[df["risk_score"] >= min_risk_score]

    total = len(df)
    page_df = df.iloc[skip : skip + limit]

    return PaginatedRisksResponse(
        total_count=total,
        skip=skip,
        limit=limit,
        data=page_df.to_dict(orient="records"),
    )


@app.get(
    "/api/v1/risks/top",
    response_model=TopRisksResponse,
    tags=["Risk Register"],
    summary="Get top-N ranked organization risks",
    dependencies=[Depends(check_rate_limit)],
)
def get_top_risks(
    n: int = Query(5, ge=1, le=20, description="Number of top risks to retrieve"),
    user: UserIdentity = Depends(require_role("viewer")),
):
    """Returns the top-N highest priority vulnerabilities ranked by the multi-dimensional scoring engine."""
    df = get_scored_data()
    engine = RiskScoringEngine(df)
    engine.df = df
    top_df = engine.get_top_risks(n=n)

    return TopRisksResponse(
        weights=settings.DIMENSION_WEIGHTS,
        top_n=n,
        risks=top_df.to_dict(orient="records"),
    )


@app.post(
    "/api/v1/risks/explain",
    tags=["Agentic AI"],
    summary="Run agentic remediation workflow for a risk",
    dependencies=[Depends(check_rate_limit)],
)
def explain_risk_endpoint(
    risk: Dict[str, Any],
    user: UserIdentity = Depends(require_role("analyst")),
):
    """
    Executes the multi-stage Agentic Remediation Workflow:
    Input Sanitization -> Multi-angle RAG -> LLM Synthesis -> Grounding Verification -> Playbook Matching
    """
    if not risk or not isinstance(risk, dict):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Risk payload must be a non-empty dictionary.",
        )

    workflow = RemediationWorkflow()
    state = workflow.run(risk)

    if not state.success:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=state.error or "Workflow failed during execution.",
        )

    return state.model_dump()


@app.get(
    "/api/v1/eval/retrieval",
    response_model=EvaluationResult,
    tags=["AI Evaluation"],
    summary="Run RAG retrieval benchmark harness",
    dependencies=[Depends(check_rate_limit)],
)
def run_retrieval_evaluation(
    top_k: int = Query(5, ge=1, le=10, description="Top-K cutoff for evaluation metrics"),
    user: UserIdentity = Depends(require_role("analyst")),
):
    """Executes the ground-truth benchmark suite and returns Recall@K and MRR metrics."""
    evaluator = RAGEvaluator()
    return evaluator.run_evaluation(top_k=top_k)


@app.get(
    "/api/v1/telemetry",
    response_model=TelemetrySummaryResponse,
    tags=["Observability"],
    summary="View LLM inference telemetry and cost metrics",
    dependencies=[Depends(check_rate_limit)],
)
def get_telemetry(
    user: UserIdentity = Depends(require_role("admin")),
):
    """Returns aggregated metrics on LLM calls, token usage, latency, and fallback utilization."""
    history = model_router.telemetry_history
    total_calls = len(history)
    total_tokens = sum(t.total_tokens for t in history)
    fallback_calls = sum(1 for t in history if t.fallback_used)
    avg_latency = (sum(t.latency_seconds for t in history) / total_calls) if total_calls > 0 else 0.0

    return TelemetrySummaryResponse(
        total_calls=total_calls,
        total_tokens=total_tokens,
        fallback_calls=fallback_calls,
        avg_latency_seconds=round(avg_latency, 3),
        records=[t.model_dump() for t in history[-50:]],
    )


# ----------------------------- Background Job Endpoints -----------------------------

@app.post(
    "/api/v1/jobs/analyze-all",
    response_model=Job,
    tags=["Background Jobs"],
    summary="Trigger asynchronous full risk register briefing analysis",
    dependencies=[Depends(check_rate_limit)],
)
def submit_bulk_analysis_job(
    top_n: int = Query(5, ge=1, le=20, description="Top risks to generate explanations for"),
    user: UserIdentity = Depends(require_role("analyst")),
):
    """Queues a non-blocking background job to re-score risks and generate NIST remediation briefings."""
    return job_manager.submit_job(
        job_type="bulk_risk_analysis",
        task_fn=_execute_bulk_analysis,
        top_n=top_n,
    )


@app.get(
    "/api/v1/jobs",
    response_model=List[Job],
    tags=["Background Jobs"],
    summary="List active and recent background jobs",
    dependencies=[Depends(check_rate_limit)],
)
def list_jobs(
    limit: int = Query(20, ge=1, le=100),
    user: UserIdentity = Depends(require_role("viewer")),
):
    """Returns list of all queued, processing, and completed background jobs."""
    return job_manager.list_jobs(limit=limit)


@app.get(
    "/api/v1/jobs/{job_id}",
    response_model=Job,
    tags=["Background Jobs"],
    summary="Get background job status and result",
    dependencies=[Depends(check_rate_limit)],
)
def get_job_status(
    job_id: str,
    user: UserIdentity = Depends(require_role("viewer")),
):
    """Retrieves progress percentage, current status, and final results of a specific background job."""
    job = job_manager.get_job(job_id)
    if not job:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Job '{job_id}' not found.",
        )
    return job


@app.get(
    "/api/v1/jobs/queue/dead-letter",
    response_model=List[Job],
    tags=["Background Jobs"],
    summary="Inspect dead-letter job queue",
    dependencies=[Depends(check_rate_limit)],
)
def get_dead_letter_queue(
    user: UserIdentity = Depends(require_role("admin")),
):
    """Returns permanently failed jobs that exceeded max retry attempts."""
    return job_manager.get_dead_letter_queue()


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("api:app", host="0.0.0.0", port=8000, reload=True)

