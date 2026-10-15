"""
VulnBastion / TawasolPay CyberSentinel — Agentic Remediation Workflow
Stateful execution graph with checkpointing, multi-angle RAG, grounding verification,
and operational remediation playbook matching.
"""
import os
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional
import pandas as pd
from pydantic import BaseModel, ConfigDict, Field

from config import settings
from logger import get_correlation_id, logger
from model_router import model_router
from rag_agent import retrieve_controls
from schemas import ExplanationOutput
from security import sanitize_risk_record


# ----------------------------- Workflow State Models -----------------------------

class NodeExecutionRecord(BaseModel):
    node_name: str
    status: str
    latency_ms: float
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    details: Optional[Dict[str, Any]] = None


class RemediationPlaybook(BaseModel):
    finding_type: str
    priority_hint: str
    technical_action: str
    validation_evidence: str


class WorkflowState(BaseModel):
    """Complete state container propagated through the agentic graph."""
    model_config = ConfigDict(populate_by_name=True, extra="allow")

    correlation_id: str
    risk_record: Dict[str, Any]
    sanitized_risk: Dict[str, Any] = Field(default_factory=dict)
    rag_queries: List[str] = Field(default_factory=list)
    candidates: List[Dict[str, Any]] = Field(default_factory=list)
    explanation: Dict[str, Any] = Field(default_factory=dict)
    grounding_verified: bool = False
    playbook: Optional[RemediationPlaybook] = None
    execution_history: List[NodeExecutionRecord] = Field(default_factory=list)
    success: bool = False
    error: Optional[str] = None


# ----------------------------- Remediation Playbook Matcher -----------------------------

class RemediationCatalog:
    """Loads and matches internal operational remediation playbooks."""

    def __init__(self, guidance_csv_path: Optional[Path] = None):
        self.path = guidance_csv_path or (settings.RAW_DATA_DIR / settings.REMEDIATION_FILE)
        self.df = pd.DataFrame()
        self._load()

    def _load(self):
        if self.path.exists():
            try:
                self.df = pd.read_csv(self.path)
                logger.debug(f"Loaded {len(self.df)} remediation playbooks from {self.path}")
            except Exception as e:
                logger.warning(f"Could not load remediation guidance CSV: {e}")

    def match_playbook(self, vulnerability_name: str, cve: str) -> Optional[RemediationPlaybook]:
        if self.df.empty:
            return None

        vuln_lower = vulnerability_name.lower()
        cve_lower = cve.lower()

        # Score matches based on substring overlap
        best_row = None
        best_score = 0

        for _, row in self.df.iterrows():
            finding = str(row.get("finding_type", "")).lower()
            tokens = finding.split()
            score = sum(1 for t in tokens if t in vuln_lower or t in cve_lower)

            if score > best_score:
                best_score = score
                best_row = row

        if best_row is not None and best_score >= 1:
            return RemediationPlaybook(
                finding_type=str(best_row.get("finding_type", "Standard Vulnerability")),
                priority_hint=str(best_row.get("priority_hint", "P1")),
                technical_action=str(best_row.get("recommended_action", "Apply vendor patch.")),
                validation_evidence=str(best_row.get("validation_evidence", "Patch log verification")),
            )
        return None


# ----------------------------- Workflow Engine -----------------------------

class RemediationWorkflow:
    """
    Deterministic Agentic Workflow implementing:
    Ingest -> RAG -> Synthesize -> Verify -> Match Playbook -> Checkpoint
    """

    def __init__(self):
        self.catalog = RemediationCatalog()

    def run(self, raw_risk: Dict[str, Any]) -> WorkflowState:
        cid = get_correlation_id()
        state = WorkflowState(correlation_id=cid, risk_record=raw_risk)

        try:
            self._node_ingest(state)
            self._node_rag_retrieval(state)
            self._node_synthesize_explanation(state)
            self._node_verify_grounding(state)
            self._node_match_playbook(state)
            state.success = True
        except Exception as e:
            state.success = False
            state.error = f"Workflow failed: {type(e).__name__}: {str(e)}"
            logger.error(f"[{cid[:8]}] {state.error}")

        return state

    def _record_node(self, state: WorkflowState, node_name: str, status: str, duration_ms: float, details: Dict = None):
        state.execution_history.append(
            NodeExecutionRecord(
                node_name=node_name,
                status=status,
                latency_ms=round(duration_ms, 2),
                details=details,
            )
        )

    # Node 1: Ingest & Sanitize
    def _node_ingest(self, state: WorkflowState):
        t0 = time.time()
        state.sanitized_risk = sanitize_risk_record(state.risk_record)
        elapsed = (time.time() - t0) * 1000
        self._record_node(state, "IngestNode", "success", elapsed, {"cve": state.sanitized_risk.get("cve")})

    # Node 2: Multi-Angle RAG Retrieval
    def _node_rag_retrieval(self, state: WorkflowState):
        t0 = time.time()
        from explainer import build_rag_queries
        queries = build_rag_queries(state.sanitized_risk)
        state.rag_queries = queries

        seen_ids = set()
        candidates = []
        for q in queries:
            hits = retrieve_controls(q, top_k=settings.TOP_K_PER_QUERY)
            for hit in hits:
                if hit["identifier"] not in seen_ids:
                    seen_ids.add(hit["identifier"])
                    candidates.append(hit)

        from reranker import rerank_diverse_controls
        state.candidates = rerank_diverse_controls(candidates, top_k=6, max_per_family=2)
        elapsed = (time.time() - t0) * 1000
        self._record_node(state, "RetrievalNode", "success", elapsed, {
            "query_count": len(queries),
            "raw_candidate_count": len(candidates),
            "diverse_candidate_count": len(state.candidates),
        })

    # Node 3: Synthesize Grounded Explanation
    def _node_synthesize_explanation(self, state: WorkflowState):
        t0 = time.time()
        from explainer import SYSTEM_PROMPT, format_candidates_for_prompt, format_risk_for_prompt

        user_message = (
            f"<risk_record>\n{format_risk_for_prompt(state.sanitized_risk)}\n</risk_record>\n\n"
            f"<candidate_nist_controls>\n{format_candidates_for_prompt(state.candidates)}\n</candidate_nist_controls>"
        )

        explanation, telemetry = model_router.generate_explanation(
            risk=state.sanitized_risk,
            candidates=state.candidates,
            system_prompt=SYSTEM_PROMPT,
            user_prompt=user_message,
        )
        state.explanation = explanation
        elapsed = (time.time() - t0) * 1000
        self._record_node(state, "SynthesisNode", "success", elapsed, {
            "model": telemetry.model,
            "tokens": telemetry.total_tokens,
            "fallback": telemetry.fallback_used,
        })

    # Node 4: Grounding Verification & Hallucination Guardrail
    def _node_verify_grounding(self, state: WorkflowState):
        t0 = time.time()
        candidate_ids = {c["identifier"] for c in state.candidates}
        chosen_id = state.explanation.get("nist_control_id", "")

        if chosen_id in candidate_ids:
            state.grounding_verified = True
            state.explanation["_validation_warning"] = False
        else:
            state.grounding_verified = False
            state.explanation["_validation_warning"] = True
            if state.candidates:
                top = state.candidates[0]
                state.explanation["nist_control_id"] = top["identifier"]
                state.explanation["nist_control_name"] = top["name"]
                state.explanation["nist_guidance"] = f"{top['document'][:250]}..."

        state.explanation["_candidates_considered"] = [c["identifier"] for c in state.candidates]
        elapsed = (time.time() - t0) * 1000
        self._record_node(state, "VerificationNode", "success", elapsed, {
            "verified": state.grounding_verified,
            "control_selected": state.explanation.get("nist_control_id"),
        })

    # Node 5: Match Operational Playbook
    def _node_match_playbook(self, state: WorkflowState):
        t0 = time.time()
        vuln = state.sanitized_risk.get("vulnerability_name", "")
        cve = state.sanitized_risk.get("cve", "")
        playbook = self.catalog.match_playbook(vuln, cve)

        if playbook:
            state.playbook = playbook
            # Enrich explanation action if playbook provides more tactical instructions
            state.explanation["playbook_priority"] = playbook.priority_hint
            state.explanation["operational_evidence_required"] = playbook.validation_evidence

        elapsed = (time.time() - t0) * 1000
        self._record_node(state, "PlaybookNode", "success", elapsed, {
            "matched": playbook is not None,
            "priority": playbook.priority_hint if playbook else None,
        })

