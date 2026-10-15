"""
VulnBastion / TawasolPay CyberSentinel — AI & RAG Evaluation Harness
Measures retrieval quality (Recall@K, MRR) and LLM grounding accuracy against a labeled benchmark.
"""
import time
from typing import Any, Dict, List
from pydantic import BaseModel, Field

from logger import logger
from rag_agent import retrieve_controls


class EvaluationResult(BaseModel):
    """Metrics summary from an evaluation run."""
    total_test_cases: int
    recall_at_1: float
    recall_at_3: float
    recall_at_5: float
    mean_reciprocal_rank: float
    avg_latency_ms: float
    detailed_results: List[Dict[str, Any]] = Field(default_factory=list)


# Authoritative ground-truth evaluation dataset: (Risk Scenario -> Canonical NIST Control)
BENCHMARK_DATASET = [
    {
        "id": "TC-01",
        "name": "Citrix ADC Session Token Leak",
        "query": "Citrix NetScaler session token theft buffer over-read vulnerability allowing authentication bypass",
        "canonical_control": "SC-23",  # Session Authenticity
        "acceptable_controls": ["SC-23", "SI-2", "RA-5", "SC-30"],
        "expected_family": "SC",
    },
    {
        "id": "TC-02",
        "name": "Legacy End-of-Life Windows Server 2012",
        "query": "unsupported operating system no security patches available legacy infrastructure end of life",
        "canonical_control": "SA-22",  # Unsupported System Components
        "acceptable_controls": ["SA-22", "SI-2", "MA-3", "CM-8"],
        "expected_family": "SA",
    },
    {
        "id": "TC-03",
        "name": "Missing Multi-Factor Authentication",
        "query": "multi-factor authentication missing for privileged administrator accounts",
        "canonical_control": "IA-2",  # Identification and Authentication
        "acceptable_controls": ["IA-2", "AC-7", "IA-5", "AC-2"],
        "expected_family": "IA",
    },
    {
        "id": "TC-04",
        "name": "Unencrypted Database Backups",
        "query": "backup data stored without encryption at rest data confidentiality compliance violation",
        "canonical_control": "SC-28",  # Protection of Information at Rest
        "acceptable_controls": ["SC-28", "CP-9", "MP-5", "SC-13"],
        "expected_family": "SC",
    },
    {
        "id": "TC-05",
        "name": "Uncollected Audit Security Logs",
        "query": "audit logs not collected or monitored for security events incident detection failure",
        "canonical_control": "AU-2",  # Event Logging
        "acceptable_controls": ["AU-2", "AU-6", "AU-5", "SI-4"],
        "expected_family": "AU",
    },
    {
        "id": "TC-06",
        "name": "Fortinet SSL-VPN Remote Code Execution",
        "query": "critical heap buffer overflow in SSL VPN gateway allowing remote code execution",
        "canonical_control": "SI-2",  # Flaw Remediation
        "acceptable_controls": ["SI-2", "SC-7", "RA-5", "SA-22"],
        "expected_family": "SI",
    },
    {
        "id": "TC-07",
        "name": "Missing EDR Endpoint Protection",
        "query": "endpoint detection response missing on internet facing production servers",
        "canonical_control": "SI-4",  # System Monitoring
        "acceptable_controls": ["SI-4", "SI-3", "IR-4", "CM-3"],
        "expected_family": "SI",
    },
    {
        "id": "TC-08",
        "name": "Default or Weak Admin Credentials",
        "query": "default administrative credentials exposed on internal network devices",
        "canonical_control": "IA-5",  # Authenticator Management
        "acceptable_controls": ["IA-5", "AC-3", "CM-6", "IA-2"],
        "expected_family": "IA",
    },
]


class RAGEvaluator:
    """Benchmark harness evaluating semantic control retrieval against known ground-truth."""

    def __init__(self, dataset: List[Dict[str, Any]] = None):
        self.dataset = dataset or BENCHMARK_DATASET

    def run_evaluation(self, top_k: int = 5) -> EvaluationResult:
        """Run retrieval benchmark and calculate Recall@K and MRR."""
        logger.info(f"Starting RAG evaluation across {len(self.dataset)} ground-truth benchmark cases...")

        hits_at_1 = 0
        hits_at_3 = 0
        hits_at_5 = 0
        reciprocal_ranks = []
        latencies = []
        case_details = []

        for case in self.dataset:
            query = case["query"]
            canonical = case["canonical_control"]
            acceptable = case.get("acceptable_controls", [canonical])

            t0 = time.time()
            retrieved = retrieve_controls(query, top_k=top_k)
            latency = (time.time() - t0) * 1000
            latencies.append(latency)

            # Extract base identifiers (e.g. SC-28(2) -> SC-28)
            retrieved_ids = [r["identifier"].split("(")[0] for r in retrieved]

            # Check match ranks
            rank_found = None
            for idx, rid in enumerate(retrieved_ids, 1):
                if rid in acceptable:
                    rank_found = idx
                    break

            if rank_found == 1:
                hits_at_1 += 1
            if rank_found and rank_found <= 3:
                hits_at_3 += 1
            if rank_found and rank_found <= 5:
                hits_at_5 += 1

            rr = 1.0 / rank_found if rank_found else 0.0
            reciprocal_ranks.append(rr)

            case_details.append({
                "test_id": case["id"],
                "name": case["name"],
                "canonical": canonical,
                "rank_found": rank_found,
                "reciprocal_rank": round(rr, 3),
                "top_retrieved": [f"{r['identifier']} - {r['name']}" for r in retrieved[:3]],
                "latency_ms": round(latency, 1),
            })

        n = len(self.dataset)
        result = EvaluationResult(
            total_test_cases=n,
            recall_at_1=round(hits_at_1 / n, 3),
            recall_at_3=round(hits_at_3 / n, 3),
            recall_at_5=round(hits_at_5 / n, 3),
            mean_reciprocal_rank=round(sum(reciprocal_ranks) / n, 3),
            avg_latency_ms=round(sum(latencies) / n, 1),
            detailed_results=case_details,
        )

        logger.info(
            f"RAG Evaluation Complete: MRR={result.mean_reciprocal_rank}, "
            f"Recall@1={result.recall_at_1}, Recall@3={result.recall_at_3}, Recall@5={result.recall_at_5}"
        )
        return result


if __name__ == "__main__":
    import json
    evaluator = RAGEvaluator()
    res = evaluator.run_evaluation(top_k=5)
    print(json.dumps(res.model_dump(), indent=2))

