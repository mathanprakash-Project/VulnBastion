"""
VulnBastion / TawasolPay CyberSentinel — Semantic Reranker & Control Diversity Filter
Applies family-aware diversity reranking to prevent candidate saturation and surface multi-layered controls.
"""
from typing import Any, Dict, List
from logger import logger


def rerank_diverse_controls(
    candidates: List[Dict[str, Any]],
    top_k: int = 5,
    max_per_family: int = 2,
) -> List[Dict[str, Any]]:
    """
    Reranks candidate controls to ensure family diversity.
    Limits redundant sub-controls from the same family (e.g., SC-7, SC-7(3), SC-7(10))
    to ensure the LLM receives diverse remediation options (e.g. SI + SC + RA).
    """
    if not candidates:
        return []

    # Sort candidates by distance ascending (lower distance = higher similarity)
    sorted_candidates = sorted(
        candidates,
        key=lambda c: c.get("distance", 1.0) if c.get("distance") is not None else 1.0,
    )

    selected: List[Dict[str, Any]] = []
    family_counts: Dict[str, int] = {}

    # Pass 1: Select candidates respecting max_per_family limit
    deferred: List[Dict[str, Any]] = []
    for cand in sorted_candidates:
        ident = cand.get("identifier", "")
        family = cand.get("family") or (ident.split("-")[0] if "-" in ident else "OTHER")

        count = family_counts.get(family, 0)
        if count < max_per_family:
            selected.append(cand)
            family_counts[family] = count + 1
        else:
            deferred.append(cand)

        if len(selected) >= top_k:
            break

    # Pass 2: If we still need more candidates to meet top_k, fill from deferred
    if len(selected) < top_k and deferred:
        needed = top_k - len(selected)
        selected.extend(deferred[:needed])

    logger.debug(
        f"Reranked {len(candidates)} candidates down to {len(selected)} diverse controls "
        f"across families: {list(family_counts.keys())}"
    )
    return selected

