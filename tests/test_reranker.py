"""
Unit tests for Diversity Reranker.
"""
import pytest
from reranker import rerank_diverse_controls


def test_diversity_reranker_limits_family_saturation():
    # 5 candidates with 4 from SC family and 1 from SI family
    candidates = [
        {"identifier": "SC-7", "family": "SC", "distance": 0.10},
        {"identifier": "SC-7(3)", "family": "SC", "distance": 0.12},
        {"identifier": "SC-7(10)", "family": "SC", "distance": 0.15},
        {"identifier": "SC-7(7)", "family": "SC", "distance": 0.18},
        {"identifier": "SI-2", "family": "SI", "distance": 0.20},
    ]

    # Rerank with max_per_family=2 and top_k=3
    reranked = rerank_diverse_controls(candidates, top_k=3, max_per_family=2)

    assert len(reranked) == 3
    sc_count = sum(1 for c in reranked if c["family"] == "SC")
    si_count = sum(1 for c in reranked if c["family"] == "SI")

    # SC was capped at 2, allowing SI-2 to surface in top 3 despite higher distance
    assert sc_count == 2
    assert si_count == 1
    assert reranked[2]["identifier"] == "SI-2"


def test_diversity_reranker_empty():
    assert rerank_diverse_controls([]) == []

