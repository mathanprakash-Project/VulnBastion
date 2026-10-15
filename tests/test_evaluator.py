"""
Unit tests for AI & RAG Evaluation Harness.
"""
import pytest
from evaluator import BENCHMARK_DATASET, EvaluationResult, RAGEvaluator


def test_benchmark_dataset_integrity():
    assert len(BENCHMARK_DATASET) >= 5
    for case in BENCHMARK_DATASET:
        assert "id" in case
        assert "name" in case
        assert "query" in case
        assert "canonical_control" in case
        assert "expected_family" in case
        assert len(case["query"]) > 10


def test_rag_evaluator_execution():
    # Run evaluation over a small subset of 2 cases to keep test fast
    subset = BENCHMARK_DATASET[:2]
    evaluator = RAGEvaluator(dataset=subset)
    res = evaluator.run_evaluation(top_k=3)

    assert isinstance(res, EvaluationResult)
    assert res.total_test_cases == 2
    assert 0.0 <= res.recall_at_1 <= 1.0
    assert 0.0 <= res.mean_reciprocal_rank <= 1.0
    assert len(res.detailed_results) == 2

