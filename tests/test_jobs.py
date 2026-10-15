"""
Unit tests for Background Job Manager and Dead-Letter Queue.
"""
import time
import pytest
from jobs import BackgroundJobManager, JobStatus


def test_job_submission_and_completion():
    manager = BackgroundJobManager(max_workers=2)

    def sample_task(x, y, progress_callback=None):
        if progress_callback:
            progress_callback(0.5)
        return x + y

    job = manager.submit_job("addition", sample_task, 10, 20)
    assert job.status in [JobStatus.QUEUED, JobStatus.PROCESSING, JobStatus.COMPLETED]

    # Wait briefly for worker thread
    time.sleep(0.2)

    completed_job = manager.get_job(job.job_id)
    assert completed_job is not None
    assert completed_job.status == JobStatus.COMPLETED
    assert completed_job.result == 30
    assert completed_job.progress == 1.0


def test_job_failure_and_dead_letter_queue():
    manager = BackgroundJobManager(max_workers=2)

    def failing_task(progress_callback=None):
        raise RuntimeError("Simulated unrecoverable failure")

    job = manager.submit_job("failing_job", failing_task)

    # Allow worker to exhaust retries
    time.sleep(3.5)

    failed_job = manager.get_job(job.job_id)
    assert failed_job is not None
    assert failed_job.status == JobStatus.DEAD_LETTER
    assert "Simulated unrecoverable failure" in (failed_job.error or "")

    # Check dead letter queue
    dlq = manager.get_dead_letter_queue()
    assert any(j.job_id == job.job_id for j in dlq)

