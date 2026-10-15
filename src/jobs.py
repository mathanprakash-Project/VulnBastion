"""
VulnBastion / TawasolPay CyberSentinel — Asynchronous Background Jobs & Dead-Letter Queue
Provides non-blocking execution for long-running workflows with retry limits,
observable statuses, and dead-letter handling.
"""
import asyncio
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable, Dict, List, Optional
from pydantic import BaseModel, Field

from config import settings
from logger import logger


class JobStatus(str, Enum):
    QUEUED = "QUEUED"
    PROCESSING = "PROCESSING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    DEAD_LETTER = "DEAD_LETTER"


class Job(BaseModel):
    job_id: str = Field(default_factory=lambda: str(uuid.uuid4())[:12])
    job_type: str
    status: JobStatus = JobStatus.QUEUED
    progress: float = 0.0
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    started_at: Optional[str] = None
    completed_at: Optional[str] = None
    retries_left: int = Field(default=settings.WORKER_MAX_RETRIES)
    params: Dict[str, Any] = Field(default_factory=dict)
    result: Optional[Any] = None
    error: Optional[str] = None


class BackgroundJobManager:
    """Manages asynchronous job queue, worker threads, retries, and dead-letter storage."""

    def __init__(self, max_workers: int = 4):
        self.max_workers = max_workers
        self.executor = ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix="job-worker")
        self.jobs: Dict[str, Job] = {}
        self.dead_letter_jobs: List[str] = []

    def submit_job(self, job_type: str, task_fn: Callable[..., Any], *args, **kwargs) -> Job:
        """Submit a task to be processed asynchronously in the worker pool."""
        job = Job(job_type=job_type, params=kwargs)
        self.jobs[job.job_id] = job
        logger.info(f"Enqueued background job '{job.job_id}' (type={job_type})")

        self.executor.submit(self._run_task_wrapper, job.job_id, task_fn, *args, **kwargs)
        return job

    def _run_task_wrapper(self, job_id: str, task_fn: Callable[..., Any], *args, **kwargs):
        job = self.jobs[job_id]
        job.status = JobStatus.PROCESSING
        job.started_at = datetime.now(timezone.utc).isoformat()
        logger.info(f"Starting execution of job '{job_id}' (type={job.job_type})")

        while job.retries_left >= 0:
            try:
                # Progress callback support
                def update_progress(pct: float):
                    job.progress = round(pct, 2)

                kwargs["progress_callback"] = update_progress
                result = task_fn(*args, **kwargs)
                job.result = result
                job.progress = 1.0
                job.status = JobStatus.COMPLETED
                job.completed_at = datetime.now(timezone.utc).isoformat()
                logger.info(f"Job '{job_id}' completed successfully")
                return

            except Exception as e:
                job.retries_left -= 1
                job.error = f"{type(e).__name__}: {str(e)}"
                logger.warning(
                    f"Job '{job_id}' attempt failed ({job.retries_left} retries left): {job.error}"
                )

                if job.retries_left < 0:
                    # Move to Dead-Letter Queue
                    job.status = JobStatus.DEAD_LETTER
                    job.completed_at = datetime.now(timezone.utc).isoformat()
                    self.dead_letter_jobs.append(job_id)
                    logger.error(f"Job '{job_id}' exhausted all retries. Moved to DEAD_LETTER queue.")
                    return
                else:
                    time.sleep(1.0)  # Brief backoff before retry

    def get_job(self, job_id: str) -> Optional[Job]:
        return self.jobs.get(job_id)

    def list_jobs(self, limit: int = 50) -> List[Job]:
        return list(self.jobs.values())[-limit:]

    def get_dead_letter_queue(self) -> List[Job]:
        return [self.jobs[jid] for jid in self.dead_letter_jobs if jid in self.jobs]


# Global worker singleton
job_manager = BackgroundJobManager(max_workers=settings.WORKER_MAX_CONCURRENT_JOBS)

