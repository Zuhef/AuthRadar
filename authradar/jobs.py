"""In-memory, async scan-job store backing the web UI.

The synchronous ``POST /scan`` endpoint runs a scan to completion inside one
request, which is fine for CI and scripting but a poor fit for a browser: a
real audit can take many seconds and the connection would simply block. This
module adds a small job abstraction so the UI can start a scan, get an id back
immediately, and poll for progress and the eventual :class:`ScanResult`.

State is intentionally process-local. AuthRadar's server is meant to run as a
single, operator-controlled instance bound to localhost (see
:mod:`authradar.api`), so an in-memory store keeps the design dependency-free
without weakening the security model. Restarting the server clears jobs.
"""

from __future__ import annotations

import asyncio
import logging
import uuid
from collections import OrderedDict
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime
from enum import StrEnum

from pydantic import BaseModel, ConfigDict

from authradar.core.config import ScanConfig
from authradar.core.models import ScanResult
from authradar.engine import run_scan

_LOGGER = logging.getLogger(__name__)

# Signature of the coroutine used to execute a scan; injectable for testing.
ScanRunner = Callable[[ScanConfig], Awaitable[ScanResult]]


class JobStatus(StrEnum):
    """Lifecycle states of a scan job."""

    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class ScanJob(BaseModel):
    """A scan request tracked through its lifecycle.

    The full :class:`ScanResult` is embedded once the job completes so the UI
    receives everything it needs from a single poll response.
    """

    model_config = ConfigDict(extra="forbid")

    id: str
    status: JobStatus
    target: str
    created_at: datetime
    started_at: datetime | None = None
    finished_at: datetime | None = None
    duration_s: float | None = None
    result: ScanResult | None = None
    error: str | None = None


class JobStore:
    """Tracks scan jobs and runs them as background asyncio tasks.

    A bounded number of finished jobs are retained (oldest evicted first) so a
    long-lived server cannot accumulate unbounded memory. All access happens on
    the server's single event loop; an :class:`asyncio.Lock` guards the small
    critical sections that mutate the ordered job map.
    """

    def __init__(self, *, max_jobs: int = 100, runner: ScanRunner | None = None) -> None:
        if max_jobs < 1:
            msg = "max_jobs must be >= 1"
            raise ValueError(msg)
        self._jobs: OrderedDict[str, ScanJob] = OrderedDict()
        self._tasks: dict[str, asyncio.Task[None]] = {}
        self._max_jobs = max_jobs
        self._runner: ScanRunner = runner or run_scan
        self._lock = asyncio.Lock()

    async def create(self, config: ScanConfig) -> ScanJob:
        """Register a new job for ``config`` and schedule it to run."""
        job_id = uuid.uuid4().hex
        job = ScanJob(
            id=job_id,
            status=JobStatus.PENDING,
            target=config.target,
            created_at=datetime.now(UTC),
        )
        async with self._lock:
            self._jobs[job_id] = job
            self._evict_locked()
        task = asyncio.create_task(self._run(job_id, config))
        self._tasks[job_id] = task
        return job

    def get(self, job_id: str) -> ScanJob | None:
        """Return the job with ``job_id`` or ``None`` if it is unknown."""
        return self._jobs.get(job_id)

    def list_jobs(self) -> list[ScanJob]:
        """Return all tracked jobs, newest first."""
        return list(self._jobs.values())[::-1]

    async def _run(self, job_id: str, config: ScanConfig) -> None:
        self._patch(job_id, status=JobStatus.RUNNING, started_at=datetime.now(UTC))
        try:
            result = await self._runner(config)
        except asyncio.CancelledError:
            self._patch(
                job_id,
                status=JobStatus.FAILED,
                finished_at=datetime.now(UTC),
                error="scan cancelled",
            )
            raise
        except Exception as exc:  # surface any scan failure to the client
            _LOGGER.exception("scan job %s failed", job_id)
            self._patch(
                job_id,
                status=JobStatus.FAILED,
                finished_at=datetime.now(UTC),
                error=f"{type(exc).__name__}: {exc}",
            )
        else:
            self._patch(
                job_id,
                status=JobStatus.COMPLETED,
                finished_at=datetime.now(UTC),
                duration_s=result.duration_s,
                result=result,
            )
        finally:
            self._tasks.pop(job_id, None)

    def _patch(self, job_id: str, **changes: object) -> None:
        job = self._jobs.get(job_id)
        if job is not None:
            self._jobs[job_id] = job.model_copy(update=changes)

    def _evict_locked(self) -> None:
        while len(self._jobs) > self._max_jobs:
            for jid, job in self._jobs.items():
                if job.status in (JobStatus.COMPLETED, JobStatus.FAILED):
                    del self._jobs[jid]
                    break
            else:
                # Nothing finished yet; stop to avoid evicting an active job.
                break
