"""Tests for the in-memory scan job store."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime

import pytest

from authradar.core.config import ScanConfig
from authradar.core.models import ScanResult
from authradar.jobs import JobStatus, JobStore


def _result(target: str) -> ScanResult:
    now = datetime.now(UTC)
    return ScanResult(
        target=target,
        started_at=now,
        finished_at=now,
        duration_s=0.0,
        findings=[],
        scanners_run=[],
        pages_crawled=0,
    )


def _config(target: str = "https://example.com") -> ScanConfig:
    return ScanConfig(target=target)


async def _ok_runner(config: ScanConfig) -> ScanResult:
    return _result(config.target)


async def _wait_for(store: JobStore, job_id: str, timeout_s: float = 2.0) -> None:
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout_s
    while True:
        job = store.get(job_id)
        assert job is not None
        if job.status in (JobStatus.COMPLETED, JobStatus.FAILED):
            return
        if loop.time() > deadline:
            raise AssertionError(f"job {job_id} did not finish (status={job.status})")
        await asyncio.sleep(0.01)


async def test_job_runs_to_completion() -> None:
    store = JobStore(runner=_ok_runner)
    job = await store.create(_config())
    assert job.status in (JobStatus.PENDING, JobStatus.RUNNING)

    await _wait_for(store, job.id)
    done = store.get(job.id)
    assert done is not None
    assert done.status == JobStatus.COMPLETED
    assert done.result is not None
    assert done.result.target == "https://example.com"
    assert done.finished_at is not None
    assert done.error is None


async def test_job_records_failure() -> None:
    async def boom(_config: ScanConfig) -> ScanResult:
        raise RuntimeError("boom")

    store = JobStore(runner=boom)
    job = await store.create(_config())

    await _wait_for(store, job.id)
    done = store.get(job.id)
    assert done is not None
    assert done.status == JobStatus.FAILED
    assert done.error is not None
    assert "boom" in done.error
    assert done.result is None


async def test_unknown_job_is_none() -> None:
    store = JobStore()
    assert store.get("nope") is None


async def test_finished_jobs_are_evicted() -> None:
    store = JobStore(max_jobs=3, runner=_ok_runner)
    ids: list[str] = []
    for i in range(5):
        job = await store.create(_config(f"https://h{i}.example"))
        ids.append(job.id)
        await _wait_for(store, job.id)

    assert len(store.list_jobs()) <= 3
    assert store.get(ids[-1]) is not None  # newest retained
    assert store.get(ids[0]) is None  # oldest evicted


async def test_list_jobs_is_newest_first() -> None:
    store = JobStore(runner=_ok_runner)
    first = await store.create(_config("https://a.example"))
    second = await store.create(_config("https://b.example"))

    assert [job.id for job in store.list_jobs()] == [second.id, first.id]

    await _wait_for(store, first.id)
    await _wait_for(store, second.id)


def test_max_jobs_must_be_positive() -> None:
    with pytest.raises(ValueError, match="max_jobs"):
        JobStore(max_jobs=0)
