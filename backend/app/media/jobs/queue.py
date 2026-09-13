"""
Asynchronous Job Queue for CyberNeura Video Media Processing.
Manages job dispatch, cancellation, worker concurrency limits, and state transitions.
"""
from __future__ import annotations

import asyncio
import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Callable, Coroutine, Dict, Optional
from app.config import settings
from app.media.models import JobStatus, MediaJob, MediaType
from app.services.scan_store import scan_store
from app.realtime.publisher import event_publisher
from app.realtime.models import RealtimeEventType, EntityType

logger = logging.getLogger(__name__)


class MediaJobQueue:
    def __init__(self):
        self._queue: asyncio.Queue[str] = asyncio.Queue(maxsize=settings.max_video_queue_size)
        self._cancelled_jobs: set[str] = set()
        self._running_tasks: Dict[str, asyncio.Task] = {}
        self._semaphore = asyncio.Semaphore(settings.max_concurrent_video_jobs)
        self._is_running = False

    def create_job(
        self,
        media_id: str,
        user_id: Optional[str] = None,
        media_type: MediaType = MediaType.VIDEO,
    ) -> MediaJob:
        """Enqueues a new asynchronous media analysis job."""
        job_id = str(uuid.uuid4())
        job = MediaJob(
            id=job_id,
            media_id=media_id,
            user_id=user_id,
            media_type=media_type,
            status=JobStatus.QUEUED,
            progress=0,
            current_stage="QUEUED",
        )
        scan_store.save_media_job(job.model_dump())
        return job

    async def enqueue(self, job_id: str, job_coroutine_factory: Callable[[str, Callable[[int, str], Coroutine]], Coroutine]) -> None:
        """Pushes job to queue and triggers background processor."""
        await self._queue.put(job_id)
        # Spawn execution task
        task = asyncio.create_task(self._process_job_wrapper(job_id, job_coroutine_factory))
        self._running_tasks[job_id] = task

    async def cancel_job(self, job_id: str) -> bool:
        """Cancels an in-flight or queued job."""
        self._cancelled_jobs.add(job_id)
        task = self._running_tasks.get(job_id)
        if task and not task.done():
            task.cancel()
        scan_store.update_media_job(job_id, {
            "status": JobStatus.CANCELLED.value,
            "current_stage": "CANCELLED_BY_USER",
            "error_message": "Job cancelled by user request.",
        })
        logger.info(f"Cancelled media job {job_id}")
        return True

    def is_cancelled(self, job_id: str) -> bool:
        return job_id in self._cancelled_jobs

    async def _process_job_wrapper(
        self,
        job_id: str,
        coro_factory: Callable[[str, Callable[[int, str], Coroutine]], Coroutine],
    ) -> None:
        """Acquires concurrency slot and executes job with timeout enforcement."""
        async with self._semaphore:
            if self.is_cancelled(job_id):
                return

            scan_store.update_media_job(job_id, {
                "status": JobStatus.PROCESSING.value,
                "current_stage": "INITIALIZING",
                "started_at": datetime.now(timezone.utc).isoformat(),
            })

            # Progress callback that updates scan_store and broadcasts Phase 5 Realtime
            async def on_progress(pct: int, stage: str):
                if self.is_cancelled(job_id):
                    raise asyncio.CancelledError()

                scan_store.update_media_job(job_id, {
                    "progress": pct,
                    "current_stage": stage,
                })
                # Emit Realtime event
                job_data = scan_store.get_media_job(job_id) or {}
                await event_publisher.publish(
                    event_type=RealtimeEventType.MEDIA_FRAME_ANALYSIS_STARTED if pct < 90 else RealtimeEventType.MEDIA_ANALYSIS_COMPLETED,
                    entity_type=EntityType.MEDIA_JOB,
                    entity_id=job_id,
                    user_id=job_data.get("user_id"),
                    payload={
                        "job_id": job_id,
                        "media_id": job_data.get("media_id"),
                        "progress": pct,
                        "current_stage": stage,
                        "status": "PROCESSING" if pct < 100 else "COMPLETED",
                    },
                )

            try:
                # Enforce timeout
                timeout = float(settings.max_video_duration_seconds) * 2.0
                await asyncio.wait_for(coro_factory(job_id, on_progress), timeout=timeout)

                scan_store.update_media_job(job_id, {
                    "status": JobStatus.COMPLETED.value,
                    "progress": 100,
                    "current_stage": "COMPLETED",
                    "completed_at": datetime.now(timezone.utc).isoformat(),
                })
            except asyncio.CancelledError:
                logger.info(f"Job {job_id} cancelled during execution.")
            except asyncio.TimeoutError:
                logger.error(f"Job {job_id} timed out.")
                scan_store.update_media_job(job_id, {
                    "status": JobStatus.FAILED.value,
                    "current_stage": "TIMED_OUT",
                    "error_message": f"Processing exceeded timeout limit ({timeout}s).",
                })
            except Exception as exc:
                logger.error(f"Job {job_id} failed with error: {exc}", exc_info=True)
                scan_store.update_media_job(job_id, {
                    "status": JobStatus.FAILED.value,
                    "current_stage": "FAILED",
                    "error_message": str(exc),
                })
            finally:
                self._running_tasks.pop(job_id, None)
                self._cancelled_jobs.discard(job_id)


job_queue = MediaJobQueue()
