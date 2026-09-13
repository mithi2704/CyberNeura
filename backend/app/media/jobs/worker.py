"""
Media Background Worker for Video Deepfake Analysis.
"""
from __future__ import annotations

import logging
from typing import Callable, Coroutine
from app.media.jobs.queue import job_queue
from app.media.video.service import video_service
from app.services.scan_store import scan_store

logger = logging.getLogger(__name__)


async def dispatch_video_job(
    media_id: str,
    video_path: str,
    user_id: str | None = None,
    sampling_rate_fps: int = 2,
    max_frames: int = 300,
) -> str:
    """Creates a job, registers the execution worker, and queues it."""
    job = job_queue.create_job(media_id=media_id, user_id=user_id)

    async def execution_worker(job_id: str, on_progress: Callable[[int, str], Coroutine]):
        logger.info(f"Worker started video deepfake analysis for job {job_id} (media: {media_id})")
        assessment = await video_service.analyze_video(
            video_path=video_path,
            media_id=media_id,
            user_id=user_id,
            sampling_rate_fps=sampling_rate_fps,
            max_frames=max_frames,
            progress_callback=on_progress,
        )
        logger.info(f"Worker completed job {job_id} with classification {assessment.classification}")

    await job_queue.enqueue(job.id, execution_worker)
    return job.id
