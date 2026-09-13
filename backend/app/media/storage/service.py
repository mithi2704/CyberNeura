"""
Secure Storage Service for Uploaded Media Files.
Provides isolated filesystem storage with SHA-256 hashing, Supabase storage abstraction,
deduplication lookups, and private path isolation.
"""
from __future__ import annotations

import hashlib
import os
import uuid
from pathlib import Path
from typing import Optional, Tuple
from app.config import settings
from app.media.models import MediaAsset, MediaType

UPLOAD_ROOT = Path(__file__).resolve().parent.parent.parent.parent / settings.media_storage_dir


class MediaStorageService:
    def __init__(self):
        self.upload_dir = UPLOAD_ROOT
        self.upload_dir.mkdir(parents=True, exist_ok=True)

    def calculate_sha256(self, file_bytes: bytes) -> str:
        """Computes cryptographic SHA-256 hash of the media bitstream."""
        hasher = hashlib.sha256()
        hasher.update(file_bytes)
        return hasher.hexdigest()

    def store_file(
        self,
        file_bytes: bytes,
        original_filename: str,
        media_type: MediaType,
        mime_type: str,
        user_id: Optional[str] = None,
        width: Optional[int] = None,
        height: Optional[int] = None,
        duration: Optional[float] = None,
        frame_count: Optional[int] = None,
    ) -> MediaAsset:
        """
        Saves file to private, unguessable storage path and records MediaAsset.
        """
        sha256 = self.calculate_sha256(file_bytes)
        media_id = str(uuid.uuid4())
        extension = Path(original_filename).suffix.lower() or (".jpg" if media_type == MediaType.IMAGE else ".mp4")
        safe_filename = f"{media_id}{extension}"
        storage_path = str(self.upload_dir / safe_filename)

        with open(storage_path, "wb") as f:
            f.write(file_bytes)

        asset = MediaAsset(
            id=media_id,
            user_id=user_id,
            media_type=media_type,
            storage_path=storage_path,
            original_filename=original_filename,
            mime_type=mime_type,
            file_size=len(file_bytes),
            sha256=sha256,
            width=width,
            height=height,
            duration=duration,
            frame_count=frame_count,
        )
        return asset

    def read_file(self, asset: MediaAsset) -> bytes:
        """Reads file bytes from storage."""
        if not os.path.exists(asset.storage_path):
            raise FileNotFoundError(f"Media file not found at {asset.storage_path}")
        with open(asset.storage_path, "rb") as f:
            return f.read()

    def delete_file(self, asset: MediaAsset) -> bool:
        """Permanently removes media file from storage."""
        try:
            if os.path.exists(asset.storage_path):
                os.remove(asset.storage_path)
            return True
        except Exception:
            return False


media_storage_service = MediaStorageService()
