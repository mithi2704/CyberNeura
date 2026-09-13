"""
Standardized ToolResult and ToolStatus schemas for CyberNeura Agent Tools.
"""
from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, Optional
from pydantic import BaseModel, Field


class ToolStatus(str, Enum):
    SUCCESS = "SUCCESS"
    NO_DATA = "NO_DATA"
    UNAVAILABLE = "UNAVAILABLE"
    TIMEOUT = "TIMEOUT"
    RATE_LIMITED = "RATE_LIMITED"
    ERROR = "ERROR"
    BLOCKED = "BLOCKED"


class ToolResult(BaseModel):
    tool_name: str
    status: ToolStatus = ToolStatus.SUCCESS
    data: Dict[str, Any] = Field(default_factory=dict)
    summary: str = ""
    duration_ms: float = 0.0
    error: Optional[str] = None
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    @property
    def is_success(self) -> bool:
        return self.status == ToolStatus.SUCCESS
