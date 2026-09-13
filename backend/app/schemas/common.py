"""Common response schemas."""
from __future__ import annotations
from typing import Any, Optional
from pydantic import BaseModel


class ErrorResponse(BaseModel):
    error: str
    message: str
    detail: Optional[Any] = None


class SuccessResponse(BaseModel):
    success: bool = True
    message: str = "OK"


class PaginatedResponse(BaseModel):
    items: list
    page: int
    page_size: int
    total: int
    total_pages: int
