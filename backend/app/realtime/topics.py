"""
Real-time Channel and Topic naming conventions.
Provides canonical channel identifiers for user-isolated and public broadcast subscriptions.
"""
from __future__ import annotations


def get_user_channel(user_id: str) -> str:
    """Channel for authenticated private user events."""
    sanitized = user_id.replace(":", "_").strip()
    return f"user:{sanitized}:events"


def get_table_channel(table_name: str) -> str:
    """Channel for Supabase Postgres Changes listeners."""
    return f"public:{table_name}"


def get_system_channel() -> str:
    """Channel for general platform health and system alerts."""
    return "public:system_status"


def get_agent_channel(session_id: str) -> str:
    """Channel dedicated to a specific agent investigation session."""
    return f"agent:{session_id}"
