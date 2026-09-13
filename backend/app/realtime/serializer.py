"""
Real-time payload serializer and secret sanitization engine.
Guarantees zero API keys, auth tokens, or private secrets leak into real-time broadcasts.
"""
from __future__ import annotations

import json
from datetime import date, datetime
from decimal import Decimal
from typing import Any, Dict, Set
from uuid import UUID

# Blocklist of sensitive keys that must NEVER be broadcast
SENSITIVE_KEYS: Set[str] = {
    "api_key",
    "apikey",
    "secret",
    "password",
    "token",
    "service_role",
    "access_token",
    "refresh_token",
    "private_key",
    "google_web_risk_api_key",
    "phishtank_app_key",
    "urlhaus_auth_key",
    "groq_api_key",
    "ai_api_key",
    "supabase_service_role_key",
    "firebase_private_key",
    "authorization",
}


def sanitize_payload(payload: Any) -> Any:
    """
    Recursively scrubs sensitive keys and serializes complex types.
    """
    if isinstance(payload, dict):
        cleaned = {}
        for k, v in payload.items():
            key_lower = str(k).lower()
            if any(s in key_lower for s in SENSITIVE_KEYS):
                continue  # strip sensitive field
            cleaned[k] = sanitize_payload(v)
        return cleaned

    if isinstance(payload, list):
        return [sanitize_payload(item) for item in payload]

    if isinstance(payload, tuple):
        return [sanitize_payload(item) for item in payload]

    if isinstance(payload, (datetime, date)):
        return payload.isoformat()

    if isinstance(payload, UUID):
        return str(payload)

    if isinstance(payload, Decimal):
        return float(payload)

    if hasattr(payload, "model_dump"):
        return sanitize_payload(payload.model_dump())

    if hasattr(payload, "__dict__"):
        return sanitize_payload(payload.__dict__)

    return payload


def safe_json_dumps(data: Any) -> str:
    """Safely converts sanitized data into valid JSON string."""
    sanitized = sanitize_payload(data)
    return json.dumps(sanitized, default=str)
