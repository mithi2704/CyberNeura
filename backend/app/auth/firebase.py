"""
Firebase Admin SDK token verification.
Falls back to demo mode if Firebase is not configured and ALLOW_DEMO_AUTH=true.
"""
from __future__ import annotations

import json
from typing import Optional

from app.config import settings
from app.utils.logger import get_logger

logger = get_logger(__name__)

_firebase_app = None


def _init_firebase():
    """Initialize Firebase Admin SDK once."""
    global _firebase_app
    if _firebase_app is not None:
        return _firebase_app

    if not settings.firebase_configured:
        logger.warning("Firebase not configured — token verification unavailable")
        return None

    try:
        import firebase_admin
        from firebase_admin import credentials, auth as firebase_auth

        if not firebase_admin._apps:
            # Build the credentials dict from env vars
            cred_dict = {
                "type": "service_account",
                "project_id": settings.firebase_project_id,
                "client_email": settings.firebase_client_email,
                "private_key": settings.firebase_private_key.replace("\\n", "\n"),
                "token_uri": "https://oauth2.googleapis.com/token",
            }
            cred = credentials.Certificate(cred_dict)
            _firebase_app = firebase_admin.initialize_app(cred)
        else:
            _firebase_app = firebase_admin.get_app()

        logger.info("Firebase Admin SDK initialized")
        return _firebase_app
    except Exception as exc:
        logger.error(f"Firebase initialization failed: {exc}")
        return None


async def verify_firebase_token(token: str) -> Optional[dict]:
    """
    Verify a Firebase ID token.
    Returns the decoded token payload (uid, email, etc.) or None if invalid.
    """
    app = _init_firebase()
    if app is None:
        return None

    try:
        from firebase_admin import auth as firebase_auth
        decoded = firebase_auth.verify_id_token(token, app=app)
        return decoded
    except Exception as exc:
        logger.warning(f"Token verification failed: {exc}")
        return None


def is_demo_token(token: str) -> bool:
    """Check if this is a demo/development token."""
    return token.startswith("demo-") or token == "mock-id-token-jwt"
