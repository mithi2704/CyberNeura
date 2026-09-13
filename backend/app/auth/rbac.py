"""
Role-Based Access Control helpers.
Roles: admin > analyst > viewer > user
"""
from __future__ import annotations

from typing import Optional
from fastapi import HTTPException, status

ROLE_HIERARCHY = {
    "admin": 4,
    "analyst": 3,
    "viewer": 2,
    "user": 1,
}


def has_role(user_role: str, required_role: str) -> bool:
    """Return True if user_role satisfies required_role or higher."""
    return ROLE_HIERARCHY.get(user_role, 0) >= ROLE_HIERARCHY.get(required_role, 99)


def require_role(user_role: str, required_role: str) -> None:
    """Raise 403 if user does not have the required role."""
    if not has_role(user_role, required_role):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "error": "INSUFFICIENT_PERMISSIONS",
                "message": f"Role '{required_role}' or higher is required",
            },
        )


def require_admin(user_role: str) -> None:
    require_role(user_role, "admin")


def require_analyst(user_role: str) -> None:
    require_role(user_role, "analyst")


def can_manage_users(role: str) -> bool:
    return has_role(role, "admin")


def can_view_threats(role: str) -> bool:
    return has_role(role, "viewer")


def can_delete_scans(role: str) -> bool:
    return has_role(role, "analyst")
