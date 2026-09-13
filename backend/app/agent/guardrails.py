"""
CyberNeura AI Security Agent guardrails.
Enforces prompt injection defense, tool allowlists, rate limiting, execution bounds,
and defensive read-only operational boundaries.
"""
from __future__ import annotations

import re
import time
from collections import defaultdict
from typing import Any, Dict, List, Optional
from app.config import settings
from app.utils.logger import get_logger

logger = get_logger(__name__)

# Prompt injection signature patterns
_INJECTION_PATTERNS = [
    re.compile(r"ignore[\s_]+(all[\s_]+)?(previous|prior|above)[\s_]+instructions?", re.IGNORECASE),
    re.compile(r"disregard[\s_]+(all[\s_]+)?(previous|prior|above)[\s_]+instructions?", re.IGNORECASE),
    re.compile(r"you[\s_]+are[\s_]+now[\s_]+(a|an)?[\s_]*", re.IGNORECASE),
    re.compile(r"system[\s_]*prompt[\s_]*:", re.IGNORECASE),
    re.compile(r"system[\s_]*override", re.IGNORECASE),
    re.compile(r"developer[\s_]*mode", re.IGNORECASE),
    re.compile(r"dan[\s_]*mode", re.IGNORECASE),
    re.compile(r"sudo[\s_]+mode", re.IGNORECASE),
]

# Offensive / Non-Defensive intent patterns that the Agent must refuse
_OFFENSIVE_PATTERNS = [
    re.compile(r"\b(exploit|hack|pentest|ddos|sql[\s_]*injection|xss[\s_]*attack|brute[\s_]*force)\b", re.IGNORECASE),
    re.compile(r"\b(execute\s+.*(shell|command|bash|powershell|cmd|code)|run\s+.*script)\b", re.IGNORECASE),
    re.compile(r"\b(modify\s+.*firewall|modify\s+.*dns|quarantine\s+.*machine|delete\s+.*file)\b", re.IGNORECASE),
    re.compile(r"\b(steal\s+.*credentials?|bypass\s+.*auth(entication)?|deploy\s+.*malware)\b", re.IGNORECASE),
]


class RateLimiter:
    """In-memory sliding window rate limiter per user."""

    def __init__(self, requests_per_minute: int = 10):
        self.rpm = requests_per_minute
        self._history: Dict[str, List[float]] = defaultdict(list)

    def is_allowed(self, user_id: str) -> bool:
        now = time.time()
        window_start = now - 60.0
        # Prune older entries
        timestamps = [t for t in self._history[user_id] if t > window_start]
        self._history[user_id] = timestamps

        if len(timestamps) >= self.rpm:
            return False

        self._history[user_id].append(now)
        return True


# Global rate limiter instance
agent_rate_limiter = RateLimiter(requests_per_minute=settings.rate_limit_per_minute if hasattr(settings, "rate_limit_per_minute") else 10)


class AgentGuardrails:
    """Core security and boundary checks for the AI Security Agent."""

    @staticmethod
    def sanitize_untrusted_input(text: str) -> str:
        """
        Ensures untrusted text (URLs, domains, metadata, feed text)
        cannot hijack instructions.
        Applies UNTRUSTED_CONTENT_CANNOT_CONTROL_AGENT policy.
        """
        if not text:
            return ""

        sanitized = text.strip()
        for pattern in _INJECTION_PATTERNS:
            if pattern.search(sanitized):
                logger.warning(f"Potential prompt injection detected and neutralized in input: {text[:80]}")
                sanitized = pattern.sub("[UNTRUSTED_INSTRUCTION_REMOVED]", sanitized)

        return sanitized

    @staticmethod
    def contains_prompt_injection(text: str) -> bool:
        """Check if raw text contains an instruction override attempt."""
        if not text:
            return False
        return any(pattern.search(text) is not None for pattern in _INJECTION_PATTERNS)

    @staticmethod
    def is_offensive_intent(text: str) -> bool:
        """
        Checks if the inquiry asks the agent to perform offensive hacking,
        arbitrary code execution, or unauthorized destructive actions.
        """
        if not text:
            return False
        return any(pattern.search(text) is not None for pattern in _OFFENSIVE_PATTERNS)

    @staticmethod
    def validate_tool_allowed(tool_name: str, allowlist: List[str]) -> bool:
        """Enforces that only registered, allowlisted defensive tools can be called."""
        return tool_name in allowlist

    @staticmethod
    def validate_execution_bounds(step_count: int, tool_call_count: int) -> Optional[str]:
        """
        Validates that the agent does not exceed configured step or tool-call bounds.
        Returns error reason if bounds are exceeded, None if healthy.
        """
        max_steps = getattr(settings, "agent_max_steps", 8)
        max_tool_calls = getattr(settings, "agent_max_tool_calls", 12)

        if step_count >= max_steps:
            return f"Maximum agent step limit reached ({max_steps} steps)."
        if tool_call_count >= max_tool_calls:
            return f"Maximum tool call limit reached ({max_tool_calls} calls)."
        return None
