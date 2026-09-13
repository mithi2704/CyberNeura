"""Base provider interface and circuit breaker for Threat Intelligence."""
from __future__ import annotations

import abc
import time
from datetime import datetime, timezone, timedelta
from typing import Optional

from app.intelligence.models import (
    ThreatIntelResult,
    ProviderVerdict,
    ProviderStatus,
    ProviderStatusInfo,
)
from app.utils.logger import get_logger

logger = get_logger(__name__)


class ThreatIntelProvider(abc.ABC):
    """
    Abstract interface for all Threat Intelligence providers.
    Every provider implementation must inherit from this class and
    normalize outputs into ThreatIntelResult.
    """

    def __init__(self, name: str, enabled: bool = True):
        self.name = name
        self.enabled = enabled
        self.consecutive_failures: int = 0
        self.last_successful_check: Optional[datetime] = None
        self.last_error: Optional[str] = None
        self.circuit_open_until: Optional[datetime] = None
        self.failure_threshold: int = 3
        self.cooldown_seconds: int = 60

    @property
    @abc.abstractmethod
    def configured(self) -> bool:
        """Return True if the required credentials/API keys are available."""
        pass

    @property
    def status(self) -> ProviderStatus:
        if not self.configured:
            return ProviderStatus.NOT_CONFIGURED
        if self.circuit_open_until and datetime.now(timezone.utc) < self.circuit_open_until:
            return ProviderStatus.DEGRADED
        return ProviderStatus.HEALTHY

    def is_circuit_open(self) -> bool:
        """Check if circuit breaker is open (tripped due to repeated errors)."""
        if not self.configured:
            return True
        if self.circuit_open_until:
            if datetime.now(timezone.utc) < self.circuit_open_until:
                return True
            # Cooldown passed, transition to half-open
            self.circuit_open_until = None
        return False

    def record_success(self):
        """Record a successful lookup, resetting failure counters."""
        self.consecutive_failures = 0
        self.last_successful_check = datetime.now(timezone.utc)
        self.circuit_open_until = None
        self.last_error = None

    def record_failure(self, error: str):
        """Record a provider failure, incrementing failure counter and tripping circuit if threshold met."""
        self.consecutive_failures += 1
        self.last_error = error
        if self.consecutive_failures >= self.failure_threshold:
            self.circuit_open_until = datetime.now(timezone.utc) + timedelta(seconds=self.cooldown_seconds)
            logger.warning(
                f"[ThreatIntel:{self.name}] Tripped circuit breaker after {self.consecutive_failures} failures. "
                f"Cooldown active until {self.circuit_open_until.isoformat()}."
            )

    def get_status_info(self) -> ProviderStatusInfo:
        """Return current status metadata."""
        return ProviderStatusInfo(
            name=self.name,
            enabled=self.enabled,
            configured=self.configured,
            status=self.status,
            lastSuccessfulCheck=self.last_successful_check.isoformat() if self.last_successful_check else None,
            lastError=self.last_error,
        )

    def make_unavailable_result(self, url: str, error: str, start_time: float) -> ThreatIntelResult:
        """Helper to create a standard UNAVAILABLE result."""
        latency_ms = int((time.perf_counter() - start_time) * 1000)
        return ThreatIntelResult(
            provider=self.name,
            indicator=url,
            indicator_type="url",
            available=False,
            matched=False,
            verdict=ProviderVerdict.UNAVAILABLE,
            categories=[],
            checked_at=datetime.now(timezone.utc).isoformat(),
            error=error,
            latency_ms=latency_ms,
        )

    def make_not_configured_result(self, url: str, start_time: float) -> ThreatIntelResult:
        """Helper to create a standard NOT_CONFIGURED result."""
        latency_ms = int((time.perf_counter() - start_time) * 1000)
        return ThreatIntelResult(
            provider=self.name,
            indicator=url,
            indicator_type="url",
            available=False,
            matched=False,
            verdict=ProviderVerdict.UNAVAILABLE,
            categories=[],
            checked_at=datetime.now(timezone.utc).isoformat(),
            error=f"{self.name} is not configured (missing API credentials)",
            latency_ms=latency_ms,
        )

    @abc.abstractmethod
    async def lookup(self, url: str) -> ThreatIntelResult:
        """
        Execute external threat intelligence lookup for the given normalized URL.
        Must catch all exceptions and return a valid ThreatIntelResult.
        """
        pass
