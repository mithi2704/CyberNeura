"""Deterministic mock provider for local development and offline automated testing."""
from __future__ import annotations

import time
from datetime import datetime, timezone
from typing import List, Optional

from app.intelligence.base import ThreatIntelProvider
from app.intelligence.models import ThreatIntelResult, ProviderVerdict


class GenericMockProvider(ThreatIntelProvider):
    """
    Simulates provider lookups deterministically based on URL patterns.
    Used ONLY when THREAT_INTEL_MOCK_MODE=true or during test suites.
    """

    def __init__(self, name: str = "mock_provider", enabled: bool = True):
        super().__init__(name=name, enabled=enabled)

    @property
    def configured(self) -> bool:
        return True

    async def lookup(self, url: str) -> ThreatIntelResult:
        start_time = time.perf_counter()
        u_lower = url.lower()

        # Simulated test conditions
        if "timeout" in u_lower or "unreachable" in u_lower:
            self.record_failure("Simulated timeout error")
            return self.make_unavailable_result(url, "Simulated provider timeout", start_time)

        if "ratelimit" in u_lower:
            self.record_failure("Simulated rate limit exceeded")
            latency_ms = int((time.perf_counter() - start_time) * 1000)
            return ThreatIntelResult(
                provider=self.name,
                indicator=url,
                indicator_type="url",
                available=False,
                matched=False,
                verdict=ProviderVerdict.RATE_LIMITED,
                categories=[],
                checked_at=datetime.now(timezone.utc).isoformat(),
                error="Simulated provider rate limit exceeded",
                latency_ms=latency_ms,
            )

        self.record_success()
        latency_ms = int((time.perf_counter() - start_time) * 1000)

        # Match conditions based on provider name and keywords
        if self.name == "google_webrisk":
            if any(k in u_lower for k in ("phish", "bank-verify", "login", "account", "malicious")):
                return ThreatIntelResult(
                    provider=self.name,
                    indicator=url,
                    indicator_type="url",
                    available=True,
                    matched=True,
                    verdict=ProviderVerdict.MATCH,
                    categories=["SOCIAL_ENGINEERING"],
                    confidence=0.96,
                    checked_at=datetime.now(timezone.utc).isoformat(),
                    latency_ms=latency_ms,
                    metadata={"matchedThreatTypes": ["SOCIAL_ENGINEERING"]},
                )
            elif "malware" in u_lower or "trojan" in u_lower:
                return ThreatIntelResult(
                    provider=self.name,
                    indicator=url,
                    indicator_type="url",
                    available=True,
                    matched=True,
                    verdict=ProviderVerdict.MATCH,
                    categories=["MALWARE"],
                    confidence=0.94,
                    checked_at=datetime.now(timezone.utc).isoformat(),
                    latency_ms=latency_ms,
                    metadata={"matchedThreatTypes": ["MALWARE"]},
                )

        elif self.name == "phishtank":
            if any(k in u_lower for k in ("phish", "bank-verify", "secure-account", "malicious")):
                return ThreatIntelResult(
                    provider=self.name,
                    indicator=url,
                    indicator_type="url",
                    available=True,
                    matched=True,
                    verdict=ProviderVerdict.MATCH,
                    categories=["PHISHING"],
                    confidence=0.98,
                    checked_at=datetime.now(timezone.utc).isoformat(),
                    latency_ms=latency_ms,
                    metadata={"verified": True, "valid": True, "phish_id": 987654},
                )

        elif self.name == "urlhaus":
            if any(k in u_lower for k in ("malware", "payload.exe", "virus", "trojan", "malicious-bank")):
                return ThreatIntelResult(
                    provider=self.name,
                    indicator=url,
                    indicator_type="url",
                    available=True,
                    matched=True,
                    verdict=ProviderVerdict.MATCH,
                    categories=["MALWARE", "MALWARE_DISTRIBUTION"],
                    confidence=0.97,
                    checked_at=datetime.now(timezone.utc).isoformat(),
                    latency_ms=latency_ms,
                    metadata={"status": "online", "threat": "malware_download", "tags": ["elf", "mozi"]},
                )

        # Default: NO_MATCH
        return ThreatIntelResult(
            provider=self.name,
            indicator=url,
            indicator_type="url",
            available=True,
            matched=False,
            verdict=ProviderVerdict.NO_MATCH,
            categories=[],
            checked_at=datetime.now(timezone.utc).isoformat(),
            latency_ms=latency_ms,
        )
