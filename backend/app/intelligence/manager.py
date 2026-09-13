"""Threat Intelligence Manager — concurrent orchestration, caching, and normalization."""
from __future__ import annotations

import asyncio
import time
from typing import Dict, List, Optional

from app.intelligence.base import ThreatIntelProvider
from app.intelligence.models import (
    ThreatIntelResult,
    ProviderVerdict,
    ProviderStatusInfo,
)
from app.intelligence.cache import threat_intel_cache
from app.intelligence.providers.google_webrisk import GoogleWebRiskProvider
from app.intelligence.providers.phishtank import PhishTankProvider
from app.intelligence.providers.urlhaus import URLhausProvider
from app.intelligence.providers.generic import GenericMockProvider
from app.config import settings
from app.utils.validators import normalize_url
from app.utils.logger import get_logger

logger = get_logger(__name__)


class ThreatIntelligenceManager:
    """
    Central coordinator for external threat-intelligence lookups.
    Manages concurrency limits, provider timeouts, caching, and result aggregation.
    """

    def __init__(self):
        self.semaphore = asyncio.Semaphore(settings.threat_intel_max_concurrent_requests)
        self.providers: Dict[str, ThreatIntelProvider] = {}
        self._init_providers()

    def _init_providers(self):
        """Initialize provider registry based on settings."""
        if settings.threat_intel_mock_mode:
            logger.info("[ThreatIntelManager] THREAT_INTEL_MOCK_MODE enabled — initializing mock providers")
            self.providers = {
                "google_webrisk": GenericMockProvider(name="google_webrisk", enabled=settings.enable_google_web_risk),
                "phishtank": GenericMockProvider(name="phishtank", enabled=settings.enable_phishtank),
                "urlhaus": GenericMockProvider(name="urlhaus", enabled=settings.enable_urlhaus),
            }
        else:
            self.providers = {
                "google_webrisk": GoogleWebRiskProvider(enabled=settings.enable_google_web_risk),
                "phishtank": PhishTankProvider(enabled=settings.enable_phishtank),
                "urlhaus": URLhausProvider(enabled=settings.enable_urlhaus),
            }

    def register_provider(self, provider: ThreatIntelProvider):
        """Allows dynamic registration of future intelligence providers."""
        self.providers[provider.name] = provider

    def get_provider(self, name: str) -> Optional[ThreatIntelProvider]:
        return self.providers.get(name)

    def get_providers_status(self) -> List[ProviderStatusInfo]:
        """Return status and health metrics for all registered providers."""
        return [p.get_status_info() for p in self.providers.values()]

    async def _lookup_single_provider(
        self,
        provider: ThreatIntelProvider,
        url: str,
        skip_cache: bool = False,
    ) -> ThreatIntelResult:
        """Query a single provider with semaphore concurrency limit, cache check, and timeout."""
        # 1. Check cache first
        if not skip_cache:
            cached = threat_intel_cache.get(provider.name, url)
            if cached:
                return cached

        # 2. Acquire concurrency semaphore
        start_time = time.perf_counter()
        async with self.semaphore:
            try:
                # 3. Enforce strict timeout
                result = await asyncio.wait_for(
                    provider.lookup(url),
                    timeout=settings.threat_intel_timeout_seconds,
                )
            except asyncio.TimeoutError:
                logger.warning(f"[ThreatIntel:{provider.name}] Lookup timed out after {settings.threat_intel_timeout_seconds}s for: {url}")
                provider.record_failure("Provider lookup timed out")
                result = provider.make_unavailable_result(url, "Provider lookup timed out", start_time)
            except Exception as exc:
                logger.error(f"[ThreatIntel:{provider.name}] Unexpected error during lookup: {exc}", exc_info=True)
                provider.record_failure(str(exc))
                result = provider.make_unavailable_result(url, f"Unexpected error: {exc}", start_time)

        # 4. Store in cache
        threat_intel_cache.set(provider.name, url, result)
        return result

    async def lookup_all(
        self,
        url: str,
        skip_cache: bool = False,
    ) -> Dict[str, ThreatIntelResult]:
        """
        Execute concurrent lookups across all enabled providers.
        Guaranteed not to raise an unhandled exception: individual provider errors
        are isolated into ThreatIntelResult objects with verdict UNAVAILABLE/ERROR.
        """
        norm_url = normalize_url(url)
        tasks = []
        provider_names = []

        for name, provider in self.providers.items():
            if provider.enabled:
                provider_names.append(provider.name)
                tasks.append(self._lookup_single_provider(provider, norm_url, skip_cache=skip_cache))

        if not tasks:
            return {}

        results_list = await asyncio.gather(*tasks, return_exceptions=True)
        results: Dict[str, ThreatIntelResult] = {}

        for p_name, res in zip(provider_names, results_list):
            if isinstance(res, Exception):
                provider = self.get_provider(p_name)
                err_msg = f"Task exception: {res}"
                logger.error(f"[ThreatIntel:{p_name}] Gather captured exception: {err_msg}")
                if provider:
                    provider.record_failure(err_msg)
                    results[p_name] = provider.make_unavailable_result(norm_url, err_msg, time.perf_counter())
            elif isinstance(res, ThreatIntelResult):
                results[p_name] = res

        return results



# Global singleton instance
threat_intel_manager = ThreatIntelligenceManager()
