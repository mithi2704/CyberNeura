"""Google Web Risk Lookup API provider implementation."""
from __future__ import annotations

import time
import asyncio
from datetime import datetime, timezone
from typing import List, Optional
import httpx

from app.intelligence.base import ThreatIntelProvider
from app.intelligence.models import ThreatIntelResult, ProviderVerdict
from app.config import settings
from app.utils.logger import get_logger

logger = get_logger(__name__)

SUPPORTED_THREAT_TYPES = [
    "SOCIAL_ENGINEERING",
    "MALWARE",
    "UNWANTED_SOFTWARE",
]


class GoogleWebRiskProvider(ThreatIntelProvider):
    """
    Google Web Risk Lookup API integration.
    Queries the official Google Web Risk uris:search endpoint.
    """

    def __init__(self, api_key: Optional[str] = None, enabled: Optional[bool] = None):
        is_enabled = enabled if enabled is not None else settings.enable_google_web_risk
        super().__init__(name="google_webrisk", enabled=is_enabled)
        self.api_key = api_key or settings.google_web_risk_api_key
        self.base_url = "https://webrisk.googleapis.com/v1/uris:search"
        self.timeout = settings.threat_intel_timeout_seconds

    @property
    def configured(self) -> bool:
        return bool(self.api_key and len(self.api_key.strip()) > 5)

    async def lookup(self, url: str) -> ThreatIntelResult:
        start_time = time.perf_counter()

        if not self.enabled:
            return self.make_unavailable_result(url, "Google Web Risk is disabled in configuration", start_time)

        if not self.configured:
            return self.make_not_configured_result(url, start_time)

        if self.is_circuit_open():
            return self.make_unavailable_result(
                url, f"Google Web Risk circuit open (degraded after {self.consecutive_failures} failures)", start_time
            )

        # Build query parameters
        params = [
            ("key", self.api_key),
            ("uri", url),
        ]
        for tt in SUPPORTED_THREAT_TYPES:
            params.append(("threatTypes", tt))

        max_retries = 2
        last_exception = None

        for attempt in range(max_retries + 1):
            try:
                logger.info(f"[ThreatIntel:google_webrisk] Lookup started for: {url} (attempt {attempt + 1})")
                async with httpx.AsyncClient(timeout=self.timeout) as client:
                    resp = await client.get(self.base_url, params=params)

                latency_ms = int((time.perf_counter() - start_time) * 1000)

                if resp.status_code == 200:
                    data = resp.json()
                    threat = data.get("threat")
                    self.record_success()

                    if threat and threat.get("threatTypes"):
                        categories = threat["threatTypes"]
                        expire_time = threat.get("expireTime")
                        logger.info(f"[ThreatIntel:google_webrisk] MATCH: {categories} (latency: {latency_ms}ms)")
                        return ThreatIntelResult(
                            provider=self.name,
                            indicator=url,
                            indicator_type="url",
                            available=True,
                            matched=True,
                            verdict=ProviderVerdict.MATCH,
                            categories=categories,
                            confidence=0.95,
                            checked_at=datetime.now(timezone.utc).isoformat(),
                            expires_at=expire_time,
                            latency_ms=latency_ms,
                            metadata={"matchedThreatTypes": categories},
                        )
                    else:
                        logger.info(f"[ThreatIntel:google_webrisk] NO_MATCH (latency: {latency_ms}ms)")
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

                # HTTP error handling
                if resp.status_code in (400, 401, 403):
                    # Auth or bad request - non-retryable
                    error_msg = f"HTTP {resp.status_code}: {resp.text[:120]}"
                    self.record_failure(error_msg)
                    logger.error(f"[ThreatIntel:google_webrisk] Non-retryable error: {error_msg}")
                    return self.make_unavailable_result(url, error_msg, start_time)

                # 5xx or transient status
                if resp.status_code in (500, 502, 503, 504):
                    if attempt < max_retries:
                        await asyncio.sleep(0.5 * (2 ** attempt))
                        continue
                    error_msg = f"HTTP {resp.status_code} server error after retries"
                    self.record_failure(error_msg)
                    return self.make_unavailable_result(url, error_msg, start_time)

                error_msg = f"Unexpected HTTP status {resp.status_code}"
                self.record_failure(error_msg)
                return self.make_unavailable_result(url, error_msg, start_time)

            except (httpx.ConnectError, httpx.ReadTimeout, httpx.WriteTimeout, httpx.PoolTimeout) as exc:
                last_exception = exc
                logger.warning(f"[ThreatIntel:google_webrisk] Transient network error on attempt {attempt + 1}: {exc}")
                if attempt < max_retries:
                    await asyncio.sleep(0.5 * (2 ** attempt))
                    continue

            except Exception as exc:
                error_msg = f"Unexpected lookup exception: {exc}"
                self.record_failure(error_msg)
                logger.error(f"[ThreatIntel:google_webrisk] Lookup failed: {error_msg}", exc_info=True)
                return self.make_unavailable_result(url, error_msg, start_time)

        error_msg = f"Lookup timed out or connection failed after retries: {last_exception}"
        self.record_failure(error_msg)
        return self.make_unavailable_result(url, error_msg, start_time)
