"""PhishTank Threat Intelligence provider implementation."""
from __future__ import annotations

import time
import asyncio
from datetime import datetime, timezone
from typing import Optional
import httpx

from app.intelligence.base import ThreatIntelProvider
from app.intelligence.models import ThreatIntelResult, ProviderVerdict
from app.config import settings
from app.utils.logger import get_logger

logger = get_logger(__name__)


class PhishTankProvider(ThreatIntelProvider):
    """
    PhishTank URL verification API integration.
    Queries the official checkurl endpoint with CyberNeura User-Agent.
    """

    def __init__(self, app_key: Optional[str] = None, enabled: Optional[bool] = None):
        is_enabled = enabled if enabled is not None else settings.enable_phishtank
        super().__init__(name="phishtank", enabled=is_enabled)
        self.app_key = app_key or settings.phishtank_app_key
        self.check_url = "https://checkurl.phishtank.com/checkurl/"
        self.timeout = settings.threat_intel_timeout_seconds
        self.user_agent = "CyberNeura/1.0 ThreatIntelligence"

    @property
    def configured(self) -> bool:
        # PhishTank allows public queries even without app_key, but having app_key increases limits
        return True

    async def lookup(self, url: str) -> ThreatIntelResult:
        start_time = time.perf_counter()

        if not self.enabled:
            return self.make_unavailable_result(url, "PhishTank is disabled in configuration", start_time)

        if self.is_circuit_open():
            return self.make_unavailable_result(
                url, f"PhishTank circuit open (degraded after {self.consecutive_failures} failures)", start_time
            )

        post_data = {
            "url": url,
            "format": "json",
        }
        if self.app_key and len(self.app_key.strip()) > 3:
            post_data["app_key"] = self.app_key.strip()

        headers = {
            "User-Agent": self.user_agent,
            "Accept": "application/json",
        }

        max_retries = 2
        last_exception = None

        for attempt in range(max_retries + 1):
            try:
                logger.info(f"[ThreatIntel:phishtank] Lookup started for: {url} (attempt {attempt + 1})")
                async with httpx.AsyncClient(timeout=self.timeout) as client:
                    resp = await client.post(self.check_url, data=post_data, headers=headers)

                latency_ms = int((time.perf_counter() - start_time) * 1000)

                # Rate limiting check
                if resp.status_code == 509 or resp.status_code == 429:
                    error_msg = "PhishTank rate limit exceeded (HTTP 509/429)"
                    logger.warning(f"[ThreatIntel:phishtank] {error_msg}")
                    self.record_failure(error_msg)
                    return ThreatIntelResult(
                        provider=self.name,
                        indicator=url,
                        indicator_type="url",
                        available=False,
                        matched=False,
                        verdict=ProviderVerdict.RATE_LIMITED,
                        categories=[],
                        checked_at=datetime.now(timezone.utc).isoformat(),
                        error=error_msg,
                        latency_ms=latency_ms,
                    )

                if resp.status_code == 200:
                    data = resp.json()
                    self.record_success()
                    results = data.get("results", {})
                    in_database = results.get("in_database", False)

                    if in_database:
                        verified = results.get("verified", False)
                        valid = results.get("valid", False)
                        phish_id = results.get("phish_id")
                        target = results.get("target")

                        logger.info(f"[ThreatIntel:phishtank] MATCH: verified={verified}, valid={valid} (latency: {latency_ms}ms)")
                        return ThreatIntelResult(
                            provider=self.name,
                            indicator=url,
                            indicator_type="url",
                            available=True,
                            matched=True,
                            verdict=ProviderVerdict.MATCH,
                            categories=["PHISHING"],
                            confidence=0.95 if verified else 0.80,
                            checked_at=datetime.now(timezone.utc).isoformat(),
                            latency_ms=latency_ms,
                            metadata={
                                "verified": verified,
                                "valid": valid,
                                "phish_id": phish_id,
                                "target": target,
                            },
                        )
                    else:
                        logger.info(f"[ThreatIntel:phishtank] NO_MATCH (latency: {latency_ms}ms)")
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

                # 5xx or transient status
                if resp.status_code in (500, 502, 503, 504):
                    if attempt < max_retries:
                        await asyncio.sleep(0.5 * (2 ** attempt))
                        continue
                    error_msg = f"HTTP {resp.status_code} server error after retries"
                    self.record_failure(error_msg)
                    return self.make_unavailable_result(url, error_msg, start_time)

                error_msg = f"HTTP {resp.status_code}: {resp.text[:120]}"
                self.record_failure(error_msg)
                return self.make_unavailable_result(url, error_msg, start_time)

            except (httpx.ConnectError, httpx.ReadTimeout, httpx.WriteTimeout, httpx.PoolTimeout) as exc:
                last_exception = exc
                logger.warning(f"[ThreatIntel:phishtank] Transient network error on attempt {attempt + 1}: {exc}")
                if attempt < max_retries:
                    await asyncio.sleep(0.5 * (2 ** attempt))
                    continue

            except Exception as exc:
                error_msg = f"Unexpected PhishTank exception: {exc}"
                self.record_failure(error_msg)
                logger.error(f"[ThreatIntel:phishtank] Lookup failed: {error_msg}", exc_info=True)
                return self.make_unavailable_result(url, error_msg, start_time)

        error_msg = f"PhishTank timed out or connection failed after retries: {last_exception}"
        self.record_failure(error_msg)
        return self.make_unavailable_result(url, error_msg, start_time)
