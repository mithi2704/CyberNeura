"""URLhaus (abuse.ch) Malware Threat Intelligence provider implementation."""
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


class URLhausProvider(ThreatIntelProvider):
    """
    URLhaus API integration for malware URL intelligence.
    LOOKUP ONLY — never submits user URLs to URLhaus.
    """

    def __init__(self, auth_key: Optional[str] = None, enabled: Optional[bool] = None):
        is_enabled = enabled if enabled is not None else settings.enable_urlhaus
        super().__init__(name="urlhaus", enabled=is_enabled)
        self.auth_key = auth_key or settings.urlhaus_auth_key
        self.lookup_url = "https://urlhaus-api.abuse.ch/v1/url/"
        self.timeout = settings.threat_intel_timeout_seconds

    @property
    def configured(self) -> bool:
        # URLhaus allows lookups publicly, or authenticated with Auth-Key
        return True

    async def lookup(self, url: str) -> ThreatIntelResult:
        start_time = time.perf_counter()

        if not self.enabled:
            return self.make_unavailable_result(url, "URLhaus is disabled in configuration", start_time)

        if self.is_circuit_open():
            return self.make_unavailable_result(
                url, f"URLhaus circuit open (degraded after {self.consecutive_failures} failures)", start_time
            )

        headers = {
            "Accept": "application/json",
        }
        if self.auth_key and len(self.auth_key.strip()) > 5:
            headers["Auth-Key"] = self.auth_key.strip()

        data = {"url": url}
        max_retries = 2
        last_exception = None

        for attempt in range(max_retries + 1):
            try:
                logger.info(f"[ThreatIntel:urlhaus] Lookup started for: {url} (attempt {attempt + 1})")
                async with httpx.AsyncClient(timeout=self.timeout) as client:
                    resp = await client.post(self.lookup_url, data=data, headers=headers)

                latency_ms = int((time.perf_counter() - start_time) * 1000)

                if resp.status_code == 200:
                    res_json = resp.json()
                    query_status = res_json.get("query_status")
                    self.record_success()

                    if query_status == "ok":
                        url_status = res_json.get("url_status", "unknown")
                        threat = res_json.get("threat", "malware_download")
                        tags = res_json.get("tags") or []
                        logger.info(f"[ThreatIntel:urlhaus] MATCH: status={url_status}, tags={tags} (latency: {latency_ms}ms)")
                        return ThreatIntelResult(
                            provider=self.name,
                            indicator=url,
                            indicator_type="url",
                            available=True,
                            matched=True,
                            verdict=ProviderVerdict.MATCH,
                            categories=["MALWARE", "MALWARE_DISTRIBUTION"],
                            confidence=0.96,
                            checked_at=datetime.now(timezone.utc).isoformat(),
                            latency_ms=latency_ms,
                            metadata={
                                "status": url_status,
                                "threat": threat,
                                "tags": tags,
                                "dateAdded": res_json.get("date_added"),
                            },
                        )
                    elif query_status == "no_results":
                        logger.info(f"[ThreatIntel:urlhaus] NO_MATCH (latency: {latency_ms}ms)")
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
                    else:
                        # e.g. invalid_url
                        error_msg = f"URLhaus query_status: {query_status}"
                        return self.make_unavailable_result(url, error_msg, start_time)

                # Rate limiting
                if resp.status_code == 429:
                    error_msg = "URLhaus rate limit exceeded (HTTP 429)"
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
                logger.warning(f"[ThreatIntel:urlhaus] Transient network error on attempt {attempt + 1}: {exc}")
                if attempt < max_retries:
                    await asyncio.sleep(0.5 * (2 ** attempt))
                    continue

            except Exception as exc:
                error_msg = f"Unexpected URLhaus exception: {exc}"
                self.record_failure(error_msg)
                logger.error(f"[ThreatIntel:urlhaus] Lookup failed: {error_msg}", exc_info=True)
                return self.make_unavailable_result(url, error_msg, start_time)

        error_msg = f"URLhaus timed out or connection failed after retries: {last_exception}"
        self.record_failure(error_msg)
        return self.make_unavailable_result(url, error_msg, start_time)
