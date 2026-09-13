"""Provider-aware in-memory TTL cache for Threat Intelligence lookups."""
from __future__ import annotations

import threading
from datetime import datetime, timezone, timedelta
from typing import Dict, Optional

from app.intelligence.models import ThreatIntelResult, ProviderVerdict
from app.config import settings
from app.utils.logger import get_logger

logger = get_logger(__name__)


class ThreatIntelCacheEntry:
    def __init__(self, result: ThreatIntelResult, expires_at: datetime):
        self.result = result
        self.expires_at = expires_at

    def is_expired(self) -> bool:
        return datetime.now(timezone.utc) >= self.expires_at


class ThreatIntelCache:
    """
    Provider-specific cache to avoid repetitive external API queries.
    Keys are formatted as: {provider}:{normalized_url}
    """

    def __init__(self, default_ttl_seconds: Optional[int] = None):
        self._lock = threading.Lock()
        self._cache: Dict[str, ThreatIntelCacheEntry] = {}
        self._default_ttl = default_ttl_seconds or settings.threat_intel_cache_ttl_seconds

    def _make_key(self, provider: str, url: str) -> str:
        return f"{provider.lower()}:{url.strip()}"

    def get(self, provider: str, url: str) -> Optional[ThreatIntelResult]:
        key = self._make_key(provider, url)
        with self._lock:
            entry = self._cache.get(key)
            if entry is None:
                return None
            if entry.is_expired():
                del self._cache[key]
                return None
            logger.debug(f"[ThreatIntelCache] Cache HIT for {key}")
            return entry.result

    def set(self, provider: str, url: str, result: ThreatIntelResult, custom_ttl: Optional[int] = None):
        # Do NOT cache transient errors or unavailable results for long periods
        if not result.available or result.verdict in (ProviderVerdict.ERROR, ProviderVerdict.UNAVAILABLE, ProviderVerdict.RATE_LIMITED):
            ttl = 30  # 30 seconds max for temporary errors
        elif result.expires_at:
            try:
                # Use provider-supplied expireTime if valid ISO string
                exp_dt = datetime.fromisoformat(result.expires_at.replace("Z", "+00:00"))
                with self._lock:
                    self._cache[self._make_key(provider, url)] = ThreatIntelCacheEntry(result, exp_dt)
                return
            except Exception:
                ttl = custom_ttl or self._default_ttl
        else:
            ttl = custom_ttl or self._default_ttl

        expires_at = datetime.now(timezone.utc) + timedelta(seconds=ttl)
        result.expires_at = expires_at.isoformat()
        key = self._make_key(provider, url)
        with self._lock:
            self._cache[key] = ThreatIntelCacheEntry(result, expires_at)
        logger.debug(f"[ThreatIntelCache] Cached {key} (TTL: {ttl}s)")

    def invalidate(self, provider: str, url: str):
        key = self._make_key(provider, url)
        with self._lock:
            self._cache.pop(key, None)

    def clear(self):
        with self._lock:
            self._cache.clear()


# Global threat intel cache instance
threat_intel_cache = ThreatIntelCache()
