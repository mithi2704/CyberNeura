"""
CyberNeura Backend Configuration
All settings are loaded from environment variables / .env file.
"""
from __future__ import annotations

import os
from functools import lru_cache
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        protected_namespaces=("settings_",),
    )

    # ── App ──────────────────────────────────────────
    app_name: str = "CyberNeura Backend"
    app_env: str = "development"
    debug: bool = False
    host: str = "0.0.0.0"
    port: int = 8000
    app_version: str = "1.0.0"

    # ── CORS ─────────────────────────────────────────
    frontend_url: str = "http://localhost:5173"

    # ── Supabase ─────────────────────────────────────
    supabase_url: str = ""
    supabase_service_role_key: str = ""
    supabase_anon_key: str = ""

    # ── Firebase ─────────────────────────────────────
    firebase_project_id: str = ""
    firebase_client_email: str = ""
    firebase_private_key: str = ""

    # ── ML ───────────────────────────────────────────
    model_path: str = "ml/models/url_model.joblib"
    model_metadata_path: str = "ml/models/model_metadata.json"

    # ── Rate Limiting ────────────────────────────────
    rate_limit_per_minute: int = 60

    # ── Demo Auth ────────────────────────────────────
    allow_demo_auth: bool = False

    # ── External AI (LLM: Groq / OpenAI) ─────────────
    ai_provider: str = ""
    ai_api_key: str = ""
    ai_model: str = "gpt-4o-mini"
    groq_api_key: str = ""

    # ── GeoIP ────────────────────────────────────────
    geoip_api_url: str = ""
    geoip_api_key: str = ""

    # ── Risk Thresholds ──────────────────────────────
    risk_threshold_safe: int = 30
    risk_threshold_suspicious: int = 70

    # ── Phase 2: Threat Intelligence ─────────────────
    google_web_risk_api_key: str = ""
    phishtank_app_key: str = ""
    urlhaus_auth_key: str = ""
    threat_intel_timeout_seconds: float = 5.0
    threat_intel_cache_ttl_seconds: int = 900
    threat_intel_max_concurrent_requests: int = 3
    enable_google_web_risk: bool = True
    enable_phishtank: bool = True
    enable_urlhaus: bool = True
    threat_intel_mock_mode: bool = False

    # ── Phase 4: AI Security Agent ───────────────────
    agent_enabled: bool = True
    agent_reasoning_provider: str = ""
    agent_model: str = "gpt-4o-mini"
    agent_max_steps: int = 8
    agent_tool_timeout_seconds: float = 10.0
    agent_max_tool_calls: int = 12
    agent_temperature: float = 0.0
    agent_max_output_tokens: int = 1500
    agent_rate_limit_per_minute: int = 10

    # ── Phase 5: Real-Time Cybersecurity Platform ─────
    realtime_enabled: bool = True
    realtime_fallback_enabled: bool = True
    realtime_fallback_interval_seconds: int = 30
    realtime_event_retention_days: int = 30
    realtime_max_events_per_request: int = 100
    realtime_reconnect_max_attempts: int = 10

    # ── Phase 6: Chrome Browser Extension ────────────
    extension_enabled: bool = True
    extension_rate_limit_per_minute: int = 120
    extension_cache_ttl_seconds: int = 300
    extension_analysis_timeout_seconds: float = 8.0
    extension_strict_mode: bool = False
    extension_allow_override: bool = True
    extension_event_retention_days: int = 30
    extension_policy_version: str = "1.0.0"

    # ── Phase 7: AI Media Security ───────────────────
    media_enabled: bool = True
    media_storage_dir: str = "media_uploads"
    max_image_size_mb: int = 15
    max_video_size_mb: int = 250
    max_video_duration_seconds: int = 300
    max_video_frames: int = 300
    max_video_width: int = 3840
    max_video_height: int = 2160
    image_model_id: str = "cyberneura-image-detector"
    image_model_version: str = "1.0.0"
    deepfake_model_id: str = "cyberneura-video-detector"
    deepfake_model_version: str = "1.0.0"
    media_retention_days: int = 30
    media_frame_retention_days: int = 7
    max_concurrent_image_jobs: int = 4
    max_concurrent_video_jobs: int = 2
    max_video_queue_size: int = 25
    default_frame_sampling_rate: int = 2



    @property
    def is_production(self) -> bool:
        return self.app_env == "production"

    @property
    def is_development(self) -> bool:
        return self.app_env == "development"

    @property
    def supabase_configured(self) -> bool:
        return bool(
            self.supabase_url
            and "mock" not in self.supabase_url
            and self.supabase_service_role_key
            and "mock" not in self.supabase_service_role_key
        )

    @property
    def firebase_configured(self) -> bool:
        return bool(
            self.firebase_project_id
            and self.firebase_client_email
            and self.firebase_private_key
        )


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
