"""
CyberNeura Database Seeder
Seeds default threat intelligence logs, scan logs, settings, and users into Supabase.

Usage:
    cd backend
    python scripts/seed_db.py
"""
from __future__ import annotations

import sys
import uuid
from datetime import datetime, timezone, timedelta
from pathlib import Path

# Allow imports from parent
sys.path.insert(0, str(Path(__file__).parent.parent))

from app.database import get_db, check_db_health
from app.config import settings

SAMPLE_SCANS = [
    {
        "url": "https://malicious-bank-verify.ru",
        "risk_score": 98,
        "prediction": "malicious",
        "confidence": 96.5,
        "threat_category": "Phishing",
        "domain_age": "12 days",
        "hosting_provider": "CloudHost Offshore LLC",
        "ip_address": "185.220.101.5",
        "country": "Russia",
        "ssl_status": "none",
        "scanned_at": (datetime.now(timezone.utc) - timedelta(minutes=5)).isoformat(),
        "scanned_by": "system",
        "recommendations": ["Block access immediately", "Alert SOC team", "Add IP to perimeter firewall"],
    },
    {
        "url": "https://secure-payment-gateway.com",
        "risk_score": 12,
        "prediction": "safe",
        "confidence": 94.0,
        "threat_category": "Safe",
        "domain_age": "8 years",
        "hosting_provider": "Amazon Web Services",
        "ip_address": "52.84.12.144",
        "country": "United States",
        "ssl_status": "valid",
        "scanned_at": (datetime.now(timezone.utc) - timedelta(minutes=15)).isoformat(),
        "scanned_by": "system",
        "recommendations": ["Monitor DNS changes", "Enforce HSTS"],
    },
    {
        "url": "https://suspicious-crypto-giveaway.xyz",
        "risk_score": 75,
        "prediction": "suspicious",
        "confidence": 88.0,
        "threat_category": "Suspicious",
        "domain_age": "24 days",
        "hosting_provider": "Namecheap Inc.",
        "ip_address": "198.51.100.45",
        "country": "Iceland",
        "ssl_status": "expired",
        "scanned_at": (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat(),
        "scanned_by": "system",
        "recommendations": ["Isolate browsing session", "Do not submit credentials"],
    },
]

SAMPLE_NOTIFICATIONS = [
    {
        "title": "High Risk URL Detected",
        "message": "A scan for https://malicious-bank-verify.ru returned risk score 98/100 (Phishing).",
        "type": "alert",
        "read": False,
        "created_at": datetime.now(timezone.utc).isoformat(),
    },
    {
        "title": "ML Model Updated",
        "message": "URL Threat Classification Model v1.0.0 is now active with 94.12% accuracy.",
        "type": "info",
        "read": True,
        "created_at": (datetime.now(timezone.utc) - timedelta(hours=2)).isoformat(),
    },
]


def seed_database():
    print(f"\n[INFO] Connecting to Supabase at {settings.supabase_url}...")
    db = get_db()
    if db is None:
        print("[WARN] Supabase client could not be initialized or credentials are mock.")
        print("[INFO] CyberNeura backend supports seamless in-memory and mock fallback.")
        return

    print("[INFO] Attempting to seed default records...")
    try:
        for scan in SAMPLE_SCANS:
            db.table("url_scans").upsert(scan, on_conflict="url").execute()
        print(f"[OK] Seeded {len(SAMPLE_SCANS)} sample scans.")
    except Exception as exc:
        print(f"[NOTE] url_scans seed skipped: {exc}")

    try:
        for notif in SAMPLE_NOTIFICATIONS:
            db.table("notifications").insert(notif).execute()
        print(f"[OK] Seeded {len(SAMPLE_NOTIFICATIONS)} sample notifications.")
    except Exception as exc:
        print(f"[NOTE] notifications seed skipped: {exc}")

    print("[OK] Database seed routine completed.")


if __name__ == "__main__":
    seed_database()
