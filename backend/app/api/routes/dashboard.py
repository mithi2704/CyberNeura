"""Dashboard analytics routes."""
from __future__ import annotations

from datetime import datetime, timezone, timedelta
from fastapi import APIRouter
from app.database import get_db
from app.dependencies import AuthUser
from app.services.scan_store import scan_store
from app.utils.logger import get_logger

logger = get_logger(__name__)
router = APIRouter(tags=["Dashboard"], prefix="/dashboard")


@router.get("/stats", summary="Dashboard KPI statistics")
async def get_stats(user: AuthUser):
    db = get_db()
    if db is None:
        return scan_store.get_stats()
    try:
        today = datetime.now(timezone.utc).date().isoformat()
        all_scans = db.table("url_scans").select("prediction, risk_score, scanned_at").execute()
        rows = all_scans.data or []

        total = len(rows)
        if total == 0:
            return scan_store.get_stats()

        scans_today = sum(1 for r in rows if str(r.get("scanned_at", "")).startswith(today))
        safe = sum(1 for r in rows if r.get("prediction") == "safe")
        suspicious = sum(1 for r in rows if r.get("prediction") == "suspicious")
        malicious = sum(1 for r in rows if r.get("prediction") == "malicious")
        avg_risk = round(sum(r.get("risk_score", 0) for r in rows) / max(1, total), 1)

        threats = db.table("threat_logs").select("id", count="exact").execute()
        threats_blocked = threats.count or 0
        provider_stats = scan_store.get_provider_stats()

        return {
            "totalScans": total,
            "scansToday": scans_today,
            "safeScans": safe,
            "suspiciousScans": suspicious,
            "maliciousScans": malicious,
            "threatsBlocked": threats_blocked,
            "averageRiskScore": avg_risk,
            "providerStats": provider_stats,
        }

    except Exception as exc:
        logger.error(f"Dashboard stats error: {exc}")
        return scan_store.get_stats()


@router.get("/trends", summary="Threat trend data for charts")
async def get_trends(user: AuthUser):
    db = get_db()
    if db is None:
        return {"data": scan_store.get_trends(days=7)}
    try:
        since = (datetime.now(timezone.utc) - timedelta(days=7)).isoformat()
        result = db.table("url_scans").select("prediction, scanned_at").gte("scanned_at", since).execute()
        rows = result.data or []
        if not rows:
            return {"data": scan_store.get_trends(days=7)}

        # Group by day
        by_day: dict = {}
        for r in rows:
            day = str(r.get("scanned_at", ""))[:10]
            if day not in by_day:
                by_day[day] = {"safe": 0, "suspicious": 0, "malicious": 0, "count": 0}
            pred = r.get("prediction", "safe")
            by_day[day][pred] = by_day[day].get(pred, 0) + 1
            by_day[day]["count"] = by_day[day].get("count", 0) + 1

        data = [{"date": d, "name": d[5:], **counts} for d, counts in sorted(by_day.items())]
        return {"data": data}
    except Exception as exc:
        logger.error(f"Trends error: {exc}")
        return {"data": scan_store.get_trends(days=7)}


@router.get("/distribution", summary="Scan outcome distribution")
async def get_distribution(user: AuthUser):
    db = get_db()
    if db is None:
        return {"data": scan_store.get_distribution()}
    try:
        result = db.table("url_scans").select("prediction").execute()
        rows = result.data or []
        if not rows:
            return {"data": scan_store.get_distribution()}

        counts = {"safe": 0, "suspicious": 0, "malicious": 0}
        for r in rows:
            p = r.get("prediction", "safe")
            counts[p] = counts.get(p, 0) + 1
        data = [
            {"name": "Safe", "value": counts["safe"], "color": "#10b981"},
            {"name": "Suspicious", "value": counts["suspicious"], "color": "#f59e0b"},
            {"name": "Malicious", "value": counts["malicious"], "color": "#ff007f"},
        ]
        return {"data": data}
    except Exception as exc:
        logger.error(f"Distribution error: {exc}")
        return {"data": scan_store.get_distribution()}
