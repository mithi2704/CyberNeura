"""Reports routes — CSV export and per-scan report."""
from __future__ import annotations

import csv
import io
from fastapi import APIRouter, HTTPException
from fastapi.responses import StreamingResponse, PlainTextResponse
from app.database import get_db
from app.dependencies import AuthUser
from app.utils.logger import get_logger

logger = get_logger(__name__)
router = APIRouter(tags=["Reports"], prefix="/reports")


@router.get("/scan/{scan_id}", summary="Get formatted text report for a scan")
async def get_scan_report(scan_id: str, user: AuthUser):
    db = get_db()
    if db is None:
        raise HTTPException(status_code=404, detail={"error": "NOT_FOUND", "message": "Scan not found"})
    try:
        result = db.table("url_scans").select("*").eq("id", scan_id).single().execute()
        if not result.data:
            raise HTTPException(status_code=404, detail={"error": "NOT_FOUND", "message": "Scan not found"})
        scan = result.data
        recs = scan.get("recommendations") or []
        rec_text = "\n".join(f"{i+1}. {r}" for i, r in enumerate(recs)) if recs else "No critical actions required."
        report = f"""
=========================================
      CYBERNEURA SECURITY PLATFORM
         DETAILED THREAT REPORT
=========================================
Generated At: {__import__('datetime').datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}
Scan Identifier: {scan_id}

[TARGET URL INFORMATION]
URL: {scan.get('url', '')}
Threat Prediction: {str(scan.get('prediction', '')).upper()}
Calculated Risk: {scan.get('risk_score', 0)}/100
Scan Confidence: {scan.get('confidence', 0)}%
Threat Category: {scan.get('threat_category', 'Unknown')}

[NETWORK & DNS TELEMETRY]
Resolving IP Address: {scan.get('ip_address', 'Unavailable')}
Location Target: {scan.get('country', 'Unknown')}
Hosting Provider: {scan.get('hosting_provider', 'Unknown')}
Domain Registration Age: {scan.get('domain_age', 'Unknown')}
SSL Status: {str(scan.get('ssl_status', 'NONE')).upper()}

[RECOMMENDATIONS]
{rec_text}

-----------------------------------------
Protected by CyberNeura AI Security
Platform Operations Center (POC)
=========================================
"""
        return PlainTextResponse(content=report, media_type="text/plain")
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=500, detail={"error": "DB_ERROR", "message": str(exc)})


@router.get("/scans/export", summary="Export all scans as CSV")
async def export_scans_csv(user: AuthUser):
    db = get_db()
    if db is None:
        raise HTTPException(status_code=503, detail={"error": "DB_UNAVAILABLE", "message": "Database not configured"})
    try:
        result = db.table("url_scans").select("*").order("scanned_at", desc=True).execute()
        rows = result.data or []

        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(["URL", "Risk Score", "Prediction", "Confidence", "Threat Category", "IP Address", "Country", "SSL Status", "Scanned At"])
        for r in rows:
            writer.writerow([
                r.get("url", ""), r.get("risk_score", ""), r.get("prediction", ""),
                r.get("confidence", ""), r.get("threat_category", ""),
                r.get("ip_address", ""), r.get("country", ""),
                r.get("ssl_status", ""), r.get("scanned_at", ""),
            ])

        output.seek(0)
        return StreamingResponse(
            iter([output.getvalue()]),
            media_type="text/csv",
            headers={"Content-Disposition": "attachment; filename=cyberneura_threat_logs.csv"},
        )
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=500, detail={"error": "DB_ERROR", "message": str(exc)})
