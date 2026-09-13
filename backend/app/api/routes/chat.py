"""
AI Security Assistant chat routes.
Matches frontend chatService.ts interface.
Uses a deterministic security-focused response engine.
If OPENAI_API_KEY is configured, delegates to GPT.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from app.database import get_db
from app.dependencies import AuthUser
from app.config import settings
from app.utils.logger import get_logger

logger = get_logger(__name__)
router = APIRouter(tags=["Chat"], prefix="/chat")


class ChatRequest(BaseModel):
    message: str
    scanId: Optional[str] = None


def _deterministic_response(message: str) -> str:
    """Security-focused deterministic response engine."""
    msg = message.lower()

    if any(k in msg for k in ["explain", "prediction", "last scan", "risk score"]):
        return (
            "### Scan Evaluation\n"
            "The scan analyses the URL against 28 extracted features including:\n\n"
            "- **URL structure** — length, subdomain depth, special characters\n"
            "- **Security indicators** — HTTPS usage, phishing keywords, suspicious TLDs\n"
            "- **Domain intelligence** — age, registrar, DNS record validity\n\n"
            "The ML model outputs a 0–100 risk score. Scores above 70 are classified as **Malicious**, "
            "31–70 as **Suspicious**, and 0–30 as **Safe**."
        )

    if any(k in msg for k in ["tips", "prevent", "protect", "phishing"]):
        return (
            "### Phishing Prevention Checklist\n\n"
            "* **Check SSL** — Only interact with HTTPS sites showing a valid certificate.\n"
            "* **Verify domains** — Phishing uses typosquatting (e.g., `paypa1.com`).\n"
            "* **Hover links** — Inspect the actual URL before clicking.\n"
            "* **Enable MFA** — Blocks 99.9% of credential theft even if a link is visited.\n"
            "* **Use DNS filtering** — Enable DNS-over-HTTPS with threat feed blacklists."
        )

    if any(k in msg for k in ["malware", "compromised", "infected", "threat advice", "incident"]):
        return (
            "### Incident Response\n\n"
            "1. **Isolate** the endpoint — disconnect from network immediately.\n"
            "2. **Revoke sessions** — invalidate all OAuth/SAML tokens in your IDP.\n"
            "3. **Review logs** — query firewall logs for the ingress timeframe.\n"
            "4. **Scan offline** — run an offline malware scan on the affected host.\n"
            "5. **Alert team** — notify your security operations center."
        )

    if any(k in msg for k in ["http", ".com", ".net", ".org", ".ru", ".xyz", "analyze", "check"]):
        import re
        urls = re.findall(r"(https?://[^\s]+|[\w-]+\.[a-z]{2,}[^\s]*)", message)
        url_str = urls[0] if urls else "the provided URL"
        return (
            f"To scan **{url_str}** use the URL Scanner on the dashboard.\n\n"
            "The scanner will analyse:\n"
            "- Domain age and registrar\n"
            "- SSL certificate validity\n"
            "- DNS record anomalies\n"
            "- Phishing keyword patterns\n"
            "- ML risk classification\n\n"
            "Results are saved to your scan history automatically."
        )

    return (
        f"I'm your CyberNeura security assistant. You asked: *\"{message}\"*\n\n"
        "I can help you with:\n"
        "- **\"Explain prediction\"** — understand how the ML risk score works\n"
        "- **\"Security tips\"** — phishing prevention best practices\n"
        "- **\"Threat advice\"** — incident response guidance\n"
        "- **\"Analyze [URL]\"** — get scan instructions for a specific URL"
    )


async def _llm_response(message: str, history: list) -> Optional[str]:
    """Delegate to Groq or OpenAI if configured."""
    provider = (settings.ai_provider or "").lower()
    groq_key = settings.groq_api_key
    ai_key = settings.ai_api_key

    # Determine endpoint, auth key, and model
    if provider == "groq" or groq_key or (ai_key and ai_key.startswith("gsk_")):
        endpoint = "https://api.groq.com/openai/v1/chat/completions"
        api_key = groq_key or ai_key
        model = settings.ai_model if settings.ai_model and settings.ai_model != "gpt-4o-mini" else "llama-3.3-70b-versatile"
    elif provider in ("openai", "azure_openai") and ai_key:
        endpoint = "https://api.openai.com/v1/chat/completions"
        api_key = ai_key
        model = settings.ai_model or "gpt-4o-mini"
    else:
        return None

    try:
        import httpx
        messages = [
            {"role": "system", "content": (
                "You are a security analyst assistant for the CyberNeura threat intelligence platform. "
                "You specialize in URL threat analysis, phishing detection, and cybersecurity best practices. "
                "Be concise, professional, and helpful. Use markdown formatting."
            )}
        ] + [{"role": m["role"], "content": m["content"]} for m in history[-6:]] + [
            {"role": "user", "content": message}
        ]
        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.post(
                endpoint,
                headers={"Authorization": f"Bearer {api_key}"},
                json={"model": model, "messages": messages, "max_tokens": 500},
            )
            data = resp.json()
            return data["choices"][0]["message"]["content"]
    except Exception as exc:
        logger.warning(f"LLM request failed: {exc}")
        return None


import re
from app.agent.agent import cyberneura_agent
from app.agent.models import AgentObjective
from app.services.scan_store import scan_store


class ChatRequest(BaseModel):
    message: str
    scanId: Optional[str] = None
    scan_id: Optional[str] = None
    mediaId: Optional[str] = None
    media_id: Optional[str] = None


@router.post("", summary="Send a message to the AI assistant")
async def chat(body: ChatRequest, user: AuthUser):
    if not body.message.strip():
        raise HTTPException(status_code=400, detail={"error": "EMPTY_MESSAGE", "message": "Message cannot be empty"})

    scan_ref = body.scan_id or body.scanId
    media_ref = body.media_id or body.mediaId
    target_url = None

    now = datetime.now(timezone.utc).isoformat()
    db = get_db()

    # Check for media ID pattern if not explicitly provided
    if not media_ref:
        media_matches = re.findall(r"(media_[a-f0-9]{8,16})", body.message)
        if media_matches:
            media_ref = media_matches[0]

    if media_ref:
        assessment = scan_store.get_media_assessment(media_ref)
        if assessment:
            prov = scan_store.get_media_provenance(media_ref)
            forensic = scan_store.get_media_forensic(media_ref)
            ev_items = scan_store.get_media_evidence(media_ref)

            prov_str = f"Provenance: {prov.provenance_status.value} (Claim valid: {prov.claim_valid})" if prov else "Provenance: None recorded"
            forensic_str = f"ELA anomaly score: {forensic.ela_anomaly_score:.2f}, noise variance: {forensic.noise_variance_anomaly:.2f}" if forensic else "Forensics: standard analysis"

            response_text = (
                f"### AI Media Security Assessment: `{media_ref}`\n\n"
                f"- **Classification:** **{assessment.classification.value}**\n"
                f"- **Risk Score:** `{assessment.risk_score:.1f}/100`\n"
                f"- **Model Confidence:** `{assessment.confidence:.2f}`\n"
                f"- **Neural/Model Score:** `{assessment.model_score:.2f}`\n\n"
                f"**Analysis Details:**\n{assessment.explanation}\n\n"
                f"**Forensic Signals:**\n- {prov_str}\n- {forensic_str}\n"
                f"- Correlated Phase 3 Evidence Items: {len(ev_items)}\n"
            )

            if db:
                try:
                    db.table("chat_history").insert([
                        {"user_id": user.uid, "role": "user", "content": body.message, "timestamp": now},
                        {"user_id": user.uid, "role": "assistant", "content": response_text, "timestamp": now},
                    ]).execute()
                except Exception as exc:
                    logger.warning(f"Could not persist chat: {exc}")

            return {
                "message": response_text,
                "answer": response_text,
                "role": "assistant",
                "timestamp": now,
                "media_id": media_ref,
                "risk": assessment.risk_score,
                "confidence": assessment.confidence,
                "threat_category": assessment.classification.value,
                "evidence": [e.summary for e in ev_items],
                "recommendations": [
                    "Examine C2PA cryptographic signature manifests before publishing.",
                    "Verify audio-visual synchronization and temporal optical flow.",
                    "Inspect high-frequency Fourier spectrum residuals for generative lattice artifacts.",
                ],
                "tools_used": ["get_media_evidence", "get_media_provenance", "get_media_forensics"],
                "timeline": [
                    {"step": "get_media_evidence", "status": "completed"},
                    {"step": "get_media_provenance", "status": "completed"},
                    {"step": "get_media_forensics", "status": "completed"},
                ],
            }

    if scan_ref:
        scan = scan_store.get_scan(scan_ref)
        if scan:
            target_url = scan.get("url")

    if not target_url:
        # Check if a URL was embedded directly in the message
        url_matches = re.findall(r"(https?://[^\s]+|[\w-]+\.[a-z]{2,}[^\s]*)", body.message)
        if url_matches:
            target_url = url_matches[0]

    now = datetime.now(timezone.utc).isoformat()
    db = get_db()

    # If a URL or scan_id is identified, delegate directly to the AI Security Agent
    if target_url:
        try:
            report = await cyberneura_agent.investigate(
                url=target_url,
                question=body.message,
                user_id=user.uid,
                scan_id=scan_ref,
                objective=AgentObjective.THREAT_EXPLANATION if "why" in body.message.lower() else AgentObjective.URL_SAFETY_ASSESSMENT,
            )

            response_text = report.final_answer or (
                report.final_assessment.get("explanation") if isinstance(report.final_assessment, dict) else None
            ) or f"Investigation completed for {target_url}."

            assessment = report.final_assessment if isinstance(report.final_assessment, dict) else {}
            risk_score = assessment.get("risk_score")
            confidence = assessment.get("confidence")

            # Persist chat
            if db:
                try:
                    db.table("chat_history").insert([
                        {"user_id": user.uid, "role": "user", "content": body.message, "timestamp": now},
                        {"user_id": user.uid, "role": "assistant", "content": response_text, "timestamp": now},
                    ]).execute()
                except Exception as exc:
                    logger.warning(f"Could not persist chat: {exc}")

            return {
                "message": response_text,
                "answer": response_text,
                "role": "assistant",
                "timestamp": now,
                "scan_id": scan_ref or report.scan_id,
                "session_id": report.session_id,
                "risk": risk_score,
                "confidence": confidence,
                "threat_category": assessment.get("threat_category"),
                "evidence": report.evidence_summary,
                "recommendations": report.recommendations,
                "tools_used": report.tools_used,
                "timeline": [
                    {"step": tc, "status": "completed"} for tc in report.tools_used
                ],
            }
        except Exception as exc:
            logger.error(f"Agent chat delegation failed: {exc}", exc_info=True)

    # Fallback to general conversational assistant
    history = []
    if db:
        try:
            hist_res = db.table("chat_history").select("role,content").eq("user_id", user.uid).order("timestamp", desc=False).limit(10).execute()
            history = hist_res.data or []
        except Exception:
            pass

    response_text = await _llm_response(body.message, history)
    if response_text is None:
        response_text = _deterministic_response(body.message)

    if db:
        try:
            db.table("chat_history").insert([
                {"user_id": user.uid, "role": "user", "content": body.message, "timestamp": now},
                {"user_id": user.uid, "role": "assistant", "content": response_text, "timestamp": now},
            ]).execute()
        except Exception as exc:
            logger.warning(f"Could not persist chat: {exc}")

    return {
        "message": response_text,
        "answer": response_text,
        "role": "assistant",
        "timestamp": now,
        "recommendations": [
            "Use the URL Scanner on the dashboard for deep multi-signal analysis.",
            "Enable MFA across all corporate and personal credentials.",
        ],
        "tools_used": ["conversational_assistant"],
        "timeline": [{"step": "conversational_assistant", "status": "completed"}],
    }


@router.get("/history", summary="Get chat history")
async def get_history(user: AuthUser):
    db = get_db()
    if db is None:
        return []
    try:
        result = (
            db.table("chat_history")
            .select("*")
            .eq("user_id", user.uid)
            .order("timestamp", desc=False)
            .limit(50)
            .execute()
        )
        return [
            {"id": str(r.get("id", "")), "role": r.get("role"), "content": r.get("content"), "timestamp": str(r.get("timestamp", ""))}
            for r in (result.data or [])
        ]
    except Exception as exc:
        logger.error(f"Chat history error: {exc}")
        return []


@router.delete("/history", summary="Clear chat history")
async def clear_history(user: AuthUser):
    db = get_db()
    if db is None:
        return {"success": True}
    try:
        db.table("chat_history").delete().eq("user_id", user.uid).execute()
        return {"success": True, "message": "Chat history cleared"}
    except Exception as exc:
        raise HTTPException(status_code=500, detail={"error": "DB_ERROR", "message": str(exc)})
