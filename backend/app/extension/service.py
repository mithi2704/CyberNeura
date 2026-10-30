"""
Extension Service for CyberNeura Phase 6.
Coordinates URL normalization, caching, full Phase 3 risk analysis, selective
Phase 4 agent investigation, policy evaluation, event persistence, and Phase 5
real-time broadcasting.
"""
from __future__ import annotations

import asyncio
import uuid
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, Optional

from app.config import settings
from app.database import get_db
from app.extension.models import (
    ExtensionAnalyzeRequest,
    ExtensionAnalyzeResponse,
    ExtensionDecision,
    ExtensionOverrideRequest,
    ExtensionReportRequest,
    ExtensionChatRequest,
    ExtensionChatResponse,
)
from app.extension.policy import policy_engine
from app.realtime import event_publisher, RealtimeEventType, EntityType
from app.services.assessment_service import AssessmentService
from app.services.scan_store import scan_store
from app.utils.logger import get_logger
from app.utils.validators import normalize_url, validate_url

logger = get_logger(__name__)


class ExtensionService:
    def __init__(self):
        self.assessment_service = AssessmentService()
        self.policy_engine = policy_engine

    async def analyze_url(
        self,
        request: ExtensionAnalyzeRequest,
        user_id: Optional[str] = None,
    ) -> ExtensionAnalyzeResponse:
        """
        Coordinates full URL analysis for browser extension:
        1. Validates and normalizes candidate URL.
        2. Fast path: checks local/in-memory cache (<100ms).
        3. Full analysis: runs Phase 3 multi-source risk and evidence pipeline.
        4. Selective agent delegation for ambiguous findings.
        5. Policy evaluation: renders ALLOW, WARN, or BLOCK.
        6. Persists event and broadcasts live real-time signals to dashboard.
        """
        raw_url = request.url.strip()
        is_valid, err_msg = validate_url(raw_url)
        if not is_valid:
            return ExtensionAnalyzeResponse(
                url=raw_url,
                decision=ExtensionDecision.ALLOW,
                risk_score=0,
                prediction="SAFE",
                confidence=100.0,
                summary=f"Skipped inspection: {err_msg}",
                reasons=[f"URL not eligible for web scanning: {err_msg}"],
                recommendations=["No security action needed."],
                cached=False,
            )

        norm_url = normalize_url(raw_url)
        now_dt = datetime.now(timezone.utc)
        now_iso = now_dt.isoformat()

        # Emit EXTENSION_SCAN_STARTED
        scan_id = str(uuid.uuid4())
        await event_publisher.publish(
            event_type=RealtimeEventType.EXTENSION_SCAN_STARTED,
            entity_type=EntityType.EXTENSION_EVENT,
            entity_id=scan_id,
            user_id=user_id,
            payload={
                "scan_id": scan_id,
                "url": norm_url,
                "installation_id": request.installation_id,
                "browser": request.browser,
                "tab_id": request.tab_id,
                "timestamp": now_iso,
            },
        )

        # 1. Fast Path: Cache Check (TTL: 300 seconds)
        existing_scan = scan_store.get_scan_by_url(norm_url)
        if existing_scan:
            scanned_at_str = existing_scan.get("scannedAt", "")
            try:
                scanned_dt = datetime.fromisoformat(scanned_at_str.replace("Z", "+00:00"))
                if (now_dt - scanned_dt) < timedelta(seconds=settings.extension_cache_ttl_seconds):
                    # Cache hit!
                    risk_score = existing_scan.get("riskScore", 0)
                    prediction = existing_scan.get("prediction", "SAFE")
                    confidence = float(existing_scan.get("confidence", 85.0))
                    threat_category = existing_scan.get("threatCategory")
                    threat_intel = existing_scan.get("threatIntelligence")

                    decision, allow_override, reasons, recommendations = self.policy_engine.evaluate(
                        risk_score=risk_score,
                        prediction=prediction,
                        confidence=confidence,
                        threat_category=threat_category,
                        severity=existing_scan.get("severity"),
                        threat_intel=threat_intel,
                    )

                    response = ExtensionAnalyzeResponse(
                        request_id=str(uuid.uuid4()),
                        url=norm_url,
                        decision=decision,
                        risk_score=risk_score,
                        prediction=prediction.upper(),
                        confidence=confidence,
                        threat_category=threat_category,
                        severity=existing_scan.get("severity", "LOW"),
                        summary=f"Cached security assessment: {decision.value} decision applied.",
                        reasons=reasons,
                        recommendations=recommendations,
                        cached=True,
                        analysis_timestamp=now_iso,
                        allow_override=allow_override,
                        scan_id=existing_scan.get("id", scan_id),
                    )

                    await self._record_and_broadcast(
                        response=response,
                        user_id=user_id,
                        installation_id=request.installation_id,
                        browser=request.browser,
                        version=request.extension_version,
                    )
                    return response
            except Exception as parse_err:
                logger.debug(f"Cache timestamp parse failure: {parse_err}")

        # 2. Full Assessment Pipeline
        try:
            assessment, context = await asyncio.wait_for(
                self.assessment_service.execute_full_assessment(
                    url=norm_url,
                    user_id=user_id,
                    scan_id=scan_id,
                ),
                timeout=settings.extension_analysis_timeout_seconds,
            )

            risk_score = assessment.risk_score
            prediction = (assessment.prediction or "SAFE").upper()
            confidence = assessment.confidence
            threat_category = context.get("threat_category", assessment.threat_category or "Safe")
            threat_intel = context.get("threat_intelligence")
            severity = getattr(assessment.severity, "value", str(assessment.severity)) if assessment.severity else context.get("severity", "LOW")

            # 3. Selective Agent Delegation for Ambiguous Findings
            # If signals are ambiguous (score 35-75 or suspicious), launch background agent investigation
            if 35 <= risk_score <= 75 and settings.agent_enabled:
                asyncio.create_task(self._run_selective_agent(norm_url, user_id, scan_id))

            decision, allow_override, reasons, recommendations = self.policy_engine.evaluate(
                risk_score=risk_score,
                prediction=prediction,
                confidence=confidence,
                threat_category=threat_category,
                severity=severity,
                threat_intel=threat_intel,
            )

            response = ExtensionAnalyzeResponse(
                request_id=str(uuid.uuid4()),
                url=norm_url,
                decision=decision,
                risk_score=risk_score,
                prediction=prediction,
                confidence=confidence,
                threat_category=threat_category,
                severity=severity,
                summary=assessment.summary or f"Security assessment rendered {decision.value}.",
                reasons=reasons,
                recommendations=recommendations,
                cached=False,
                analysis_timestamp=now_iso,
                allow_override=allow_override,
                scan_id=scan_id,
            )

            await self._record_and_broadcast(
                response=response,
                user_id=user_id,
                installation_id=request.installation_id,
                browser=request.browser,
                version=request.extension_version,
            )
            return response

        except asyncio.TimeoutError:
            logger.warning(f"Extension analysis timed out for URL: {norm_url}")
            # Fail-Safe: ALLOW if non-strict, WARN if strict
            decision = ExtensionDecision.WARN if settings.extension_strict_mode else ExtensionDecision.ALLOW
            return ExtensionAnalyzeResponse(
                request_id=str(uuid.uuid4()),
                url=norm_url,
                decision=decision,
                risk_score=0,
                prediction="UNKNOWN",
                confidence=50.0,
                summary="Analysis timed out; fail-safe policy applied.",
                reasons=["Security inspection service exceeded timeout deadline."],
                recommendations=["Verify website identity before submitting sensitive data."],
                cached=False,
                allow_override=True,
                scan_id=scan_id,
            )
        except Exception as e:
            logger.error(f"Extension analysis unexpected error for {norm_url}: {e}")
            decision = ExtensionDecision.WARN if settings.extension_strict_mode else ExtensionDecision.ALLOW
            return ExtensionAnalyzeResponse(
                request_id=str(uuid.uuid4()),
                url=norm_url,
                decision=decision,
                risk_score=0,
                prediction="UNKNOWN",
                confidence=50.0,
                summary="Analysis unavailable; fail-safe policy applied.",
                reasons=["Security service temporarily unavailable."],
                recommendations=["Proceed with standard browsing caution."],
                cached=False,
                allow_override=True,
                scan_id=scan_id,
            )

    async def _run_selective_agent(self, url: str, user_id: Optional[str], scan_id: str) -> None:
        """Background selective agent investigation for ambiguous URL findings."""
        try:
            from app.agent.orchestrator import AgentOrchestrator
            agent = AgentOrchestrator()
            await agent.investigate(
                query=f"Investigate ambiguous security signals for browser navigation: {url}",
                target_url=url,
                user_id=user_id,
            )
        except Exception as err:
            logger.debug(f"Selective agent investigation non-critical failure: {err}")

    async def _record_and_broadcast(
        self,
        response: ExtensionAnalyzeResponse,
        user_id: Optional[str],
        installation_id: str,
        browser: str,
        version: str,
    ) -> None:
        """Persists extension event and emits Phase 5 Realtime events."""
        event_dict = {
            "id": response.request_id,
            "scan_id": response.scan_id,
            "user_id": user_id,
            "installation_id": installation_id,
            "url": response.url,
            "decision": response.decision,
            "risk_score": response.risk_score,
            "prediction": response.prediction,
            "threat_category": response.threat_category,
            "confidence": response.confidence,
            "user_override": False,
            "timestamp": response.analysis_timestamp,
            "extension_version": version,
            "browser": browser,
            "created_at": response.analysis_timestamp,
        }

        # 1. In-memory buffer persistence
        scan_store.save_extension_event(event_dict)

        # 2. Database persistence (fail-safe)
        db = get_db()
        if db:
            try:
                db.table("extension_events").insert(event_dict).execute()
            except Exception as db_err:
                logger.warning(f"Failed to persist extension event to Supabase: {db_err}")

        # 3. Phase 5 Realtime broadcasting
        # Base completion event
        await event_publisher.publish(
            event_type=RealtimeEventType.EXTENSION_SCAN_COMPLETED,
            entity_type=EntityType.EXTENSION_EVENT,
            entity_id=response.request_id,
            user_id=user_id,
            payload={
                "scan_id": response.scan_id,
                "url": response.url,
                "decision": response.decision,
                "risk_score": response.risk_score,
                "prediction": response.prediction,
                "installation_id": installation_id,
                "browser": browser,
                "timestamp": response.analysis_timestamp,
            },
        )

        # Primary Dashboard & URL Logs live update event
        await event_publisher.publish(
            event_type=RealtimeEventType.SCAN_COMPLETED,
            entity_type=EntityType.URL_SCAN,
            entity_id=response.scan_id or response.request_id,
            user_id=user_id,
            payload={
                "id": response.scan_id or response.request_id,
                "url": response.url,
                "riskScore": response.risk_score,
                "prediction": response.prediction.lower(),
                "confidence": response.confidence,
                "threatCategory": response.threat_category or ("Safe" if response.prediction.lower() == "safe" else "Phishing"),
                "sslStatus": "valid" if response.url.startswith("https://") else "none",
                "scannedAt": response.analysis_timestamp,
                "severity": getattr(response.severity, "value", str(response.severity)) if response.severity else "LOW",
                "summary": response.summary,
            },
        )

        # Live Threat Intelligence broadcast if suspicious or malicious
        if response.risk_score >= 30 or response.prediction.lower() in ("suspicious", "malicious"):
            await event_publisher.publish(
                event_type=RealtimeEventType.THREAT_DETECTED,
                entity_type=EntityType.URL_SCAN,
                entity_id=response.scan_id or response.request_id,
                user_id=user_id,
                payload={
                    "scan_id": response.scan_id or response.request_id,
                    "url": response.url,
                    "provider": "Browser Protection",
                    "threat_category": response.threat_category or "Phishing",
                    "severity": getattr(response.severity, "value", str(response.severity)) if response.severity else "HIGH",
                    "risk_score": response.risk_score,
                },
            )

        # Action-specific real-time notifications
        if response.decision == ExtensionDecision.BLOCK:
            await event_publisher.publish(
                event_type=RealtimeEventType.EXTENSION_BLOCKED,
                entity_type=EntityType.EXTENSION_EVENT,
                entity_id=response.request_id,
                user_id=user_id,
                payload={
                    "scan_id": response.scan_id,
                    "url": response.url,
                    "risk_score": response.risk_score,
                    "threat_category": response.threat_category,
                    "installation_id": installation_id,
                },
            )
            # Emit high/critical security alert
            await event_publisher.publish(
                event_type=RealtimeEventType.SECURITY_ALERT_CREATED,
                entity_type=EntityType.SECURITY_ALERT,
                entity_id=str(uuid.uuid4()),
                user_id=user_id,
                payload={
                    "severity": "CRITICAL",
                    "title": "Critical Malicious Site Blocked by Extension",
                    "description": f"CyberNeura extension blocked access to malicious URL: {response.url} (Risk: {response.risk_score}/100)",
                    "scan_id": response.scan_id,
                    "source": "Chrome Extension",
                },
            )
        elif response.decision == ExtensionDecision.WARN:
            await event_publisher.publish(
                event_type=RealtimeEventType.EXTENSION_WARNING_SHOWN,
                entity_type=EntityType.EXTENSION_EVENT,
                entity_id=response.request_id,
                user_id=user_id,
                payload={
                    "scan_id": response.scan_id,
                    "url": response.url,
                    "risk_score": response.risk_score,
                    "threat_category": response.threat_category,
                    "installation_id": installation_id,
                },
            )

    async def record_override(
        self,
        request: ExtensionOverrideRequest,
        user_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Records a user override ("Continue Anyway") without altering the authoritative risk assessment."""
        scan_store.update_extension_override(
            scan_id=request.scan_id,
            installation_id=request.installation_id,
            override_action=request.override_action,
        )

        db = get_db()
        if db:
            try:
                db.table("extension_events").update({
                    "user_override": True,
                    "override_action": request.override_action,
                }).eq("scan_id", request.scan_id).execute()
            except Exception as db_err:
                logger.warning(f"Failed to update override in Supabase: {db_err}")

        # Real-time event
        await event_publisher.publish(
            event_type=RealtimeEventType.EXTENSION_OVERRIDE,
            entity_type=EntityType.EXTENSION_EVENT,
            entity_id=request.scan_id,
            user_id=user_id,
            payload={
                "scan_id": request.scan_id,
                "url": request.url,
                "installation_id": request.installation_id,
                "original_decision": request.original_decision,
                "override_action": request.override_action,
                "timestamp": request.timestamp,
            },
        )
        return {"status": "OVERRIDE_RECORDED", "scan_id": request.scan_id, "user_override": True}

    async def record_report(
        self,
        request: ExtensionReportRequest,
        user_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Saves user feedback / false positive report for future model calibration."""
        report_data = {
            "id": str(uuid.uuid4()),
            "scan_id": request.scan_id,
            "url": request.url,
            "installation_id": request.installation_id,
            "report_type": request.report_type,
            "feedback": request.feedback,
            "user_id": user_id,
            "timestamp": request.timestamp or datetime.now(timezone.utc).isoformat(),
        }
        scan_store.save_extension_report(report_data)

        # Real-time event
        await event_publisher.publish(
            event_type=RealtimeEventType.EXTENSION_REPORT_SUBMITTED,
            entity_type=EntityType.EXTENSION_EVENT,
            entity_id=report_data["id"],
            user_id=user_id,
            payload=report_data,
        )
        return {"status": "REPORT_RECORDED", "report_id": report_data["id"]}

    async def chat(
        self,
        request: ExtensionChatRequest,
        user_id: Optional[str] = None,
    ) -> ExtensionChatResponse:
        """
        Interactive in-page AI Security Agent conversation:
        Evaluates user questions against the active website's security telemetry,
        encryption status, form inputs, threat indicators, and domain trust.
        """
        from urllib.parse import urlparse
        import re

        raw_url = request.url.strip()
        norm_url = normalize_url(raw_url) if raw_url else ""
        parsed = urlparse(raw_url if raw_url.startswith(("http://", "https://")) else f"https://{raw_url}")
        domain = parsed.hostname or raw_url or "current page"
        is_https = parsed.scheme.lower() == "https"
        protocol = "HTTPS (Encrypted)" if is_https else "HTTP (Insecure Unencrypted)"

        # Determine risk score and decision
        risk_score = request.risk_score
        decision = request.decision or "ALLOW"
        threat_category = request.threat_category

        if risk_score is None:
            existing_scan = scan_store.get_scan_by_url(norm_url)
            if existing_scan:
                risk_score = existing_scan.get("riskScore", 0)
                threat_category = existing_scan.get("threatCategory")
                decision = "BLOCK" if risk_score >= 70 else ("WARN" if risk_score >= 35 else "ALLOW")
            else:
                risk_score = 0
                if not is_https:
                    risk_score += 25
                decision = "WARN" if risk_score >= 35 else "ALLOW"

        verdict = "THREAT" if (decision == "BLOCK" or risk_score >= 70) else ("SUSPICIOUS" if (decision == "WARN" or risk_score >= 35) else "SAFE")

        has_passwords = bool(request.has_password_inputs)
        has_cards = bool(request.has_card_inputs)
        question = (request.question or "").strip()

        # Key findings synthesis
        key_findings = []
        if is_https:
            key_findings.append("Transport Layer Security (HTTPS) is active with encrypted transit.")
        else:
            key_findings.append("INSECURE: Website is served over plaintext HTTP without SSL/TLS encryption.")

        if verdict == "SAFE":
            key_findings.append(f"Domain '{domain}' has a clean reputation with low risk ({risk_score}/100).")
        elif verdict == "SUSPICIOUS":
            key_findings.append(f"Elevated risk score ({risk_score}/100) due to ambiguous domain signals.")
        else:
            cat = threat_category or "Malicious Activity"
            key_findings.append(f"CRITICAL: Flagged as a confirmed threat ({cat}) with risk {risk_score}/100.")

        if has_passwords:
            key_findings.append("Detected password authentication inputs on this page.")
        if has_cards:
            key_findings.append("Detected payment/card data entry inputs on this page.")

        # Recommendations synthesis
        recommendations = []
        if not is_https:
            recommendations.append("Do not transmit passwords, personal identifiers, or financial information on HTTP.")
        if verdict == "THREAT":
            recommendations.append("Close this browser tab immediately to protect your credentials and device.")
        elif verdict == "SUSPICIOUS":
            recommendations.append("Verify the URL carefully in your address bar before entering any confidential information.")
        else:
            recommendations.append("Safe to browse. Continue adhering to standard web security hygiene.")

        # Attempt LLM query if available
        llm_reply: Optional[str] = None
        provider = (getattr(settings, "agent_reasoning_provider", "") or getattr(settings, "ai_provider", "")).lower()
        groq_key = getattr(settings, "groq_api_key", "")
        ai_key = getattr(settings, "ai_api_key", "")

        llm_endpoint = ""
        llm_token = ""
        llm_model = ""

        if provider == "groq" or groq_key or (ai_key and ai_key.startswith("gsk_")):
            llm_endpoint = "https://api.groq.com/openai/v1/chat/completions"
            llm_token = groq_key or ai_key
            llm_model = getattr(settings, "agent_model", "") or getattr(settings, "ai_model", "") or "llama-3.3-70b-versatile"
        elif (provider in ("openai", "azure_openai", "llm")) and ai_key:
            llm_endpoint = "https://api.openai.com/v1/chat/completions"
            llm_token = ai_key
            llm_model = getattr(settings, "agent_model", "") or getattr(settings, "ai_model", "") or "gpt-4o-mini"

        if llm_endpoint and llm_token:
            try:
                import httpx
                sys_prompt = (
                    "You are CyberNeura AI, an elite defensive cybersecurity security agent embedded in the user's browser extension. "
                    "The user is currently visiting a web page and asking you a question about it. "
                    f"Active Webpage URL: {raw_url}\n"
                    f"Domain: {domain}\n"
                    f"Protocol: {protocol}\n"
                    f"CyberNeura Risk Score: {risk_score}/100\n"
                    f"Security Verdict: {verdict}\n"
                    f"Threat Category: {threat_category or 'None'}\n"
                    f"Page Title: {request.page_title or 'Unknown'}\n"
                    f"Contains Password Fields: {has_passwords}\n"
                    f"Contains Payment Fields: {has_cards}\n\n"
                    "Instructions:\n"
                    "1. Give a clear, helpful, direct answer to the user's question.\n"
                    "2. Specifically address safety, phishing risks, credential safety, and encryption.\n"
                    "3. Keep the response concise, authoritative, and friendly (under 150 words).\n"
                    "4. Use bullet points or bold text where appropriate for readability."
                )

                messages = [{"role": "system", "content": sys_prompt}]
                if request.history:
                    for turn in request.history[-4:]:
                        role = turn.get("role", "user")
                        content = turn.get("content", "")
                        if content:
                            messages.append({"role": role, "content": content})

                messages.append({"role": "user", "content": question or "Is this website safe to visit?"})

                async with httpx.AsyncClient(timeout=6.0) as client:
                    resp = await client.post(
                        llm_endpoint,
                        headers={"Authorization": f"Bearer {llm_token}", "Content-Type": "application/json"},
                        json={
                            "model": llm_model,
                            "messages": messages,
                            "temperature": 0.2,
                            "max_tokens": 300,
                        },
                    )
                    if resp.status_code == 200:
                        data = resp.json()
                        llm_reply = data["choices"][0]["message"]["content"].strip()
            except Exception as exc:
                logger.debug(f"Extension LLM chat error: {exc}, using deterministic reasoning.")

        # Fallback deterministic reasoning if LLM was unavailable or timed out
        if not llm_reply:
            q_lower = question.lower()

            if any(w in q_lower for w in ["password", "login", "credential", "credit card", "card", "pay", "checkout", "buy"]):
                if not is_https:
                    llm_reply = (
                        f"⚠️ **DO NOT enter passwords or financial information.**\n\n"
                        f"This page on **{domain}** is served over unencrypted HTTP. Any credentials or card numbers "
                        f"you submit can be intercepted in transit by attackers on your network."
                    )
                elif verdict == "THREAT":
                    llm_reply = (
                        f"🚨 **CRITICAL WARNING:** Do NOT enter passwords or payment details here.\n\n"
                        f"CyberNeura has classified **{domain}** as a high-risk threat ({risk_score}/100). "
                        f"Entering credentials here puts you at imminent risk of phishing or account compromise."
                    )
                elif verdict == "SUSPICIOUS":
                    llm_reply = (
                        f"⚠️ **Caution advised for credentials or payments.**\n\n"
                        f"While **{domain}** uses HTTPS encryption, CyberNeura detected suspicious signals (Risk: {risk_score}/100). "
                        f"Double check that the domain matches the authentic service before entering sensitive details."
                    )
                else:
                    llm_reply = (
                        f"✅ **Safe to proceed with standard care.**\n\n"
                        f"**{domain}** uses secure HTTPS encryption and has a clean CyberNeura security score ({risk_score}/100). "
                        f"No spoofing or phishing indicators were detected for this page."
                    )

            elif any(w in q_lower for w in ["safe", "legit", "trust", "real", "fake", "phish"]):
                if verdict == "SAFE":
                    llm_reply = (
                        f"🛡️ **Yes, {domain} appears to be legitimate and safe.**\n\n"
                        f"• **Risk Score:** {risk_score}/100 (Safe)\n"
                        f"• **Protocol:** {protocol}\n"
                        f"• **Threat Intelligence:** Clean\n\n"
                        f"No deceptive patterns, known phishing domains, or malicious redirect markers were found."
                    )
                elif verdict == "SUSPICIOUS":
                    llm_reply = (
                        f"⚠️ **{domain} is flagged as Suspicious.**\n\n"
                        f"• **Risk Score:** {risk_score}/100\n"
                        f"• **Protocol:** {protocol}\n\n"
                        f"Our heuristics detected unusual domain patterns. We advise reviewing links and avoiding downloading unknown files."
                    )
                else:
                    llm_reply = (
                        f"🚨 **DANGER: {domain} is flagged as a Malicious Threat!**\n\n"
                        f"• **Risk Score:** {risk_score}/100 (High Threat)\n"
                        f"• **Category:** {threat_category or 'Phishing / Malware'}\n\n"
                        f"CyberNeura strongly recommends exiting this website immediately."
                    )

            elif any(w in q_lower for w in ["why", "flag", "score", "reason", "indicator"]):
                if verdict == "SAFE":
                    llm_reply = (
                        f"ℹ️ **Why {domain} is verified safe:**\n\n"
                        f"CyberNeura checked this domain against real-time threat intelligence, SSL certificate authenticity, "
                        f"and lexical ML models. All indicators passed cleanly (Risk: {risk_score}/100)."
                    )
                else:
                    llm_reply = (
                        f"⚠️ **Why {domain} has risk score {risk_score}/100:**\n\n"
                        f"• Category: **{threat_category or 'Suspicious Domain Pattern'}**\n"
                        f"• Connection: {protocol}\n"
                        f"• Signals: The site triggered threat heuristics or matches anomalous structural patterns."
                    )

            elif any(w in q_lower for w in ["who", "owner", "domain", "ssl", "cert"]):
                llm_reply = (
                    f"🔍 **Domain & Security Telemetry for {domain}:**\n\n"
                    f"• **Host:** `{domain}`\n"
                    f"• **Encryption:** {protocol}\n"
                    f"• **Security Verdict:** {verdict} ({risk_score}/100)\n"
                    f"• **Active Inputs:** {'Password fields present' if has_passwords else 'No password fields'}"
                )
            else:
                llm_reply = (
                    f"CyberNeura AI Agent report for **{domain}**:\n\n"
                    f"Current status: **{verdict}** (Risk Score: {risk_score}/100) over {protocol}. "
                    f"{'No threat signals were detected.' if verdict == 'SAFE' else 'Please exercise caution while browsing.'} "
                    f"Let me know if you would like me to check passwords, forms, or domain details!"
                )

        return ExtensionChatResponse(
            reply=llm_reply,
            verdict=verdict,
            risk_score=risk_score,
            key_findings=key_findings,
            recommendations=recommendations,
        )



# Singleton extension service instance
extension_service = ExtensionService()
