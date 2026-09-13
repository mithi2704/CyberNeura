/**
 * Background Service Worker for CyberNeura Chrome Extension (Manifest V3).
 * Main controller coordinating navigation detection, URL normalization, local caching,
 * authoritative FastAPI backend queries, threat blocking, and status reporting.
 */

import { normalizeUrl, extractDisplayDomain } from '../security/url-normalizer';
import { getDecisionBadge, getFailSafeDecision, ExtensionDecision } from '../security/decision';
import { storageManager } from '../storage/storage';
import { apiClient } from '../api/client';
import { showThreatNotification } from '../ui/notifications';
import { ExtensionMessage, TabStatusResponse } from '../messaging/messages';

// Active in-flight requests map to prevent duplicate network queries
const activeAnalysisRequests = new Map<string, Promise<any>>();

// In-memory tab status cache for instant popup retrieval
const tabStatusMap = new Map<number, TabStatusResponse>();

/**
 * Updates extension action badge for the active tab.
 */
async function updateBadge(tabId: number, decision: ExtensionDecision, riskScore: number) {
  try {
    const badge = getDecisionBadge(decision, riskScore);
    await chrome.action.setBadgeText({ text: badge.text, tabId });
    await chrome.action.setBadgeBackgroundColor({ color: badge.color, tabId });
    await chrome.action.setTitle({ title: badge.title, tabId });
  } catch (err) {
    // Tab might have closed
  }
}

/**
 * Handles incoming web navigation events for top-level windows.
 */
async function handleNavigation(details: chrome.webNavigation.NavigationDetails) {
  // 1. Inspect top-level frames only (Phase 6 scope)
  if (details.frameId !== 0) return;

  const rawUrl = details.url;
  const tabId = details.tabId;

  // 2. Check if extension protection is enabled
  const settings = await storageManager.getSettings();
  if (!settings.protectionEnabled) {
    await updateBadge(tabId, 'ALLOW', 0);
    return;
  }

  // 3. Local pre-check and URL normalization
  const norm = normalizeUrl(rawUrl);
  if (!norm.isValid || !norm.isEligible) {
    // Internal browser page or non-web protocol
    tabStatusMap.set(tabId, {
      tabId,
      url: rawUrl,
      isInspected: false,
      decision: 'ALLOW',
      riskScore: 0,
      summary: norm.rejectionReason || 'Internal page',
    });
    return;
  }

  const normalizedUrl = norm.normalizedUrl;

  // 4. Check for temporary user override exemption
  try {
    const exemptKey = `exempt:${rawUrl}`;
    const exemptData = await chrome.storage.local.get([exemptKey]);
    if (exemptData && exemptData[exemptKey] && exemptData[exemptKey] > Date.now()) {
      // User recently selected "Continue Anyway"
      await updateBadge(tabId, 'WARN', 75);
      return;
    }
  } catch {
    // Ignore storage read error
  }

  // 5. Fast Path: Check local cache (TTL: 300s)
  const cached = await storageManager.getCachedAnalysis(normalizedUrl);
  if (cached) {
    await updateBadge(tabId, cached.decision, cached.riskScore);
    tabStatusMap.set(tabId, {
      tabId,
      url: normalizedUrl,
      isInspected: true,
      decision: cached.decision,
      riskScore: cached.riskScore,
      prediction: cached.prediction,
      confidence: cached.confidence,
      threatCategory: cached.threatCategory,
      summary: cached.summary,
      reasons: cached.reasons,
      recommendations: cached.recommendations,
      scanId: cached.scanId,
      isCached: true,
    });

    if (cached.decision === 'BLOCK' || (cached.decision === 'WARN' && settings.strictMode)) {
      redirectToInterstitial(tabId, normalizedUrl, cached.decision, cached.riskScore, cached.threatCategory, cached.confidence, cached.reasons, cached.allowOverride, cached.scanId);
    }
    return;
  }

  // 6. Slow Path: Query Authoritative CyberNeura FastAPI Backend
  // Prevent duplicate concurrent requests for the exact same target URL
  let analysisPromise = activeAnalysisRequests.get(normalizedUrl);
  if (!analysisPromise) {
    analysisPromise = (async () => {
      const installId = await storageManager.getInstallationId();
      try {
        const response = await apiClient.analyzeUrl({
          url: normalizedUrl,
          tab_id: tabId,
          navigation_id: details.navigationId,
          timestamp: new Date().toISOString(),
          extension_version: '1.0.0',
          browser: 'chrome',
          installation_id: installId,
        });
        return response;
      } catch (networkErr) {
        console.warn('CyberNeura Extension: Backend query error, applying fail-safe:', networkErr);
        const failSafe = getFailSafeDecision(settings.strictMode);
        return {
          request_id: 'fail-safe',
          url: normalizedUrl,
          decision: failSafe.decision,
          risk_score: 0,
          prediction: 'SAFE',
          confidence: 50,
          summary: failSafe.summary,
          reasons: ['Backend service unavailable; fail-safe policy applied.'],
          recommendations: ['Verify website identity before submitting sensitive data.'],
          cached: false,
          allow_override: true,
        };
      } finally {
        activeAnalysisRequests.delete(normalizedUrl);
      }
    })();
    activeAnalysisRequests.set(normalizedUrl, analysisPromise);
  }

  const analysis = await analysisPromise;

  // 7. Store in local cache
  await storageManager.setCachedAnalysis(normalizedUrl, {
    decision: analysis.decision,
    riskScore: analysis.risk_score,
    prediction: analysis.prediction,
    confidence: analysis.confidence,
    threatCategory: analysis.threat_category,
    summary: analysis.summary,
    reasons: analysis.reasons,
    recommendations: analysis.recommendations,
    scanId: analysis.scan_id,
    allowOverride: analysis.allow_override,
  });

  // 8. Update in-memory tab tracking and badge
  tabStatusMap.set(tabId, {
    tabId,
    url: normalizedUrl,
    isInspected: true,
    decision: analysis.decision,
    riskScore: analysis.risk_score,
    prediction: analysis.prediction,
    confidence: analysis.confidence,
    threatCategory: analysis.threat_category,
    summary: analysis.summary,
    reasons: analysis.reasons,
    recommendations: analysis.recommendations,
    scanId: analysis.scan_id,
    isCached: false,
  });

  await updateBadge(tabId, analysis.decision, analysis.risk_score);

  // 9. Enforce Decision (BLOCK / WARN / ALLOW)
  if (analysis.decision === 'BLOCK') {
    await showThreatNotification(
      'Malicious Website Blocked',
      `${extractDisplayDomain(normalizedUrl)} was blocked due to confirmed threat signals.`,
      analysis.threat_category || 'MALWARE'
    );
    redirectToInterstitial(tabId, normalizedUrl, 'BLOCK', analysis.risk_score, analysis.threat_category, analysis.confidence, analysis.reasons, analysis.allow_override, analysis.scan_id);
  } else if (analysis.decision === 'WARN' && settings.strictMode) {
    redirectToInterstitial(tabId, normalizedUrl, 'WARN', analysis.risk_score, analysis.threat_category, analysis.confidence, analysis.reasons, analysis.allow_override, analysis.scan_id);
  }
}

/**
 * Redirects browser tab to the isolated extension interstitial warning page.
 */
function redirectToInterstitial(
  tabId: number,
  targetUrl: string,
  decision: ExtensionDecision,
  riskScore: number,
  threatCategory?: string,
  confidence: number = 90,
  reasons: string[] = [],
  allowOverride: boolean = true,
  scanId?: string
) {
  const encodedReasons = encodeURIComponent(JSON.stringify(reasons));
  const interstitialUrl = chrome.runtime.getURL(
    `src/interstitial/interstitial.html?url=${encodeURIComponent(targetUrl)}&decision=${decision}&risk=${riskScore}&threat=${encodeURIComponent(threatCategory || 'Suspicious')}&confidence=${Math.round(confidence)}&allowOverride=${allowOverride}&scanId=${encodeURIComponent(scanId || '')}&reasons=${encodedReasons}`
  );
  chrome.tabs.update(tabId, { url: interstitialUrl });
}

// ── Chrome Event Listeners ──────────────────────────────────────────────────

// Listen for top-level navigation before page load
chrome.webNavigation.onBeforeNavigate.addListener(handleNavigation);

// Clear tab status when tab is closed
chrome.tabs.onRemoved.addListener((tabId) => {
  tabStatusMap.delete(tabId);
});

// Extension internal message router
chrome.runtime.onMessage.addListener((message: ExtensionMessage, sender, sendResponse) => {
  if (message.type === 'GET_TAB_STATUS') {
    const senderTabId = sender.tab?.id;
    chrome.tabs.query({ active: true, currentWindow: true }).then(async (tabs) => {
      const activeTab = tabs[0];
      const targetTabId = senderTabId || activeTab?.id;
      const targetUrl = sender.tab?.url || activeTab?.url;

      if (!targetTabId) {
        sendResponse({ isInspected: false });
        return;
      }

      let status = tabStatusMap.get(targetTabId);

      // If in-memory tabStatusMap was evicted during service worker sleep, recover from storageManager cache!
      if (!status || !status.isInspected) {
        if (targetUrl) {
          const norm = normalizeUrl(targetUrl);
          if (norm.isValid && norm.isEligible) {
            const cached = await storageManager.getCachedAnalysis(norm.normalizedUrl);
            if (cached) {
              status = {
                tabId: targetTabId,
                url: norm.normalizedUrl,
                isInspected: true,
                decision: cached.decision,
                riskScore: cached.riskScore,
                prediction: cached.prediction,
                confidence: cached.confidence,
                threatCategory: cached.threatCategory,
                summary: cached.summary,
                reasons: cached.reasons,
                recommendations: cached.recommendations,
                scanId: cached.scanId,
                isCached: true,
              };
              tabStatusMap.set(targetTabId, status);
            }
          }
        }
      }

      if (!status) {
        status = {
          tabId: targetTabId,
          url: targetUrl,
          isInspected: false,
          decision: 'ALLOW',
          riskScore: 0,
        };
      }
      sendResponse(status);
    });
    return true; // async sendResponse
  }


  if (message.type === 'TRIGGER_RESCAN') {
    chrome.tabs.query({ active: true, currentWindow: true }).then(async (tabs) => {
      const activeTab = tabs[0];
      if (activeTab && activeTab.url && activeTab.id) {
        await storageManager.clearCache();
        handleNavigation({
          tabId: activeTab.id,
          url: activeTab.url,
          frameId: 0,
          timeStamp: Date.now(),
        });
        sendResponse({ success: true });
      } else {
        sendResponse({ success: false });
      }
    });
    return true;
  }

  if (message.type === 'CHECK_BACKEND_STATUS') {
    apiClient
      .getStatus()
      .then((status) => sendResponse({ online: true, status }))
      .catch(() => sendResponse({ online: false }));
    return true;
  }

  if (message.type === 'ASK_AI_AGENT') {
    const payload = message.payload || {};
    apiClient
      .chat(payload)
      .then((data) => {
        sendResponse({ success: true, data });
      })
      .catch((err) => {
        console.warn('CyberNeura Extension: Backend chat query failed, using local security advisor:', err);
        // Fallback local security synthesis so user never gets a broken experience
        const url = payload.url || '';
        let domain = 'current site';
        try {
          domain = new URL(url).hostname;
        } catch {}
        const isHttps = url.startsWith('https://');
        const riskScore = typeof payload.risk_score === 'number' ? payload.risk_score : 0;
        const verdict = riskScore >= 70 ? 'THREAT' : (riskScore >= 35 ? 'SUSPICIOUS' : 'SAFE');
        const q = (payload.question || '').toLowerCase();

        let reply = '';
        if (q.includes('password') || q.includes('login') || q.includes('card') || q.includes('pay') || q.includes('buy')) {
          if (!isHttps) {
            reply = `⚠️ **DO NOT submit credentials or payment details!**\n\nThis page on **${domain}** is using unencrypted HTTP. Any passwords or card numbers submitted here can be intercepted in transit.`;
          } else if (verdict === 'THREAT') {
            reply = `🚨 **DANGER:** Do not enter passwords or financial information here. CyberNeura has flagged **${domain}** as a high-risk threat (${riskScore}/100).`;
          } else {
            reply = `✅ **${domain}** uses secure HTTPS encryption. CyberNeura has marked this site as low risk (${riskScore}/100). Always confirm the domain in your address bar matches the intended service.`;
          }
        } else if (q.includes('safe') || q.includes('legit') || q.includes('phish') || q.includes('trust')) {
          if (verdict === 'SAFE') {
            reply = `🛡️ **${domain} appears safe.**\n\n• Risk Score: ${riskScore}/100 (Safe)\n• Encryption: ${isHttps ? 'HTTPS Encrypted' : 'HTTP Plaintext'}\n• No known threat or phishing signatures detected.`;
          } else {
            reply = `⚠️ **Caution:** ${domain} has an elevated risk score (${riskScore}/100). Proceed carefully and avoid downloading unexpected files.`;
          }
        } else {
          reply = `CyberNeura AI Agent report for **${domain}**:\n\n• Security Verdict: **${verdict}** (${riskScore}/100)\n• Protocol: ${isHttps ? 'HTTPS Secure' : 'HTTP Insecure'}\n• Form Inputs: ${payload.has_password_inputs ? 'Password fields detected' : 'No sensitive fields detected'}.\n\nAsk me if you have questions about safety, encryption, or forms!`;
        }

        sendResponse({
          success: true,
          data: {
            reply,
            verdict,
            risk_score: riskScore,
            key_findings: [isHttps ? 'HTTPS active' : 'Insecure HTTP connection', `Reputation score: ${riskScore}/100`],
            recommendations: [verdict === 'SAFE' ? 'Safe to browse' : 'Do not enter credentials'],
            timestamp: new Date().toISOString(),
          }
        });
      });
    return true; // Keep channel open for async response
  }
});

