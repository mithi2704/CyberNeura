/**
 * Interstitial Page Controller for CyberNeura Chrome Extension.
 * Renders verified threat evidence without executing remote scripts or iframes.
 */

import { apiClient } from '../api/client';
import { storageManager } from '../storage/storage';

function getQueryParams(): Record<string, string> {
  const params = new URLSearchParams(window.location.search);
  const result: Record<string, string> = {};
  params.forEach((value, key) => {
    result[key] = value;
  });
  return result;
}

document.addEventListener('DOMContentLoaded', async () => {
  const params = getQueryParams();
  const rawUrl = params.url || 'Unknown Target URL';
  const decision = (params.decision || 'BLOCK').toUpperCase();
  const riskScore = parseInt(params.risk || '85', 10);
  const threatCategory = (params.threat || 'Malicious Website').toUpperCase();
  const confidence = params.confidence || '90';
  const scanId = params.scanId || '';
  const allowOverride = params.allowOverride === 'true' || decision === 'WARN';

  const threatCard = document.getElementById('threatCard');
  const threatIcon = document.getElementById('threatIcon');
  const threatTitle = document.getElementById('threatTitle');
  const riskPill = document.getElementById('riskPill');
  const urlDisplay = document.getElementById('urlDisplay');
  const threatCategoryEl = document.getElementById('threatCategory');
  const confidenceVal = document.getElementById('confidenceVal');
  const decisionPolicy = document.getElementById('decisionPolicy');
  const reasonsList = document.getElementById('reasonsList');
  const recsList = document.getElementById('recsList');
  const goBackBtn = document.getElementById('goBackBtn');
  const continueBtn = document.getElementById('continueBtn');
  const viewDashboardBtn = document.getElementById('viewDashboardBtn');

  // Populate dynamic metadata
  if (urlDisplay) urlDisplay.textContent = rawUrl;
  if (riskPill) riskPill.textContent = `Risk: ${riskScore} / 100`;
  if (threatCategoryEl) threatCategoryEl.textContent = threatCategory;
  if (confidenceVal) confidenceVal.textContent = `${confidence}%`;

  if (decision === 'WARN') {
    if (threatCard) threatCard.classList.add('warn-mode');
    if (threatIcon) threatIcon.textContent = '⚠️';
    if (threatTitle) threatTitle.textContent = 'CyberNeura Security Warning';
    if (decisionPolicy) decisionPolicy.textContent = 'SUSPICIOUS WARNING';
  } else {
    if (threatIcon) threatIcon.textContent = '🛑';
    if (threatTitle) threatTitle.textContent = 'CyberNeura Blocked This Website';
    if (decisionPolicy) decisionPolicy.textContent = 'MALICIOUS THREAT BLOCK';
  }

  // Populate parsed reasons if provided
  if (params.reasons && reasonsList) {
    try {
      const parsedReasons = JSON.parse(decodeURIComponent(params.reasons));
      if (Array.isArray(parsedReasons) && parsedReasons.length > 0) {
        reasonsList.innerHTML = '';
        parsedReasons.forEach((r: string) => {
          const li = document.createElement('li');
          li.textContent = r;
          reasonsList.appendChild(li);
        });
      }
    } catch {
      // Keep default template reasons
    }
  }

  // Show or hide "Continue Anyway" button based on policy
  if (continueBtn && allowOverride) {
    continueBtn.classList.remove('hidden');
    continueBtn.addEventListener('click', async () => {
      continueBtn.setAttribute('disabled', 'true');
      continueBtn.textContent = 'Authorizing Bypass...';

      const installId = await storageManager.getInstallationId();

      // Record override with backend
      if (scanId) {
        await apiClient.recordOverride({
          scan_id: scanId,
          url: rawUrl,
          installation_id: installId,
          original_decision: decision as any,
          override_action: 'CONTINUE_ANYWAY',
          timestamp: new Date().toISOString(),
        });
      }

      // Mark exemption in session storage so service-worker won't re-intercept
      try {
        const exemptKey = `exempt:${rawUrl}`;
        await chrome.storage.local.set({ [exemptKey]: Date.now() + 60000 }); // 60s bypass grace window
      } catch (e) {
        console.warn('Could not store exemption:', e);
      }

      // Navigate to destination
      window.location.href = rawUrl;
    });
  }

  // Go Back
  if (goBackBtn) {
    goBackBtn.addEventListener('click', () => {
      if (window.history.length > 1) {
        window.history.back();
      } else {
        window.close();
      }
    });
  }

  // Open Dashboard
  if (viewDashboardBtn) {
    viewDashboardBtn.addEventListener('click', async () => {
      const settings = await storageManager.getSettings();
      chrome.tabs.create({ url: `${settings.backendUrl.replace(':8000', ':5173')}/logs` });
    });
  }
});
