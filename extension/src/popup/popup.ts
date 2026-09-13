/**
 * Popup Interface Controller for CyberNeura Chrome Extension.
 * Displays live risk status, confidence, threat categories, and quick actions.
 */

import { extractDisplayDomain } from '../security/url-normalizer';
import { TabStatusResponse } from '../messaging/messages';
import { storageManager } from '../storage/storage';
import { apiClient } from '../api/client';

document.addEventListener('DOMContentLoaded', async () => {
  const domainText = document.getElementById('domainText');
  const riskVal = document.getElementById('riskVal');
  const statusVal = document.getElementById('statusVal');
  const confidenceVal = document.getElementById('confidenceVal');
  const meterFill = document.getElementById('meterFill');
  const summaryText = document.getElementById('summaryText');
  const categoryVal = document.getElementById('categoryVal');
  const liveBadge = document.getElementById('liveBadge');
  const badgeText = document.getElementById('badgeText');
  const backendStatus = document.getElementById('backendStatus');

  const refreshBtn = document.getElementById('refreshBtn');
  const dashboardBtn = document.getElementById('dashboardBtn');
  const reportBtn = document.getElementById('reportBtn');
  const closeReportBtn = document.getElementById('closeReportBtn');
  const reportDrawer = document.getElementById('reportDrawer');
  const submitReportBtn = document.getElementById('submitReportBtn');
  const reportTypeSelect = document.getElementById('reportTypeSelect') as HTMLSelectElement;
  const reportFeedbackText = document.getElementById('reportFeedbackText') as HTMLTextAreaElement;
  const settingsBtn = document.getElementById('settingsBtn');

  let currentTabStatus: TabStatusResponse | null = null;

  // 1. Fetch current tab security status from service-worker
  chrome.runtime.sendMessage({ type: 'GET_TAB_STATUS' }, (status: TabStatusResponse) => {
    currentTabStatus = status;
    if (!status || !status.url) {
      if (domainText) domainText.textContent = 'No active webpage';
      return;
    }

    const domain = extractDisplayDomain(status.url);
    if (domainText) domainText.textContent = domain;

    const riskScore = status.riskScore || 0;
    const decision = status.decision || 'ALLOW';
    const confidence = status.confidence ? `${Math.round(status.confidence)}%` : '85%';

    if (riskVal) {
      riskVal.textContent = `${riskScore} / 100`;
      riskVal.className = 'metric-val ' + (riskScore >= 70 ? 'text-red' : riskScore >= 30 ? 'text-amber' : 'text-green');
    }

    if (meterFill) {
      meterFill.style.width = `${Math.min(100, Math.max(5, riskScore))}%`;
      meterFill.style.backgroundColor = riskScore >= 70 ? '#ef4444' : riskScore >= 30 ? '#f59e0b' : '#10b981';
    }

    if (statusVal) {
      statusVal.textContent = status.prediction || (riskScore >= 70 ? 'MALICIOUS' : riskScore >= 30 ? 'SUSPICIOUS' : 'SAFE');
      statusVal.className = 'metric-val ' + (riskScore >= 70 ? 'text-red' : riskScore >= 30 ? 'text-amber' : 'text-green');
    }

    if (confidenceVal) confidenceVal.textContent = confidence;
    if (categoryVal) categoryVal.textContent = status.threatCategory || (riskScore >= 30 ? 'Suspicious URL' : 'Safe');

    if (summaryText) {
      summaryText.textContent = status.summary || (decision === 'BLOCK' ? 'Malicious threat blocked by CyberNeura.' : decision === 'WARN' ? 'Suspicious characteristics detected.' : 'Legitimate verified web resource.');
    }

    // Badge formatting
    if (liveBadge && badgeText) {
      if (decision === 'BLOCK') {
        liveBadge.className = 'status-badge block';
        badgeText.textContent = 'Blocked';
      } else if (decision === 'WARN') {
        liveBadge.className = 'status-badge warn';
        badgeText.textContent = 'Suspicious';
      } else {
        liveBadge.className = 'status-badge';
        badgeText.textContent = 'Protected';
      }
    }
  });

  // 2. Check Backend Server Health
  chrome.runtime.sendMessage({ type: 'CHECK_BACKEND_STATUS' }, (res) => {
    if (backendStatus) {
      if (res && res.online) {
        backendStatus.textContent = '● Backend Connected';
        backendStatus.style.color = '#10b981';
      } else {
        backendStatus.textContent = '○ Backend Offline (Fallback)';
        backendStatus.style.color = '#f59e0b';
      }
    }
  });

  // 3. Quick Action Button Handlers
  if (refreshBtn) {
    refreshBtn.addEventListener('click', () => {
      refreshBtn.textContent = '⏳ Scanning...';
      chrome.runtime.sendMessage({ type: 'TRIGGER_RESCAN' }, () => {
        setTimeout(() => window.location.reload(), 1200);
      });
    });
  }

  if (dashboardBtn) {
    dashboardBtn.addEventListener('click', async () => {
      const settings = await storageManager.getSettings();
      const dashboardBase = settings.backendUrl.replace(':8000', ':5173');
      chrome.tabs.create({ url: `${dashboardBase}/extension` });
    });
  }

  if (reportBtn && reportDrawer) {
    reportBtn.addEventListener('click', () => {
      reportDrawer.classList.toggle('hidden');
    });
  }

  if (closeReportBtn && reportDrawer) {
    closeReportBtn.addEventListener('click', () => {
      reportDrawer.classList.add('hidden');
    });
  }

  if (submitReportBtn && reportTypeSelect && reportFeedbackText && reportDrawer) {
    submitReportBtn.addEventListener('click', async () => {
      if (!currentTabStatus || !currentTabStatus.url) return;

      submitReportBtn.textContent = 'Sending...';
      submitReportBtn.setAttribute('disabled', 'true');

      const installId = await storageManager.getInstallationId();
      const reportType = reportTypeSelect.value as any;
      const feedback = reportFeedbackText.value.trim() || 'User submitted feedback via extension popup';

      await apiClient.submitReport({
        scan_id: currentTabStatus.scanId || 'ext-popup',
        url: currentTabStatus.url,
        installation_id: installId,
        report_type: reportType,
        feedback,
      });

      submitReportBtn.textContent = '✓ Reported';
      setTimeout(() => {
        reportDrawer.classList.add('hidden');
        submitReportBtn.textContent = 'Submit Feedback';
        submitReportBtn.removeAttribute('disabled');
        reportFeedbackText.value = '';
      }, 1500);
    });
  }

  if (settingsBtn) {
    settingsBtn.addEventListener('click', () => {
      chrome.runtime.openOptionsPage();
    });
  }
});
