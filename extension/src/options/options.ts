/**
 * Options and Preferences Controller for CyberNeura Chrome Extension.
 */

import { storageManager } from '../storage/storage';
import { apiClient } from '../api/client';

document.addEventListener('DOMContentLoaded', async () => {
  const protectionToggle = document.getElementById('protectionToggle') as HTMLInputElement;
  const strictModeSelect = document.getElementById('strictModeSelect') as HTMLSelectElement;
  const notificationsToggle = document.getElementById('notificationsToggle') as HTMLInputElement;
  const backendUrlInput = document.getElementById('backendUrlInput') as HTMLInputElement;
  const authTokenInput = document.getElementById('authTokenInput') as HTMLInputElement;
  const saveBtn = document.getElementById('saveBtn');
  const clearCacheBtn = document.getElementById('clearCacheBtn');
  const saveToast = document.getElementById('saveToast');
  const connectionStatus = document.getElementById('connectionStatus');

  // 1. Populate initial form state from storage
  const settings = await storageManager.getSettings();
  if (protectionToggle) protectionToggle.checked = settings.protectionEnabled;
  if (strictModeSelect) strictModeSelect.value = settings.strictMode ? 'true' : 'false';
  if (notificationsToggle) notificationsToggle.checked = settings.notificationsEnabled;
  if (backendUrlInput) backendUrlInput.value = settings.backendUrl || 'http://localhost:8000';
  if (authTokenInput && settings.authToken) authTokenInput.value = settings.authToken;

  // 2. Health check
  try {
    const status = await apiClient.getStatus();
    if (connectionStatus) {
      connectionStatus.textContent = `● Connected (${status.service} v${status.policy_version})`;
      connectionStatus.style.color = '#10b981';
    }
  } catch {
    if (connectionStatus) {
      connectionStatus.textContent = '○ Backend Unreachable (Fallback Mode)';
      connectionStatus.style.color = '#f59e0b';
    }
  }

  // 3. Save Settings Handler
  if (saveBtn) {
    saveBtn.addEventListener('click', async () => {
      saveBtn.textContent = 'Saving...';
      const updated = await storageManager.saveSettings({
        protectionEnabled: protectionToggle.checked,
        strictMode: strictModeSelect.value === 'true',
        notificationsEnabled: notificationsToggle.checked,
        backendUrl: backendUrlInput.value.trim() || 'http://localhost:8000',
        authToken: authTokenInput.value.trim() || null,
      });

      saveBtn.textContent = 'Save Preferences';
      if (saveToast) {
        saveToast.classList.remove('hidden');
        setTimeout(() => saveToast.classList.add('hidden'), 2500);
      }
    });
  }

  // 4. Clear Cache Handler
  if (clearCacheBtn) {
    clearCacheBtn.addEventListener('click', async () => {
      await storageManager.clearCache();
      clearCacheBtn.textContent = '✓ Cache Cleared';
      setTimeout(() => {
        clearCacheBtn.textContent = 'Clear Local Cache';
      }, 1500);
    });
  }
});
