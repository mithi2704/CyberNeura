/**
 * Native Chrome Notifications Controller for CyberNeura Extension.
 * Dispatches alerts strictly for high and critical threats without spamming users.
 */

import { storageManager } from '../storage/storage';

export async function showThreatNotification(
  title: string,
  message: string,
  threatType: string = 'Threat Alert'
): Promise<void> {
  const settings = await storageManager.getSettings();
  if (!settings.notificationsEnabled) return;

  try {
    const iconUrl = chrome.runtime.getURL('icons/icon-128.png');
    await chrome.notifications.create(`threat-${Date.now()}`, {
      type: 'basic',
      iconUrl,
      title: `CyberNeura: ${title}`,
      message: `${threatType.toUpperCase()} — ${message}`,
      priority: 2,
    });
  } catch (err) {
    console.debug('Notification create fallback:', err);
  }
}
